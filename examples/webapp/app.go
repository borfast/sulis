package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"

	"github.com/borfast/sulis"
	"github.com/borfast/sulis/passkey"
	"github.com/borfast/sulis/recovery"
	"github.com/borfast/sulis/store/sql/sqlite"
	"github.com/borfast/sulis/totp"
)

// templateFS embeds the page templates so `go run .` works from any
// directory, not just examples/webapp.
//
//go:embed templates/*.html
var templateFS embed.FS

// staticFS embeds the static assets for the same reason.
//
//go:embed static
var staticFS embed.FS

// staticFiles is staticFS rebased so its root is the static directory's
// contents rather than the directory itself, ready to serve at /static/.
var staticFiles = func() fs.FS {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		// static/ is embedded above, so this can only fail if the embed
		// directive itself is broken, which would already fail the build.
		panic(err)
	}
	return sub
}()

// app holds every dependency the HTTP handlers need: the sulis service, its
// three second-factor services, direct access to the user store, the
// database handle (for cleanup and shutdown), parsed templates, a logger,
// and the base URL used to build absolute links.
type app struct {
	auth     *sulis.Sulis
	totp     *totp.Service
	passkeys *passkey.Service
	recovery *recovery.Service
	users    *sqlite.UserStore
	db       *sqlite.DB
	mail     *outbox
	tmpl     *template.Template
	log      *slog.Logger
	baseURL  string // http(s)://localhost:PORT, from -addr and -tls
}

// secondFactors answers sulis.SecondFactorChecker by consulting the TOTP and
// passkey stores directly. sulis.New needs this answer before the totp and
// passkey services exist, so it cannot go through them.
type secondFactors struct {
	totp     *sqlite.TOTPStore
	passkeys *sqlite.PasskeyStore
}

// HasSecondFactor reports true when the user has a verified TOTP credential
// or at least one passkey. A not-found result from either store means "no
// factor", not an error; any other error propagates.
func (f secondFactors) HasSecondFactor(ctx context.Context, userID string) (bool, error) {
	_, err := f.totp.GetActiveTOTP(ctx, userID)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, totp.ErrTOTPNotEnrolled):
		// No TOTP credential. Fall through to the passkey check.
	default:
		return false, err
	}

	creds, err := f.passkeys.GetCredentialsByUserID(ctx, userID)
	if err != nil {
		return false, err
	}
	return len(creds) > 0, nil
}

// newApp opens and migrates the SQLite database, wires the sulis service
// and its three second-factor services, and parses the templates. It does
// not start the background cleanup loop; main starts that, so tests that
// build an app directly never start it.
func newApp(ctx context.Context, dsn, baseURL string, logger *slog.Logger) (*app, error) {
	db, err := sqlite.Open(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	if err := sqlite.Migrate(ctx, db.SQL()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrating database: %w", err)
	}

	factors := secondFactors{totp: db.TOTPStore(), passkeys: db.PasskeyStore()}

	auth, err := sulis.New(db.UserStore(), db.SessionStore(), db.TokenStore(), factors,
		sulis.WithEventSink(sulis.NewSlogSink(logger)))
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("creating sulis service: %w", err)
	}

	// sulis.MemoryLimiter satisfies totp.Limiter and recovery.Limiter too
	// (they are structurally identical), so one instance can rate-limit
	// TOTP code checks the same way sulis.New's own default limiter guards
	// login.
	limiter := sulis.NewMemoryLimiter()

	// WithoutSecretEncryption: this demo has no key management story, and
	// NewService requires an explicit choice either way. A real deployment
	// should pass WithEncryptor instead.
	totpSvc, err := totp.NewService(db.TOTPStore(), "Sulis Example",
		totp.WithLimiter(limiter), totp.WithoutSecretEncryption())
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("creating totp service: %w", err)
	}

	passkeySvc, err := passkey.NewService(db.PasskeyStore(), db.ChallengeStore(), passkey.WebAuthnConfig{
		RPDisplayName: "Sulis Example",
		RPID:          "localhost",
		RPOrigins:     []string{baseURL},
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("creating passkey service: %w", err)
	}

	recoverySvc, err := recovery.NewService(db.RecoveryStore())
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("creating recovery service: %w", err)
	}

	tmpl, err := template.ParseFS(templateFS, "templates/base.html")
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("parsing base template: %w", err)
	}

	return &app{
		auth:     auth,
		totp:     totpSvc,
		passkeys: passkeySvc,
		recovery: recoverySvc,
		users:    db.UserStore(),
		db:       db,
		mail:     &outbox{},
		tmpl:     tmpl,
		log:      logger,
		baseURL:  baseURL,
	}, nil
}

// routes builds the app's HTTP handler.
func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.handleHome)
	mux.HandleFunc("GET /healthz", a.handleHealthz)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticFiles)))

	mux.HandleFunc("GET /register", a.handleRegisterForm)
	mux.HandleFunc("GET /login", a.handleLoginForm)
	mux.HandleFunc("GET /verify", a.handleVerify)
	mux.HandleFunc("GET /dev/mailbox", a.handleMailbox)
	mux.Handle("GET /account", a.requireAuth(a.handleAccount))

	// postMux carries every state-changing route. RequireSameOrigin and
	// RequireCSRFToken both only act on unsafe methods (POST here), so
	// mounting them once at "POST /" protects every route below without
	// repeating the wiring per handler.
	postMux := http.NewServeMux()
	postMux.HandleFunc("POST /register", a.handleRegister)
	postMux.HandleFunc("POST /login", a.handleLogin)
	postMux.HandleFunc("POST /verify/resend", a.handleResendVerification)
	postMux.Handle("POST /logout", a.requireAuth(a.handleLogout))
	postMux.Handle("POST /sessions/revoke", a.requireAuth(a.handleRevokeSession))
	mux.Handle("POST /", a.auth.RequireSameOrigin([]string{a.baseURL})(a.auth.RequireCSRFToken(postMux)))

	return mux
}

func (a *app) handleHome(w http.ResponseWriter, r *http.Request) {
	a.render(w, http.StatusOK, "home", nil)
}

func (a *app) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// render executes the named page template through base.html and writes the
// result with the given status code. page is a template file's base name
// without extension, e.g. "home" for templates/home.html.
//
// It clones the parsed base template before parsing the page file into the
// clone, so each page's "title", "content", and "footer" blocks stay
// independent instead of overwriting each other in a shared template set.
func (a *app) render(w http.ResponseWriter, status int, page string, data any) {
	t, err := a.tmpl.Clone()
	if err != nil {
		a.log.Error("cloning template set", "page", page, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	t, err = t.ParseFS(templateFS, "templates/"+page+".html")
	if err != nil {
		a.log.Error("parsing page template", "page", page, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := t.ExecuteTemplate(w, "base", data); err != nil {
		a.log.Error("rendering page", "page", page, "error", err)
	}
}

// requestInfo builds a sulis.RequestInfo from the incoming request, for the
// library calls that take one.
func requestInfo(r *http.Request) sulis.RequestInfo {
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = host
	}
	return sulis.RequestInfo{IP: ip, UserAgent: r.UserAgent()}
}
