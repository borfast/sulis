# Example Web App Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A runnable demo web app at `examples/webapp/` that wires every sulis flow the way a production app should.

**Architecture:** One `main` package split by flow (account, mfa, passkeys), server-rendered `html/template` pages, SQLite via `store/sql/sqlite`, an in-memory dev mailbox instead of SMTP, and the library's own limiter, CSRF, cookie, and event helpers.

**Tech Stack:** Go 1.27, `github.com/borfast/sulis` (root and `store/sql` modules), stdlib only otherwise. One plain JavaScript file for WebAuthn.

**Spec:** docs/superpowers/specs/2026-09-23-example-webapp-design.md

## Global Constraints

- New module `github.com/borfast/sulis/examples/webapp`, go directive 1.27, with `replace github.com/borfast/sulis => ../..` and `replace github.com/borfast/sulis/store/sql => ../../store/sql`.
- No dependencies beyond the two sulis modules and their transitive deps. No JS or CSS frameworks, no QR library (show the otpauth URI and secret as text).
- Every state-changing route: CSRF token issued on the GET form (`a.auth.IssueCSRFToken`) and enforced on POST (`a.auth.RequireCSRFToken` plus `a.auth.RequireSameOrigin(origins)`).
- Session cookies only through `a.auth.SessionCookie(rawToken, expires)` and `a.auth.ClearSessionCookie()`.
- Every library call that takes `sulis.RequestInfo` gets `requestInfo(r)` (IP from `r.RemoteAddr` host part, `UserAgent` from the header). Never `RequestInfo{}` in handlers.
- Library sentinel errors map to generic user-facing messages; raw errors go to `slog` only.
- Tests run against `sqlite.MemoryDSN()`. `go test ./... && go vet ./... && gofmt -l .` clean inside `examples/webapp` before every commit.
- Commit subjects: plain imperative, no type prefix, NO trailer lines.
- Every page template ends with a footer partial listing the library calls that page uses (the spec's "teaches while it runs" requirement).

## Review Focus

Spec-implied behaviors no happy-path test covers; each line's test is added to the owning task:

1. POST with a missing or stale CSRF token renders a 403 page, not a 500 (Task 2).
2. A garbage or expired token in any emailed link (verify, reset, magic, email change) renders a friendly error page with a retry link, never a 500 (Task 3).
3. A magic link opened in a different browser (no binding-nonce cookie) explains "open the link in the browser you requested it from" (Task 3).
4. A 2FA account never gets a session cookie before the second factor; a tampered pending cookie fails generically (Task 4).
5. Unauthenticated requests to protected pages redirect to `/login`, they do not 500 or render empty shells (Task 2).

---

### Task 1: Module Skeleton, Wiring, TLS

**Files:**
- Create: `examples/webapp/go.mod`, `examples/webapp/main.go`, `examples/webapp/app.go`, `examples/webapp/tls.go`, `examples/webapp/templates/base.html`, `examples/webapp/templates/home.html`, `examples/webapp/templates/error.html`, `examples/webapp/static/style.css`, `examples/webapp/README.md` (run instructions stub)
- Test: `examples/webapp/app_test.go`

**Interfaces:**
- Consumes: `sqlite.Open(ctx, dsn) (*sqlite.DB, error)`, `sqlite.Migrate(ctx, db.SQL())`, `sqlite.FileDSN(path)`, `sqlite.MemoryDSN()`, the seven `*sqlite.DB` store getters; `sulis.New(users, sessions, tokens, factors, opts...)`, `sulis.WithEventSink(sulis.NewSlogSink(logger))`; `totp.NewService(store, "Sulis Example")`, `passkey.NewService(store, challenges, passkey.WebAuthnConfig{RPDisplayName, RPID, RPOrigins}, ...)`, `recovery.NewService(store)`.
- Produces (later tasks build on these exact names):

```go
type app struct {
	auth      *sulis.Sulis
	totp      *totp.Service
	passkeys  *passkey.Service
	recovery  *recovery.Service
	users     *sqlite.UserStore
	db        *sqlite.DB
	tmpl      *template.Template
	log       *slog.Logger
	baseURL   string // http(s)://localhost:PORT, from -addr and -tls
}
func newApp(ctx context.Context, dsn, baseURL string, logger *slog.Logger) (*app, error)
func (a *app) routes() http.Handler
func requestInfo(r *http.Request) sulis.RequestInfo
func (a *app) render(w http.ResponseWriter, status int, page string, data any)
type secondFactors struct{ totp *sqlite.TOTPStore; passkeys *sqlite.PasskeyStore }
func (f secondFactors) HasSecondFactor(ctx context.Context, userID string) (bool, error)
```

- [ ] **Step 1: Write the failing smoke test** in `app_test.go`

```go
func newTestApp(t *testing.T) *app  // newApp with sqlite.MemoryDSN(), discard logger
func TestHomePageRenders(t *testing.T)   // GET / via httptest -> 200, body contains "Sulis"
func TestHealthz(t *testing.T)           // GET /healthz -> 200 "ok"
```

- [ ] **Step 2: Run `go test ./...` in `examples/webapp` and verify RED** (module does not compile yet)

- [ ] **Step 3: Implement**

`go.mod` with the two replace directives. `newApp`: open and migrate SQLite; build `secondFactors` (true when the user has a verified TOTP credential or at least one passkey, via the two stores' lookup methods; a not-found result means false, other errors propagate); `sulis.New(users, sessions, tokens, factors, sulis.WithEventSink(sulis.NewSlogSink(logger)))` (the default in-process `MemoryLimiter` and password blocklist stay as defaults on purpose); construct the three services (`RPID` "localhost", `RPOrigins` = `[]string{baseURL}`); parse templates. `main.go`: flags `-addr :8443`, `-db webapp.db`, `-tls` (default true; note Safari needs it), background cleanup loop every 10 minutes calling the session store's `CleanExpired` and token store's `DeleteExpiredTokens`, graceful shutdown on SIGINT. `tls.go`: `selfSignedCert()` generating an ECDSA cert for localhost/127.0.0.1 at startup. `routes()`: home, healthz, static files. `render` writes templates through `base.html`; `error.html` is the friendly error page used everywhere later.

- [ ] **Step 4: Run `go test ./... && go vet ./... && gofmt -l .` and verify GREEN**

- [ ] **Step 5: Commit** `Add example web app skeleton with SQLite wiring and TLS`

### Task 2: Mailbox, Register, Verify, Login, Logout, Sessions, CSRF

**Files:**
- Create: `examples/webapp/mailbox.go`, `examples/webapp/handlers_account.go`, templates: `register.html`, `login.html`, `account.html`, `mailbox.html`, `verify_sent.html`
- Modify: `examples/webapp/app.go` (add `mail *outbox` field), `routes()`
- Test: `examples/webapp/account_test.go`

**Interfaces:**
- Consumes: `Register(ctx, email, password, ri) (*sulis.User, *sulis.Session, string, error)`, `CreateEmailVerificationToken`, `VerifyEmail`, `Login(ctx, email, password, ri) (*sulis.LoginResult, error)` and its `NeedsSecondFactor` contract, `RevokeSession(ctx, userID, sessionID)`, `ListUserSessions`, `Authenticate` middleware, `UserFromContext`/`SessionFromContext`, CSRF and cookie helpers from Global Constraints.
- Produces:

```go
type outbox struct{ mu sync.Mutex; msgs []mailMessage }
type mailMessage struct{ To, Subject, Body string; SentAt time.Time }
func (o *outbox) Send(to, subject, body string)   // also logs the body to slog
func (o *outbox) Messages() []mailMessage
func (a *app) requireAuth(next http.HandlerFunc) http.Handler // Authenticate + redirect to /login when 401
const pendingUserCookie, pendingTokenCookie = "pending_2fa_user", "pending_2fa_token" // 5 min, HttpOnly
func (a *app) startSession(w http.ResponseWriter, token string, s *sulis.Session) // sets the session cookie
func (a *app) handleLoginResult(w, r, res *sulis.LoginResult) // branch: 2FA -> pending cookies + redirect /login/second-factor; else startSession + redirect /account
```

- [ ] **Step 1: Write failing tests**

```go
func TestRegisterVerifyLoginRoundtrip(t *testing.T) // register -> mailbox link -> GET verify -> logout -> login -> /account 200
func TestUnauthenticatedAccountRedirectsToLogin(t *testing.T)
func TestPostWithoutCSRFTokenIs403(t *testing.T)     // Review Focus 1
func TestLoginWrongPasswordIsGenericError(t *testing.T) // same message as unknown email
func TestLogoutClearsSessionAndRevokes(t *testing.T)
func TestSessionListShowsAndRevokesOtherSession(t *testing.T)
```

Tests use a small cookie-jar helper around `httptest` and pull links out of `app.mail.Messages()` with a regexp.

- [ ] **Step 2: Verify RED**

- [ ] **Step 3: Implement** the handlers exactly per the flows above. Registration keeps the signup session (library behavior) but the account page shows "email not verified" until `VerifyEmail`; login of an unverified account maps `sulis.ErrEmailNotVerified` to a page offering to resend the verification email. `/dev/mailbox` lists messages with clickable links. Wire `RequireSameOrigin([]string{baseURL})` around the whole POST mux and `RequireCSRFToken` inside it.

- [ ] **Step 4: Verify GREEN, run gofmt/vet**

- [ ] **Step 5: Commit** `Add registration, verification, login, and session pages`

### Task 3: Password Reset, Magic Link, Change Email

**Files:**
- Create: templates `forgot.html`, `reset.html`, `magic.html`, `change_email.html`
- Modify: `examples/webapp/handlers_account.go`, `routes()`
- Test: `examples/webapp/recover_test.go`

**Interfaces:**
- Consumes: `CreatePasswordResetToken(ctx, email, ri)` (non-strict variant), `ResetPassword(ctx, rawToken, newPassword)`, `CreateMagicLinkToken(ctx, email, ri) (token, bindingNonce, error)`, `RedeemMagicLink(ctx, rawToken, bindingNonce, ri) (*sulis.LoginResult, error)`, `ChangeEmail(ctx, userID, newEmail) (string, error)`, `ConfirmEmailChange(ctx, rawToken)`, `handleLoginResult` from Task 2.
- Produces: `const magicNonceCookie = "magic_nonce"` (15 min, HttpOnly), reused by nothing else; error page rendering via Task 1's `error.html`.

- [ ] **Step 1: Write failing tests**

```go
func TestPasswordResetRoundtripRevokesSessions(t *testing.T)
func TestForgotUnknownEmailRendersSamePage(t *testing.T)     // enumeration-safe
func TestMagicLinkRoundtrip(t *testing.T)
func TestMagicLinkInDifferentBrowserExplainsBinding(t *testing.T) // Review Focus 3: no nonce cookie -> error page names the fix
func TestGarbageTokenLinksRenderFriendlyErrors(t *testing.T) // Review Focus 2: /verify, /reset, /magic/redeem, /email/confirm with token=garbage -> error.html, not 500
func TestChangeEmailRoundtrip(t *testing.T)                  // token goes to the NEW address; old address unchanged until confirm
```

- [ ] **Step 2: Verify RED**

- [ ] **Step 3: Implement.** `/forgot` POST always renders "check your email" (treat `sulis.ErrUserNotFound` as success). `/magic` POST stores the binding nonce in `magicNonceCookie` and mails the link; the redeem handler reads the cookie, calls `RedeemMagicLink`, and routes the result through `handleLoginResult` (magic-link users can have 2FA too). `/account/email` POST calls `ChangeEmail` and mails the confirm link to the new address.

- [ ] **Step 4: Verify GREEN, gofmt/vet**

- [ ] **Step 5: Commit** `Add password reset, magic link, and email change flows`

### Task 4: TOTP, Recovery Codes, Second-Factor Login

**Files:**
- Create: `examples/webapp/handlers_mfa.go`, templates `security.html`, `totp_enroll.html`, `recovery_codes.html`, `second_factor.html`
- Modify: `routes()`
- Test: `examples/webapp/mfa_test.go`

**Interfaces:**
- Consumes: `totp.Service.Enroll/ConfirmEnrollment/Validate/Unenroll/ReplaceEnrollment`, `totp.Service.Generate(secret, t)` (tests mint codes with it), `recovery.Service.Generate/Consume/Remaining/Disable`, `CreateTwoFactorToken`, `CompleteTwoFactor(ctx, userID, rawToken, ri) (*sulis.LoginResult, error)`, pending cookies and `handleLoginResult` from Task 2.
- Produces: `/security` page skeleton that Task 5 extends with the passkey list.

- [ ] **Step 1: Write failing tests**

```go
func TestTOTPEnrollConfirmAndTwoFactorLogin(t *testing.T) // enroll, confirm, logout, login -> second-factor page (no session cookie yet), submit code -> session
func TestRecoveryCodeCompletesSecondFactor(t *testing.T)  // shows remaining count decreased
func TestSecondFactorReplayRejected(t *testing.T)         // same TOTP code twice -> generic failure
func TestTamperedPendingCookieFailsGenerically(t *testing.T) // Review Focus 4: altered pending token or user -> error, no session
func TestNoSessionCookieBeforeSecondFactor(t *testing.T)  // Review Focus 4: assert Set-Cookie absent on the 2FA redirect
```

- [ ] **Step 2: Verify RED**

- [ ] **Step 3: Implement.** `/security` (requireAuth): TOTP status, enroll/confirm/disable forms, recovery generate button, remaining count. Enrollment page shows the secret and otpauth URI as text. `/login/second-factor` GET renders one form with a code field and a "use a recovery code" toggle; POST reads the pending cookies, verifies the factor (`totp.Validate` or `recovery.Consume`), then `CompleteTwoFactor` and `handleLoginResult`; clear pending cookies either way.

- [ ] **Step 4: Verify GREEN, gofmt/vet**

- [ ] **Step 5: Commit** `Add TOTP, recovery codes, and second-factor login`

### Task 5: Passkeys, Step-Up, README, CI

**Files:**
- Create: `examples/webapp/handlers_passkey.go`, `examples/webapp/static/passkeys.js`, template `reauth.html`
- Modify: `security.html` (passkey list + register button), `login.html` (passkey buttons), `handlers_account.go` (step-up guard on change email), `.github/workflows/ci.yml` (add the examples/webapp module the same way store/sql is listed), `examples/webapp/README.md` (full)
- Test: `examples/webapp/passkey_test.go`

**Interfaces:**
- Consumes: `passkey.Service.BeginRegistration/FinishRegistrationResponse/BeginLogin/FinishLoginResponse/BeginDiscoverableLogin/FinishDiscoverableLoginResponse/DeleteCredential`, `passkey.User{ID, Name, DisplayName}`, `IssueSessionUnchecked(ctx, userID, sulis.AuthMethodPasskey)`, `RequireRecentAuth(ctx, session, 5*time.Minute)`, `ReAuthenticate(ctx, session, password, ri)`, `sulis.ErrReauthRequired`-style sentinel (use the exact sentinel `RequireRecentAuth` documents; check `go doc sulis RequireRecentAuth` in the tree).
- Produces: JSON endpoints under `/api/passkeys/...`; `(a *app) requireRecentAuth(w, r, session) bool` helper that redirects to `/reauth?next=...` when auth is stale.

- [ ] **Step 1: Write failing tests**

```go
func TestPasskeyBeginRegistrationRequiresAuth(t *testing.T)   // 401/redirect when logged out
func TestPasskeyFinishWithGarbageBodyFailsCleanly(t *testing.T) // 400 JSON error, no 500, no session cookie
func TestDiscoverableBeginReturnsCeremonyID(t *testing.T)
func TestStepUpGuardsChangeEmail(t *testing.T) // stale auth -> redirected to /reauth; after ReAuthenticate the change goes through
func TestReauthWrongPasswordFails(t *testing.T)
```

The WebAuthn happy path needs a real authenticator; the README documents the manual test (register a passkey, log out, sign in with it, then usernameless).

- [ ] **Step 2: Verify RED**

- [ ] **Step 3: Implement.** JSON endpoints return `{"error": "..."}` with correct status codes; `passkeys.js` does begin/finish fetch calls with base64url encode/decode for the WebAuthn fields and wires three buttons (register, sign in with email, usernameless sign-in). After `FinishLoginResponse`/`FinishDiscoverableLoginResponse` succeed, issue the session with `IssueSessionUnchecked(..., sulis.AuthMethodPasskey)`; first confirm from its doc comment whether it applies the verified-email gate, and if it does not, check `user.EmailVerifiedAt` in the handler before issuing. Passkey delete and change email go through `requireRecentAuth` (step-up demo). Finish the README: run commands (`go run .` and the `-tls` Safari note), a page-to-library-call map, and the manual passkey walkthrough. Add the module to CI.

- [ ] **Step 4: Verify GREEN, gofmt/vet; also run the root repo suite once to confirm nothing there changed**

- [ ] **Step 5: Commit** `Add passkey endpoints, step-up re-auth, and example docs`
