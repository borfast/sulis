package main

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/borfast/sulis"
)

// pendingUserCookie and pendingTokenCookie hold the user ID and pending
// two-factor token between the first-factor Login call and the
// second-factor step. Task 4 reads them; this task only sets them.
const (
	pendingUserCookie  = "pending_2fa_user"
	pendingTokenCookie = "pending_2fa_token"
)

// pendingCookieTTL is how long the pending-2FA cookies live: long enough to
// enter a code, short enough that an abandoned login attempt cannot be
// resumed much later.
const pendingCookieTTL = 5 * time.Minute

// mailLinkPattern finds the first http(s) URL in a mail body, so the
// mailbox page can render it as a clickable link.
var mailLinkPattern = regexp.MustCompile(`https?://\S+`)

// requireAuth wraps next so it only runs for a request carrying a valid
// session. Authenticate itself would answer an invalid session with its own
// 401 response, which is right for an API but wrong for a browser page, so
// this wrapper pre-checks the session cookie with ValidateSession and
// redirects to /login on failure, then calls Authenticate to attach the
// user and session to the request context for next.
func (a *app) requireAuth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookieName := a.auth.ClearSessionCookie().Name
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if _, _, err := a.auth.ValidateSession(r.Context(), cookie.Value); err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		a.auth.Authenticate(next).ServeHTTP(w, r)
	})
}

// startSession sets the session cookie for a newly issued session.
func (a *app) startSession(w http.ResponseWriter, token string, s *sulis.Session) {
	http.SetCookie(w, a.auth.SessionCookie(token, s.ExpiresAt))
}

// handleLoginResult finishes a successful first factor. Callers must branch
// on NeedsSecondFactor rather than assuming a session exists: when a second
// factor is required, no session is issued yet, so this sets short-lived
// pending cookies instead and sends the browser on to the (not yet built)
// second-factor page.
func (a *app) handleLoginResult(w http.ResponseWriter, r *http.Request, res *sulis.LoginResult) {
	if res.NeedsSecondFactor {
		secure := strings.HasPrefix(a.baseURL, "https://")
		expires := time.Now().Add(pendingCookieTTL)
		http.SetCookie(w, &http.Cookie{
			Name: pendingUserCookie, Value: res.User.ID, Path: "/",
			HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, Expires: expires,
		})
		http.SetCookie(w, &http.Cookie{
			Name: pendingTokenCookie, Value: res.PendingToken, Path: "/",
			HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, Expires: expires,
		})
		http.Redirect(w, r, "/login/second-factor", http.StatusSeeOther)
		return
	}

	a.startSession(w, res.SessionToken, res.Session)
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

// registerPageData feeds register.html.
type registerPageData struct {
	CSRFToken string
	Error     string
	Email     string
}

func (a *app) handleRegisterForm(w http.ResponseWriter, r *http.Request) {
	token, cookie, err := a.auth.IssueCSRFToken()
	if err != nil {
		a.log.Error("issuing csrf token", "error", err)
		a.render(w, http.StatusInternalServerError, "error", "Something went wrong. Try again.")
		return
	}
	http.SetCookie(w, cookie)
	a.render(w, http.StatusOK, "register", registerPageData{CSRFToken: token})
}

func (a *app) handleRegister(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.log.Error("parsing register form", "error", err)
		a.render(w, http.StatusBadRequest, "error", "Could not read that form submission.")
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	user, session, token, err := a.auth.Register(r.Context(), email, password, requestInfo(r))
	if err != nil {
		a.log.Error("registering user", "email", email, "error", err)
		a.rerenderRegister(w, r, email, registerErrorMessage(err))
		return
	}

	a.sendVerificationEmail(r, user)
	a.startSession(w, token, session)
	a.render(w, http.StatusOK, "verify_sent", verifySentData{Email: user.Email})
}

// rerenderRegister re-shows the registration form with an error, issuing a
// fresh CSRF token since the failed submission consumed the one the client
// had.
func (a *app) rerenderRegister(w http.ResponseWriter, r *http.Request, email, message string) {
	token, cookie, err := a.auth.IssueCSRFToken()
	if err != nil {
		a.log.Error("issuing csrf token", "error", err)
		a.render(w, http.StatusInternalServerError, "error", "Something went wrong. Try again.")
		return
	}
	http.SetCookie(w, cookie)
	a.render(w, http.StatusUnprocessableEntity, "register", registerPageData{
		CSRFToken: token, Error: message, Email: email,
	})
}

// registerErrorMessage maps a Register error to a message safe to show a
// user. Raw errors are logged by the caller; only this generic text reaches
// the page.
func registerErrorMessage(err error) string {
	switch {
	case errors.Is(err, sulis.ErrUserAlreadyExists):
		return "That email is already registered."
	case errors.Is(err, sulis.ErrInvalidEmail):
		return "Enter a valid email address."
	case errors.Is(err, sulis.ErrPasswordTooShort), errors.Is(err, sulis.ErrPasswordTooLong):
		return "Choose a different password: it does not meet the length requirements."
	case errors.Is(err, sulis.ErrPasswordCompromised):
		return "That password has appeared in a data breach. Choose a different one."
	default:
		return "Could not create your account. Try again."
	}
}

// sendVerificationEmail creates a verification token and delivers the link
// through the demo outbox. A failure here is logged but does not fail the
// surrounding request: the account still exists, and the link can be
// resent.
func (a *app) sendVerificationEmail(r *http.Request, user *sulis.User) {
	tok, err := a.auth.CreateEmailVerificationToken(r.Context(), user.ID)
	if err != nil {
		a.log.Error("creating verification token", "user_id", user.ID, "error", err)
		return
	}
	link := a.baseURL + "/verify?token=" + tok
	body := "Click the link below to verify your email address:\n\n" + link + "\n"
	a.mail.Send(user.Email, "Verify your email", body)
}

// loginPageData feeds login.html.
type loginPageData struct {
	CSRFToken  string
	Error      string
	Email      string
	ShowResend bool
}

func (a *app) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	token, cookie, err := a.auth.IssueCSRFToken()
	if err != nil {
		a.log.Error("issuing csrf token", "error", err)
		a.render(w, http.StatusInternalServerError, "error", "Something went wrong. Try again.")
		return
	}
	http.SetCookie(w, cookie)
	a.render(w, http.StatusOK, "login", loginPageData{CSRFToken: token})
}

func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.log.Error("parsing login form", "error", err)
		a.render(w, http.StatusBadRequest, "error", "Could not read that form submission.")
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	// The CSRF token already on the request was verified by RequireCSRFToken
	// before this handler ran, and it stays valid for the cookie it came
	// with, so it can be echoed straight back into a re-rendered form.
	csrfToken := r.FormValue(sulis.CSRFFormField)

	result, err := a.auth.Login(r.Context(), email, password, requestInfo(r))
	if err != nil {
		a.log.Error("login failed", "email", email, "error", err)
		if errors.Is(err, sulis.ErrEmailNotVerified) {
			a.render(w, http.StatusUnprocessableEntity, "login", loginPageData{
				CSRFToken: csrfToken, Email: email,
				Error:      "Please verify your email before logging in.",
				ShowResend: true,
			})
			return
		}
		// Every other failure, including an unknown email and a wrong
		// password, reads identically: telling them apart would let an
		// attacker enumerate registered addresses.
		a.render(w, http.StatusUnprocessableEntity, "login", loginPageData{
			CSRFToken: csrfToken, Email: email, Error: "Incorrect email or password.",
		})
		return
	}

	a.handleLoginResult(w, r, result)
}

// verifySentData feeds verifySent.html, both right after registration (a
// link was just sent) and after following that link (the address is now
// verified).
type verifySentData struct {
	Email    string
	Verified bool
}

func (a *app) handleVerify(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	user, err := a.auth.VerifyEmail(r.Context(), tok)
	if err != nil {
		a.log.Error("verifying email", "error", err)
		a.render(w, http.StatusBadRequest, "error", "That verification link is invalid or has expired.")
		return
	}
	a.render(w, http.StatusOK, "verify_sent", verifySentData{Email: user.Email, Verified: true})
}

func (a *app) handleResendVerification(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.log.Error("parsing resend form", "error", err)
		a.render(w, http.StatusBadRequest, "error", "Could not read that form submission.")
		return
	}

	email := r.FormValue("email")
	user, err := a.users.GetUserByEmail(r.Context(), strings.ToLower(strings.TrimSpace(email)))
	if err != nil {
		// Say the same thing whether or not the address is registered, so
		// this cannot be used to enumerate accounts.
		a.log.Error("looking up user for resend", "error", err)
		a.render(w, http.StatusOK, "verify_sent", verifySentData{Email: email})
		return
	}

	if user.EmailVerifiedAt == nil {
		a.sendVerificationEmail(r, user)
	}
	a.render(w, http.StatusOK, "verify_sent", verifySentData{Email: email})
}

// accountPageData feeds account.html.
type accountPageData struct {
	Email            string
	Verified         bool
	CSRFToken        string
	CurrentSessionID string
	Sessions         []sulis.Session
}

func (a *app) handleAccount(w http.ResponseWriter, r *http.Request) {
	user, ok := sulis.UserFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	session, _ := sulis.SessionFromContext(r.Context())

	sessions, err := a.auth.ListUserSessions(r.Context(), user.ID)
	if err != nil {
		a.log.Error("listing sessions", "user_id", user.ID, "error", err)
		a.render(w, http.StatusInternalServerError, "error", "Could not load your account.")
		return
	}

	token, cookie, err := a.auth.IssueCSRFToken()
	if err != nil {
		a.log.Error("issuing csrf token", "error", err)
		a.render(w, http.StatusInternalServerError, "error", "Could not load your account.")
		return
	}
	http.SetCookie(w, cookie)

	currentSessionID := ""
	if session != nil {
		currentSessionID = session.ID
	}

	a.render(w, http.StatusOK, "account", accountPageData{
		Email:            user.Email,
		Verified:         user.EmailVerifiedAt != nil,
		CSRFToken:        token,
		CurrentSessionID: currentSessionID,
		Sessions:         sessions,
	})
}

func (a *app) handleLogout(w http.ResponseWriter, r *http.Request) {
	user, hasUser := sulis.UserFromContext(r.Context())
	session, hasSession := sulis.SessionFromContext(r.Context())
	if hasUser && hasSession {
		if err := a.auth.RevokeSession(r.Context(), user.ID, session.ID); err != nil {
			a.log.Error("revoking session on logout", "user_id", user.ID, "error", err)
		}
	}
	http.SetCookie(w, a.auth.ClearSessionCookie())
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *app) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.log.Error("parsing revoke-session form", "error", err)
		a.render(w, http.StatusBadRequest, "error", "Could not read that form submission.")
		return
	}

	user, ok := sulis.UserFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	sessionID := r.FormValue("session_id")
	if err := a.auth.RevokeSession(r.Context(), user.ID, sessionID); err != nil {
		a.log.Error("revoking session", "user_id", user.ID, "session_id", sessionID, "error", err)
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

// mailboxMessageView adds a pre-extracted link to a mailMessage so the
// template can render it as a clickable anchor without needing template
// helper functions.
type mailboxMessageView struct {
	To, Subject, Body, Link string
	SentAt                  time.Time
}

// mailboxPageData feeds mailbox.html.
type mailboxPageData struct {
	Messages []mailboxMessageView
}

func (a *app) handleMailbox(w http.ResponseWriter, r *http.Request) {
	msgs := a.mail.Messages()
	views := make([]mailboxMessageView, 0, len(msgs))
	for _, m := range msgs {
		views = append(views, mailboxMessageView{
			To: m.To, Subject: m.Subject, Body: m.Body, SentAt: m.SentAt,
			Link: mailLinkPattern.FindString(m.Body),
		})
	}
	a.render(w, http.StatusOK, "mailbox", mailboxPageData{Messages: views})
}
