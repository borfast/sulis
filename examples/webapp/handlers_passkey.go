package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/borfast/sulis"
	"github.com/borfast/sulis/passkey"
)

// maxCeremonyBodyBytes caps how much of a WebAuthn ceremony response body
// these handlers read before handing it to passkey.Service, mirroring the
// limit the library enforces internally (WithMaxCeremonyBody's default of
// 64 KiB). Capping it here too means an oversized body is rejected while
// still being read, not after being buffered into memory in full.
const maxCeremonyBodyBytes = 64 * 1024

// Cookie names for the two login ceremonies whose Begin call returns a
// ceremony ID that must round-trip to Finish: BeginLogin (identified) and
// BeginDiscoverableLogin (usernameless). BeginRegistration keys its
// challenge by user ID internally, so registration needs no such cookie.
const (
	passkeyLoginUserCookie            = "passkey_login_user"     // #nosec G101 -- a cookie name, not a credential
	passkeyLoginCeremonyCookie        = "passkey_login_ceremony" // #nosec G101 -- a cookie name, not a credential
	passkeyDiscoverableCeremonyCookie = "passkey_discoverable_ceremony"
)

// passkeyCeremonyCookieTTL is how long a begun login ceremony's cookies
// live: long enough to complete a WebAuthn prompt, short enough that an
// abandoned attempt cannot be resumed much later. It mirrors
// pendingCookieTTL's reasoning in handlers_account.go.
const passkeyCeremonyCookieTTL = 5 * time.Minute

// stepUpMaxAge is how recent a session's proven authentication must be
// before requireRecentAuth lets a step-up-gated action proceed.
const stepUpMaxAge = 5 * time.Minute

// writeJSON writes v as a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONError writes {"error": message} with the given status code.
// Every JSON handler below uses this rather than a.render, so a passkey
// ceremony's raw error never reaches the browser: only this generic message
// does, with the raw error going to a.log instead.
func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// readCeremonyBody reads r.Body capped at maxCeremonyBodyBytes, the same way
// passkey.Service's own *http.Request-taking methods do internally. This
// file calls the []byte-taking core methods instead (FinishRegistrationResponse
// and friends), so it applies the same bound itself rather than relying on
// the library to impose it after the body is already read.
func readCeremonyBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxCeremonyBodyBytes)
	return io.ReadAll(r.Body)
}

// requireAuthJSON is requireAuth's JSON counterpart: it answers a missing or
// invalid session with a JSON 401 instead of a redirect. The passkey
// endpoints below are reached by fetch(), not page navigation, so a
// redirect response would hand a JSON client an HTML login page instead of
// an error body it can read.
func (a *app) requireAuthJSON(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookieName := a.auth.ClearSessionCookie().Name
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "You must be logged in.")
			return
		}
		if _, _, err := a.auth.ValidateSession(r.Context(), cookie.Value); err != nil {
			writeJSONError(w, http.StatusUnauthorized, "You must be logged in.")
			return
		}
		a.auth.Authenticate(next).ServeHTTP(w, r)
	})
}

// setPasskeyCookie sets a short-lived HttpOnly cookie carrying ceremony
// state between a Begin call and its matching Finish call, the same pattern
// handleLoginResult uses for the pending-2FA cookies in handlers_account.go.
func (a *app) setPasskeyCookie(w http.ResponseWriter, name, value string) {
	// #nosec G124 -- HttpOnly and SameSite are set; Secure is computed from
	// the -tls flag rather than a literal, which this rule's static check
	// for `Secure: true` does not recognize.
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/",
		HttpOnly: true, Secure: strings.HasPrefix(a.baseURL, "https://"),
		SameSite: http.SameSiteLaxMode, Expires: time.Now().Add(passkeyCeremonyCookieTTL),
	})
}

// clearPasskeyCookie removes a cookie set by setPasskeyCookie, with matching
// attributes so the browser actually deletes it rather than keeping a stale
// value under slightly different attributes.
func (a *app) clearPasskeyCookie(w http.ResponseWriter, name string) {
	// #nosec G124 -- HttpOnly and SameSite are set; Secure is computed from
	// the -tls flag rather than a literal, which this rule's static check
	// for `Secure: true` does not recognize.
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: strings.HasPrefix(a.baseURL, "https://"),
		SameSite: http.SameSiteLaxMode,
	})
}

// recentAuthRequiredMessage is what the passkey register endpoint answers
// with when the session's authentication is too old. It is a JSON 403
// rather than the redirect the form posts get, because this endpoint is
// called by fetch(): passkeys.js turns it into a message naming /reauth.
const recentAuthRequiredMessage = "recent authentication required"

// handlePasskeyRegisterBegin starts WebAuthn registration for the
// authenticated user and returns the credential creation options as JSON.
// Adding a passkey is step-up gated like every other change to a second
// factor: it is the one that would let an attacker back in later without
// the password at all.
func (a *app) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	user, ok := sulis.UserFromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "You must be logged in.")
		return
	}
	session, ok := sulis.SessionFromContext(r.Context())
	if !ok || session == nil {
		writeJSONError(w, http.StatusUnauthorized, "You must be logged in.")
		return
	}
	if err := a.auth.RequireRecentAuth(r.Context(), session, stepUpMaxAge); err != nil {
		a.log.Error("passkey registration needs recent auth", "user_id", user.ID, "error", err)
		writeJSONError(w, http.StatusForbidden, recentAuthRequiredMessage)
		return
	}

	creation, err := a.passkeys.BeginRegistration(r.Context(), &passkey.User{
		ID: []byte(user.ID), Name: user.Email, DisplayName: user.Email,
	})
	if err != nil {
		a.log.Error("beginning passkey registration", "user_id", user.ID, "error", err)
		writeJSONError(w, http.StatusInternalServerError, "Could not start passkey registration.")
		return
	}

	writeJSON(w, http.StatusOK, creation)
}

// handlePasskeyRegisterFinish completes registration from the authenticator
// response the browser posts and, on success, tells the client where to go
// next: the security page, where the new passkey now appears.
func (a *app) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	user, ok := sulis.UserFromContext(r.Context())
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "You must be logged in.")
		return
	}

	body, err := readCeremonyBody(w, r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Could not read that request.")
		return
	}

	if _, err := a.passkeys.FinishRegistrationResponse(r.Context(), &passkey.User{
		ID: []byte(user.ID), Name: user.Email, DisplayName: user.Email,
	}, body); err != nil {
		a.log.Error("finishing passkey registration", "user_id", user.ID, "error", err)
		writeJSONError(w, http.StatusBadRequest, "Could not register that passkey. Try again.")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"redirect": "/security"})
}

// passkeyLoginBeginRequest is the JSON body handlePasskeyLoginBegin reads:
// the email identifying which user's credentials to challenge.
type passkeyLoginBeginRequest struct {
	Email string `json:"email"`
}

// handlePasskeyLoginBegin starts an identified WebAuthn login ceremony for
// the email the client posts. An unknown email and any BeginLogin failure
// produce the same generic response, so this endpoint cannot be used to
// enumerate registered addresses.
func (a *app) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	body, err := readCeremonyBody(w, r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Could not read that request.")
		return
	}
	var req passkeyLoginBeginRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Could not read that request.")
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	user, err := a.users.GetUserByEmail(r.Context(), email)
	if err != nil {
		a.log.Error("looking up user for passkey login", "error", err)
		writeJSONError(w, http.StatusUnprocessableEntity, "Could not start sign-in.")
		return
	}

	assertion, ceremonyID, err := a.passkeys.BeginLogin(r.Context(), &passkey.User{
		ID: []byte(user.ID), Name: user.Email, DisplayName: user.Email,
	})
	if err != nil {
		a.log.Error("beginning passkey login", "user_id", user.ID, "error", err)
		writeJSONError(w, http.StatusUnprocessableEntity, "Could not start sign-in.")
		return
	}

	a.setPasskeyCookie(w, passkeyLoginUserCookie, user.ID)
	a.setPasskeyCookie(w, passkeyLoginCeremonyCookie, ceremonyID)
	writeJSON(w, http.StatusOK, assertion)
}

// handlePasskeyLoginFinish completes an identified login ceremony and, on
// success, issues a session exactly like any other first factor. Both
// ceremony cookies are cleared on every outcome, mirroring
// handleSecondFactor/clearPendingCookies in handlers_account.go: a begun
// ceremony is meant to be resolved by exactly one submission.
func (a *app) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	userCookie, userErr := r.Cookie(passkeyLoginUserCookie)
	ceremonyCookie, ceremonyErr := r.Cookie(passkeyLoginCeremonyCookie)
	a.clearPasskeyCookie(w, passkeyLoginUserCookie)
	a.clearPasskeyCookie(w, passkeyLoginCeremonyCookie)
	if userErr != nil || ceremonyErr != nil {
		writeJSONError(w, http.StatusBadRequest, "Your sign-in attempt expired. Try again.")
		return
	}

	body, err := readCeremonyBody(w, r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Could not read that request.")
		return
	}

	cred, err := a.passkeys.FinishLoginResponse(r.Context(), &passkey.User{ID: []byte(userCookie.Value)},
		ceremonyCookie.Value, body)
	if err != nil {
		a.log.Error("finishing passkey login", "error", err)
		writeJSONError(w, http.StatusBadRequest, "Could not complete sign-in.")
		return
	}

	a.finishPasskeySession(w, r, cred.UserID)
}

// handlePasskeyDiscoverableBegin starts a usernameless WebAuthn login
// ceremony: no email is needed up front, since the authenticator itself
// supplies the credential (and so the user) in the Finish step.
func (a *app) handlePasskeyDiscoverableBegin(w http.ResponseWriter, r *http.Request) {
	assertion, ceremonyID, err := a.passkeys.BeginDiscoverableLogin(r.Context())
	if err != nil {
		a.log.Error("beginning discoverable passkey login", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "Could not start sign-in.")
		return
	}

	a.setPasskeyCookie(w, passkeyDiscoverableCeremonyCookie, ceremonyID)
	writeJSON(w, http.StatusOK, assertion)
}

// handlePasskeyDiscoverableFinish completes a usernameless login ceremony.
// The user is resolved from the credential the authenticator returns, never
// from anything the client claims.
func (a *app) handlePasskeyDiscoverableFinish(w http.ResponseWriter, r *http.Request) {
	ceremonyCookie, err := r.Cookie(passkeyDiscoverableCeremonyCookie)
	a.clearPasskeyCookie(w, passkeyDiscoverableCeremonyCookie)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Your sign-in attempt expired. Try again.")
		return
	}

	body, err := readCeremonyBody(w, r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "Could not read that request.")
		return
	}

	cred, err := a.passkeys.FinishDiscoverableLoginResponse(r.Context(), ceremonyCookie.Value, body)
	if err != nil {
		a.log.Error("finishing discoverable passkey login", "error", err)
		writeJSONError(w, http.StatusBadRequest, "Could not complete sign-in.")
		return
	}

	a.finishPasskeySession(w, r, cred.UserID)
}

// finishPasskeySession issues a session for a successful passkey ceremony.
// IssueSessionUnchecked's own doc comment confirms it applies the same
// ErrUserNotFound/ErrEmailNotVerified gating IssueSession does, so no
// separate EmailVerifiedAt check is needed here: an unverified account is
// already rejected by the call below.
func (a *app) finishPasskeySession(w http.ResponseWriter, r *http.Request, userID string) {
	session, token, err := a.auth.IssueSessionUnchecked(r.Context(), userID, sulis.AuthMethodPasskey)
	if err != nil {
		a.log.Error("issuing session after passkey login", "user_id", userID, "error", err)
		writeJSONError(w, http.StatusBadRequest, "Could not complete sign-in.")
		return
	}
	a.startSession(w, token, session)
	writeJSON(w, http.StatusOK, map[string]string{"redirect": "/account"})
}

// handlePasskeyDelete removes one of the user's own passkeys. Unlike
// registration and login above, it is a plain form POST, not a JSON
// endpoint: a step-up redirect to /reauth is a page navigation, which a
// fetch() caller would have to special-case for no benefit, and the
// security page's other actions (TOTP enroll/disable, recovery generate)
// are already ordinary <form> submissions.
func (a *app) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.log.Error("parsing passkey-delete form", "error", err)
		a.render(w, http.StatusBadRequest, "error", "Could not read that form submission.")
		return
	}
	user, ok := sulis.UserFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	session, _ := sulis.SessionFromContext(r.Context())
	if !a.requireRecentAuth(w, r, session) {
		return
	}

	credentialID := r.FormValue("credential_id")
	if err := a.passkeys.DeleteCredential(r.Context(), user.ID, credentialID, passkey.DeleteOptions{}); err != nil {
		a.log.Error("deleting passkey", "user_id", user.ID, "error", err)
		message := "Could not remove that passkey."
		if errors.Is(err, passkey.ErrLastCredential) {
			message = "Cannot remove your only passkey. Enable another second factor first."
		}
		a.render(w, http.StatusUnprocessableEntity, "error", message)
		return
	}

	http.Redirect(w, r, "/security", http.StatusSeeOther)
}

// allowedNextPaths is the fixed set of local pages /reauth may send a user
// back to after a successful step-up re-authentication. sanitizeNext checks
// membership in exactly this map, never the raw "next" value itself, which
// is what keeps an attacker-supplied ?next=https://evil.example from ever
// being followed: it simply is not a key in this map.
var allowedNextPaths = map[string]bool{
	"/account/email": true,
	"/security":      true,
	"/account":       true,
}

// sanitizeNext returns next if it names one of allowedNextPaths, and
// "/account" otherwise.
func sanitizeNext(next string) string {
	if allowedNextPaths[next] {
		return next
	}
	return "/account"
}

// stepUpReturnPath maps a step-up-gated POST path to the page a user should
// land back on after proving their password again: the page holding the
// form they were submitting, not the POST-only path itself. Every gated
// POST under /security (enrolling or disabling TOTP, generating recovery
// codes, removing a passkey) is submitted from the one /security page, so
// they share a return path.
func stepUpReturnPath(postPath string) string {
	switch {
	case postPath == "/account/email":
		return "/account/email"
	case strings.HasPrefix(postPath, "/security/"):
		return "/security"
	default:
		return "/account"
	}
}

// requireRecentAuth reports whether session's authentication is recent
// enough (within stepUpMaxAge) for a step-up-gated action to proceed. When
// it is not, it redirects the browser to /reauth naming the calling page as
// where to return to afterward, and returns false; callers must return
// immediately without performing the gated action.
func (a *app) requireRecentAuth(w http.ResponseWriter, r *http.Request, session *sulis.Session) bool {
	if session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return false
	}
	if err := a.auth.RequireRecentAuth(r.Context(), session, stepUpMaxAge); err != nil {
		next := stepUpReturnPath(r.URL.Path)
		http.Redirect(w, r, "/reauth?next="+url.QueryEscape(next), http.StatusSeeOther)
		return false
	}
	return true
}

// reauthPageData feeds reauth.html.
type reauthPageData struct {
	CSRFToken string
	Error     string
	Next      string
}

// handleReauthForm shows the step-up password form. next is read from the
// query string and passed through sanitizeNext before being echoed into the
// page, so a tampered link cannot turn this into an open redirect.
func (a *app) handleReauthForm(w http.ResponseWriter, r *http.Request) {
	next := sanitizeNext(r.URL.Query().Get("next"))

	token, cookie, err := a.auth.IssueCSRFToken()
	if err != nil {
		a.log.Error("issuing csrf token", "error", err)
		a.render(w, http.StatusInternalServerError, "error", "Something went wrong. Try again.")
		return
	}
	http.SetCookie(w, cookie)
	a.render(w, http.StatusOK, "reauth", reauthPageData{CSRFToken: token, Next: next})
}

// handleReauth verifies the submitted password with ReAuthenticate and, on
// success, redirects to the sanitized next page: RequireRecentAuth now
// passes for this same session.
func (a *app) handleReauth(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.log.Error("parsing reauth form", "error", err)
		a.render(w, http.StatusBadRequest, "error", "Could not read that form submission.")
		return
	}

	session, ok := sulis.SessionFromContext(r.Context())
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	password := r.FormValue("password")
	csrfToken := r.FormValue(sulis.CSRFFormField)
	next := sanitizeNext(r.FormValue("next"))

	if err := a.auth.ReAuthenticate(r.Context(), session, password, requestInfo(r)); err != nil {
		a.log.Error("re-authenticating", "error", err)
		a.render(w, http.StatusUnprocessableEntity, "reauth", reauthPageData{
			CSRFToken: csrfToken, Next: next, Error: "Incorrect password.",
		})
		return
	}

	// #nosec G710 -- next is sanitizeNext's return value, which is always
	// either the request's own "next" value checked against
	// allowedNextPaths or the fixed fallback "/account"; it is never the
	// raw, attacker-controlled form value itself.
	http.Redirect(w, r, next, http.StatusSeeOther)
}
