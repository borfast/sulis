package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/borfast/sulis"
)

// postJSON sends a JSON POST through c's handler with the given CSRF token
// in the header sulis.VerifyCSRFToken checks first, mirroring what
// static/passkeys.js does for the passkey ceremony endpoints (which take a
// JSON body, not a form, so testClient.post cannot be reused here).
func postJSON(t *testing.T, c *testClient, path, csrfToken string, body any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshaling json body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, c.base.String()+path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if csrfToken != "" {
		req.Header.Set(sulis.CSRFHeaderName, csrfToken)
	}
	for _, ck := range c.jar.Cookies(c.base) {
		req.AddCookie(ck)
	}
	rec := httptest.NewRecorder()
	c.handler.ServeHTTP(rec, req)
	c.jar.SetCookies(c.base, rec.Result().Cookies())
	return rec
}

// jsonError reads the {"error": "..."} shape every passkey JSON endpoint
// uses for a failure response.
func jsonError(t *testing.T, body []byte) string {
	t.Helper()
	var v struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("response is not the expected JSON error shape: %v, body = %s", err, body)
	}
	return v.Error
}

// backdateSession sets c's current session's AuthenticatedAt to age in the
// past, using the store directly: there is no other way to make a session's
// authentication go stale inside a single fast test run.
func backdateSession(t *testing.T, a *app, c *testClient, age time.Duration) {
	t.Helper()
	sessionCookie := c.cookie(a.auth.ClearSessionCookie().Name)
	if sessionCookie == nil {
		t.Fatalf("no session cookie to backdate")
	}
	session, _, err := a.auth.ValidateSession(t.Context(), sessionCookie.Value)
	if err != nil {
		t.Fatalf("validating session: %v", err)
	}
	if err := a.db.SessionStore().UpdateAuthenticatedAt(t.Context(), session.ID, time.Now().Add(-age)); err != nil {
		t.Fatalf("backdating AuthenticatedAt: %v", err)
	}
}

// TestPasskeyBeginRegistrationRequiresAuth checks that starting passkey
// registration without a session is rejected rather than silently starting
// a ceremony for no one.
func TestPasskeyBeginRegistrationRequiresAuth(t *testing.T) {
	a := newTestApp(t)
	c := newTestClient(t, a)

	rec := c.get("/login")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login: status = %d", rec.Code)
	}
	csrf := extractCSRFToken(t, rec.Body.String())

	rec = postJSON(t, c, "/api/passkeys/register/begin", csrf, map[string]string{})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	if msg := jsonError(t, rec.Body.Bytes()); msg == "" {
		t.Errorf("expected a JSON error message, body = %s", rec.Body.String())
	}
}

// TestPasskeyFinishWithGarbageBodyFailsCleanly checks that a Finish endpoint
// given a body that is not valid WebAuthn JSON fails with a clean 400 JSON
// error, not a 500, and never issues a session cookie along the way.
func TestPasskeyFinishWithGarbageBodyFailsCleanly(t *testing.T) {
	a := newTestApp(t)
	c := newTestClient(t, a)

	rec := c.get("/login")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login: status = %d", rec.Code)
	}
	csrf := extractCSRFToken(t, rec.Body.String())

	rec = postJSON(t, c, "/api/passkeys/discoverable/begin", csrf, map[string]string{})
	if rec.Code != http.StatusOK {
		t.Fatalf("discoverable begin: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, c.base.String()+"/api/passkeys/discoverable/finish",
		strings.NewReader("this is not json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(sulis.CSRFHeaderName, csrf)
	for _, ck := range c.jar.Cookies(c.base) {
		req.AddCookie(ck)
	}
	rec = httptest.NewRecorder()
	c.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("garbage body: status = %d, want %d, body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if msg := jsonError(t, rec.Body.Bytes()); msg == "" {
		t.Errorf("expected a JSON error message, body = %s", rec.Body.String())
	}
	sessionCookieName := a.auth.ClearSessionCookie().Name
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == sessionCookieName {
			t.Errorf("a garbage ceremony body must never set a session cookie")
		}
	}
}

// TestDiscoverableBeginReturnsCeremonyID checks that starting a usernameless
// login ceremony hands back a non-empty ceremony ID (carried in a
// short-lived cookie, per the ceremony-cookie pattern this file uses) along
// with the WebAuthn assertion options.
func TestDiscoverableBeginReturnsCeremonyID(t *testing.T) {
	a := newTestApp(t)
	c := newTestClient(t, a)

	rec := c.get("/login")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login: status = %d", rec.Code)
	}
	csrf := extractCSRFToken(t, rec.Body.String())

	rec = postJSON(t, c, "/api/passkeys/discoverable/begin", csrf, map[string]string{})
	if rec.Code != http.StatusOK {
		t.Fatalf("discoverable begin: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"challenge"`) {
		t.Errorf("expected a WebAuthn challenge in the response body: %s", rec.Body.String())
	}

	var ceremonyCookie *http.Cookie
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == passkeyDiscoverableCeremonyCookie {
			ceremonyCookie = ck
		}
	}
	if ceremonyCookie == nil || ceremonyCookie.Value == "" {
		t.Fatalf("expected a non-empty %s cookie, got cookies: %v",
			passkeyDiscoverableCeremonyCookie, rec.Result().Cookies())
	}
}

// TestStepUpGuardsChangeEmail checks that changing email on a session whose
// authentication has gone stale is redirected to /reauth, and that the same
// change goes through once ReAuthenticate has refreshed it.
func TestStepUpGuardsChangeEmail(t *testing.T) {
	a := newTestApp(t)
	c := newTestClient(t, a)
	email := "stepup@example.com"

	rec := registerUser(t, c, email, testPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("register: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = verifyEmail(t, a, c, email)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = login(t, c, email, testPassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	backdateSession(t, a, c, 10*time.Minute)

	rec = c.get("/account/email")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /account/email: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	csrf := extractCSRFToken(t, rec.Body.String())
	newEmail := "stepup-new@example.com"

	rec = c.post("/account/email", url.Values{"csrf_token": {csrf}, "email": {newEmail}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("change email with stale auth: status = %d, want redirect, body = %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/reauth?next=") {
		t.Fatalf("Location = %q, want /reauth?next=...", loc)
	}

	rec = c.get(loc)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status = %d, body = %s", loc, rec.Code, rec.Body.String())
	}
	reauthCSRF := extractCSRFToken(t, rec.Body.String())

	rec = c.post("/reauth", url.Values{
		"csrf_token": {reauthCSRF}, "password": {testPassword}, "next": {"/account/email"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("reauth: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	afterReauthLoc := rec.Header().Get("Location")
	if afterReauthLoc != "/account/email" {
		t.Errorf("reauth redirect = %q, want /account/email", afterReauthLoc)
	}

	// Following the redirect re-renders /account/email with a fresh CSRF
	// token (GET /reauth issued a new CSRF cookie, invalidating the one
	// "csrf" above was bound to). The session's authentication is now
	// fresh, so submitting the change with this token succeeds.
	rec = c.get(afterReauthLoc)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status = %d, body = %s", afterReauthLoc, rec.Code, rec.Body.String())
	}
	freshCSRF := extractCSRFToken(t, rec.Body.String())

	rec = c.post("/account/email", url.Values{"csrf_token": {freshCSRF}, "email": {newEmail}})
	if rec.Code != http.StatusOK {
		t.Fatalf("change email after reauth: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

// TestStepUpGuardsTOTPEnroll checks that the same gate covers adding a
// second factor, not just changing the email address: a stale session is
// sent to /reauth, and the enrollment goes through once the password has
// been proven again.
func TestStepUpGuardsTOTPEnroll(t *testing.T) {
	a := newTestApp(t)
	c := newTestClient(t, a)
	email := "stepup-totp@example.com"

	rec := registerUser(t, c, email, testPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("register: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = verifyEmail(t, a, c, email)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = login(t, c, email, testPassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	backdateSession(t, a, c, 10*time.Minute)

	rec = c.get("/security")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /security: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	csrf := extractCSRFToken(t, rec.Body.String())

	rec = c.post("/security/totp/enroll", url.Values{"csrf_token": {csrf}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("enroll with stale auth: status = %d, want redirect, body = %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/reauth?next=") {
		t.Fatalf("Location = %q, want /reauth?next=...", loc)
	}

	rec = c.get(loc)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status = %d, body = %s", loc, rec.Code, rec.Body.String())
	}
	reauthCSRF := extractCSRFToken(t, rec.Body.String())

	rec = c.post("/reauth", url.Values{
		"csrf_token": {reauthCSRF}, "password": {testPassword}, "next": {"/security"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("reauth: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/security" {
		t.Fatalf("reauth redirect = %q, want /security", got)
	}

	// The authentication is fresh again, so the same POST now enrolls. The
	// CSRF token has to be re-read from /security: GET /reauth issued a new
	// CSRF cookie, which the one read above no longer matches.
	rec = c.get("/security")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /security after reauth: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	freshCSRF := extractCSRFToken(t, rec.Body.String())

	rec = c.post("/security/totp/enroll", url.Values{"csrf_token": {freshCSRF}})
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll after reauth: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if extractTOTPSecret(t, rec.Body.String()) == "" {
		t.Errorf("expected an enrollment secret on the page, body = %s", rec.Body.String())
	}
}

// TestReauthWrongPasswordFails checks that submitting the wrong password on
// /reauth fails with a visible error and leaves the step-up gate closed: a
// gated action attempted right after still redirects back to /reauth.
func TestReauthWrongPasswordFails(t *testing.T) {
	a := newTestApp(t)
	c := newTestClient(t, a)
	email := "reauth-wrong@example.com"

	rec := registerUser(t, c, email, testPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("register: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = verifyEmail(t, a, c, email)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = login(t, c, email, testPassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	backdateSession(t, a, c, 10*time.Minute)

	rec = c.get("/account/email")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /account/email: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	csrf := extractCSRFToken(t, rec.Body.String())
	newEmail := "reauth-wrong-new@example.com"

	rec = c.post("/account/email", url.Values{"csrf_token": {csrf}, "email": {newEmail}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("change email with stale auth: status = %d, want redirect, body = %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")

	rec = c.get(loc)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: status = %d, body = %s", loc, rec.Code, rec.Body.String())
	}
	reauthCSRF := extractCSRFToken(t, rec.Body.String())

	rec = c.post("/reauth", url.Values{
		"csrf_token": {reauthCSRF}, "password": {"totally-wrong-password-1234"}, "next": {"/account/email"},
	})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("wrong password reauth: status = %d, want %d, body = %s",
			rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
	if msg := extractError(rec.Body.String()); msg == "" {
		t.Errorf("expected an error message for a wrong password, body = %s", rec.Body.String())
	}

	// The gate is still closed: the same gated action redirects to /reauth
	// again instead of going through. It uses reauthCSRF, not the original
	// csrf: GET /reauth issued a new CSRF cookie, and the failed reauth
	// attempt re-rendered the page under that same cookie without
	// reissuing it, so reauthCSRF is what currently matches the cookie in
	// the jar.
	rec = c.post("/account/email", url.Values{"csrf_token": {reauthCSRF}, "email": {newEmail}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("change email after failed reauth: status = %d, want redirect, body = %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); !strings.HasPrefix(got, "/reauth") {
		t.Errorf("Location = %q, want /reauth again", got)
	}
}
