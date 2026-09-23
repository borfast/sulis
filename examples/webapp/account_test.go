package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// testPassword satisfies both sulis's minimum length and its
// compromised-password blocklist: a long, non-dictionary constant rather
// than something like "password12345".
const testPassword = "horse-battery-staple-9481"

// csrfInputPattern and errorPattern pull values out of rendered HTML, the
// same way a human would read the page rather than reaching into the
// handler.
var (
	csrfInputPattern  = regexp.MustCompile(`name="csrf_token" value="([^"]*)"`)
	errorPattern      = regexp.MustCompile(`<p class="error">([^<]*)</p>`)
	sessionIDPattern  = regexp.MustCompile(`name="session_id" value="([^"]*)"`)
	mailLinkPatternTs = regexp.MustCompile(`https?://\S+`)
)

// testClient drives a.routes() through httptest, keeping a cookie jar so
// requests behave like a browser session across calls without opening a
// real network listener.
type testClient struct {
	t       *testing.T
	handler http.Handler
	jar     *cookiejar.Jar
	base    *url.URL
}

func newTestClient(t *testing.T, a *app) *testClient {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	base, err := url.Parse(a.baseURL)
	if err != nil {
		t.Fatalf("parsing base URL %q: %v", a.baseURL, err)
	}
	return &testClient{t: t, handler: a.routes(), jar: jar, base: base}
}

// do sends one request through the app's handler with this client's stored
// cookies attached, then stores any cookies the response sets. It does not
// follow redirects: tests inspect the redirect response directly.
func (c *testClient) do(method, path string, form url.Values) *httptest.ResponseRecorder {
	c.t.Helper()

	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, c.base.String()+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, ck := range c.jar.Cookies(c.base) {
		req.AddCookie(ck)
	}

	rec := httptest.NewRecorder()
	c.handler.ServeHTTP(rec, req)
	c.jar.SetCookies(c.base, rec.Result().Cookies())
	return rec
}

func (c *testClient) get(path string) *httptest.ResponseRecorder {
	c.t.Helper()
	return c.do(http.MethodGet, path, nil)
}

func (c *testClient) post(path string, form url.Values) *httptest.ResponseRecorder {
	c.t.Helper()
	return c.do(http.MethodPost, path, form)
}

// cookie returns the named cookie this client currently holds, or nil.
func (c *testClient) cookie(name string) *http.Cookie {
	for _, ck := range c.jar.Cookies(c.base) {
		if ck.Name == name {
			return ck
		}
	}
	return nil
}

func extractCSRFToken(t *testing.T, body string) string {
	t.Helper()
	m := csrfInputPattern.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no csrf token found in body:\n%s", body)
	}
	return m[1]
}

func extractError(body string) string {
	m := errorPattern.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return m[1]
}

// verificationLinkFor returns the verification link from the most recent
// mail sent to the given address.
func verificationLinkFor(t *testing.T, a *app, to string) string {
	t.Helper()
	msgs := a.mail.Messages()
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].To != to {
			continue
		}
		link := mailLinkPatternTs.FindString(msgs[i].Body)
		if link == "" {
			t.Fatalf("no link found in mail to %s: %q", to, msgs[i].Body)
		}
		return link
	}
	t.Fatalf("no mail sent to %s", to)
	return ""
}

// registerUser drives GET/POST /register for a fresh account and returns
// the response to the POST, leaving the signup session in the client's jar.
func registerUser(t *testing.T, c *testClient, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	rec := c.get("/register")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /register: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	token := extractCSRFToken(t, rec.Body.String())
	return c.post("/register", url.Values{
		"csrf_token": {token}, "email": {email}, "password": {password},
	})
}

// verifyEmail follows the verification link most recently sent to email.
func verifyEmail(t *testing.T, a *app, c *testClient, email string) *httptest.ResponseRecorder {
	t.Helper()
	link := verificationLinkFor(t, a, email)
	linkURL, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parsing verification link %q: %v", link, err)
	}
	return c.get(linkURL.Path + "?" + linkURL.RawQuery)
}

// login drives GET/POST /login for an existing account.
func login(t *testing.T, c *testClient, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	rec := c.get("/login")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	token := extractCSRFToken(t, rec.Body.String())
	return c.post("/login", url.Values{
		"csrf_token": {token}, "email": {email}, "password": {password},
	})
}

func TestRegisterVerifyLoginRoundtrip(t *testing.T) {
	a := newTestApp(t)
	c := newTestClient(t, a)
	email := "roundtrip@example.com"

	rec := registerUser(t, c, email, testPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("register: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	msgs := a.mail.Messages()
	if len(msgs) != 1 {
		t.Fatalf("mailbox has %d messages, want 1", len(msgs))
	}
	if msgs[0].Subject != "Verify your email" {
		t.Errorf("subject = %q, want %q", msgs[0].Subject, "Verify your email")
	}

	// Verify BEFORE logging in again: the default config requires a
	// verified email for a fresh login. Verifying the first email for an
	// account that already has a password also revokes every existing
	// session as a security measure (see sulis's VerifyEmail doc comment),
	// so the signup session above does not survive this step.
	rec = verifyEmail(t, a, c, email)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = c.get("/account")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("account (post-verify, signup session revoked): status = %d, want redirect", rec.Code)
	}

	// Log out to clear the now-stale cookie before logging back in.
	rec = c.get("/login")
	token := extractCSRFToken(t, rec.Body.String())
	rec = c.post("/logout", url.Values{"csrf_token": {token}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("logout: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// Log back in now that the email is verified.
	rec = login(t, c, email, testPassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/account" {
		t.Errorf("login redirect = %q, want /account", loc)
	}

	rec = c.get("/account")
	if rec.Code != http.StatusOK {
		t.Fatalf("account (post-login): status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

// TestRegisterIsRateLimitedPerIP hammers /register from one address and
// checks the app stops doing the work rather than creating an account per
// request. sulis throttles the flows it owns; registration is not one of
// them, so this is the app's own limiter answering.
func TestRegisterIsRateLimitedPerIP(t *testing.T) {
	a := newTestApp(t)
	c := newTestClient(t, a)

	// The budget is 5 per minute, so one more attempt than that is enough
	// to see the limit; a few extra make the test independent of the exact
	// number, since every request here comes from the same test IP.
	throttled := false
	for i := 0; i < 8; i++ {
		rec := registerUser(t, c, fmt.Sprintf("flood-%d@example.com", i), testPassword)
		if rec.Code != http.StatusTooManyRequests {
			continue
		}
		throttled = true
		if msg := extractError(rec.Body.String()); msg != tooManyAttemptsMessage {
			t.Errorf("throttled message = %q, want %q", msg, tooManyAttemptsMessage)
		}
		break
	}
	if !throttled {
		t.Errorf("expected a 429 from /register after repeated attempts from one IP")
	}
}

func TestUnauthenticatedAccountRedirectsToLogin(t *testing.T) {
	a := newTestApp(t)
	c := newTestClient(t, a)

	rec := c.get("/account")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want /login", loc)
	}
}

func TestPostWithoutCSRFTokenIs403(t *testing.T) {
	a := newTestApp(t)
	c := newTestClient(t, a)

	// Load the page so a CSRF cookie exists, then post without echoing the
	// token back in the form.
	rec := c.get("/register")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /register: status = %d", rec.Code)
	}

	rec = c.post("/register", url.Values{
		"email": {"no-token@example.com"}, "password": {testPassword},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestLoginWrongPasswordIsGenericError(t *testing.T) {
	a := newTestApp(t)
	c := newTestClient(t, a)

	// An unknown email.
	rec := login(t, c, "nobody@example.com", testPassword)
	unknownMsg := extractError(rec.Body.String())
	if unknownMsg == "" {
		t.Fatalf("expected an error message for an unknown email, body = %s", rec.Body.String())
	}

	// A real, registered (but unverified) account with the wrong password.
	// VerifyPassword rejects a wrong password before completeFirstFactor
	// ever checks whether the email is verified, so this still exercises
	// ErrInvalidCredentials, not ErrEmailNotVerified.
	email := "wrongpass@example.com"
	rec = registerUser(t, c, email, testPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("register: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = login(t, c, email, "not-the-right-password-8214")
	wrongPassMsg := extractError(rec.Body.String())
	if wrongPassMsg == "" {
		t.Fatalf("expected an error message for a wrong password, body = %s", rec.Body.String())
	}

	if unknownMsg != wrongPassMsg {
		t.Errorf("messages differ: unknown email = %q, wrong password = %q", unknownMsg, wrongPassMsg)
	}
}

func TestLogoutClearsSessionAndRevokes(t *testing.T) {
	a := newTestApp(t)
	c := newTestClient(t, a)
	email := "logout@example.com"

	rec := registerUser(t, c, email, testPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("register: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	sessionCookieName := a.auth.ClearSessionCookie().Name
	staleCookie := c.cookie(sessionCookieName)
	if staleCookie == nil {
		t.Fatalf("expected a session cookie after registering")
	}

	rec = c.get("/account")
	if rec.Code != http.StatusOK {
		t.Fatalf("account: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	token := extractCSRFToken(t, rec.Body.String())

	rec = c.post("/logout", url.Values{"csrf_token": {token}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("logout: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// The response must clear the cookie (a negative Max-Age deletes it).
	cleared := false
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == sessionCookieName && ck.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Errorf("expected logout to clear the session cookie, got cookies: %v", rec.Result().Cookies())
	}

	// The pre-logout token must no longer authenticate: RevokeSession, not
	// just clearing the cookie client-side, is what makes this fail.
	req := httptest.NewRequest(http.MethodGet, c.base.String()+"/account", nil)
	req.AddCookie(staleCookie)
	rr := httptest.NewRecorder()
	a.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Errorf("account with the revoked session token: status = %d, want redirect", rr.Code)
	}
}

func TestSessionListShowsAndRevokesOtherSession(t *testing.T) {
	a := newTestApp(t)
	email := "multisession@example.com"

	clientA := newTestClient(t, a)
	rec := registerUser(t, clientA, email, testPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("register: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = verifyEmail(t, a, clientA, email)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// Verifying the first email for an account with a password revokes
	// every existing session (see sulis's VerifyEmail doc comment), so
	// clientA's signup session is already dead; log in fresh to get a live
	// session of its own.
	rec = login(t, clientA, email, testPassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("clientA login: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// A second "browser" logs into the same, now-verified account,
	// creating a second session.
	clientB := newTestClient(t, a)
	rec = login(t, clientB, email, testPassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("clientB login: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// clientA's account page should list exactly one revocable session:
	// its own is current and has no revoke form.
	rec = clientA.get("/account")
	if rec.Code != http.StatusOK {
		t.Fatalf("clientA account: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	matches := sessionIDPattern.FindAllStringSubmatch(body, -1)
	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 revocable session, got %d:\n%s", len(matches), body)
	}
	otherSessionID := matches[0][1]

	token := extractCSRFToken(t, body)
	rec = clientA.post("/sessions/revoke", url.Values{
		"csrf_token": {token}, "session_id": {otherSessionID},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// clientB's session is now dead.
	rec = clientB.get("/account")
	if rec.Code != http.StatusSeeOther {
		t.Errorf("clientB account after revoke: status = %d, want redirect", rec.Code)
	}

	// clientA's own session still works.
	rec = clientA.get("/account")
	if rec.Code != http.StatusOK {
		t.Errorf("clientA account after revoking the other session: status = %d", rec.Code)
	}
}
