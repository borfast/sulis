package main

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var (
	totpSecretPattern        = regexp.MustCompile(`Secret: <code>([^<]*)</code>`)
	recoveryCodePattern      = regexp.MustCompile(`<li><code>([^<]*)</code></li>`)
	recoveryRemainingPattern = regexp.MustCompile(`(\d+) recovery codes remaining\.`)
)

func extractTOTPSecret(t *testing.T, body string) string {
	t.Helper()
	m := totpSecretPattern.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no totp secret found in body:\n%s", body)
	}
	return m[1]
}

func extractRecoveryCodes(t *testing.T, body string) []string {
	t.Helper()
	matches := recoveryCodePattern.FindAllStringSubmatch(body, -1)
	codes := make([]string, len(matches))
	for i, m := range matches {
		codes[i] = m[1]
	}
	return codes
}

func extractRecoveryRemaining(t *testing.T, body string) int {
	t.Helper()
	m := recoveryRemainingPattern.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no recovery-remaining count found in body:\n%s", body)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parsing recovery remaining count %q: %v", m[1], err)
	}
	return n
}

// logoutClient logs out an authenticated client, fetching a CSRF token from
// the account page first.
func logoutClient(t *testing.T, c *testClient) {
	t.Helper()
	rec := c.get("/account")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /account before logout: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	csrf := extractCSRFToken(t, rec.Body.String())
	rec = c.post("/logout", url.Values{"csrf_token": {csrf}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("logout: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

// enrollTOTP drives enrollment and confirmation for an already-authenticated
// client, returning the enrolled base32 secret so tests can mint codes with
// a.totp.Generate.
func enrollTOTP(t *testing.T, a *app, c *testClient) string {
	t.Helper()

	rec := c.get("/security")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /security: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	csrf := extractCSRFToken(t, rec.Body.String())

	rec = c.post("/security/totp/enroll", url.Values{"csrf_token": {csrf}})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /security/totp/enroll: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	secret := extractTOTPSecret(t, rec.Body.String())
	confirmCSRF := extractCSRFToken(t, rec.Body.String())

	code, err := a.totp.Generate(secret, time.Now())
	if err != nil {
		t.Fatalf("generating totp code: %v", err)
	}
	rec = c.post("/security/totp/confirm", url.Values{"csrf_token": {confirmCSRF}, "code": {code}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /security/totp/confirm: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/security" {
		t.Fatalf("confirm redirect = %q, want /security", loc)
	}

	return secret
}

// TestTOTPEnrollConfirmAndTwoFactorLogin enrolls a TOTP factor, confirms it,
// logs out, and checks that logging back in requires the second factor
// before a session exists.
func TestTOTPEnrollConfirmAndTwoFactorLogin(t *testing.T) {
	a := newTestApp(t)
	c := newTestClient(t, a)
	email := "totp-login@example.com"

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
		t.Fatalf("first login: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/account" {
		t.Fatalf("first login redirect = %q, want /account (no second factor enrolled yet)", loc)
	}

	secret := enrollTOTP(t, a, c)

	rec = c.get("/security")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /security after enrolling: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "/security/totp/disable") {
		t.Errorf("expected the security page to show TOTP as active:\n%s", rec.Body.String())
	}

	logoutClient(t, c)

	rec = login(t, c, email, testPassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("second login: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/login/second-factor" {
		t.Fatalf("second login redirect = %q, want /login/second-factor", loc)
	}
	sessionCookieName := a.auth.ClearSessionCookie().Name
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == sessionCookieName {
			t.Errorf("session cookie set before the second factor was completed")
		}
	}

	rec = c.get("/login/second-factor")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login/second-factor: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	sfCSRF := extractCSRFToken(t, rec.Body.String())

	code, err := a.totp.Generate(secret, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatalf("generating login totp code: %v", err)
	}
	rec = c.post("/login/second-factor", url.Values{"csrf_token": {sfCSRF}, "code": {code}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /login/second-factor: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/account" {
		t.Errorf("second-factor redirect = %q, want /account", loc)
	}

	cleared := false
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == pendingTokenCookie && ck.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Errorf("expected the pending token cookie cleared, got cookies: %v", rec.Result().Cookies())
	}

	rec = c.get("/account")
	if rec.Code != http.StatusOK {
		t.Fatalf("account after second-factor login: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

// TestRecoveryCodeCompletesSecondFactor generates recovery codes, uses one to
// complete a second-factor login, and checks the remaining count decreased.
func TestRecoveryCodeCompletesSecondFactor(t *testing.T) {
	a := newTestApp(t)
	c := newTestClient(t, a)
	email := "recovery-login@example.com"

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
		t.Fatalf("first login: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	enrollTOTP(t, a, c)

	rec = c.get("/security")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /security: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	csrf := extractCSRFToken(t, rec.Body.String())
	rec = c.post("/security/recovery/generate", url.Values{"csrf_token": {csrf}})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /security/recovery/generate: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	codes := extractRecoveryCodes(t, rec.Body.String())
	if len(codes) == 0 {
		t.Fatalf("expected at least one recovery code, body = %s", rec.Body.String())
	}

	logoutClient(t, c)

	rec = login(t, c, email, testPassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("second login: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/login/second-factor" {
		t.Fatalf("second login redirect = %q, want /login/second-factor", loc)
	}

	rec = c.get("/login/second-factor")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login/second-factor: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	sfCSRF := extractCSRFToken(t, rec.Body.String())

	rec = c.post("/login/second-factor", url.Values{
		"csrf_token": {sfCSRF}, "code": {codes[0]}, "use_recovery": {"1"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("second factor via recovery code: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/account" {
		t.Errorf("second-factor redirect = %q, want /account", loc)
	}

	rec = c.get("/security")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /security after recovery login: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	remaining := extractRecoveryRemaining(t, rec.Body.String())
	if remaining != len(codes)-1 {
		t.Errorf("remaining = %d, want %d", remaining, len(codes)-1)
	}
}

// TestSecondFactorReplayRejected checks that a TOTP code accepted once
// cannot be used again on a later login attempt.
func TestSecondFactorReplayRejected(t *testing.T) {
	a := newTestApp(t)
	c := newTestClient(t, a)
	email := "replay@example.com"

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
		t.Fatalf("first login: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	secret := enrollTOTP(t, a, c)
	logoutClient(t, c)

	rec = login(t, c, email, testPassword)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login/second-factor" {
		t.Fatalf("second login: status = %d, location = %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = c.get("/login/second-factor")
	sfCSRF := extractCSRFToken(t, rec.Body.String())

	code, err := a.totp.Generate(secret, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatalf("generating totp code: %v", err)
	}
	rec = c.post("/login/second-factor", url.Values{"csrf_token": {sfCSRF}, "code": {code}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("first use of the code: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	logoutClient(t, c)

	rec = login(t, c, email, testPassword)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login/second-factor" {
		t.Fatalf("third login: status = %d, location = %q", rec.Code, rec.Header().Get("Location"))
	}
	rec = c.get("/login/second-factor")
	sfCSRF = extractCSRFToken(t, rec.Body.String())

	// Same code, already accepted once: must be rejected as a replay.
	rec = c.post("/login/second-factor", url.Values{"csrf_token": {sfCSRF}, "code": {code}})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("replayed code: status = %d, want %d, body = %s",
			rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
	if msg := extractError(rec.Body.String()); msg == "" {
		t.Errorf("expected an error message for a replayed code, body = %s", rec.Body.String())
	}
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == a.auth.ClearSessionCookie().Name {
			t.Errorf("session cookie set for a rejected replayed code")
		}
	}
}

// TestTamperedPendingCookieFailsGenerically checks that altering the
// pending token cookie fails the second-factor login generically, without a
// session. The token is now the only pending state the browser holds, so
// tampering with it leaves the server with no pending login to resolve.
func TestTamperedPendingCookieFailsGenerically(t *testing.T) {
	a := newTestApp(t)
	c := newTestClient(t, a)
	email := "tampered@example.com"

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
		t.Fatalf("first login: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	secret := enrollTOTP(t, a, c)
	logoutClient(t, c)

	rec = login(t, c, email, testPassword)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login/second-factor" {
		t.Fatalf("second login: status = %d, location = %q", rec.Code, rec.Header().Get("Location"))
	}

	// Tamper with the pending token cookie the browser is holding. The code
	// submitted below is genuinely valid for this user, so only the
	// tampered token can make the attempt fail.
	c.jar.SetCookies(c.base, []*http.Cookie{{Name: pendingTokenCookie, Value: "not-a-real-token", Path: "/"}})

	rec = c.get("/login/second-factor")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login/second-factor: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	sfCSRF := extractCSRFToken(t, rec.Body.String())

	code, err := a.totp.Generate(secret, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatalf("generating totp code: %v", err)
	}
	rec = c.post("/login/second-factor", url.Values{"csrf_token": {sfCSRF}, "code": {code}})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("tampered token: status = %d, want %d, body = %s",
			rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
	if msg := extractError(rec.Body.String()); msg == "" {
		t.Errorf("expected a generic error message, body = %s", rec.Body.String())
	}
	sessionCookieName := a.auth.ClearSessionCookie().Name
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == sessionCookieName {
			t.Errorf("session cookie set despite the tampered token")
		}
	}

	// The tampered attempt must not have left a usable session behind.
	rec = c.get("/account")
	if rec.Code != http.StatusSeeOther {
		t.Errorf("account after tampered second-factor attempt: status = %d, want redirect", rec.Code)
	}
}

// TestFabricatedPendingCookieCannotProbeFactors is the reason the pending
// user ID lives on the server. An attacker who holds one of a victim's
// recovery codes, but no pending login of their own, invents a pending
// token cookie and submits that code. The server has no pending entry for
// the invented token, so it has no account to test the code against: the
// attempt fails generically and the victim's code is still unspent.
func TestFabricatedPendingCookieCannotProbeFactors(t *testing.T) {
	a := newTestApp(t)
	victim := newTestClient(t, a)
	email := "probe-victim@example.com"

	rec := registerUser(t, victim, email, testPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("register: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = verifyEmail(t, a, victim, email)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = login(t, victim, email, testPassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	enrollTOTP(t, a, victim)

	rec = victim.get("/security")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /security: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	csrf := extractCSRFToken(t, rec.Body.String())
	rec = victim.post("/security/recovery/generate", url.Values{"csrf_token": {csrf}})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /security/recovery/generate: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	codes := extractRecoveryCodes(t, rec.Body.String())
	if len(codes) == 0 {
		t.Fatalf("expected at least one recovery code, body = %s", rec.Body.String())
	}

	user, err := a.users.GetUserByEmail(t.Context(), email)
	if err != nil {
		t.Fatalf("looking up the victim: %v", err)
	}
	before, err := a.recovery.Remaining(t.Context(), user.ID)
	if err != nil {
		t.Fatalf("reading remaining recovery codes: %v", err)
	}

	// A different browser entirely: it never logged in, so the only pending
	// state it has is what it just made up. It sends the victim's user ID
	// in the cookie an earlier version of this app read that value from,
	// alongside an invented token: if anything still believed a
	// client-supplied user ID, this is the request that would consume the
	// victim's recovery code.
	attacker := newTestClient(t, a)
	attacker.jar.SetCookies(attacker.base, []*http.Cookie{
		{Name: pendingTokenCookie, Value: "fabricated-pending-token", Path: "/"},
		{Name: "pending_2fa_user", Value: user.ID, Path: "/"},
	})

	rec = attacker.get("/login/second-factor")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /login/second-factor: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	sfCSRF := extractCSRFToken(t, rec.Body.String())

	rec = attacker.post("/login/second-factor", url.Values{
		"csrf_token": {sfCSRF}, "code": {codes[0]}, "use_recovery": {"1"},
	})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("fabricated pending cookie: status = %d, want %d, body = %s",
			rec.Code, http.StatusUnprocessableEntity, rec.Body.String())
	}
	if msg := extractError(rec.Body.String()); msg == "" {
		t.Errorf("expected a generic error message, body = %s", rec.Body.String())
	}
	sessionCookieName := a.auth.ClearSessionCookie().Name
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == sessionCookieName {
			t.Errorf("session cookie set for a fabricated pending cookie")
		}
	}

	// The factor check never ran, so the victim's code was never consumed.
	after, err := a.recovery.Remaining(t.Context(), user.ID)
	if err != nil {
		t.Fatalf("reading remaining recovery codes after the attempt: %v", err)
	}
	if after != before {
		t.Errorf("remaining recovery codes = %d, want %d: the submitted code was checked against an account",
			after, before)
	}
}

// TestNoSessionCookieBeforeSecondFactor checks that the redirect to
// /login/second-factor never sets a session cookie, only the pending ones.
func TestNoSessionCookieBeforeSecondFactor(t *testing.T) {
	a := newTestApp(t)
	c := newTestClient(t, a)
	email := "no-session-yet@example.com"

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
		t.Fatalf("first login: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	enrollTOTP(t, a, c)
	logoutClient(t, c)

	rec = login(t, c, email, testPassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("second login: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/login/second-factor" {
		t.Fatalf("second login redirect = %q, want /login/second-factor", loc)
	}

	sessionCookieName := a.auth.ClearSessionCookie().Name
	sawPendingToken := false
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == sessionCookieName {
			t.Errorf("a session cookie must not be set before the second factor is completed, got: %v", ck)
		}
		if ck.Name == pendingTokenCookie {
			sawPendingToken = true
		}
		// The user ID must not travel to the client at all: the pending
		// entry on the server holds it, keyed by this token.
		if ck.Name == "pending_2fa_user" {
			t.Errorf("the second-factor user ID must not be sent to the client, got: %v", ck)
		}
	}
	if !sawPendingToken {
		t.Errorf("expected the pending token cookie to be set, got cookies: %v", rec.Result().Cookies())
	}
}
