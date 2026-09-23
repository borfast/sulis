package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestPasswordResetRoundtripRevokesSessions checks that resetting a
// password revokes every session that existed before it.
func TestPasswordResetRoundtripRevokesSessions(t *testing.T) {
	a := newTestApp(t)
	c := newTestClient(t, a)
	email := "resetme@example.com"

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

	// Confirm the session actually works before resetting.
	rec = c.get("/account")
	if rec.Code != http.StatusOK {
		t.Fatalf("account before reset: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// Request the reset from a separate "browser": /forgot carries no
	// session and doesn't need one.
	forgot := newTestClient(t, a)
	rec = forgot.get("/forgot")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /forgot: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	csrf := extractCSRFToken(t, rec.Body.String())
	rec = forgot.post("/forgot", url.Values{"csrf_token": {csrf}, "email": {email}})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /forgot: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	link := verificationLinkFor(t, a, email)
	linkURL, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parsing reset link %q: %v", link, err)
	}

	rec = forgot.get(linkURL.Path + "?" + linkURL.RawQuery)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /reset: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	resetCSRF := extractCSRFToken(t, rec.Body.String())

	const newPassword = "correct-horse-battery-4471"
	rec = forgot.post("/reset", url.Values{
		"csrf_token": {resetCSRF}, "token": {linkURL.Query().Get("token")}, "password": {newPassword},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /reset: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// The old session must be dead.
	rec = c.get("/account")
	if rec.Code != http.StatusSeeOther {
		t.Errorf("account with pre-reset session: status = %d, want redirect", rec.Code)
	}

	// The old password must be rejected; the new one must work.
	fresh := newTestClient(t, a)
	rec = login(t, fresh, email, testPassword)
	if rec.Code == http.StatusSeeOther {
		t.Errorf("expected the old password to be rejected after reset")
	}

	rec = login(t, fresh, email, newPassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login with new password: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

// TestForgotUnknownEmailRendersSamePage is the enumeration-safety check: a
// known and an unknown address must get identical responses.
func TestForgotUnknownEmailRendersSamePage(t *testing.T) {
	a := newTestApp(t)

	known := "known@example.com"
	knownClient := newTestClient(t, a)
	rec := registerUser(t, knownClient, known, testPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("register: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	forgotAs := func(email string) *httptest.ResponseRecorder {
		c := newTestClient(t, a)
		rec := c.get("/forgot")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /forgot: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		csrf := extractCSRFToken(t, rec.Body.String())
		return c.post("/forgot", url.Values{"csrf_token": {csrf}, "email": {email}})
	}

	knownRec := forgotAs(known)
	unknownRec := forgotAs("nobody@example.com")

	if knownRec.Code != unknownRec.Code {
		t.Fatalf("status differs: known = %d, unknown = %d", knownRec.Code, unknownRec.Code)
	}
	if knownRec.Body.String() != unknownRec.Body.String() {
		t.Errorf("bodies differ between known and unknown email:\nknown:\n%s\nunknown:\n%s",
			knownRec.Body.String(), unknownRec.Body.String())
	}

	// A reset email should only have gone out for the known address (the
	// registration above also sends a verification email, so count by
	// subject rather than by mailbox size).
	resets := 0
	for _, m := range a.mail.Messages() {
		if m.Subject == "Reset your password" {
			resets++
		}
	}
	if resets != 1 {
		t.Errorf("mailbox has %d password-reset messages, want 1 (for the known address only)", resets)
	}
}

// TestMagicLinkRoundtrip drives GET/POST /magic, follows the emailed link,
// and checks the browser that requested it lands signed in.
func TestMagicLinkRoundtrip(t *testing.T) {
	a := newTestApp(t)
	c := newTestClient(t, a)
	email := "magic@example.com"

	rec := c.get("/magic")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /magic: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	csrf := extractCSRFToken(t, rec.Body.String())
	rec = c.post("/magic", url.Values{"csrf_token": {csrf}, "email": {email}})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /magic: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if c.cookie(magicNonceCookie) == nil {
		t.Fatalf("expected a %s cookie after requesting a magic link", magicNonceCookie)
	}

	link := verificationLinkFor(t, a, email)
	linkURL, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parsing magic link %q: %v", link, err)
	}

	rec = c.get(linkURL.Path + "?" + linkURL.RawQuery)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("GET /magic/redeem: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/account" {
		t.Errorf("redeem redirect = %q, want /account", loc)
	}

	cleared := false
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == magicNonceCookie && ck.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Errorf("expected /magic/redeem to clear %s, got cookies: %v", magicNonceCookie, rec.Result().Cookies())
	}

	rec = c.get("/account")
	if rec.Code != http.StatusOK {
		t.Fatalf("account after magic-link login: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), email) {
		t.Errorf("account page does not show %q:\n%s", email, rec.Body.String())
	}
}

// TestMagicLinkInDifferentBrowserExplainsBinding: a magic link opened
// without its nonce cookie must name the fix, not just say "invalid".
func TestMagicLinkInDifferentBrowserExplainsBinding(t *testing.T) {
	a := newTestApp(t)
	requester := newTestClient(t, a)
	email := "bound@example.com"

	rec := requester.get("/magic")
	csrf := extractCSRFToken(t, rec.Body.String())
	rec = requester.post("/magic", url.Values{"csrf_token": {csrf}, "email": {email}})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /magic: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	link := verificationLinkFor(t, a, email)
	linkURL, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parsing magic link %q: %v", link, err)
	}

	// A different browser: a fresh jar, so no magic_nonce cookie exists.
	other := newTestClient(t, a)
	rec = other.get(linkURL.Path + "?" + linkURL.RawQuery)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("redeem without nonce cookie: status = %d, want %d, body = %s",
			rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	msg := extractError(rec.Body.String())
	if !strings.Contains(msg, "browser") {
		t.Errorf("expected the binding error to name the browser it was requested from, got %q", msg)
	}
}

// TestGarbageTokenLinksRenderFriendlyErrors: /verify, /reset, /magic/redeem,
// and /email/confirm must turn a garbage token into a friendly page, not 500.
func TestGarbageTokenLinksRenderFriendlyErrors(t *testing.T) {
	a := newTestApp(t)

	assertFriendlyError := func(t *testing.T, rec *httptest.ResponseRecorder, label string) {
		t.Helper()
		if rec.Code == http.StatusInternalServerError {
			t.Fatalf("%s: got a 500, want a friendly error page: %s", label, rec.Body.String())
		}
		if extractError(rec.Body.String()) == "" {
			t.Errorf("%s: expected an error message on the page, body = %s", label, rec.Body.String())
		}
	}

	c := newTestClient(t, a)

	rec := c.get("/verify?token=garbage")
	assertFriendlyError(t, rec, "/verify")

	// /reset only checks the token once a new password is submitted: the
	// GET just shows the form with the token embedded.
	rec = c.get("/reset?token=garbage")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /reset: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	resetCSRF := extractCSRFToken(t, rec.Body.String())
	rec = c.post("/reset", url.Values{
		"csrf_token": {resetCSRF}, "token": {"garbage"}, "password": {testPassword},
	})
	assertFriendlyError(t, rec, "/reset")

	// Seed a real nonce cookie first, so the garbage token hits the generic
	// invalid-token path rather than the missing-cookie one.
	rec = c.get("/magic")
	magicCSRF := extractCSRFToken(t, rec.Body.String())
	rec = c.post("/magic", url.Values{"csrf_token": {magicCSRF}, "email": {"garbage-magic@example.com"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /magic: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = c.get("/magic/redeem?token=garbage")
	assertFriendlyError(t, rec, "/magic/redeem")

	rec = c.get("/email/confirm?token=garbage")
	assertFriendlyError(t, rec, "/email/confirm")
}

// TestChangeEmailRoundtrip: the confirm link goes to the NEW address, and
// the OLD address stays live until confirmation swaps it over.
func TestChangeEmailRoundtrip(t *testing.T) {
	a := newTestApp(t)
	c := newTestClient(t, a)
	oldEmail := "old@example.com"
	newEmail := "new@example.com"

	rec := registerUser(t, c, oldEmail, testPassword)
	if rec.Code != http.StatusOK {
		t.Fatalf("register: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = verifyEmail(t, a, c, oldEmail)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = login(t, c, oldEmail, testPassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = c.get("/account/email")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /account/email: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	csrf := extractCSRFToken(t, rec.Body.String())
	rec = c.post("/account/email", url.Values{"csrf_token": {csrf}, "email": {newEmail}})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /account/email: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	link := verificationLinkFor(t, a, newEmail)
	for _, m := range a.mail.Messages() {
		if m.To == oldEmail && strings.Contains(m.Body, "/email/confirm") {
			t.Errorf("a confirmation link must not be mailed to the old address: %+v", m)
		}
	}

	if u, err := a.users.GetUserByEmail(t.Context(), oldEmail); err != nil || u.Email != oldEmail {
		t.Fatalf("old address should still be live before confirmation: user = %+v, err = %v", u, err)
	}

	linkURL, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parsing email-change link %q: %v", link, err)
	}
	rec = c.get(linkURL.Path + "?" + linkURL.RawQuery)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /email/confirm: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), newEmail) {
		t.Errorf("confirmation page does not mention the new address:\n%s", rec.Body.String())
	}

	if _, err := a.users.GetUserByEmail(t.Context(), oldEmail); err == nil {
		t.Errorf("old address should no longer resolve to a user after confirmation")
	}
	u, err := a.users.GetUserByEmail(t.Context(), newEmail)
	if err != nil {
		t.Fatalf("new address should resolve to the user after confirmation: %v", err)
	}
	if u.Email != newEmail {
		t.Errorf("user.Email = %q, want %q", u.Email, newEmail)
	}

	// Confirming an email change revokes every session on the account.
	rec = c.get("/account")
	if rec.Code != http.StatusSeeOther {
		t.Errorf("account after email change: status = %d, want redirect", rec.Code)
	}
}

// TestInvalidEmailOnForgotAndMagicRendersForm: a malformed or empty email
// must re-render the form with a message, never a 500.
func TestInvalidEmailOnForgotAndMagicRendersForm(t *testing.T) {
	a := newTestApp(t)

	assertFriendlyForm := func(t *testing.T, rec *httptest.ResponseRecorder, label string) {
		t.Helper()
		if rec.Code == http.StatusInternalServerError {
			t.Fatalf("%s: got a 500, want the form re-rendered: %s", label, rec.Body.String())
		}
		if msg := extractError(rec.Body.String()); msg == "" {
			t.Errorf("%s: expected an inline error message, body = %s", label, rec.Body.String())
		}
	}

	for _, email := range []string{"not-an-email", ""} {
		c := newTestClient(t, a)

		rec := c.get("/forgot")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /forgot: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		csrf := extractCSRFToken(t, rec.Body.String())
		rec = c.post("/forgot", url.Values{"csrf_token": {csrf}, "email": {email}})
		assertFriendlyForm(t, rec, "POST /forgot email="+email)

		rec = c.get("/magic")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /magic: status = %d, body = %s", rec.Code, rec.Body.String())
		}
		csrf = extractCSRFToken(t, rec.Body.String())
		rec = c.post("/magic", url.Values{"csrf_token": {csrf}, "email": {email}})
		assertFriendlyForm(t, rec, "POST /magic email="+email)
	}
}
