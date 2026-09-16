package sulis

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestIssueCSRFTokenCookieAttributes(t *testing.T) {
	token, cookie, err := IssueCSRFToken()
	if err != nil {
		t.Fatalf("IssueCSRFToken: %v", err)
	}
	if token == "" {
		t.Fatal("expected a non-empty token")
	}
	if cookie.Value != token {
		t.Fatalf("expected cookie value to equal the returned token; got %q vs %q", cookie.Value, token)
	}
	if cookie.Name != CSRFCookieName {
		t.Fatalf("expected cookie name %q, got %q", CSRFCookieName, cookie.Name)
	}
	if cookie.HttpOnly {
		t.Fatal("expected the CSRF cookie to NOT be HttpOnly: client script must be able to read it")
	}
	if !cookie.Secure {
		t.Fatal("expected Secure=true")
	}
	if cookie.Path != "/" {
		t.Fatalf("expected Path=/, got %q", cookie.Path)
	}
	if cookie.Domain != "" {
		t.Fatalf("expected no Domain, got %q", cookie.Domain)
	}
}

func TestIssueCSRFTokenIsRandomPerCall(t *testing.T) {
	t1, _, err := IssueCSRFToken()
	if err != nil {
		t.Fatalf("IssueCSRFToken: %v", err)
	}
	t2, _, err := IssueCSRFToken()
	if err != nil {
		t.Fatalf("IssueCSRFToken: %v", err)
	}
	if t1 == t2 {
		t.Fatal("expected two calls to IssueCSRFToken to produce different tokens")
	}
}

func TestSulisIssueCSRFTokenUsesConfiguredNameAndFixedAttributes(t *testing.T) {
	const customName = "csrf_token"
	s, _, _, _ := newTestEnv(WithCSRFCookieName(customName))

	token, cookie, err := s.IssueCSRFToken()
	if err != nil {
		t.Fatalf("(*Sulis).IssueCSRFToken: %v", err)
	}
	if cookie.Name != customName {
		t.Fatalf("expected cookie name %q, got %q", customName, cookie.Name)
	}
	if cookie.Value != token {
		t.Fatalf("expected cookie value to equal the returned token; got %q vs %q", cookie.Value, token)
	}
	if !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" || cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("custom CSRF cookie changed fixed attributes: %+v", cookie)
	}

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(cookie)
	req.Header.Set(CSRFHeaderName, token)
	if err := s.VerifyCSRFToken(req); err != nil {
		t.Fatalf("(*Sulis).VerifyCSRFToken with custom cookie: %v", err)
	}
	if err := VerifyCSRFToken(req); err == nil {
		t.Fatal("package-level VerifyCSRFToken unexpectedly accepted a custom-name cookie")
	}

	formReq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(url.Values{CSRFFormField: {token}}.Encode()))
	formReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	formReq.AddCookie(cookie)
	if err := s.VerifyCSRFToken(formReq); err != nil {
		t.Fatalf("(*Sulis).VerifyCSRFToken with custom cookie and form fallback: %v", err)
	}
	precedenceReq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(url.Values{CSRFFormField: {token}}.Encode()))
	precedenceReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	precedenceReq.AddCookie(cookie)
	precedenceReq.Header.Set(CSRFHeaderName, "wrong-header-token")
	if err := s.VerifyCSRFToken(precedenceReq); err == nil {
		t.Fatal("(*Sulis).VerifyCSRFToken unexpectedly fell back to the form when the header was present")
	}

	defaultToken, defaultCookie, err := IssueCSRFToken()
	if err != nil {
		t.Fatalf("IssueCSRFToken: %v", err)
	}
	defaultReq := httptest.NewRequest(http.MethodPost, "/", nil)
	defaultReq.AddCookie(defaultCookie)
	defaultReq.Header.Set(CSRFHeaderName, defaultToken)
	if err := VerifyCSRFToken(defaultReq); err != nil {
		t.Fatalf("package-level VerifyCSRFToken with default cookie: %v", err)
	}
	if err := s.VerifyCSRFToken(defaultReq); err == nil {
		t.Fatal("configured VerifyCSRFToken unexpectedly accepted a default-name cookie")
	}
}

func TestWithCSRFCookieNameRejectsInvalidName(t *testing.T) {
	for _, name := range []string{"", "not a valid name"} {
		t.Run(name, func(t *testing.T) {
			users := newMemUserStore()
			sessions := newMemSessionStore()
			tokens := newMemTokenStore()
			factors := newFakeFactors()
			if _, err := New(users, sessions, tokens, factors, WithCSRFCookieName(name)); err == nil {
				t.Fatal("expected invalid CSRF cookie name to be rejected")
			}
		})
	}
}

func TestNewRejectsCollidingCookieNames(t *testing.T) {
	const shared = "app_token"
	users := newMemUserStore()
	sessions := newMemSessionStore()
	tokens := newMemTokenStore()
	factors := newFakeFactors()
	_, err := New(users, sessions, tokens, factors,
		WithArgon2Params(testArgon2Params),
		WithCookieName(shared), WithCSRFCookieName(shared))
	if err == nil {
		t.Fatal("expected New to reject a session cookie name equal to the CSRF cookie name")
	}
	if !strings.Contains(err.Error(), shared) {
		t.Fatalf("error should name the colliding value, got %v", err)
	}
}

func TestSulisRequireCSRFTokenUsesConfiguredName(t *testing.T) {
	const customName = "csrf_token"
	s, _, _, _ := newTestEnv(WithCSRFCookieName(customName))
	token, cookie, err := s.IssueCSRFToken()
	if err != nil {
		t.Fatalf("(*Sulis).IssueCSRFToken: %v", err)
	}

	handler := s.RequireCSRFToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(cookie)
	req.Header.Set(CSRFHeaderName, token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("configured middleware rejected its configured cookie: got %d", rec.Code)
	}

	packageHandler := RequireCSRFToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	packageRec := httptest.NewRecorder()
	packageHandler.ServeHTTP(packageRec, req)
	if packageRec.Code != http.StatusForbidden {
		t.Fatalf("package-level middleware accepted a custom-name cookie: got %d", packageRec.Code)
	}
}

func TestSulisRequireCSRFTokenEmitsRejectionForCustomName(t *testing.T) {
	sink := &recordingSink{}
	s, _, _, _ := newTestEnv(WithCSRFCookieName("csrf_token"), WithEventSink(sink))
	_, defaultCookie, err := IssueCSRFToken()
	if err != nil {
		t.Fatalf("IssueCSRFToken: %v", err)
	}

	handler := s.RequireCSRFToken(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(defaultCookie)
	req.Header.Set(CSRFHeaderName, defaultCookie.Value)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected custom-name middleware to reject default-name cookie, got %d", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	e, ok := sink.first(EventCSRFRejected)
	if !ok {
		t.Fatal("expected EventCSRFRejected from custom-name middleware")
	}
	if e.Metadata[MetaReason] != ReasonCSRFTokenInvalid {
		t.Fatalf("event reason = %q, want %q", e.Metadata[MetaReason], ReasonCSRFTokenInvalid)
	}
}

func TestVerifyCSRFTokenAcceptsMatchingHeader(t *testing.T) {
	token, cookie, err := IssueCSRFToken()
	if err != nil {
		t.Fatalf("IssueCSRFToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(cookie)
	req.Header.Set(CSRFHeaderName, token)

	if err := VerifyCSRFToken(req); err != nil {
		t.Fatalf("expected VerifyCSRFToken to succeed, got %v", err)
	}
}

func TestVerifyCSRFTokenAcceptsMatchingFormField(t *testing.T) {
	token, cookie, err := IssueCSRFToken()
	if err != nil {
		t.Fatalf("IssueCSRFToken: %v", err)
	}

	body := strings.NewReader(url.Values{CSRFFormField: {token}}.Encode())
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)

	if err := VerifyCSRFToken(req); err != nil {
		t.Fatalf("expected VerifyCSRFToken to succeed, got %v", err)
	}
}

func TestVerifyCSRFTokenRejectsMissingCookie(t *testing.T) {
	_, _, err := IssueCSRFToken()
	if err != nil {
		t.Fatalf("IssueCSRFToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set(CSRFHeaderName, "whatever-value")

	if err := VerifyCSRFToken(req); err == nil {
		t.Fatal("expected an error for a missing CSRF cookie")
	}
}

func TestVerifyCSRFTokenRejectsMissingEchoedValue(t *testing.T) {
	_, cookie, err := IssueCSRFToken()
	if err != nil {
		t.Fatalf("IssueCSRFToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(cookie)

	if err := VerifyCSRFToken(req); err == nil {
		t.Fatal("expected an error when the client echoes back nothing")
	}
}

func TestVerifyCSRFTokenRejectsMismatch(t *testing.T) {
	_, cookie, err := IssueCSRFToken()
	if err != nil {
		t.Fatalf("IssueCSRFToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(cookie)
	req.Header.Set(CSRFHeaderName, "not-the-right-token")

	if err := VerifyCSRFToken(req); err == nil {
		t.Fatal("expected an error for a mismatched token")
	}
}

// TestRequireCSRFTokenAllowsSafeMethods asserts GET/HEAD/OPTIONS are never
// blocked by RequireCSRFToken, even with no cookie/header at all.
func TestRequireCSRFTokenAllowsSafeMethods(t *testing.T) {
	handler := RequireCSRFToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		req := httptest.NewRequest(method, "/", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("method %s: expected 200, got %d", method, rec.Code)
		}
	}
}

func TestRequireCSRFTokenRejectsStateChangingMethodWithoutToken(t *testing.T) {
	called := false
	handler := RequireCSRFToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if called {
		t.Fatal("expected handler not to be called")
	}
}

func TestRequireCSRFTokenAllowsStateChangingMethodWithMatchingToken(t *testing.T) {
	token, cookie, err := IssueCSRFToken()
	if err != nil {
		t.Fatalf("IssueCSRFToken: %v", err)
	}

	handler := RequireCSRFToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(cookie)
	req.Header.Set(CSRFHeaderName, token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

// constantTimeCompareCallPattern matches a call to subtle.ConstantTimeCompare
// tolerating whitespace (including a line break) between the name and the
// opening paren, so reformatting the call across multiple lines doesn't
// break TestVerifyCSRFTokenUsesConstantTimeCompare below. It is still
// sensitive to changes that don't merely reformat the call: aliasing the
// "crypto/subtle" import (e.g. `csubtle "crypto/subtle"`) or moving the
// comparison into a helper function elsewhere would both need this pattern
// (or the test) updated to match. That residual brittleness is accepted
// deliberately — the goal is to catch an accidental regression to a
// data-dependent comparison in the ordinary course of editing this file,
// not to survive an adversarial rewrite of it.
var constantTimeCompareCallPattern = regexp.MustCompile(`subtle\.ConstantTimeCompare\s*\(`)

// TestVerifyCSRFTokenUsesConstantTimeCompare is an implementation-inspection
// assertion, not a timing measurement: timing-based tests are inherently
// flaky under a shared CI runner and would either flake or need enough
// slack to stop meaning anything. Instead this asserts the source actually
// calls crypto/subtle's constant-time comparison rather than a data-
// dependent one like bytes.Equal/==, which is the property that actually
// matters (a reviewer or a future edit removing the subtle.
// ConstantTimeCompare call is caught here even though a real timing attack
// against a short-lived, single-request token is already a stretch).
func TestVerifyCSRFTokenUsesConstantTimeCompare(t *testing.T) {
	src, err := os.ReadFile("csrf.go")
	if err != nil {
		t.Fatalf("reading csrf.go: %v", err)
	}
	if !strings.Contains(string(src), `"crypto/subtle"`) {
		t.Fatal("expected csrf.go to import crypto/subtle")
	}
	if !constantTimeCompareCallPattern.MatchString(string(src)) {
		t.Fatal("expected csrf.go to compare the CSRF token via subtle.ConstantTimeCompare")
	}
}
