package sulis

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionCookieAttributes(t *testing.T) {
	s := newTestSulis()
	expires := time.Now().Add(24 * time.Hour)

	c := s.SessionCookie("raw-token-value", expires)

	if c.Name != defaultCookieName {
		t.Fatalf("expected cookie name %q, got %q", defaultCookieName, c.Name)
	}
	if !strings.HasPrefix(c.Name, "__Host-") {
		t.Fatalf("expected default cookie name to carry the __Host- prefix, got %q", c.Name)
	}
	if c.Value != "raw-token-value" {
		t.Fatalf("expected cookie value %q, got %q", "raw-token-value", c.Value)
	}
	if !c.HttpOnly {
		t.Fatal("expected HttpOnly=true")
	}
	if !c.Secure {
		t.Fatal("expected Secure=true")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected SameSite=Lax, got %v", c.SameSite)
	}
	if c.Path != "/" {
		t.Fatalf("expected Path=/, got %q", c.Path)
	}
	if c.Domain != "" {
		t.Fatalf("expected no Domain (required for __Host-), got %q", c.Domain)
	}
	if !c.Expires.Equal(expires) {
		t.Fatalf("expected Expires %v, got %v", expires, c.Expires)
	}

	// __Host- requires exactly Secure + Path=/ + no Domain. Assert the
	// combination directly, in addition to the individual attributes above,
	// so a change that satisfies each field in isolation but breaks the
	// combination still fails this test.
	if strings.HasPrefix(c.Name, "__Host-") {
		if !c.Secure || c.Path != "/" || c.Domain != "" {
			t.Fatalf("cookie name %q carries the __Host- prefix but violates its requirements: %+v", c.Name, c)
		}
	}
}

func TestSessionCookieRespectsWithCookieName(t *testing.T) {
	s, _, _, _ := newTestEnv(WithCookieName("myapp_session"))

	c := s.SessionCookie("raw-token-value", time.Now().Add(time.Hour))

	if c.Name != "myapp_session" {
		t.Fatalf("expected cookie name %q, got %q", "myapp_session", c.Name)
	}
	// Secure/Path=/ are not configurable down, regardless of name.
	if !c.Secure || c.Path != "/" || c.HttpOnly != true {
		t.Fatalf("expected Secure/Path=//HttpOnly to remain set even for a non-__Host- name: %+v", c)
	}
}

func TestClearSessionCookieAttributes(t *testing.T) {
	s := newTestSulis()

	c := s.ClearSessionCookie()

	if c.Name != defaultCookieName {
		t.Fatalf("expected cookie name %q, got %q", defaultCookieName, c.Name)
	}
	if c.Value != "" {
		t.Fatalf("expected empty value, got %q", c.Value)
	}
	if !c.HttpOnly || !c.Secure {
		t.Fatalf("expected HttpOnly/Secure to remain set on the clearing cookie: %+v", c)
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected SameSite=Lax, got %v", c.SameSite)
	}
	if c.Path != "/" {
		t.Fatalf("expected Path=/, got %q", c.Path)
	}
	if c.MaxAge >= 0 {
		t.Fatalf("expected MaxAge < 0 (delete immediately), got %d", c.MaxAge)
	}
	if !c.Expires.Before(time.Now()) {
		t.Fatalf("expected Expires in the past, got %v", c.Expires)
	}
}

func TestWithCookieNameRejectsEmptyName(t *testing.T) {
	users := newMemUserStore()
	sessions := newMemSessionStore()
	tokens := newMemTokenStore()
	factors := newFakeFactors()

	_, err := New(users, sessions, tokens, factors, WithCookieName(""))
	if err == nil {
		t.Fatal("expected an error for an empty cookie name")
	}
}

func TestWithCookieNameRejectsInvalidToken(t *testing.T) {
	users := newMemUserStore()
	sessions := newMemSessionStore()
	tokens := newMemTokenStore()
	factors := newFakeFactors()

	// A space is not a valid HTTP cookie-name token character.
	_, err := New(users, sessions, tokens, factors, WithCookieName("not a valid name"))
	if err == nil {
		t.Fatal("expected an error for a cookie name containing invalid characters")
	}
}

// TestRequireSameOriginAllowsSafeMethods asserts that GET/HEAD/OPTIONS are
// never blocked, even with a cross-site Sec-Fetch-Site and an unlisted
// Origin, since RequireSameOrigin only guards state-changing methods.
func TestRequireSameOriginAllowsSafeMethods(t *testing.T) {
	mw := RequireSameOrigin([]string{"https://app.example.com"})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		req := httptest.NewRequest(method, "/", nil)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.Header.Set("Origin", "https://evil.example.com")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("method %s: expected 200, got %d", method, rec.Code)
		}
	}
}

// TestRequireSameOriginRejectsCrossSitePost is the core CSRF-relevant
// property: a cross-site Sec-Fetch-Site on a state-changing method is
// rejected.
func TestRequireSameOriginRejectsCrossSitePost(t *testing.T) {
	mw := RequireSameOrigin([]string{"https://app.example.com"})
	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if called {
		t.Fatal("expected handler not to be called")
	}
}

func TestRequireSameOriginRejectsUnlistedOriginOnStateChangingMethod(t *testing.T) {
	mw := RequireSameOrigin([]string{"https://app.example.com"})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		req := httptest.NewRequest(method, "/", nil)
		req.Header.Set("Origin", "https://evil.example.com")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("method %s: expected 403, got %d", method, rec.Code)
		}
	}
}

func TestRequireSameOriginAllowsSameOriginSecFetchSite(t *testing.T) {
	mw := RequireSameOrigin([]string{"https://app.example.com"})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, sfs := range []string{"same-origin", "none"} {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Sec-Fetch-Site", sfs)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Sec-Fetch-Site=%s: expected 200, got %d", sfs, rec.Code)
		}
	}
}

func TestRequireSameOriginAllowsAllowlistedOrigin(t *testing.T) {
	mw := RequireSameOrigin([]string{"https://app.example.com"})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for an allow-listed origin, got %d", rec.Code)
	}
}

// TestRequireSameOriginAllowsAbsentHeadersOnStateChangingMethod documents
// the deliberate policy for a non-browser client (e.g. a Bearer-token API
// caller) that sends neither Sec-Fetch-Site nor Origin: allow. See the
// T507 Decisions row in PROGRESS.md.
func TestRequireSameOriginAllowsAbsentHeadersOnStateChangingMethod(t *testing.T) {
	mw := RequireSameOrigin([]string{"https://app.example.com"})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 when both headers are absent, got %d", rec.Code)
	}
}

// TestRequireSameOriginRejectsCrossSiteWithNoOrigin covers the case a
// pre-Fetch-Metadata browser or a stripped-header proxy might produce:
// Sec-Fetch-Site says cross-site, but there's no Origin to check against
// the allow list either. Reject.
func TestRequireSameOriginRejectsCrossSiteWithNoOrigin(t *testing.T) {
	mw := RequireSameOrigin([]string{"https://app.example.com"})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

// TestRequireSameOriginSameSiteNeedsTheAllowList covers other ports of the
// same host and sibling subdomains. The browser calls them same-site, and they
// can read a non-HttpOnly CSRF cookie, so only a listed Origin passes.
func TestRequireSameOriginSameSiteNeedsTheAllowList(t *testing.T) {
	for _, tc := range []struct {
		name    string
		allowed []string
		origin  string
		want    int
	}{
		{"no allow list", nil, "https://app.example.com:8443", http.StatusForbidden},
		{"unlisted origin", []string{"https://app.example.com"}, "https://other.example.com", http.StatusForbidden},
		{"no Origin", []string{"https://app.example.com"}, "", http.StatusForbidden},
		{"listed origin", []string{"https://app.example.com"}, "https://app.example.com", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := RequireSameOrigin(tc.allowed)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.Header.Set("Sec-Fetch-Site", "same-site")
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

// TestRequireSameOriginPassesSameOriginOnTheHeaderAlone: same-origin and none
// pass with no allow list, whatever the Origin says.
func TestRequireSameOriginPassesSameOriginOnTheHeaderAlone(t *testing.T) {
	handler := RequireSameOrigin(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, sfs := range []string{"same-origin", "none"} {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Sec-Fetch-Site", sfs)
		req.Header.Set("Origin", "https://app.example.com")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("Sec-Fetch-Site=%s: expected 200, got %d", sfs, rec.Code)
		}
	}
}

// TestSulisRequireSameOriginReportsARefusedSameSiteRequest covers the method
// form: the refusal reaches the sink as an unlisted origin, with or without
// an Origin header to look up.
func TestSulisRequireSameOriginReportsARefusedSameSiteRequest(t *testing.T) {
	for _, origin := range []string{"https://other.example.com", ""} {
		sink := &recordingSink{}
		s, _, _, _ := newTestEnv(WithEventSink(sink))
		called := false
		handler := s.RequireSameOrigin(nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			called = true
		}))
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Sec-Fetch-Site", "same-site")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden || called {
			t.Fatalf("Origin %q: status = %d, handler called = %v; want 403 and not called", origin, rec.Code, called)
		}
		e, ok := sink.first(EventSameOriginRejected)
		if !ok || e.Metadata[MetaReason] != ReasonOriginNotAllowed {
			t.Errorf("Origin %q: event metadata = %v (found: %v), want reason %q", origin, e.Metadata, ok, ReasonOriginNotAllowed)
		}
	}
}

// TestRequireSameOriginRefusesAnUnknownSecFetchSite pins the 0.7.0 rule that
// only same-origin and none pass on the header alone. An unknown value used to
// pass; now it needs a listed Origin like any other value.
func TestRequireSameOriginRefusesAnUnknownSecFetchSite(t *testing.T) {
	for _, tc := range []struct {
		origin, wantReason string
	}{
		{"", ReasonCrossSite},
		{"https://other.example.com", ReasonOriginNotAllowed},
	} {
		t.Run("Origin="+tc.origin, func(t *testing.T) {
			sink := &recordingSink{}
			s, _, _, _ := newTestEnv(WithEventSink(sink))
			called := false
			handler := s.RequireSameOrigin([]string{"https://app.example.com"})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				called = true
			}))
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			req.Header.Set("Sec-Fetch-Site", "bogus")
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden || called {
				t.Fatalf("status = %d, handler called = %v; want 403 and not called", rec.Code, called)
			}
			e, ok := sink.first(EventSameOriginRejected)
			if !ok || e.Metadata[MetaReason] != tc.wantReason {
				t.Errorf("event metadata = %v (found: %v), want reason %q", e.Metadata, ok, tc.wantReason)
			}
		})
	}
}
