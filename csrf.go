package sulis

import (
	"crypto/subtle"
	"net/http"
)

// Double-submit CSRF defense.
//
// This is meaningful only for cookie-authenticated requests: a Bearer
// token is never attached to a request by the browser on its own, so a
// forged cross-site request has nothing to ride along with in the first
// place. A deployment configured with WithTokenSource(TokenSourceBearerOnly)
// — one that never calls SessionCookie either — needs none of this; see
// the README's "Cookie sessions and CSRF" section.
//
// This is a PURE double-submit: CSRFCookieName's value is a bare random
// token, not cryptographically bound to the session that requested it (no
// HMAC over a session ID, no server-side lookup). By itself that means
// anyone who can get their own chosen value written into that cookie for
// this origin could echo the very same value back in CSRFHeaderName/
// CSRFFormField themselves, defeating the check — the classical weakness
// of a bare double-submit token versus a session-bound one. This package
// closes that gap by layering, not by binding the token: CSRFCookieName
// carries the __Host- prefix, so neither a sibling subdomain nor a
// network attacker without HTTPS can set it for this origin in the first
// place, and RequireSameOrigin adds an independent, Fetch-Metadata-based
// check that doesn't depend on cookie contents at all. Treat
// IssueCSRFToken/RequireCSRFToken/VerifyCSRFToken as one layer of a
// defense meant to be combined with __Host- and RequireSameOrigin, not as
// a standalone guarantee.
const (
	// CSRFCookieName is the cookie IssueCSRFToken sets and
	// RequireCSRFToken/VerifyCSRFToken read the expected value from.
	// Unlike the session cookie it is intentionally NOT HttpOnly: a
	// same-origin script must be able to read it, to mirror it into
	// CSRFHeaderName on the requests it makes — that same-origin-only
	// readability, enforced by the browser regardless of this cookie's own
	// attributes, is the property the whole pattern rests on.
	CSRFCookieName = "__Host-csrf_token"

	// CSRFHeaderName is the request header VerifyCSRFToken checks first
	// for the client's echoed-back copy of the token.
	CSRFHeaderName = "X-CSRF-Token" // #nosec G101 -- a header name, not a credential

	// CSRFFormField is the fallback form field VerifyCSRFToken checks when
	// CSRFHeaderName is absent, for a traditional <form> POST that can't
	// set a custom header — render it as a hidden input alongside the
	// form.
	CSRFFormField = "csrf_token" // #nosec G101 -- a field name, not a credential

	csrfTokenBytes = 32
)

// IssueCSRFToken generates a new random CSRF token for the double-submit
// pattern described above and returns both the raw value — embed it in a
// hidden form field, or hand it to a same-origin script that will set
// CSRFHeaderName itself on the requests it makes — and the cookie to set
// alongside it (http.SetCookie(w, cookie)).
//
// Call it once per session (right after SessionCookie, at login, is the
// natural place) or once per page/form render; either works, since
// VerifyCSRFToken only ever compares against whatever value is currently
// in the cookie, not anything remembered server-side.
func IssueCSRFToken() (token string, cookie *http.Cookie, err error) {
	token, _, err = generateRawToken(csrfTokenBytes)
	if err != nil {
		return "", nil, err
	}
	cookie = &http.Cookie{ // #nosec G124 -- HttpOnly is deliberately false: see CSRFCookieName's doc comment
		Name:     CSRFCookieName,
		Value:    token,
		Path:     "/",
		Secure:   true,
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
	}
	return token, cookie, nil
}

// RequireCSRFToken returns middleware enforcing the double-submit check
// (see VerifyCSRFToken) on every state-changing request — any method other
// than GET/HEAD/OPTIONS; safe methods pass through untouched, same as
// RequireSameOrigin.
//
// Apply this to routes reachable via a cookie-authenticated session; a
// route reachable only via an Authorization: Bearer header (see
// WithTokenSource(TokenSourceBearerOnly)) gains nothing from it.
// It emits no security event: a package-level function has no Sulis and so
// no configured EventSink to emit to. Use the identically-behaved
// (*Sulis).RequireCSRFToken method instead if you want rejections to reach
// your sink as EventCSRFRejected.
func RequireCSRFToken(next http.Handler) http.Handler {
	return requireCSRFToken(nil, next)
}

// RequireCSRFToken is the package-level RequireCSRFToken bound to this Sulis,
// so a rejection reaches the configured EventSink as EventCSRFRejected. The
// check itself is identical — same VerifyCSRFToken, same 403, same
// Cache-Control — and either form may be used; this one is simply the one
// that can report.
//
// A method and a package-level function of the same name is deliberate
// rather than a rename: RequireCSRFToken is already-shipped public API, and
// emitting requires state (the sink) that a free function has no way to
// reach. See the T509 Decisions row in PROGRESS.md.
func (s *Sulis) RequireCSRFToken(next http.Handler) http.Handler {
	return requireCSRFToken(s, next)
}

// requireCSRFToken is the shared implementation. A nil *Sulis means "no
// events" — emit is nil-receiver safe for exactly this.
func requireCSRFToken(s *Sulis, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		if err := VerifyCSRFToken(r); err != nil {
			s.emit(r.Context(), Event{
				Kind:        EventCSRFRejected,
				RequestInfo: requestInfoFromRequest(r),
				Metadata:    meta(string(MetaReason), ReasonCSRFTokenInvalid),
			})
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// VerifyCSRFToken implements the double-submit comparison at the heart of
// RequireCSRFToken: the value in the CSRFCookieName cookie must be present
// and must match, byte for byte, whatever the client echoed back —
// checked first in the CSRFHeaderName header, then (for a traditional
// <form> POST that can't set a custom header) the CSRFFormField form
// value. A missing cookie, a missing echoed value, and a mismatch all
// return the same ErrCSRFTokenInvalid.
//
// This check alone is a pure double-submit — not bound to the session,
// only to whoever can read this cookie — see the package doc comment
// above for why that's layered with the __Host- prefix and
// RequireSameOrigin rather than relied on in isolation.
//
// The comparison is constant-time (crypto/subtle.ConstantTimeCompare), so
// a timing side channel can't be used to recover the token byte by byte.
// This is asserted by TestVerifyCSRFTokenUsesConstantTimeCompare
// (csrf_test.go) via implementation inspection — it greps this file's
// source for the subtle.ConstantTimeCompare call — rather than by timing
// the comparison directly: a real timing test is inherently flaky on a
// shared CI runner, and would either flake occasionally or need enough
// slack to stop actually testing anything. The mutation this guards
// against: replacing the call below with a data-dependent comparison
// (cookie.Value == sent, or bytes.Equal) still passes every functional
// test above but fails this one, which is the point.
//
// FormValue parses the request body when its Content-Type is
// application/x-www-form-urlencoded or multipart/form-data (and only
// then — see net/http's ParseForm), so calling this before a JSON handler
// reads r.Body is safe; calling it before a form handler reads r.Body
// directly is not, for the same reason any Go form-handling code already
// has to call ParseForm before touching the raw body once.
func VerifyCSRFToken(r *http.Request) error {
	cookie, err := r.Cookie(CSRFCookieName)
	if err != nil || cookie.Value == "" {
		return ErrCSRFTokenInvalid
	}

	sent := r.Header.Get(CSRFHeaderName)
	if sent == "" {
		sent = r.FormValue(CSRFFormField)
	}
	if sent == "" {
		return ErrCSRFTokenInvalid
	}

	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(sent)) != 1 {
		return ErrCSRFTokenInvalid
	}
	return nil
}
