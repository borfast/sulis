package sulis

import (
	"fmt"
	"net/http"
	"time"
)

// SessionCookie returns an *http.Cookie carrying rawToken as its value,
// ready to be set on the response with http.SetCookie(w, cookie). Every
// attribute a secure session cookie needs is fixed here, not left to the
// caller:
//
//   - HttpOnly: never readable by JavaScript, closing off the most common
//     session-theft vector (script injection reading document.cookie).
//   - Secure: never sent over plain HTTP.
//   - SameSite=Lax: sent on top-level, safe-method navigation and
//     same-site requests; withheld from cross-site subrequests and
//     cross-site state-changing navigation, which is most of CSRF exposure
//     with no extra work. It is NOT a substitute for RequireSameOrigin/
//     RequireCSRFToken — see the README's "Cookie sessions and CSRF"
//     section for what SameSite alone does and doesn't cover.
//   - Path=/: the cookie is valid for the whole origin, matching the
//     __Host- prefix requirement below.
//
// The cookie's Name is CookieName (default: "__Host-session", see
// WithCookieName), and the __Host- prefix's other two requirements —
// Secure and no Domain attribute — are exactly what this method always
// sets/omits, regardless of name, so the guarantee never silently stops
// applying. See defaultCookieName's doc comment for why this is enforced
// by construction rather than by validating the combination at runtime.
func (s *Sulis) SessionCookie(rawToken string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    rawToken,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// ClearSessionCookie returns an *http.Cookie that, once set on the
// response with http.SetCookie(w, cookie), instructs the browser to delete
// the session cookie immediately: the same Name/Path/HttpOnly/Secure/
// SameSite as SessionCookie, an empty Value, and both MaxAge=-1 and an
// Expires in the past — belt and suspenders, since not every HTTP
// client or intermediary proxy honors MaxAge.
func (s *Sulis) ClearSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// validateCookieName rejects a CookieName that isn't a valid HTTP cookie
// name token (empty, or containing whitespace/control/separator
// characters) — the one part of the cookie WithCookieName actually hands
// the caller control over. It deliberately does not special-case the
// "__Host-"/"__Secure-" prefixes: SessionCookie/ClearSessionCookie always
// set Secure and Path=/ and never set Domain regardless of name, so no
// value reaching this function can violate either prefix's requirements —
// see defaultCookieName's doc comment.
func validateCookieName(name string) error {
	probe := &http.Cookie{Name: name, Value: "x"} // #nosec G124 -- a name-validity probe, never sent on any response
	if err := probe.Valid(); err != nil {
		return fmt.Errorf("sulis: invalid cookie name %q: %w", name, err)
	}
	return nil
}

// isSafeMethod reports whether method is one of the HTTP methods defined
// as "safe" (no side effects expected) by RFC 9110 §9.2.1 — the methods
// RequireSameOrigin and RequireCSRFToken both let through unconditionally.
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// RequireSameOrigin returns middleware that rejects a cross-site,
// state-changing request (any method other than GET/HEAD/OPTIONS) using
// the Fetch Metadata Sec-Fetch-Site header, falling back to Origin when
// Sec-Fetch-Site is absent. allowed lists origins — scheme://host[:port],
// e.g. "https://app.example.com" — that are trusted even when the browser
// reports (or Origin implies) a cross-site request; include every origin
// your own frontend is actually served from if it differs from the API's
// origin.
//
// This is a CSRF defense for cookie-authenticated routes; apply it (and/or
// RequireCSRFToken) to any route reachable via a cookie-sourced session.
// It costs nothing extra on a Bearer-only route, but such a route gains
// nothing from it either — see the README's "Cookie sessions and CSRF"
// section.
//
// Decision on missing headers (recorded in PROGRESS.md's T507 Decisions):
// when BOTH Sec-Fetch-Site and Origin are absent, the request is allowed
// through. Every browser new enough to send either header will send at
// least one of them on a cross-site request; a request with neither is the
// signature of a non-browser client — a Bearer-token API caller, in
// particular, which is not CSRF-exploitable in the first place, since a
// browser never attaches a Bearer header to a request on its own.
// Rejecting on absence would block exactly that population for no CSRF
// benefit. The residual gap this leaves — a pre-Fetch-Metadata browser
// that also omits Origin on some cross-site state-changing request — is
// the reason RequireCSRFToken exists as defense in depth: it does not
// depend on either header at all.
func RequireSameOrigin(allowed []string) func(http.Handler) http.Handler {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, origin := range allowed {
		allowedSet[origin] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isSafeMethod(r.Method) {
				next.ServeHTTP(w, r)
				return
			}

			secFetchSite := r.Header.Get("Sec-Fetch-Site")
			origin := r.Header.Get("Origin")

			allow := false
			switch {
			case secFetchSite == "" && origin == "":
				// Neither header present: not a browser request context
				// this check can evaluate. See the policy note above.
				allow = true
			case secFetchSite != "" && secFetchSite != "cross-site":
				// same-origin, same-site, or none.
				allow = true
			case origin != "":
				_, allow = allowedSet[origin]
			}

			if !allow {
				w.Header().Set("Cache-Control", "no-store")
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
