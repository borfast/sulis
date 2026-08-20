# Proposal: `WithCSRFCookieName` — configurable CSRF cookie name

Status: proposed (2026-08-19). Origin: family-photos integration (first real consumer).

## Problem

The CSRF double-submit cookie name is a hard-coded constant, `CSRFCookieName = "__Host-csrf_token"`
(csrf.go, const block). `IssueCSRFToken` sets it, and `VerifyCSRFToken` / `RequireCSRFToken`
(both the package-level functions and the `(*Sulis)` method) read it. There is no configuration
surface for it.

The session cookie has exactly the escape hatch the CSRF cookie lacks: `WithCookieName`
(config.go) lets a deployment opt out of the `__Host-` *name prefix* while `SessionCookie` /
`ClearSessionCookie` keep Secure, Path=/, and no-Domain fixed by construction (cookie.go).

Why the hatch matters — local development over plain HTTP:

- A `__Host-` cookie is only stored by the browser when set with `Secure`, `Path=/`, no `Domain`,
  **from a secure context**. Chrome and Firefox treat `http://localhost` as a trustworthy origin
  and store it; **Safari does not**, and silently drops the cookie.
- Result on Safari against a plain-http dev server: `IssueCSRFToken`'s cookie never persists, so
  every state-changing request fails `VerifyCSRFToken` and dies with 403 in `RequireCSRFToken`.
  The session cookie side is already solvable (`WithCookieName("session")` in dev); the CSRF side
  is not, so the whole app remains broken on Safari regardless.

family-photos ships with this as a documented caveat ("dev on localhost with Chrome/Firefox, or
run local TLS") and selects the session cookie name per environment. The CSRF cookie should be
configurable the same way, for the same reason. Forking behavior downstream is the wrong fix;
this belongs in sulis.

## Proposed solution

Mirror `WithCookieName` exactly — same validation, same "fixed attributes, configurable name
only" philosophy, and the same already-established dual package-function/method pattern that
`RequireCSRFToken` uses (see the T509 Decisions row in PROGRESS.md).

### 1. Config

- Add `CSRFCookieName string` to `Config`; `defaultConfig()` sets it to the existing
  `CSRFCookieName` const so behavior is unchanged by default.
- Add `WithCSRFCookieName(name string) Option`. `New` validates it with the existing
  `validateCookieName` (cookie.go), exactly as it validates `CookieName`.

### 2. Issue path

- New method `func (s *Sulis) IssueCSRFToken() (token string, cookie *http.Cookie, err error)`:
  identical to the package-level function (same token generation, `Path=/`, `Secure: true`,
  `HttpOnly: false`, `SameSite=Lax`; Secure/Path/no-Domain stay fixed by construction, not
  configurable) except `cookie.Name = s.cfg.CSRFCookieName`.
- The package-level `IssueCSRFToken()` stays as-is (shipped API; a free function has no config to
  read) and its doc comment gains one line pointing config-aware callers at the method.

### 3. Verify path

- Extract the body of `VerifyCSRFToken` into an unexported
  `verifyCSRFToken(r *http.Request, cookieName string) error` (header-then-form fallback and the
  `subtle.ConstantTimeCompare` untouched — note `TestVerifyCSRFTokenUsesConstantTimeCompare`
  greps this file for that call; keep the call textually present).
- Package-level `VerifyCSRFToken(r)` delegates with the const name (unchanged behavior).
- New method `func (s *Sulis) VerifyCSRFToken(r *http.Request) error` delegates with
  `s.cfg.CSRFCookieName`.
- `requireCSRFToken(s *Sulis, next http.Handler)` currently calls the package-level
  `VerifyCSRFToken` for both forms; change it to use the configured name when `s != nil` and the
  const when `s == nil`. Net effect: the package-level `RequireCSRFToken` middleware keeps the
  fixed name; the `(*Sulis).RequireCSRFToken` method honors the option (and keeps emitting
  `EventCSRFRejected`). This asymmetry is the same one those two forms already have for event
  emission, documented the same way.

### 4. Documentation (the important half)

- `WithCSRFCookieName`'s doc comment must carry the security trade-off, in `WithCookieName`'s
  "valid, explicit opt-out" voice: the `__Host-` prefix is one of the two layers that rescue a
  pure (session-unbound) double-submit token — it is what stops a sibling subdomain or a non-HTTPS
  network attacker from planting a chosen cookie value for this origin (see the layering
  discussion in csrf.go's package comment). Dropping the prefix removes that layer; the remaining
  defenses are `RequireSameOrigin` and SameSite. Recommended use is local development over plain
  HTTP only (the Safari case), never production.
- Update: csrf.go package comment (name now configurable), README "Cookie sessions and CSRF" +
  "Operational requirements", CHANGELOG.

### 5. Tests

- `New` rejects an invalid name via `WithCSRFCookieName` (mirror the `WithCookieName` case).
- Round-trip with a custom name: method `IssueCSRFToken` sets the custom cookie; method
  `VerifyCSRFToken` and method `RequireCSRFToken` accept it; package-level forms still use the
  default name (both directions: custom-config Sulis rejects a token sent under the default name,
  and vice versa).
- Attribute invariants under a custom name: Secure, Path=/, no Domain, HttpOnly=false.
- `EventCSRFRejected` still emitted from the method middleware with a custom name.
- Constant-time grep test still passes after the extraction.

## Consumer follow-up (family-photos, after the sulis release)

- Switch `webauth`'s `EnsureCSRFCookie` from package-level `sulis.IssueCSRFToken()` /
  `sulis.CSRFCookieName` to the new method forms, and select the CSRF cookie name alongside the
  session cookie name: `__Host-csrf_token` in production, `csrf_token` in development.
- Bump the sulis pseudo-version, re-run the store conformance suite (`make test-integration`),
  and delete the Safari caveat from the design watch-items / README.
