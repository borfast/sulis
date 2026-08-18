# Threat Model

This document describes what sulis defends against, naming the specific
mechanism that ships for each threat, what is explicitly out of scope, and
the residual risks that remain even when every mitigation below is
configured as documented. It describes the code as it exists on this
branch today — every mitigation named here is shipped, not planned. Where
a defense has a known limitation, that limitation is stated next to it
rather than left implicit.

sulis is a library: it owns authentication logic, session/token
lifecycle, and the cryptographic primitives around them. It does not own
persistence, HTTP routing, or the application's UI. Several of the
mitigations below are opt-in or depend on the consumer wiring something up
— those are called out explicitly, alongside what happens if you don't.

See the [README](../README.md) for full usage detail on every mechanism
named here; this document only asserts what each one is *for*.

## In scope

### Credential guessing (password brute force)

- **Rate limiting is on by default.** `sulis.New` installs an in-process
  `MemoryLimiter` — a token bucket consulted on both an account dimension
  (`"password:"+email`, and equivalently for reset/magic-link keys) and,
  when a `RequestInfo` carrying an IP is passed, an IP dimension
  (`"password:ip:"+ip`). Budgets use longest-prefix matching so per-account
  stays generous (an attacker guessing one victim's password can't be used
  to lock the victim out) while per-IP stays tight (an attacker spraying
  many accounts from one address is throttled quickly). See "Operational
  requirements" in the README.
- **Optional automatic lockout with backoff.** `WithFailureLockout(threshold,
  baseBackoff, maxBackoff)` (default off) locks an account after
  `threshold` consecutive wrong passwords, with the lockout window doubling
  on repeated failures up to `maxBackoff`. It is opt-in because it is
  itself a denial-of-service vector against the account's legitimate
  owner — the rate limiter above is the mitigation that doesn't share that
  failure mode, and is meant to be the first line of defense.
- **Password quality checks.** Every path that sets a password
  (`Register`, `ChangePassword`, `ResetPassword`, `SetInitialPassword`)
  runs it through NFKC normalization, a configurable minimum length
  (default 12 bytes of the normalized form), and a `PasswordChecker`.
  `passwordcheck.NewBlocklist()` (the default checker) screens against an
  embedded 10k-common-password corpus with no network dependency;
  `passwordcheck.NewHIBP()` is available to add Have I Been Pwned
  k-anonymous range-API screening. Verification paths never consult the
  checker, so hardening the policy later can't lock out existing users.

### Token theft and replay

- **Single-use atomic consumption.** `TokenStore.ConsumeToken`,
  `ChallengeStore.ConsumeChallenge`, and `recovery.Store.ConsumeCode` are
  all specified as one atomic find-and-mark-used (or find-and-delete)
  operation — a lookup followed by a separate write is a race that lets
  two concurrent redemptions both succeed, which the contract forbids and
  `storetest`'s concurrency subtests check for.
- **Hashed at rest.** Password-reset, magic-link, two-factor, and
  email-verification tokens are stored only as `Token.TokenHash` (SHA-256
  of the raw token); the raw value is returned once for out-of-band
  delivery and never persisted. Session bearer tokens are stored the same
  way (`Session` has no `Token` field at all, only `TokenHash`). Recovery
  codes are stored as SHA-256 hashes.
- **Short TTLs.** Two-factor pending tokens expire after
  `TwoFactorTokenDuration` (default 5 minutes), magic links after
  `MagicLinkDuration` (default 15 minutes — deliberately independent of,
  and shorter than, password-reset tokens' `TokenDuration`, since a magic
  link is a credential that can sit in an inbox or get prefetched by a
  scanner), and email-verification tokens after 24 hours.
- **Magic-link requester binding.** By default (`MagicLinkBinding`, true),
  `CreateMagicLinkToken` also returns a random binding nonce meant to be
  set as a short-lived `HttpOnly` cookie on the issuing response;
  `RedeemMagicLink` rejects a redemption whose nonce doesn't match. A
  forwarded or prefetched link therefore fails to redeem for anyone but
  the browser that requested it, even though the token itself is still
  valid — closing the gap between "single-use token" and "single-use by
  the intended person."

### Enumeration (account existence oracle)

- **Uniform password-reset responses.** `CreatePasswordResetToken` returns
  `("", nil)` for an unregistered address rather than `ErrUserNotFound`,
  and performs the same token-generation and hashing work for the unknown
  path before discarding the result, so the two paths can't be
  distinguished by the work performed either. (`CreatePasswordResetTokenStrict`
  exists for authenticated admin tooling that legitimately needs to know —
  never wire it to a public endpoint.)
- **Dummy-hash timing equalization.** `Login`, `VerifyPassword`, and
  `ReAuthenticate` run the same Argon2 work against an internal dummy hash
  for an unknown email or a passwordless account, and return the same
  `ErrInvalidCredentials` for unknown-email, passwordless-account, and
  wrong-password cases alike — the error never reveals which.
- **Uniform magic-link behavior.** `CreateMagicLinkToken` never returns a
  not-found error for any address, known or not: it defers user creation
  to redemption time, so there is no account-existence branch to leak in
  the first place.

### Database compromise

- **Argon2id for passwords**, with an optional pepper. `WithPepper`
  applies HMAC-SHA256 with a secret held only in application
  configuration (never alongside the database) before Argon2 sees the
  password, so a database-only leak (row data, no application secrets)
  cannot be dictionary-attacked offline even after Argon2 is defeated for
  a specific hash — though a pepper does nothing against a full
  application compromise, since the same process holds both the pepper
  and the verification code.
- **TOTP secrets can be encrypted at rest, but are not by default.**
  `totp.WithEncryptor` (AES-256-GCM via `totp.NewAESEncryptor`, or a
  custom `Encryptor`) means your `totp.Store` implementation only ever
  sees ciphertext. **Unconfigured, `Credential.Secret` reaches your store
  as base32 plaintext** — a database leak then hands an attacker every
  enrolled user's shared secret, usable to generate valid codes
  indefinitely with no work factor slowing that down. This is the one
  mitigation in this document that requires explicit action to be in
  effect; see "Operational requirements" in the README.
- **Hashed tokens, session tokens, nonces, and recovery codes** (see
  "Token theft and replay" above) mean a database leak by itself does not
  hand out any of those as usable bearer credentials — the stored hash
  cannot be replayed as if it were the raw value, because sulis hashes
  whatever is *presented* and compares hashes, not the reverse.
- **What a database leak still yields**, even with every mitigation above
  configured: password hashes (computationally expensive but not
  impossible to crack, especially for weak passwords the blocklist
  screen didn't cover retroactively — see "Residual risks"), email
  addresses and other plaintext `User` fields (disable reasons, metadata),
  passkey *public* keys (the private key never leaves the authenticator),
  and — if `totp.WithEncryptor` is not configured — usable TOTP secrets.

### Session hijacking

- **Token hashing.** `SessionStore` implementations persist only
  `TokenHash`; the root package always clears `Session.Token` before
  calling `CreateSession`, and `ValidateSession` never returns the raw
  token back to a caller who didn't already have it.
- **Revocation.** `RevokeSession(ctx, userID, sessionID)` is scoped to the
  caller's own `userID` (a session belonging to someone else is
  indistinguishable from a nonexistent one), `RevokeAllSessions` clears
  every session for a user, and sessions are revoked automatically on
  password change/reset (default on), on disabling an account, and on the
  first email verification for an account with a password.
- **Idle timeout.** `WithIdleTimeout(d)` (opt-in) rejects a session in
  `ValidateSession` once it has gone unused for longer than `d`, on top of
  its absolute `SessionDuration` lifetime.
- **`__Host-`-prefixed cookies.** `SessionCookie` defaults to
  `HttpOnly`/`Secure`/`SameSite=Lax`/`Path=/` and a cookie name of
  `__Host-session` — a browser-enforced guarantee that the cookie could
  only have been set by this exact origin over HTTPS for the whole
  origin, closing the classic cross-subdomain cookie-injection route.
- **Refresh fails closed on revocation.** `RefreshSession` deletes the old
  session row *first* and only mints the replacement if that delete
  succeeds, and re-checks account status before minting — so a caller
  holding a stale `*Session` from before a revocation (explicit, or via a
  disabled/locked account) cannot use `RefreshSession` to un-evict itself.

### 2FA bypass

- **`SecondFactorChecker` is required at construction.** `sulis.New`
  rejects a nil checker; there is no default that would silently issue
  fully-privileged sessions to accounts expecting two-factor
  authentication. Applications with no second factor pass
  `sulis.NoSecondFactors{}` — an explicit, greppable declaration.
- **Magic-link login is gated the same as a password.** `RedeemMagicLink`
  treats proving mailbox control as a first factor only: if the account
  has a second factor enrolled, redemption returns a `PendingToken`, not a
  session — a magic link is not a shortcut past 2FA.
- **`Authentication` is an unforgeable proof.** Its fields are unexported
  and there is no exported constructor that takes a bare user ID, so only
  the root package itself can produce a value `IssueSession` will accept;
  `IssueSession` rejects the zero value with `ErrNotAuthenticated`.
- **`IssueSessionUnchecked` is deliberately named for greppability.** It
  is the only way to mint a session from a bare user ID (for factors
  sulis cannot verify itself, such as a finished WebAuthn ceremony), and
  its name says in code review that the caller — not sulis — is vouching
  every required factor was checked.
- **TOTP replay protection.** Each accepted code's counter is persisted as
  `Credential.LastUsedCounter`, and both `Validate` and `ConfirmEnrollment`
  accept a code only if its counter is strictly greater than the last one
  accepted for that credential — reusing or replaying an old code returns
  `ErrTOTPReplayed`.
- **TOTP and recovery-code guessing rate limits are shipped, but not
  wired by default.** `totp.Config.Limiter` and `recovery.Config.Limiter`
  both default to `nil`; unless an application calls
  `totp.WithLimiter`/`recovery.WithLimiter`, `Validate`, `ConfirmEnrollment`,
  and `Consume` skip the rate-limit check entirely, no matter how many
  wrong codes are submitted. `sulis.MemoryLimiter` ships a `"totp:"`
  budget pre-configured (the same generous per-account shape as the
  password budget) precisely so that wiring it up is
  `totp.WithLimiter(sameLimiterInstance)` rather than an application
  having to design its own budget — but that pre-configured budget does
  nothing until that line is written. This is an **operational
  requirement**, in the README's own words: "a 6-digit code is a 10^6
  space, brute-forceable without a limiter." `recovery.WithLimiter` has
  the same off-by-default shape, at lower severity — a recovery code is
  80 bits of `crypto/rand`, not a 6-digit space, so throttling it is
  defense in depth rather than the only thing standing between a code and
  a brute force. Both are also listed under "Residual risks" below.
- **WebAuthn user verification is required by default.** `passkey.NewService`
  sets `UserVerification: required`, so a presence-only tap (no PIN, no
  biometric) is rejected rather than silently accepted as a full factor.
- **WebAuthn clone detection.** go-webauthn flags a sign-count anomaly —
  a credential presenting a counter that didn't advance the way a single
  physical authenticator would — as `Authenticator.CloneWarning`; both
  `FinishLogin` and `FinishDiscoverableLogin` treat that as a hard
  rejection (`ErrCloneWarning`), not a routine auth failure. This is the
  shipped defense against a duplicated authenticator standing in for the
  genuine one: a passkey's value as a factor rests partly on it being
  unclonable hardware, and a sign-count anomaly is the signal that this
  may no longer hold for a given credential.

### CSRF on the cookie path

- **`SameSite=Lax`** on the session cookie, set unconditionally by
  `SessionCookie`.
- **Double-submit helpers.** `IssueCSRFToken`/`RequireCSRFToken`/
  `VerifyCSRFToken` implement a double-submit cookie pattern: the value in
  the (non-`HttpOnly`, `__Host-`-prefixed) CSRF cookie must match, byte for
  byte via `crypto/subtle.ConstantTimeCompare`, whatever the client echoes
  back in a header or form field.
- **`RequireSameOrigin`** rejects a cross-site, state-changing request
  using the `Sec-Fetch-Site` header (falling back to `Origin`) —
  independent of, and layered alongside, the double-submit defense. When
  both headers are absent, the request is allowed through by design: that
  combination is the signature of a non-browser client (a Bearer-token
  API caller, in particular), which was never CSRF-exploitable to begin
  with, so rejecting on absence would block that population for no CSRF
  benefit.
- **Bearer-header cookie-fallback suppression.** `extractToken` treats
  *any* non-empty `Authorization` header — not only a well-formed
  `"Bearer <token>"` one — as suppressing the cookie fallback for that
  request. This closes a gap where a cross-site request carrying an
  attacker-controlled, non-Bearer `Authorization` value (permitted by a
  permissive CORS policy) could otherwise still ride the victim's ambient
  session cookie on a route a developer assumed was Bearer-only and
  therefore CSRF-safe.

## Out of scope

- **Application-level XSS.** sulis does not render HTML or own any
  template layer. If an application has an XSS vulnerability, an attacker
  can act as the logged-in user in their own browser session regardless
  of anything sulis does — `HttpOnly` on the session cookie stops
  JavaScript from reading the *raw token*, but does not stop a script
  from issuing requests the CSRF defenses above are the actual control
  for. Escaping output and a sound Content-Security-Policy are the
  application's responsibility.
- **Compromised hosts.** If an attacker gains code execution on the
  server running sulis, every in-process secret (a configured pepper, an
  encryption key passed to `totp.WithEncryptor`, the process's view of
  plaintext passwords in flight) is reachable. No control described here
  defends against this; it is a deployment/infrastructure concern.
- **Malicious store implementations.** `storetest` verifies that a store
  *behaves* according to the documented contracts (atomicity, error
  sentinels, no aliasing) under test conditions — it does not, and
  cannot, verify that a store implementation is not deliberately doing
  something else in production (e.g. logging plaintext tokens on the
  side, or serving a different backend under load). A conformance suite
  proves contract compliance, not benign intent.
- **Phishing, beyond WebAuthn's origin binding.** WebAuthn ceremonies are
  cryptographically bound to the relying party's origin, so a passkey
  assertion minted for the real site cannot be replayed against, or
  produced for, a phishing site impersonating it. Nothing else in this
  library defends against phishing: a user who is convinced to type their
  password into a fake site, or to relay a TOTP code or magic link to an
  attacker over the phone/chat, has authenticated the attacker exactly as
  effectively as themselves. This is a user-education and (for TOTP/
  password specifically) an argument for offering passkeys, not something
  a library-level control can close.
- **Mailbox compromise.** Magic links and password-reset tokens are
  delivered by email and are, plainly, only as strong as the recipient's
  mailbox. An attacker who controls a user's email can request and redeem
  a magic link, or request and redeem a password reset, exactly as the
  legitimate user would. Magic-link requester binding (see above) narrows
  this to "the attacker must redeem from the same browser/device that
  requested the link," which does not help at all if the attacker is the
  one who requested it in the first place because they control the inbox.
  There is no mitigation for this in sulis; an application with a
  security posture that can't tolerate it should not offer magic-link
  login, or should pair it with a second factor that isn't also
  delivered by email.

## Residual risks

Even when every mitigation above is configured as documented, the
following are known, accepted limitations — carried forward from the
implementation record rather than invented for this document:

- **The double-submit CSRF token is not cryptographically bound to the
  session.** It is a bare random value proving only that the requester
  can read the `__Host-`-prefixed CSRF cookie for this origin, not that
  they hold any particular session. This is mitigated, but not
  eliminated, by the `__Host-` prefix (blocking cross-subdomain cookie
  injection) and by `RequireSameOrigin` as an independent, cookie-content-
  agnostic layer — but the two mechanisms are genuinely separate defenses
  stacked together, not one defense reinforcing the other cryptographically.
- **The default rate limiter is per-process.** `MemoryLimiter` is
  in-memory; a deployment running several instances behind a load
  balancer has each instance enforcing its own budget independently,
  which in effect multiplies an attacker's usable guessing budget by the
  instance count unless `WithLimiter` is configured with a shared
  (e.g. Redis-backed) implementation.
- **TOTP and recovery-code rate limiting are opt-in, not shipped-on.**
  Unlike the root package's own guessable surfaces (password, reset,
  magic-link — all throttled the moment `sulis.New` is called), `totp`
  and `recovery` ship no limiter at all until the application explicitly
  passes one via `totp.WithLimiter`/`recovery.WithLimiter`. An application
  that wires up `totp.Service`/`recovery.Service` without also doing that
  gets a fully unthrottled 6-digit-code or recovery-code guessing surface
  — the library does not fail loudly, or at all, to flag the omission. See
  "2FA bypass" above for the specifics.
- **Security events are best-effort, not a guarantee.** `EventSink.Emit`
  cannot fail a flow — a panicking sink is contained and dropped, a slow
  sink runs on the caller's own goroutine and latency budget, and several
  internal writes that would otherwise generate events (session
  liveness touches, lockout bookkeeping) are themselves best-effort and
  swallow store errors silently. `password.rehash_failed` is the one
  case with a dedicated event for an otherwise-silent failure; most other
  swallowed failures leave no trace at all. Treat the event stream as an
  observability aid, not as an audit log with delivery guarantees.
- **Advisory-lock namespace sharing in the Postgres store.**
  `store/sql/postgres` takes `pg_advisory_xact_lock` on two fixed,
  hand-picked 32-bit class values (one for TOTP operations, one for
  passkey operations) to make three specific store contracts atomic under
  real concurrency. PostgreSQL has exactly one advisory-lock key space per
  database, shared by every caller regardless of which advisory-lock
  function they use (`pg_advisory_lock`, `pg_advisory_xact_lock`, and the
  `_shared` variants all draw from the same space) — it is not scoped to
  sulis's own tables. The two class values here are chosen to be unlikely
  to collide with typical application use, but nothing enforces that. An
  application (or another library sharing the same database) that
  happens to take an advisory lock with the same class and a colliding
  per-user key could contend with, or in principle deadlock against,
  sulis's own locking. Different users' locks never collide with each
  other; this risk is specifically about sulis's fixed class constants
  colliding with something else's chosen keys.
