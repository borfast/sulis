# sulis

`sulis` is a small Go authentication library for consumer-owned persistence. The root package provides password-based auth, password reset, magic-link login, two-factor pending-login tokens, email verification, server-side sessions, and HTTP middleware for attaching the authenticated user and session to a request context. The `totp`, `passkey`, and `recovery` subpackages add TOTP, WebAuthn passkeys, and recovery codes as second factors or standalone credentials, and `passwordcheck` screens new passwords against known-compromised values. Because you own persistence, the `storetest` package ships a conformance suite that proves your store implementations satisfy the contracts the library depends on, and `memstore` is a reference in-memory implementation of all of them — see [Proving your stores correct](#proving-your-stores-correct).

Requires Go 1.25+ (matching `go.mod`).

## Root Package

Create a service with `sulis.New(userStore, sessionStore, tokenStore, secondFactorChecker, opts...)`, which returns `(*Sulis, error)`.

`secondFactorChecker` is **required and must not be nil**. It is how the library learns that a user has a second factor, and defaulting it would mean silently issuing fully-privileged sessions to accounts that expect two-factor authentication:

```go
type SecondFactorChecker interface {
    HasSecondFactor(ctx context.Context, userID string) (bool, error)
}
```

Implement it against whatever your application counts as a second factor — a verified TOTP enrollment, a registered passkey, or both. Applications with no second factors pass `sulis.NoSecondFactors{}`, which states that in code rather than by omission.

The root package owns the auth logic and data types:

- `User`, `Session`, and `Token`
- `Register`, `Login`, `VerifyPassword`, `IssueSession`, `IssueSessionUnchecked`, `ChangePassword`, `SetInitialPassword`
- `ValidateSession`, `RevokeSession`, `RevokeAllSessions`
- `ListUserSessions`, `RefreshSession`
- `RequireRecentAuth`, `ReAuthenticate`
- `DisableUser`, `EnableUser`
- `CreatePasswordResetToken`, `CreatePasswordResetTokenStrict`, `ResetPassword`
- `CreateMagicLinkToken`, `RedeemMagicLink`
- `CreateTwoFactorToken`, `CompleteTwoFactor`
- `CreateEmailVerificationToken`, `VerifyEmail`
- `ChangeEmail`, `ConfirmEmailChange`
- `Authenticate`, `UserFromContext`, `SessionFromContext`
- `SessionCookie`, `ClearSessionCookie`, `RequireSameOrigin`
- `IssueCSRFToken`, `RequireCSRFToken`, `VerifyCSRFToken`
- `WithEventSink`, `NewSlogSink`, `EventSink`, `Event`, `EventKind`

Password hashes use Argon2id over the NFKC-normalized password, optionally peppered first — see [Peppering](#peppering). New passwords are screened for length and against a corpus of known-compromised values — see [Password quality](#password-quality). Reset, magic-link, two-factor, and email-verification tokens are random, single-use, purpose-scoped, and time-limited.

## Core Flows

### Register

`Register(ctx, email, password, requestInfo)` returns `(*User, *Session, string, error)` — the third value is the raw session token. It normalizes and validates the email, puts the password through the policy (length, then the configured `PasswordChecker` — see [Password quality](#password-quality)), hashes the password, creates the user, and immediately creates a new session. It returns `ErrUserAlreadyExists` if the email is already taken, `ErrInvalidEmail` for malformed/empty/overlong addresses, `ErrPasswordTooShort`/`ErrPasswordTooLong` if the password falls outside the configured bounds, and `ErrPasswordCompromised` if the checker recognizes it. Registration does not mark the email as verified — only a redeemed magic link or a completed `VerifyEmail` does that.

### Password quality

Every path that stores a password — `Register`, `ChangePassword`, `ResetPassword`, `SetInitialPassword` — puts it through the same three steps, in this order:

1. **NFKC normalization.** The password is folded to its Unicode NFKC form before anything else looks at it, and that form is what gets hashed. Without this, whether a password verifies depends on which keyboard typed it: `café` arrives from macOS as `e` plus a combining acute accent and from Windows as the single precomposed rune, and those are different byte strings with different Argon2 hashes. NFKC rather than NFC so the compatibility mappings fold too — the `ﬁ` ligature, fullwidth digits, and friends, which are one keystroke on some input methods and plain ASCII on others.
2. **Length.** `MinPasswordLength` (default **12**, raised from 8 in this release) and `MaxPasswordLength` (default 1024), measured in bytes of the *normalized* password, since that is what Argon2 actually consumes. Twelve fullwidth digits are 36 raw bytes and 12 normalized ones; measuring the raw form would wave a password through a minimum it does not meet. `WithPasswordLengthLimits(min, max)` changes both.
3. **The `PasswordChecker`.** Length alone lets `iloveyou1234` through. The configured checker gets the normalized password and returns `ErrPasswordCompromised` to reject it.

```go
type PasswordChecker interface {
    Check(ctx context.Context, password string) error
}
```

**A checker is configured by default.** `sulis.New` installs `passwordcheck.NewBlocklist()`, which compares against an embedded corpus of the ten thousand most common passwords: no network, no third party, nothing to switch on. Comparison folds case, since an attacker's dictionary does too. Note the interaction with the raised minimum, though — common passwords are short, so at `MinPasswordLength` 12 only ten of those ten thousand entries are even reachable; the length gate rejects the rest first. The blocklist earns its keep when you *lower* the minimum, and when you pass site-specific words to `NewBlocklist("Acme-Corp", "acme-stadium", ...)` — exactly the long passwords a targeted attacker tries first, which no general corpus can know about.

**For real breadth, add Have I Been Pwned.** `passwordcheck.NewHIBP()` queries the range API using k-anonymity: only the first five hexadecimal digits of the password's SHA-1 leave the process, and the match against the several hundred suffixes that come back is made locally. The password, its full hash, and even the hash's suffix are never transmitted — a property pinned by a test that inspects the entire outbound request and fails if any of the three appears in it. Compose rather than replace, or you silently drop the local blocklist:

```go
s, err := sulis.New(users, sessions, tokens, factors,
    sulis.WithPasswordChecker(passwordcheck.All(
        passwordcheck.NewBlocklist(),   // local, free, always available
        passwordcheck.NewHIBP(),        // network, opt-in
    )),
)
```

**HIBP fails open by default.** If the service is unreachable — connection refused, timeout, 5xx, 429 — the password is allowed through unchecked rather than rejected. The alternative makes another organization's uptime a hard dependency of your registration *and* password-reset flows, including the reset someone is doing because they were just breached; failing open costs a few unscreened passwords during an outage, and they still face the length policy and the local blocklist. `passwordcheck.WithHIBPFailClosed()` inverts it for deployments whose policy demands it — pair it with alerting, because "nobody can change their password" is the failure mode to actually fear. Either way, an unreachable service produces an ordinary error and never `ErrPasswordCompromised`: surface it as "try again in a moment", not as "your password is compromised", because nobody looked. `WithHIBPBaseURL`, `WithHIBPTimeout` (default 5s, applied to the request context), and `WithHIBPHTTPClient` cover self-hosted mirrors, tests, and shared transports.

Pass `WithPasswordChecker(nil)` to disable screening entirely.

**Verification never consults the checker.** `VerifyPassword`, `Login`, and `ReAuthenticate` do not screen the password they are checking, and cannot return `ErrPasswordCompromised`. Screening at verification time would lock out every existing user whose password is in the corpus the moment one is added or refreshed — a hardening change turned into a mass outage whose only remedy is itself a login-adjacent flow. A password is screened where it is chosen. If you want existing users moved off a now-known-bad password, detect that out of band and require a change, which leaves the user in control of when it happens.

#### Upgrading: what NFKC normalization does to existing hashes

A hash written before this release was derived from the raw bytes the user typed, not from the NFKC form. **Nobody is locked out.** Verification tries the normalized form first and, only if that fails *and* the two forms differ, falls back to comparing the raw bytes — so a pre-existing hash still verifies against the spelling it was created from. A match that way is treated exactly like a hash with outdated Argon2 parameters: it is re-derived from the normalized form and written back on the spot, through the same best-effort, concurrency-guarded path described under [Login and VerifyPassword](#login-and-verifypassword). After one successful login (or one `ReAuthenticate`) the account is migrated, every equivalent spelling of its password starts working, and the fallback never fires for it again.

The fallback widens nothing: it compares the caller's exact bytes against the stored hash, so the only password it can accept is the one that hash was already derived from. No string that failed before this change succeeds after it. It also costs nothing for an already-normalized password — every ASCII password, so very nearly all of them — because there is no second form to compare.

Two things genuinely do change for existing deployments. The **default minimum length is now 12**, so accounts with shorter passwords keep working but cannot re-use them on a change or reset; set `WithPasswordLengthLimits(8, 1024)` to keep the old behavior. And **`ChangePassword`/`ResetPassword` can now fail with `ErrPasswordCompromised`**, which your handlers should present as "choose a different password" rather than as a credential error.

### Login and VerifyPassword

`Login(ctx, email, password, requestInfo)` treats a correct password as the **first factor only**. It verifies the password, then asks the configured `SecondFactorChecker` whether the account has a second factor enrolled, and returns a `*LoginResult`:

```go
res, err := auth.Login(ctx, email, password, sulis.RequestInfo{IP: ip})
if err != nil {
    return err
}
if res.NeedsSecondFactor {
    // No session exists yet. Stash res.PendingToken server-side, prompt for
    // the second factor, then call CompleteTwoFactor.
    return promptForSecondFactor(res.User, res.PendingToken)
}
setSessionCookie(res.SessionToken)
```

Exactly one outcome is populated: either `Session` + `SessionToken`, or `PendingToken` with `NeedsSecondFactor` set. **Branch on `NeedsSecondFactor`** — treating a non-nil `LoginResult` as "logged in" defeats two-factor authentication.

If the checker returns an error, `Login` fails closed: no session, no pending token, error propagated. An unavailable factor store must never silently downgrade an account to one factor.

`VerifyPassword(ctx, email, password, requestInfo)` checks credentials without creating anything, for applications that want to drive the second-factor step entirely themselves.

Both equalize response timing for unknown-user and passwordless-user cases by running the same Argon2 work against an internal dummy hash, and both return `ErrInvalidCredentials` for any of: unknown email, passwordless account, or wrong password — the error never reveals which. If a `Limiter` is configured (see [Operational requirements](#operational-requirements)), it is consulted before the store lookup, keyed by `"password:"+<normalized email>`.

**Raising `Argon2Params` upgrades existing hashes transparently as users log in.** Both `Login` and `VerifyPassword` compare the just-verified hash's cost parameters (memory, iterations, parallelism) against the currently configured `Argon2Params` and, if the stored hash is weaker, re-hash the password that was just verified with the current parameters and write it back — no migration script, no forced password reset, and no change to either method's signature or return value. This only ever runs after a *successful* verification, so a wrong password, an unknown email, or a passwordless account never triggers a rehash and the timing-equalization story above is unaffected. The write is **best-effort**: it goes through the same optimistic-concurrency retry (`UserStore.UpdateUser`'s `Version` contract) every other password write uses, guarded so a password changed by a concurrent request is never overwritten with a rehash of the password it just replaced, but if the write is lost to a losing race or a store error, the login still succeeds — only the cost of the *next* login is affected, and that next successful login simply tries the upgrade again. Lowering `Argon2Params` does not downgrade existing hashes; only a hash weaker than the configured parameters is ever rewritten. `ReAuthenticate` (see [Step-up authentication](#step-up-authentication)) does the same on its own successful password comparisons; `RedeemMagicLink` and `IssueSession`/`IssueSessionUnchecked` never verify a password at all, so there is nothing for them to upgrade.

`IssueSession(ctx, auth)` returns `(*Session, string, error)` and creates a new session for the user named by an `Authentication` proof. `Authentication` is opaque — its fields are unexported, and there is no exported constructor that takes a bare user ID — so only this package can produce a valid value, and `IssueSession` rejects the zero value `Authentication{}` with `ErrNotAuthenticated` before touching any store. Beyond that check it behaves like `IssueSessionUnchecked` below: `ErrUserNotFound` if the proof's user no longer exists, and — by default — `ErrEmailNotVerified` if the account's email isn't verified yet; see [Operational requirements](#operational-requirements) for the `RequireVerifiedEmail` flag. `Login` applies the same verified-email gate before consulting the second-factor checker, so a correct password for an unverified account returns `ErrEmailNotVerified` rather than a session or a pending token.

`IssueSession` deliberately does **not** consult the `SecondFactorChecker`: it is the primitive for a login that has already cleared every factor. That is also why there is no way to obtain an `Authentication` from outside this package: minting one *is* the guarantee that every factor was checked, and only `sulis` itself is in a position to make that claim.

**`IssueSessionUnchecked(ctx, userID, method)`** returns the same `(*Session, string, error)` and applies the same `ErrUserNotFound`/`ErrEmailNotVerified` gating, but takes a bare user ID instead of an `Authentication` — it is `IssueSession`'s old, unguarded behavior kept under a name that shows up in code review. Call it only for a factor `sulis` does not know how to verify itself — the canonical example is a finished passkey ceremony, which is verified entirely by the `passkey` subpackage and has no way to produce an `Authentication`. Calling `IssueSessionUnchecked` means **you**, not `sulis`, are vouching that `userID` completed every factor your application requires; `sulis` performs no credential check of its own here. `method` records which credential you're vouching for.

`ChangePassword(ctx, userID, oldPassword, newPassword, requestInfo)` is for accounts that already have a password. It consults the configured `Limiter` (key `"password:"+email`, the same key `Login`/`VerifyPassword` use) before verifying the old password, so a stolen session token can't be used to brute-force it once rate limiting is enabled. It returns `ErrInvalidCredentials` for a passwordless account or a wrong old password. The old password is re-verified against the freshly loaded user as part of the write, so a password changed by a concurrent request is never overwritten on the strength of a stale check.

`SetInitialPassword(ctx, userID, newPassword)` is for passwordless accounts created through flows such as magic link. Call it only after your application has already authenticated the user through a trusted flow; it returns `ErrInvalidCredentials` if the account already has a password.

### Peppering

`WithPepper(pepper []byte)` mixes a secret pepper into every password via HMAC-SHA256 before Argon2 ever sees it:

```go
s, err := sulis.New(users, sessions, tokens, factors,
    sulis.WithPepper(loadPepperFromSecretsManager()),
)
```

**What it protects against, and what it doesn't.** A pepper is not stored anywhere near the password hashes — unlike a salt, which travels with the hash it protects. It defends against a *database-only* leak: a copy of the user table with no access to your application's configuration or secrets yields Argon2 hashes nobody can run an offline dictionary attack against without also having the pepper. It does **not** protect against a full application compromise — the same process that hashes and verifies passwords holds the pepper, so an attacker who reaches that process reaches both.

**Losing the pepper makes every hash unverifiable. There is no fallback.** Store it with the same care as a private key: a secrets manager or environment variable, never checked in, never beside the database it is meant to protect.

**Set it before the first password is ever hashed, or plan on password resets.** A pepper is a first-deployment decision, not a knob to turn on a running system. `verifyPassword` applies whichever pepper is *currently* configured, uniformly, to both forms its [NFKC compatibility fallback](#upgrading-what-nfkc-normalization-does-to-existing-hashes) already tries — it does not also try every pepper this deployment has ever used. That fallback is safe to widen because it can only ever match the exact bytes a hash was already derived from; a pepper introduced later, changed, or removed has no such single "old form" to fall back to, only an unbounded list of past values this library has no way to know. Concretely:

- Introducing a pepper on a deployment that started without one makes every existing hash unverifiable.
- Changing a pepper's value makes every hash written under the old value unverifiable.
- Removing a pepper makes every hash written while one was set unverifiable.

In every case, the recovery path is the same one already used for a lost password: reset it. This is a deliberate choice, not a gap — building dual-path verification the way T505's NFKC fallback works would mean guessing which of an unbounded set of historical peppers produced a given hash, which is a fundamentally different (and unsafe) problem from "try the one other form a password can take."

### ValidateSession

`ValidateSession(ctx, token)` hashes the presented token, loads the session by hash, rejects expired sessions with `ErrSessionExpired` (deleting the expired record as it goes), and returns the session plus its user.

**`Session` has no `Token` field.** The raw token exists only as a return value at issue time — `LoginResult.SessionToken`, or the third result of `Register`, `IssueSession`, `IssueSessionUnchecked`, and `RefreshSession` — so the struct handed to `SessionStore` has no way to carry it and no store can persist a live bearer token by accident. Stores see `TokenHash` and nothing else.

**`RevokeSession(ctx, userID, sessionID)` is scoped to the caller's own userID.** It deletes `sessionID` only if it belongs to `userID`, returning `ErrSessionNotFound` (and leaving the session untouched) otherwise — so a session-management UI wired straight to this method can't let one user revoke another's session by guessing or leaking its ID. Pass the userID of the account the caller is authenticated as, not a value taken from the request body. `RevokeAllSessions(ctx, userID)` deletes every session for a user and has no such ambiguity to begin with.

**Idle expiry is opt-in via `WithIdleTimeout(d)`.** A session unused for longer than `d` is rejected by `ValidateSession` with `ErrSessionExpired` even if its absolute `SessionDuration` lifetime has not elapsed yet — useful for "sign me out after 30 minutes of inactivity" on top of a long-lived `SessionDuration`. Passing `d <= 0` (the default; no option needed) disables idle expiry entirely: `IdleExpiresAt` stays nil forever and `ValidateSession` never checks it.

"Unused" is tracked by `Session.LastSeenAt`/`IdleExpiresAt`, stamped at issuance and refreshed by `ValidateSession` on every successful call — but **throttled**, not written every time: a write only happens once the session's current `LastSeenAt` is already older than an interval (`IdleTimeout / 4` when idle expiry is configured, so a session in steady use never drifts more than a quarter of the timeout behind reality; a fixed 5 minutes when it isn't, purely to bound staleness for the "where you're signed in" screen below). Skipping this throttle would mean a store write on every single authenticated request — for most applications, on nearly every request they serve. The touch is best-effort: a failed write never fails the validation itself, since the session is still valid regardless of whether its "last seen" bookkeeping happens to update at that exact moment.

### Cookie sessions and CSRF

`Authenticate` reads the session token from whichever channel(s) `TokenSource` permits (default `TokenSourceBoth`: an `Authorization: Bearer` header or a cookie), then calls `ValidateSession` and attaches the result to the request context. This section is what to wire up if you want the cookie half of that to actually work, plus the CSRF defense a cookie needs and a Bearer header doesn't.

**`SessionCookie(rawToken, expires) *http.Cookie` and `ClearSessionCookie() *http.Cookie`** build the `Set-Cookie` your handler needs — `http.SetCookie(w, auth.SessionCookie(res.SessionToken, expiresAt))` at login, `http.SetCookie(w, auth.ClearSessionCookie())` at logout. Every security attribute is fixed by these methods, not left to you: `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, and a `Name` that defaults to `"__Host-session"`. The `__Host-` prefix is a browser-enforced guarantee — this cookie can only have been set by this exact origin, over HTTPS, for the whole origin — that requires exactly `Secure`, `Path=/`, and no `Domain` attribute; both methods always set the first two and never set the third, for any `CookieName`, so the combination can never quietly become invalid. `WithCookieName` overrides the name; picking one without the `__Host-` prefix is a valid, explicit opt-out (e.g. if a reverse proxy in front of you needs to also read it via a shared `Domain`), and `New` rejects a name that isn't a valid cookie-name token at all (empty, or containing whitespace/control characters).

**`TokenSource` and `WithTokenSource` decide which channel(s) `Authenticate` reads.** The default, `TokenSourceBoth`, is today's behavior and stays the default even though this same release adds cookie support and the CSRF defenses below: a `Bearer` header is never attached to a request by a browser on its own, so accepting one alongside a cookie doesn't create or widen a CSRF exposure by itself — that exposure comes entirely from the cookie channel, and closing it is exactly what `RequireSameOrigin`/`RequireCSRFToken` are for. `TokenSourceCookieOnly` makes `Authenticate` never read the `Authorization` header at all; `TokenSourceBearerOnly` makes it never read the cookie. A deployment that sets `TokenSourceBearerOnly`, and never calls `SessionCookie`, needs neither `RequireSameOrigin` nor the CSRF helpers below — without a cookie there's no ambient credential for a forged cross-site request to ride on.

**`RequireSameOrigin(allowed []string) func(http.Handler) http.Handler`** rejects a cross-site, state-changing request (any method other than `GET`/`HEAD`/`OPTIONS`) using the Fetch Metadata `Sec-Fetch-Site` header, falling back to `Origin` when `Sec-Fetch-Site` is absent; `allowed` lists origins (`"https://app.example.com"`) trusted even when the browser reports cross-site. Wrap it around any mux/handler reachable via a cookie-sourced session:

```go
mux.Handle("/api/", sulis.RequireSameOrigin([]string{"https://app.example.com"})(apiHandler))
```

**When both `Sec-Fetch-Site` and `Origin` are absent, the request is allowed through.** Every browser new enough to send either header sends at least one of them on a cross-site request; a request with neither is the signature of a non-browser client — a `Bearer`-token API caller, in particular, which was never CSRF-exploitable to begin with. Rejecting on absence would block exactly that population for no CSRF benefit. This leaves a narrow residual gap — a pre-Fetch-Metadata browser that also omits `Origin` on some cross-site state-changing request — which is what the double-submit helpers below cover independently of either header.

**`IssueCSRFToken`, `RequireCSRFToken`, and `VerifyCSRFToken` are the double-submit half of the defense**, and work whether or not `RequireSameOrigin` is also wired up. `IssueCSRFToken() (token string, cookie *http.Cookie, err error)` mints a random token; set the cookie it returns and hand the token to the page (a hidden form field, or a value for a same-origin script to mirror into the `X-CSRF-Token` header — `CSRFHeaderName`). `RequireCSRFToken` is middleware that checks state-changing requests the same way `RequireSameOrigin` does (safe methods pass through); `VerifyCSRFToken(r) error` is the underlying check, exported separately for handlers that want to run it themselves. Either way, the rule is: the value in the `CSRFCookieName` cookie (`"__Host-csrf_token"`, deliberately **not** `HttpOnly` — a same-origin script has to be able to read it) must match, byte for byte, whatever the client echoed back in `CSRFHeaderName` or (falling back, for a plain `<form>` POST) the `CSRFFormField` form value. The comparison is constant-time (`crypto/subtle.ConstantTimeCompare`), so a timing side channel can't be used to recover the token. A mismatch, a missing cookie, or a missing echoed value all fail the same way (`ErrCSRFTokenInvalid` / 403 Forbidden) — deliberately: telling an attacker which one failed would leak a bit about a cookie they can't otherwise read.

**None of this applies to a Bearer-only deployment.** If `TokenSource` is `TokenSourceBearerOnly` and you never call `SessionCookie`, skip `RequireSameOrigin` and the CSRF helpers entirely — there is no cookie for either defense to protect. Add them back the moment you call `SessionCookie` for any route, even one that also accepts a Bearer header.

**`Authenticate`'s 401 response carries `WWW-Authenticate` and `Cache-Control: no-store`.** The former names the scheme a `Bearer`-token client should retry with (RFC 7235/6750); the latter keeps a shared or browser cache from ever storing an authentication failure — or, worse, a response accidentally produced for someone else's stale session.

### Session visibility and lifecycle

`ListUserSessions(ctx, userID)` returns every session belonging to a user — `CreatedAt`, `LastSeenAt`, `AuthenticatedAt`, `Method`, `IP`, `UserAgent`, all populated — for building a "where you're signed in" screen: render each entry ("Chrome, last active 2 hours ago, 203.0.113.4") and let the user call `RevokeSession` on anything they don't recognize.

**`TokenHash` is always empty on what `ListUserSessions` returns**, even though the underlying store does store and return one — a device-management screen has no legitimate reason to see even a hash of a bearer credential, so this method blanks it before the slice ever leaves the package. This is the property to test first if you're implementing your own `SessionStore.ListUserSessions`: the store method itself returns `TokenHash` exactly as stored (the same as `GetSessionByTokenHash`); `sulis.Sulis.ListUserSessions` is what strips it.

`RefreshSession(ctx, session)` returns `(*Session, string, error)` and rotates a session's token: a new ID, a new raw token, and `ExpiresAt` extended from now, while `UserID`, `Method`, `AuthenticatedAt`, `CreatedAt`, `IP`, `UserAgent`, and `Metadata` all carry forward unchanged. **`AuthenticatedAt` is preserved, not refreshed** — a token rotation is not a new authentication proof, and resetting it would silently extend how long a stolen-but-since-rotated session passes `RequireRecentAuth`. Call it periodically (e.g. once per day of active use) to bound how long any one bearer token stays valid, independent of `SessionDuration`.

**The old session row is deleted FIRST, and minting the new one only happens if that succeeds.** This is a fail-closed liveness check on `session`, not an ordering nicety: without it, a caller holding a stale `*Session` from before a revocation (`RevokeSession`, `RevokeAllSessions`, or an eviction via the "where you're signed in" screen above) could call `RefreshSession` and mint a working replacement anyway — un-evicting themselves. `RefreshSession` also reloads the user and checks account status before minting, so a disabled or locked account's stale `*Session` can't be refreshed into a live one either, even in the edge case where the old row happened to survive whatever disabled the account. Both checks run after the delete succeeds, so an attempt that fails either one still burns the caller's old session on its way to the error. The cost is a small crash window: a crash between the delete and the create logs the caller out rather than leaving two valid tokens briefly outstanding — the safe direction to fail in.

**`IP`/`UserAgent` are carried forward from the stale `*Session` you pass in, not re-derived** — `RefreshSession` takes no `RequestInfo`. A session refreshed repeatedly over a long life can therefore show the IP/UserAgent it was originally issued with in a `ListUserSessions` listing, even while `LastSeenAt` looks current from `ValidateSession`'s own touch.

There is no facade method for "sign out everywhere else, keeping this one": compose it from what's here — `ListUserSessions` to find the other IDs, `RevokeSession` per ID. `SessionStore.DeleteUserSessionsExcept(ctx, userID, keepSessionID)` exists as a single-query store-level primitive for an application implementing its own store that wants to skip the per-session loop; see [Store Contracts](#store-contracts).

### Step-up authentication

Every session carries `AuthenticatedAt` (when its owning credential was last proven) and `Method` (which credential proved it), both stamped at issuance by `Register`, `Login`/`RedeemMagicLink` (via `completeFirstFactor`), `CompleteTwoFactor` (`AuthMethodTwoFactor`, regardless of which method passed the first factor), and `IssueSession`/`IssueSessionUnchecked`.

`RequireRecentAuth(ctx, session, maxAge)` returns `ErrReauthRequired` if `session.AuthenticatedAt` is older than `maxAge`, and `nil` otherwise. It's a pure check against a `*Session` you already have (typically whatever `ValidateSession` just returned) — no store round trip. **A session issued before this field existed reads back with a zero `AuthenticatedAt`, which is always older than any `maxAge`: such a session fails closed, never treated as fresh.**

**Gate these operations behind `RequireRecentAuth`, not a bare session** — each changes something an attacker who merely stole a cookie should not be able to change:

- Enrolling or replacing a TOTP factor (`totp.Service.Enroll`, `ReplaceEnrollment`)
- Disabling two-factor authentication
- Adding or removing a passkey
- Changing email (`ChangeEmail`)
- Regenerating recovery codes

```go
session, user, err := auth.ValidateSession(ctx, token)
if err != nil {
    return err
}
if err := auth.RequireRecentAuth(ctx, session, 15*time.Minute); err != nil {
    // Prompt for the password again, then call ReAuthenticate, before
    // letting the request through to totp.Enroll / passkey removal / etc.
    return err
}
```

`ReAuthenticate(ctx, session, password, requestInfo)` is the write side: it verifies `password` for `session`'s owning user and, on success, stamps `session.AuthenticatedAt` with the current time — both on the stored session and on the `*Session` you passed in, so you don't need to reload it. **It mints no new session and does not rotate the token**: `session.ID` and its token hash are unchanged, so the user's existing session (and its raw token, if they still hold it) keeps working exactly as before, just freshly re-authenticated. Like `VerifyPassword`, it's rate-limited on both the account (`"password:"+email`, the same budget `Login`/`VerifyPassword`/`ChangePassword` share) and IP dimensions, and equalizes timing for a passwordless account via the same dummy-hash path. Returns `ErrInvalidCredentials` for a passwordless account or a wrong password, and in neither case is `AuthenticatedAt` touched. It also returns `ErrAccountDisabled`/`ErrAccountLocked` via the same account-status check every other issuance path applies (see [Account disable and lockout](#account-disable-and-lockout)) — checked right after loading the user, before spending an `Argon2` verification on a call that cannot succeed either way. A successful call is also a real password comparison against a real stored hash, so it participates in the same transparent hash upgrade `Login`/`VerifyPassword` do (see [Login and VerifyPassword](#login-and-verifypassword)) — best-effort, and with no effect on `AuthenticatedAt` or the returned error either way.

### Account disable and lockout

`DisableUser(ctx, userID, reason)` takes an account out of service immediately: it stamps `User.DisabledAt` and records `reason` (caller-supplied context — `sulis` never inspects it), then revokes every session the account currently holds. `EnableUser(ctx, userID)` reverses it — `DisabledAt`/`DisabledReason` are cleared and the account authenticates normally again. Both return `ErrUserNotFound` for an unknown user.

**Disabling invalidates sessions already issued, not just future logins.** `ValidateSession` checks `DisabledAt` on every call, independent of whether `DisableUser`'s own session revocation happens to succeed — so even a store that failed to delete a session, or a session created after the disable took effect but somehow missed by the delete, still dies on its very next use. This is the check that matters most: without it, disabling would leave every session an attacker (or a since-fired employee, or a compromised account) already holds working for the rest of its natural lifetime.

Every session-issuance path checks account status: `VerifyPassword` (and so `Login`), `completeFirstFactor` (the choke point shared by `Login` and `RedeemMagicLink`), `IssueSession`/`IssueSessionUnchecked`, and `CompleteTwoFactor`. `Register` is exempt by nature — a freshly created account cannot already be disabled or locked. `ReAuthenticate` checks it too, even though it issues no session: without that check it could still refresh `AuthenticatedAt` for a disabled or locked account's already-held session (see [Step-up authentication](#step-up-authentication)).

**`VerifyPassword` checks status only *after* the password has verified.** An unauthenticated caller who has not proven the password must not be able to use a distinct `ErrAccountDisabled`/`ErrAccountLocked` to learn that an account exists and is disabled or locked — that is exactly the kind of oracle the dummy-hash timing equalization above already closes for existence and password-presence; checking status any earlier would reopen an equivalent one for account status. A wrong password against a disabled account returns the ordinary `ErrInvalidCredentials`, same as any other wrong password.

`LockedUntil` is the automatic-lockout counterpart to `DisabledAt` (see below) and is checked the same way — after the password verifies — but **`ValidateSession` does not check it**. A temporary lockout throttles new authentication attempts; it does not retroactively invalidate a session issued before the lockout began, since the account owner already proved their identity once to get that session and an automatic, attacker-triggerable mechanism killing it too would make the denial-of-service risk below worse, not better.

**Automatic lockout is off by default.** `WithFailureLockout(threshold, baseBackoff, maxBackoff)` enables it: after `threshold` consecutive wrong passwords, `VerifyPassword` sets `LockedUntil` to `baseBackoff` past the triggering failure, and every further wrong password while still locked pushes it out again, doubling up to `maxBackoff`. It clears itself — both `LockedUntil` and the failure count — the next time a correct password verifies outside the window; there is no explicit unlock call. It is deliberately opt-in: this mechanism locks out the legitimate owner exactly as effectively as it locks out an attacker, so anyone who merely knows (or guesses) an email address can weaponize it as a denial-of-service against that account. The rate limiter (on by default; see [Operational requirements](#operational-requirements)) is the first line of defense against guessing and does not share this failure mode, since it throttles the guesser without touching the account's own ability to log in once its window passes. Enable automatic lockout only if your threat model needs an escalating response beyond rate limiting, and prefer a long `baseBackoff`/`maxBackoff` over a short one.

`DisableUser`/`EnableUser` are a separate, operator-initiated mechanism from automatic lockout — disabling doesn't touch `LockedUntil`/`FailedLoginAttempts`, and enabling doesn't forgive an in-progress automatic lockout the operator may not know about.

**A successful password change or reset also clears an active lockout.** `ChangePassword`, `ResetPassword`, and `SetInitialPassword` all clear `FailedLoginAttempts`/`LockedUntil` on success, the same as a correct login password does. This matters because the two mechanisms compose badly otherwise: with `WithFailureLockout` enabled, an attacker can lock a victim's account with nothing but repeated wrong guesses, and the victim's own recovery path — proving control via an out-of-band reset token, which is at least as strong an identity proof as a login password — would otherwise leave them waiting out `maxBackoff` anyway, defeating the point of being able to reset a password at all. **`DisabledAt`/`DisabledReason` are never touched by a password change or reset** — disabling is an operator's decision, and only `EnableUser` reverses it; no proof of the password lifts it.

### Password Reset

`CreatePasswordResetToken(ctx, email, requestInfo)` creates a password-reset token and returns the raw token so the caller can deliver it out-of-band. If no account exists for `email`, it returns `("", nil)` rather than `ErrUserNotFound` — like `Login`/`VerifyPassword`, the response can't be used to tell a registered address from an unregistered one. The unknown-address path still generates and hashes a token of the same size the known-address path would create, then discards it, so the two paths can't be distinguished by the work they perform either; see [Operational requirements](#operational-requirements) for the one residual asymmetry (a store write) this can't equalize away.

`CreatePasswordResetTokenStrict(ctx, email, requestInfo)` is the same call with the safe default turned off: it returns `ErrUserNotFound` verbatim for an unknown address. It exists for admin tooling that has already authenticated an operator and genuinely needs to know whether the address is registered — never wire it to a public-facing endpoint, or you reopen the enumeration oracle `CreatePasswordResetToken` exists to close.

`ResetPassword(ctx, rawToken, newPassword)` checks the password policy first — length and the configured `PasswordChecker`, see [Password quality](#password-quality) — so a policy failure doesn't burn the token, then atomically consumes it (hash + purpose, single-use), loads the user, and updates the password hash. It returns `ErrTokenInvalid` for an unknown or wrong-purpose token and `ErrTokenExpired` for an expired one. A replay's error depends on timing: redeeming the same still-live token twice (e.g. a concurrent racing request) returns `ErrTokenAlreadyUsed` for the loser; redeeming it again *after* a successful reset returns `ErrTokenInvalid` instead, because a successful reset purges the user's outstanding password-reset tokens, so the replay finds nothing to consume rather than an already-used row.

By default, both `ChangePassword` and `ResetPassword` revoke every session belonging to the user and delete any other outstanding password-reset tokens for that user — see [Operational requirements](#operational-requirements).

### Magic Link

`CreateMagicLinkToken(ctx, email, requestInfo) (token, bindingNonce string, err error)` creates a magic-link token and returns the raw token for delivery. If no user exists for the email yet, **no user row is created at this point** — only the token, carrying the email — so that requesting magic links for arbitrary addresses can't be used to flood the user store. The user is created lazily at redemption. This also means `CreateMagicLinkToken` never returns `ErrUserNotFound` — unlike `CreatePasswordResetTokenStrict`, which does; `CreatePasswordResetToken` itself, like `CreateMagicLinkToken`, never leaks that distinction to a public caller.

The token expires after `MagicLinkDuration` (default **15m**), not `TokenDuration` (which now governs password-reset tokens only — see `WithMagicLinkDuration`). A magic link is a full credential delivered in cleartext over email, where it can sit in an inbox, get forwarded, get scanned by a corporate mail-security appliance, or get prefetched by a client before a human ever clicks it — all things a password-reset link, typed by a human who just requested it, is far less exposed to. Fifteen minutes is deliberately short; raise it only if your delivery pipeline (queueing, retries) genuinely needs the slack.

`RedeemMagicLink(ctx, rawToken, bindingNonce string, requestInfo)` atomically consumes the token, checks `bindingNonce` (see "Binding a magic link to its requester" below), loads the user (creating a passwordless one now if the token predates the account), stamps `EmailVerifiedAt` (redeeming a magic link proves control of the mailbox), and then returns a `*LoginResult` on exactly the same terms as `Login`.

**A magic link is a full first factor, not a shortcut past 2FA.** Proving control of the mailbox is equivalent to knowing the password, so if the account has a second factor enrolled the result carries a `PendingToken` and no session. Verification is stamped *before* that branch, so a 2FA-enabled user with an unverified address can still verify it by following a magic link.

**Migration note:** both signatures changed — `CreateMagicLinkToken` now returns a third value (`bindingNonce`) and `RedeemMagicLink` now takes it as a new second parameter — so every existing call site needs updating to compile, not just to behave correctly. Two defaults changed with them: the magic-link TTL dropped from the shared `TokenDuration` (1h) to its own `MagicLinkDuration` (15m) — pass `WithMagicLinkDuration(time.Hour)` to keep the old window — and binding is on by default, so a deployment that doesn't wire up the nonce cookie (see below) will see every redemption rejected with `ErrTokenInvalid` unless it either does the wiring or passes `WithMagicLinkBinding(false)`.

#### Binding a magic link to its requester

By default (`MagicLinkBinding`, default **true**), `CreateMagicLinkToken` also generates a random binding nonce and returns it alongside the token; the created `Token` stores only the nonce's SHA-256 hash (`Token.NonceHash`), never the plaintext, exactly as `TokenHash` never stores the raw token. Wire it up like this:

1. **At issuance**, set `bindingNonce` as a short-lived, `HttpOnly` cookie on the response to the request that triggered `CreateMagicLinkToken` — **not** in the emailed link itself, which would defeat the entire point by traveling with the token to wherever the link ends up.
2. **At redemption**, read that cookie back and pass its value as `RedeemMagicLink`'s `bindingNonce` argument, alongside the token recovered from the link's query string.

Because the nonce lives only in a cookie scoped to the browser that requested the link, a copy of the link forwarded to someone else — or opened on a different device, such as a phone that didn't request it — arrives without the matching cookie. `RedeemMagicLink` then rejects it with `ErrTokenInvalid`, even though the token itself is still valid, unused, and unexpired. That is the property this task exists for: **a forwarded magic link cannot sign anyone in.** A missing and a wrong nonce fail identically, so neither leaks which half was the problem, and the comparison is constant-time (`crypto/subtle.ConstantTimeCompare` over the hashes). The check runs *after* the token is atomically consumed, so a wrong nonce still burns the token — the same fail-safe-forward direction `ResetPassword`/`RedeemMagicLink` already apply to an expired token (see `consumeToken`'s own doc comment) — which is why an attacker holding a stolen token but not its cookie gets exactly one chance to guess right, not unlimited retries against a token that stays live.

**`WithMagicLinkBinding(false)` turns this off entirely**: `CreateMagicLinkToken` stops generating a nonce (`bindingNonce` comes back `""`), the stored token carries no `NonceHash`, and `RedeemMagicLink` accepts any `bindingNonce` value, including `""`. This is a real, sometimes-legitimate trade-off — mail is routinely read on a different device than the one that requested it (desktop request, phone inbox) — but it also means a link forwarded to someone else, or fetched early by an automated mail scanner, signs that other party or scanner in instead of the intended recipient. Turn it off deliberately, with that risk in mind; it is not the default for a reason.

**Prefetch hazard, independent of binding:** some corporate mail gateways and antivirus scanners follow every link in an email to check where it leads, before a human ever opens the message — which, against a single-use token, consumes it. Binding limits the *blast radius* of that (the scanner's redemption fails without the requester's cookie, so at most it burns the token rather than signing the scanner in) but does not stop the token from being wasted. Mitigate this at the application layer with an explicit confirmation step: land the clicked link on an interstitial page that asks the user to click a button before the token is actually redeemed, rather than redeeming on the bare `GET`. A scanner that only follows links, and never clicks a button on the page it lands on, then never touches the token at all.

### Two-Factor

Two-factor authentication is a pending-login token sandwiched between a verified first factor and a verified second factor. `sulis` doesn't implement any second factor itself — pair it with `totp`, `recovery`, or `passkey` below — it only issues and redeems the short-lived pending token that stands in for "first factor passed, second factor pending."

Flow: `VerifyPassword` → your app checks whether the user has 2FA enabled → `CreateTwoFactorToken` → your app independently verifies the second factor (TOTP, recovery code, or passkey) → `CompleteTwoFactor(ctx, userID, rawToken, requestInfo)`, which returns a `*LoginResult` on the same terms as `Login`. No session exists until `CompleteTwoFactor` succeeds; the pending token is single-use, purpose-scoped (rejected by `ResetPassword`, `RedeemMagicLink`, and `VerifyEmail`), and expires after `TwoFactorTokenDuration` (default 5 minutes).

By default, `CreateTwoFactorToken` returns `ErrEmailNotVerified` for an unverified account, failing before your app ever prompts for a second factor. `CompleteTwoFactor` re-checks the same condition as defense in depth (the token is consumed either way), against the account's *current* verification state rather than its state when the token was minted.

`CompleteTwoFactor` takes `userID` as an explicit argument and rejects the token with `ErrTokenInvalid` if it wasn't minted for that user (consuming the token either way, so a mismatched attempt also burns it). Your app must carry the `userID` obtained from `VerifyPassword` through its own server-side state across the two requests — e.g. keyed by the pending token, or in a short-lived server session — and pass that value to `CompleteTwoFactor`. **Never accept a client-supplied `userID` for this call**: if the second-factor request's `userID` came from the client instead, an attacker who can produce a *valid* second factor for their own account (their own TOTP code, their own passkey) could pair it with someone else's pending token and pass someone else's `userID`, since `sulis` only checks that the token and the userID match each other, not that the caller is who they claim.

```go
ri := sulis.RequestInfo{IP: ip, UserAgent: ua}

user, err := auth.VerifyPassword(ctx, email, password, ri)
if err != nil {
    return err // ErrInvalidCredentials or ErrRateLimited
}

if !userHasTwoFactorEnabled(user) {
    // This app determines 2FA status itself rather than through Login's
    // SecondFactorChecker, so sulis has no Authentication to offer here —
    // IssueSessionUnchecked is the caller-vouches-for-it primitive for
    // exactly that case. The raw session token comes back beside the
    // *Session, never on it (Session has no Token field).
    session, sessionToken, err := auth.IssueSessionUnchecked(ctx, user.ID, sulis.AuthMethodPassword)
    return finish(user, session, sessionToken, err)
}

// First factor passed; hold a pending token instead of a session.
pending, err := auth.CreateTwoFactorToken(ctx, user.ID)
if err != nil {
    return err
}
// Return `pending` to the client (e.g. in a short-lived, httpOnly value) and
// prompt for a second factor. Persist user.ID server-side (e.g. keyed by
// `pending`) so the follow-up request doesn't have to trust the client for it.

// On the follow-up request:
if err := totpSvc.Validate(ctx, user.ID, submittedCode); err != nil {
    // totp.ErrTOTPInvalid (wrong code), totp.ErrTOTPNotEnrolled,
    // totp.ErrTOTPNotVerified, totp.ErrTOTPReplayed, or
    // totp.ErrTOTPRateLimited; consider falling back to a recovery code.
    remaining, rerr := recoverySvc.Consume(ctx, user.ID, submittedRecoveryCode)
    if rerr != nil {
        return rerr // recovery.ErrCodeInvalid or recovery.ErrCodeRateLimited
    }
    // A recovery code is a full bypass of every other factor. Your app,
    // not recovery, must now revoke the user's other sessions, and once
    // remaining reaches 0, push them to re-enroll a real second factor —
    // see "Recovery codes and the 2FA lifecycle" under the recovery
    // subpackage below.
    _ = remaining
}

// user.ID here comes from server-side state established above, never from
// the client's request. CompleteTwoFactor returns a *LoginResult, the same
// shape Login returns — the session and its raw token are fields on it.
res, err := auth.CompleteTwoFactor(ctx, user.ID, pending, ri)
if err != nil {
    return err
}
return finish(res.User, res.Session, res.SessionToken, nil)
```

### Email Verification

`CreateEmailVerificationToken(ctx, userID)` issues a single-use token proving control of the user's registered address (default TTL 24h), bound to that address: if the user's email changes before redemption, `VerifyEmail` rejects the stale token with `ErrTokenInvalid` rather than verifying the new address. `VerifyEmail(ctx, rawToken)` consumes it and stamps `User.EmailVerifiedAt`. Verification is idempotent — once set, `EmailVerifiedAt` is never overwritten by a later verification (e.g. a second magic-link redemption keeps the original timestamp). By default, an unverified `EmailVerifiedAt` also blocks new sessions elsewhere in the library — see [Operational requirements](#operational-requirements) for `RequireVerifiedEmail`.

The *first* time an account with a password gets verified (via either `VerifyEmail` or a redeemed magic link), all of that user's sessions are revoked unconditionally — regardless of `RevokeSessionsOnPasswordChange`. This closes a residual account-takeover window: an attacker who registered the victim's email with their own password before the victim ever proved mailbox control could otherwise keep a live session through the victim's later verification. Applications should additionally prompt for a password reset on this path, since the attacker's chosen password itself remains valid until changed.

### Changing an email address

An email address is an identity, and on most products it is also the reset channel — so changing one is an account-takeover primitive if it is done in a single step. `sulis` splits it in two.

`ChangeEmail(ctx, userID, newEmail)` **stages** the new address and returns a raw, single-use token to deliver to it. `User.Email` and `User.EmailVerifiedAt` are untouched; only `User.PendingEmail` is set. It returns `ErrInvalidEmail` for a malformed address and `ErrUserAlreadyExists` if `newEmail` is already the live address of any account, including this one. Staging a second address supersedes the first, invalidating the earlier token. The token expires after `EmailVerificationTokenDuration` (default 24h).

`ConfirmEmailChange(ctx, rawToken)` consumes the token and makes the staged address live: `Email` is swapped in from `PendingEmail`, `PendingEmail` is cleared, and **`EmailVerifiedAt` is re-stamped with a fresh timestamp** — the old stamp proved control of the old address, not this one. The swap also **revokes every session on the account and purges its outstanding password-reset and two-factor tokens**, since both were minted against (or reachable through) the identity that just changed. It returns `ErrTokenInvalid` if the token is unknown, expired, already used, of the wrong purpose, or bound to an address that is no longer the account's `PendingEmail` (a later `ChangeEmail` superseded it), and `ErrUserAlreadyExists` if another account claimed the staged address in the meantime.

**`sulis` sends no mail, and two of the notifications are not optional.** Deliver the token to the **new** address — that is what proves the requester can receive there. But you must also notify the **old** address, twice: once when a change is staged, and once when it is confirmed. That notification goes to an address the attacker does not control, and it is the only way a victim catches a takeover — the first while the pending change can still be undone, the second at least in time to start recovery.

Gate `ChangeEmail` behind [`RequireRecentAuth`](#step-up-authentication), not a bare session.

### Security events

Every security-relevant decision the root package makes can be reported to an `EventSink` — failed logins, limiter trips, second-factor demands, session issuance and expiry, password rehashes, magic-link rejections, account disables. Nothing is emitted by default.

Wiring it up is one line if you already have a `*slog.Logger`:

```go
auth, err := sulis.New(users, sessions, tokens, factors,
    sulis.WithEventSink(sulis.NewSlogSink(logger)))
```

Or implement the interface yourself:

```go
type EventSink interface {
    Emit(ctx context.Context, e sulis.Event)
}
```

`Emit` returns nothing, on purpose: **a sink cannot fail a flow.** There is no error to propagate and none to ignore. Emissions happen *after* the decision they report, never before, so an event records what already happened rather than announcing what is about to. A sink that panics is contained (recovered and dropped) rather than allowed to unwind the flow — an observability hook must not be able to deny authentication to everybody — but don't build on that: `Emit` runs on the caller's goroutine and inside the caller's latency budget, so hand the event to a channel, a logger, or a buffer and return.

With no sink configured the cost is one nil check per decision point: nothing is allocated, no timestamp is read. That is a tested claim rather than an aspiration — `Event.Metadata` is built inside the emission helper *after* the nil check, from variadic labels, precisely because a map built at the call site would be allocated whether or not anybody was listening, and `TestNilSinkPathAllocatesNothing` measures it.

#### What an event contains — and what it never contains

```go
type Event struct {
    Kind        EventKind
    UserID      string                 // when known
    SessionID   string                 // when relevant
    RequestInfo RequestInfo            // what you passed to the flow
    At          time.Time
    Metadata    map[MetadataKey]string // reason / method / scope / dimension
}
```

**No event ever carries credential material.** There is deliberately no field that could hold one — no token, no password, no hash, no nonce. Beyond that, the package never copies *any* caller-supplied string into an event except the `RequestInfo` you explicitly passed. In particular an event never carries:

- a raw password, session token, reset/magic-link/two-factor/email token, or magic-link binding nonce;
- a stored password hash or session token hash;
- **the submitted email address** — people type passwords into the email field, and an event taxonomy that copies caller input is one bad day away from being a credential log;
- the operator-supplied `reason` you passed to `DisableUser`, for the same reason.

Accounts are identified by `UserID` and sessions by `SessionID`: opaque identifiers sulis generated, neither of which authenticates anything on its own. The rule is enforced by test, not only by convention — `TestNoEventCarriesSecretMaterial` drives every emitting flow and scans every field of every emitted event against every secret those flows were fed, and a companion test proves the scanner catches a planted one.

`Metadata` has a closed key set — `MetaReason`, `MetaMethod`, `MetaScope`, `MetaDimension` — whose values are short fixed labels chosen by sulis (the `Reason*`, `Scope*`, and `Dimension*` constants), never error text and never caller input.

#### The taxonomy

| Kind | Emitted when | Metadata |
|---|---|---|
| `account.registered` | `Register` created an account | — |
| `login.succeeded` | a password verified (**not** "a session exists" — a second factor may follow) | `method` |
| `login.failed` | an authentication attempt was refused | `reason`, `method` |
| `password.changed` | `ChangePassword` succeeded | — |
| `password.set` | `SetInitialPassword` succeeded | — |
| `password.reset_requested` | a reset token was issued (unknown addresses emit nothing) | — |
| `password.reset` | `ResetPassword` succeeded | — |
| `password.rehashed` | a stored hash was upgraded on successful verification | — |
| `password.rehash_failed` | that upgrade was attempted and lost | `reason` |
| `password.legacy_form_matched` | a password matched only via the pre-NFKC fallback | — |
| `twofactor.demanded` | a verified first factor earned a pending token, not a session | `method` |
| `twofactor.completed` | `CompleteTwoFactor` accepted the second factor | — |
| `twofactor.failed` | `CompleteTwoFactor` refused | `reason` |
| `session.issued` | a session row was created, by any path | `method` |
| `session.revoked` | one or all of an account's sessions were deleted | `scope` |
| `session.refreshed` | `RefreshSession` rotated a token | `method` |
| `session.expired` | `ValidateSession` rejected a session past `ExpiresAt` | `reason` |
| `session.idle_expired` | `ValidateSession` rejected a session past `IdleExpiresAt` | `reason` |
| `email.change_staged` | `ChangeEmail` staged an address and issued a token | — |
| `email.change_confirmed` | `ConfirmEmailChange` made a staged address live | — |
| `email.verified` | an address was verified for the first time | — |
| `magiclink.created` | `CreateMagicLinkToken` issued a link | — |
| `magiclink.redeemed` | a link's token and binding nonce both checked out | — |
| `magiclink.rejected` | `RedeemMagicLink` refused | `reason` |
| `ratelimit.tripped` | the configured `Limiter` denied a key | `scope`, `dimension` |
| `account.disabled` | `DisableUser` stamped the account | — |
| `account.enabled` | `EnableUser` cleared it | — |
| `account.locked` | automatic lockout set or extended a deadline | — |
| `account.lockout_cleared` | a correct password cleared stale lockout bookkeeping | — |
| `reauth.succeeded` | `ReAuthenticate` refreshed the step-up clock | — |
| `reauth.failed` | `ReAuthenticate` refused | `reason` |
| `csrf.rejected` | `(*Sulis).RequireCSRFToken` refused a request | `reason` |
| `sameorigin.rejected` | `(*Sulis).RequireSameOrigin` refused a request | `reason` |

A few of these repay watching directly:

- **`password.legacy_form_matched`** is what makes retiring the pre-NFKC verification fallback answerable. When it stops appearing for your deployment, every account has migrated and the fallback can go — without it, the fallback would have to stay forever on the grounds that nobody can prove it's unused.
- **`password.rehash_failed`** is the *only* trace a lost hash upgrade leaves. The failure is deliberately swallowed so it can't fail an otherwise-correct login (see [Rehash on login](#login-and-verifypassword)), which means without this event a store quietly refusing every upgrade would be invisible.
- **`magiclink.rejected` with `reason=binding_mismatch`** means a genuine token was presented by a browser other than the one that asked for the link: forwarded, prefetched, or stolen.
- **`ratelimit.tripped`** distinguishes `dimension=account` from `dimension=ip`. One account being guessed and one host spraying many accounts are different incidents, which is why the two keys exist.
- **`login.failed` with `reason=factor_check_failed`** means your `SecondFactorChecker` errored and sulis failed closed. Correct behaviour, invisible without this.

#### Middleware and events

`RequireCSRFToken` and `RequireSameOrigin` exist both as package-level functions and as methods on `*Sulis`. The behaviour is identical; only the methods can emit, because a free function has no configured sink to emit to. Use the methods if you want rejections observable:

```go
mux.Handle("/api/", auth.RequireSameOrigin(origins)(auth.RequireCSRFToken(handler)))
```

These are the one place sulis derives a `RequestInfo` itself, from `r.RemoteAddr` and `User-Agent`. **That address is the transport peer**: behind a reverse proxy it is the proxy, not the client. sulis does not read `X-Forwarded-For` or any other hop header, because which of them to trust is a deployment fact no library can know and guessing wrong means trusting an attacker-supplied address.

#### Scope

This taxonomy (`EventKind`/`Event`/`EventSink`/`WithEventSink`) covers the root package only. `totp` and `passkey` have their own services and stores and do not emit events. `recovery` is the one exception: it ships its own, independent `EventKind`/`Event`/`EventSink`/`WithEventSink` — see "Recovery codes and the 2FA lifecycle" under the `recovery` subpackage below for its three-kind taxonomy and for why it can't just reuse this one. `Authenticate`'s 401 is not its own kind either — the decisions behind it (`session.expired`, `session.idle_expired`) already emit, and a kind for "a request arrived with no valid token" would make this a request log rather than a security-decision log.

## Subpackages

### `totp`

`totp` implements RFC 6238 TOTP without external dependencies. `NewService(store, issuer, opts...)` returns an error if the resolved config is out of bounds (empty/`:`-containing issuer, digits outside 6-8, period outside 15-300s, skew above 4, or secret size below 16 bytes).

It supports enrollment (`Enroll`, pending until `ConfirmEnrollment`), explicit replacement (`ReplaceEnrollment`), validation (`Validate`), unenrollment (`Unenroll`), configurable HMAC algorithms (`SHA1`, `SHA256`, `SHA512`), configurable digit/period/skew settings, and `otpauth://` URI generation for authenticator apps.

`Validate(ctx, userID, code) error` returns nil if and only if the code is valid; every rejection is a distinct, non-nil error, so a caller that only checks `err != nil` before granting access rejects a wrong code correctly. A wrong code returns `ErrTOTPInvalid`, distinguishable via `errors.Is` from the other rejections below.

`Validate` and `ConfirmEnrollment` enforce replay protection: each accepted code's time-step counter is persisted as `Credential.LastUsedCounter`, and a code is only accepted if its counter is strictly greater than the last one accepted for that credential. Reusing a code, or presenting an older one after a newer counter has already been accepted, returns `ErrTOTPReplayed`.

**A stray `Enroll` call cannot clobber a working factor.** `totp.Store` keeps a user's active (verified) credential and a pending (unverified) enrollment as two separate slots. `Enroll` refuses with `ErrTOTPAlreadyEnrolled` if the user already has an active credential — a double-submitted form, a CSRF'd POST, or a retried request must not be able to silently replace a confirmed second factor with an unconfirmed one. `ReplaceEnrollment(ctx, userID, accountName) (secret, uri string, err error)` is the explicit path for superseding an active factor on purpose: it always succeeds, and the old factor stays active — `Validate` keeps accepting its codes — until `ConfirmEnrollment` verifies a code for the new secret and promotes it. A pending enrollment sitting unconfirmed never affects `Validate` against the active credential.

`ConfirmEnrollment` promotes the pending enrollment to active atomically (`Store.ConfirmEnrollment`), carrying `LastUsedCounter` forward monotonically: if an active credential already existed (a replacement is being confirmed), the promoted credential's counter is never set lower than what the replaced factor had already recorded, so swapping factors can't roll a user's replay-protection clock backward.

**A confirm retry looks like `ErrTOTPNotEnrolled`, not success.** Once `ConfirmEnrollment` promotes a pending enrollment, that slot is consumed exactly once. A double-submitted confirmation form, or a dropped HTTP response after the server already committed the promotion, means a second call with the same code finds nothing pending and also returns `ErrTOTPNotEnrolled` — even though the user is enrolled and the first call's factor is active and working. Don't render that error as "you are not enrolled"; check current status (e.g. via your own record of enrollment, or by attempting `Validate`) before reacting to a confirm retry.

`totp.WithLimiter` configures a rate limiter (structurally identical to the root `Limiter` interface, declared separately so this package has no dependency on the root module) consulted by both `Validate` and `ConfirmEnrollment`, keyed by `"totp:"+userID`. A denied check returns `ErrTOTPRateLimited`. This is not optional in production: a 6-digit code is a 10^6 space, brute-forceable without a limiter.

Enrollment changes a security-relevant setting for the account: gate `Enroll`/`ReplaceEnrollment` behind `RequireRecentAuth` — see [Step-up authentication](#step-up-authentication) — rather than a bare session.

The package depends on a consumer-owned `totp.Store` for saving and loading TOTP credentials — see [Store Contracts](#store-contracts) below for the active/pending separation and its atomicity requirements.

#### Encrypting stored secrets

**By default, `Credential.Secret` reaches your store as base32 plaintext.** Unlike a password hash, a TOTP secret has no work factor standing between a leak and its use: whoever reads it can generate valid codes for that account indefinitely, silently, with no way to detect or revoke the compromise short of re-enrollment. This is fine for a throwaway store in tests, and not something you should ship to production unencrypted.

`totp.WithEncryptor(e Encryptor)` fixes this from inside the package, so the protection does not depend on your store implementation at all:

```go
enc, err := totp.NewAESEncryptor(key) // key: 32 bytes, AES-256
svc, err := totp.NewService(store, "MyApp", totp.WithEncryptor(enc))
```

`Service` encrypts a secret before every write (`Enroll`, `ReplaceEnrollment`, `Validate`'s replay-counter bump) and decrypts it immediately after every read (`ConfirmEnrollment`, `Validate`) — entirely inside this package. Your `totp.Store` implementation never receives, persists, or reads back a usable secret; `Credential.Secret` is still just a string either way, so no store contract, schema, or column type needs to know encryption exists. Nothing in [Store Contracts](#store-contracts) changes.

`NewAESEncryptor` implements `Encryptor` with AES-256-GCM: a random 96-bit nonce on every `Encrypt` call, and a key-ID fingerprint (derived from the key itself, not assigned or positional) prefixed onto the ciphertext so `Decrypt` knows which key produced it. **Key rotation:**

```go
// Today: everything is encrypted under keyA.
enc, _ := totp.NewAESEncryptor(keyA)

// Rotating in keyB: it becomes current for all new Encrypt calls; keyA is
// kept only so ciphertext already written under it keeps decrypting.
enc, _ := totp.NewAESEncryptor(keyB, keyA)
```

There is no in-place "re-encrypt everything" step — like the rehash-on-login upgrade path for Argon2 parameters, a secret only actually moves onto the new key the next time `Service` writes it (a fresh enrollment, or `Validate`'s counter bump), not immediately on rotation. Once you're confident nothing still needs a retired key, drop it from the `rotated` list.

**Decryption fails closed.** A wrong key, a truncated ciphertext, an unrecognized key-ID, or a tampered payload all return a non-nil error from `Decrypt` — never a plausible-looking but wrong plaintext. `Service` propagates that error distinctly from `ErrTOTPInvalid`/`ErrTOTPNotEnrolled`: a decrypt failure means the enrollment genuinely exists but this instance's `Encryptor` cannot recover its secret (most likely a missing rotated key), which is a different problem from a wrong code or no enrollment at all and should be alerted on differently.

**Turning on `WithEncryptor` for the first time on an existing deployment does not silently break, and does not silently do nothing.** Rows enrolled before an `Encryptor` was configured are still base32 plaintext; `AESEncryptor.Decrypt` never mistakes that for its own ciphertext — depending on the stored secret's length, it fails either at base64 decoding or (for the default 20-byte secret size, whose base32 alphabet happens to also be valid base64) because the bytes it reads as a key-ID fingerprint were never registered by any configured key. Either way, the next `ConfirmEnrollment` or `Validate` call against that enrollment fails closed with a distinct, non-nil error rather than reading the row as plaintext or as a wrong code. There is no automatic migration: the recovery path for a pre-`Encryptor` enrollment is re-enrollment (`ReplaceEnrollment`), the same as recovering from a lost authenticator.

Bring your own `Encryptor` (a KMS or HSM-backed one, for instance) by implementing the two-method interface directly; `AESEncryptor` is provided because it needs nothing beyond the standard library, not because it's the only option.

### `passkey`

**User verification is required by default.** `NewService` sets `UserVerification: required` on the relying-party config and on both login ceremonies. This matters because go-webauthn only checks the UV flag in the authenticator data when the ceremony's session data says `required` — leaving it unset means a presence-only tap (no PIN, no biometric) is accepted, which reduces a passwordless passkey from two factors to bare possession of an unlocked device.

Pass `passkey.WithUserVerification(protocol.VerificationDiscouraged)` only when the passkey is a **second** factor behind a verified password.

**Registration requests a discoverable credential by default.** `NewService` also sets `ResidentKey: required` (plus the legacy `RequireResidentKey` boolean, for authenticators that predate the `residentKey` enum) on the relying-party config, and `BeginRegistration` asks for the `credProps` extension. Without this, `BeginDiscoverableLogin` (usernameless login) only works when an authenticator happens to create a discoverable credential anyway, and the fallback to identified login trains users back onto typing a username. Pass `passkey.WithResidentKey(protocol.ResidentKeyRequirementPreferred)` (or `...Discouraged`) only if you don't offer usernameless login and every caller of `BeginLogin` always supplies a username first.

`FinishRegistration` records what the client actually reported, not just what was requested: `Credential.Discoverable` is populated from the client's `credProps.rk` extension output. This is a client-reported (unsigned) signal, not a cryptographic property of the credential — an older browser or authenticator may omit `credProps` entirely even for a credential that is, in fact, discoverable, in which case `Discoverable` is recorded as `false` (see the field's GoDoc for the full caveat).

`passkey` wraps `github.com/go-webauthn/webauthn` to provide higher-level passkey registration and login helpers. It manages begin/finish WebAuthn ceremonies, persists credentials through a consumer-owned `passkey.Store`, and persists transient ceremony state through a consumer-owned `passkey.ChallengeStore`.

Besides the identified `BeginRegistration`/`FinishRegistration` pair (which requires the caller to already know the user), `passkey` supports **discoverable ("usernameless") login**: `BeginDiscoverableLogin(ctx)` returns the assertion options plus a `ceremonyID` that the caller must round-trip to `FinishDiscoverableLogin(ctx, ceremonyID, r)`. The user is resolved from the credential's stored owner (via the authenticator's user handle), not supplied by the caller.

`BeginLogin(ctx, user)` (the identified, non-discoverable login path) likewise returns `(*protocol.CredentialAssertion, string, error)` — an assertion plus a `ceremonyID` — and `FinishLogin(ctx, user, ceremonyID, r)` takes that ceremony ID back. The challenge is keyed per-ceremony rather than per-user so that a second login ceremony for the same user (e.g. started from another device) cannot clobber the first device's in-flight challenge.

Both finish paths reject a credential flagged with a sign-count anomaly by returning `ErrCloneWarning` — treat this as a signal of possible credential cloning, not a routine auth failure. On success, `FinishLogin`/`FinishDiscoverableLogin` persist the updated sign count, backup state, and `LastUsedAt`, then return the stored `Credential`; `passkey` does not create a `sulis` session for you. A finished passkey ceremony is verified entirely inside `passkey`, so `sulis` has no `Authentication` proof to offer for it — call `IssueSessionUnchecked(ctx, userID, sulis.AuthMethodPasskey)` (directly or via the two-factor flow) after a successful finish.

**Credential metadata for a management UI.** Besides the fields already covered above, `Credential` carries `Name` (caller-supplied display metadata — `passkey` never generates or validates it; set it via `Store.RenameCredential`), `Transports` (the client's reported transport list — `"usb"`, `"nfc"`, `"ble"`, `"hybrid"`, `"internal"` — from the registration response, persisted once at registration and not re-verified afterward), `BackupEligible` (whether the authenticator is capable of being backed up/synced, a verified property derived from the signed authenticator data), `BackupState` (whether the credential is *currently* backed up — unlike `BackupEligible` this can flip over the credential's lifetime, so it is re-derived and re-persisted on every successful login, not only set at registration), and `LastUsedAt` (nil until the credential's first post-registration login; registering a credential is not "using" it).

`BackupEligible`/`BackupState` are not just descriptive: go-webauthn's own login verification compares the credential's stored `BackupEligible` bit against the fresh assertion's bit on every login and rejects a mismatch with "Backup Eligible flag inconsistency detected". `passkey` feeds the persisted flags back into every ceremony's credential list for exactly this reason — a store that returns stale or zero-valued flags from `GetCredentialsByUserID`/`GetCredentialByID` will cause later logins for a genuinely backup-eligible credential to fail this check.

**Deleting credentials requires an explicit decision about the last one.** `passkey` cannot see whether a `sulis` account has a password or another second factor — it only knows its own credential count for a user — so `Service.DeleteCredential(ctx, userID, id string, opts DeleteOptions)` rejects removing a user's only remaining credential with `ErrLastCredential` unless `opts.AllowLast` is set. Set `AllowLast` only after your application has independently confirmed, through its own re-authentication or explicit confirmation flow, that the account will remain reachable once this credential is gone. `id` here is the store's own `Credential.ID`, not the raw WebAuthn `Credential.CredentialID`.

The guard itself lives in `Store.DeleteCredential(ctx, userID, id string, allowLast bool)`, not in `Service` — `Service.DeleteCredential` is a thin wrapper. This matters for your `Store` implementation: the membership check ("does `id` belong to `userID`?"), the remaining-count check, and the removal **must** happen as a single atomic operation with respect to any concurrent call for the same `userID` — the same requirement `ChallengeStore.ConsumeChallenge`, `TokenStore.ConsumeToken`, and `recovery.Store.ConsumeCode` already place on their own check-and-mutate operations. Without that atomicity, two concurrent calls deleting a user's last two credentials (one ID each) could each read the pre-deletion count before either delete lands, both pass the guard, and both succeed — leaving the user with zero credentials, exactly the lockout state the guard exists to prevent, reached *through* the guarded path. For SQL, run the count check and the `DELETE` in one transaction after locking the user's credential rows (`SELECT ... FOR UPDATE`), or express both in a single statement; a mutex-guarded in-memory store can simply perform the check and the removal while holding the same lock. `Store.DeleteCredentialsByUserID` (for removing every credential a user has, e.g. as part of deleting the account) applies no such guard — deleting a whole account is a stronger, presumably already-gated action.

Challenge/session keys are ceremony-scoped (`"register:<userID>"`, `"login:<ceremonyID>"`, `"discover:<ceremonyID>"`) so concurrent ceremonies can't clobber each other's saved challenge. Each of the three finish paths consumes its challenge via `ChallengeStore.ConsumeChallenge` — an atomic fetch-and-delete — **before** running verification, so only one caller can ever receive a given challenge, and a failed verification still burns it (the safe direction: a rejected ceremony can't be retried against session data an attacker may have observed). A `passkey.ChallengeStore` should expire entries after roughly 5 minutes, matching the lifetime of a WebAuthn ceremony.

**Ceremony response bodies are size-capped.** go-webauthn's own body decoding (`protocol.decodeBody`) is a bare `json.NewDecoder(body).Decode(v)` with no limit, so an attacker who can reach a finish endpoint could otherwise send an arbitrarily large body and have it read fully into memory before any validation runs. `passkey.WithMaxCeremonyBody(max int64)` caps this (default 64 KiB); a larger body is rejected with `ErrCeremonyBodyTooLarge` up front, before the challenge is consumed or any JSON parsing happens. The `*http.Request` methods (`FinishRegistration`, `FinishLogin`, `FinishDiscoverableLogin`) are thin wrappers that read `r.Body` through `http.MaxBytesReader`, so the cap stops the read itself rather than buffering an oversized body first and rejecting it afterward. `passkey`'s core no longer imports `net/http` at all — it works from `[]byte` via `FinishRegistrationResponse`, `FinishLoginResponse`, and `FinishDiscoverableLoginResponse`, which non-`net/http` callers (or callers who parse the body some other way) can call directly, subject to the same cap.

### `passwordcheck`

`passwordcheck` holds the checkers behind [Password quality](#password-quality): `NewBlocklist(extra ...string)` over an embedded common-password corpus, `NewHIBP(opts...)` for the k-anonymous Have I Been Pwned range API, and `All(checkers...)` to run several in order and stop at the first rejection. `ErrCompromised` is the *same* error value the root package exports as `sulis.ErrPasswordCompromised`, so `errors.Is` matches under either name — the sentinel lives here because the root package's default configuration constructs a `Blocklist`, and an import the other way would be a cycle.

`Checker` there and `sulis.PasswordChecker` here are the same method set, so anything written against either interface satisfies both. A checker used outside sulis is handed whatever its caller passes; sulis always hands it the NFKC-normalized password.

### `recovery`

`recovery` implements one-time recovery codes as a fallback second factor for when a user loses their TOTP device or passkey. `NewService(store, opts...)` defaults to generating 10 codes (`WithCount` to change it); each code is 10 bytes of `crypto/rand`, base32-encoded and displayed as `xxxx-xxxx-xxxx-xxxx`.

`Generate(ctx, userID)` atomically replaces the user's entire code set and returns the plaintext codes for one-time display — only their SHA-256 hashes are persisted, so the plaintext cannot be recovered later. `Consume(ctx, userID, code) (remaining int, err error)` normalizes the input (case, whitespace, and dash-grouping insensitive) and atomically consumes a single matching code, returning how many unused codes are left afterward, or `ErrCodeInvalid` (`remaining` is always 0 on error) if none matches. `Remaining(ctx, userID)` reports the unused count without consuming anything. `Disable(ctx, userID)` removes all codes for a user — see "Recovery codes and the 2FA lifecycle" below for its second job.

`recovery.WithLimiter(l Limiter)` configures a rate limiter Consume consults, keyed by `"recovery:"+userID`, before it ever hashes or looks up the submitted code — the interface is structurally identical to the root package's `Limiter` and `totp.Limiter` (`Allow(ctx, key) error`), so a single `sulis.MemoryLimiter` instance guards all three. A denied attempt returns `ErrCodeRateLimited`. The default (no limiter) is unchanged from before this option existed — recovery codes are 80 bits of `crypto/rand`, far larger than a TOTP code's 10^6 space, but still a value worth throttling if you don't already rate-limit this endpoint at another layer.

#### Recovery codes and the 2FA lifecycle

`recovery` only validates and consumes a code — it has no session store, no notification mechanism, and no idea what your product looks like, so it cannot do the following three things for you. A real integration should do all three itself, immediately after a successful `Consume`:

1. **Revoke every other active session for the user** (e.g. the root package's `RevokeAllSessions`). A recovery-code login means the primary factor was lost, so a session an attacker already holds should not survive it — the same reasoning behind `sulis`'s own session revocation on a password change.
2. **Record the event somewhere auditable.** `recovery.WithEventSink(sink)` routes `EventCodeConsumed` (carries the new `Remaining` count), `EventCodeRejected`, and `EventCodesExhausted` (emitted alongside `EventCodeConsumed` when `Remaining` hits 0) to an `EventSink` you configure — `Emit(ctx, Event)`, same shape as the root package's `EventSink`, but **not** wire-compatible with it: `Event`'s payload is a distinct type per package, so (unlike `Limiter`) one implementation cannot satisfy both interfaces. Write a small adapter if you want one unified event stream. As with the root taxonomy, no event field can hold the code or its hash.
3. **Push the user toward re-enrolling a real second factor**, especially once `Consume`'s returned `remaining` reaches 0 (also reported as `EventCodesExhausted`). Recovery codes are a bridge back to a working TOTP credential or passkey, not a permanent substitute for one.

Symmetrically, when the user's **last other second factor is removed** (their only TOTP credential unenrolled, their last passkey deleted), call `Disable(ctx, userID)` to purge whatever recovery codes are left over — a recovery code that outlives the factor it was meant to back up is no longer a fallback, it's the account's *only* remaining guard, silently. `recovery` cannot detect this moment itself (it has no visibility into `totp.Store` or `passkey.Store`), so this call is the calling application's responsibility, at the same point it would otherwise disable the 2FA setting on the account.

## Store Contracts

`sulis` does not ship a database layer. Consumers own persistence and implement these interfaces:

- `UserStore`: create, fetch, update, and delete users by ID/email. `UpdateUser` must apply the write **only** if the stored row's `version` still equals `user.Version`, incrementing it on success and returning `ErrConcurrentUpdate` otherwise:

  ```sql
  UPDATE users SET ..., version = version + 1
   WHERE id = $1 AND version = $2
  ```

  Zero rows affected means another writer won. Without this check, two flows that each read-modify-write the whole row can clobber each other, and the dangerous direction restores a password hash the user just rotated away from — silently undoing a reset. The library reloads and retries on `ErrConcurrentUpdate`, so a correct store makes the race invisible to callers. `User`'s disable/lockout fields (`DisabledAt`, `DisabledReason`, `LockedUntil`, `FailedLoginAttempts`; see [Account disable and lockout](#account-disable-and-lockout)) are ordinary fields on the same struct — no new `UserStore` method was needed for them, the same way `Version` was chosen in the first place so future fields would not force interface churn. `DisabledAt`/`LockedUntil` are pointers, so they fall under the no-aliasing rule below alongside `EmailVerifiedAt`.
- `SessionStore`: create sessions, load them by token-hash lookup, list a user's sessions, revoke one session, revoke all (or all-but-one) sessions for a user, and `CleanExpired`. `CleanExpired` is never called by the library itself — see [Operational requirements](#operational-requirements). `DeleteSession(ctx, userID, id)` **must** scope its delete to both columns (`DELETE FROM sessions WHERE id = ? AND user_id = ?`) and return `ErrSessionNotFound` on zero rows affected — whether `id` doesn't exist at all, or exists but belongs to a different user. This is what makes `RevokeSession` safe to expose directly to a session-management UI: it always passes the caller's own `userID`, so a guessed or leaked session ID belonging to someone else is indistinguishable from a nonexistent one. `DeleteUserSessionsExcept(ctx, userID, keepSessionID)` is the same "sign out everywhere else" shape as a single query (`DELETE FROM sessions WHERE user_id = ? AND id <> ?`); `keepSessionID` matching nothing is not an error, since every *other* session for `userID` still counts as removable. `ListUserSessions(ctx, userID)` returns full `Session` values, `TokenHash` included — the same as `GetSessionByTokenHash` — since blanking it is `Sulis.ListUserSessions`'s job, not the store's; see [Session visibility and lifecycle](#session-visibility-and-lifecycle).

  `UpdateAuthenticatedAt(ctx, id, at)` stamps a single session's `AuthenticatedAt`, leaving every other column untouched:

  ```sql
  UPDATE sessions SET authenticated_at = $2 WHERE id = $1
  ```

  Zero rows affected (`id` unknown) **must** return `ErrSessionNotFound`. This is `ReAuthenticate`'s write path — see [Step-up authentication](#step-up-authentication).

  `TouchSession(ctx, id, lastSeen, idleExpires)` stamps `LastSeenAt`/`IdleExpiresAt` together, leaving every other column untouched:

  ```sql
  UPDATE sessions SET last_seen_at = $2, idle_expires_at = $3 WHERE id = $1
  ```

  `idleExpires` is nil whenever `WithIdleTimeout` isn't configured; a nil value **must** be written as SQL `NULL`, clearing any previously-stored deadline — an application that enables idle expiry and later disables it again must not have a stale deadline linger. Zero rows affected **must** return `ErrSessionNotFound`. This is `ValidateSession`'s throttled liveness-touch write path — see [ValidateSession](#validatesession) for the throttle. `TouchSession` is deliberately its own method rather than an extra parameter folded onto `UpdateAuthenticatedAt`: a step-up re-authentication and a liveness heartbeat are different events from different callers at very different frequencies, and one method serving both would let a caller that means to refresh only one silently refresh the other too.
- `TokenStore`:
  - `CreateToken` persists a new token.
  - `ConsumeToken(ctx, hash, purpose)` must atomically find the unused token matching hash **and** purpose and mark it used in one operation (e.g. `UPDATE ... WHERE hash=? AND purpose=? AND used=false`), returning `ErrTokenNotFound` if nothing matches and `ErrTokenAlreadyUsed` if it was already consumed. Lookup and mark-used are not allowed to be separate steps — that would open a race where two concurrent redemptions both succeed.
  - `DeleteExpiredTokens(ctx)` deletes expired tokens; also never called by the library itself.
  - `DeleteUserTokens(ctx, userID, purpose)` deletes all of a user's tokens for a given purpose (deleting zero is not an error) — used internally to purge outstanding password-reset tokens after a successful reset/change.
- `totp.Store`: keeps a user's active (verified) credential and pending (unverified) enrollment as two separate slots, at most one of each. `GetActiveTOTP`/`GetPendingTOTP` fetch each slot (`ErrTOTPNotEnrolled` if empty). `EnrollPending` atomically checks that no active credential exists before storing cred as the new pending enrollment — the check and the write **must** be one atomic operation, or a concurrent `ConfirmEnrollment` could promote a different pending enrollment to active in the gap between them — and returns `ErrTOTPAlreadyEnrolled` otherwise; `ReplacePending` is the same write without that guard, for `ReplaceEnrollment`'s explicit supersession. `ConfirmEnrollment(ctx, userID, pendingID, counter)` atomically promotes the pending enrollment to active **only if** it is still the exact one named by `pendingID` (a compare-and-swap against a concurrent `EnrollPending`/`ReplacePending`), carrying `LastUsedCounter` forward to whichever is greater of `counter` and the previously-active credential's counter, and returns `ErrTOTPNotEnrolled` if `pendingID` no longer matches. `SaveTOTP` persists updates to the existing active credential (in practice, `Validate`'s counter bump) and must persist `LastUsedCounter` atomically with respect to concurrent `Validate` calls, rejecting any save that would lower it for the same credential ID, so two racing validations can't both accept the same (or an older) counter. `DeleteTOTP` removes both slots.
- `passkey.Store`: save passkey credentials, list credentials for a user, fetch a credential by WebAuthn credential ID, delete all of a user's credentials, and rename a credential (`RenameCredential` returns `ErrPasskeyNotFound` for an unknown ID). `UpdateCredentialAfterLogin` persists sign count, backup state, and `LastUsedAt` together in one call — go-webauthn's own storage guidance says sign count, clone-warning, and backup state must be written back on every successful login so the next ceremony observes current values, and bundling them keeps that invariant from being split across calls a caller could apply out of order or only partially. `DeleteCredential(ctx, userID, id string, allowLast bool)` **must** perform its membership check, its remaining-credential-count check, and the removal as a single atomic operation — see [`passkey`](#passkey) above for why a non-atomic implementation reopens the exact lockout race the guard exists to prevent.
- `passkey.ChallengeStore`: `SaveChallenge` stores the temporary WebAuthn session data used between begin/finish calls, keyed per-ceremony (see above) with a ~5-minute TTL. `ConsumeChallenge(ctx, key)` must atomically fetch **and** delete that data in one operation (e.g. Redis `GETDEL`, or SQL `DELETE ... RETURNING`) — the same race concern as `ConsumeToken`: a separate get-then-delete lets two concurrent finishes of the same ceremony both read the challenge before either removes it, so both proceed past the "expired" check.
- `recovery.Store`: `ReplaceCodes` atomically swaps a user's full code set; `ConsumeCode` must atomically find-and-delete a matching hash (same race concern as `ConsumeToken`), returning `ErrCodeNotFound` if absent; `CountCodes`; `DeleteCodes`.

These stores are part of the security boundary. They should enforce uniqueness where needed and persist enough data for expiry and revocation. Only some flows depend on specific sentinel errors from stores, such as `ErrUserNotFound`, `ErrUserAlreadyExists`, `ErrTokenNotFound`, and `recovery.ErrCodeNotFound`; other store errors are propagated or normalized by the service.

**No store may share mutable state with its callers, in either direction.** `User.Metadata` and `Session.Metadata` are maps and `User.EmailVerifiedAt`, `User.DisabledAt`, `User.LockedUntil`, and `Session.IdleExpiresAt` are each a pointer, so copying one of those structs with a plain `cp := *user` copies a map header and an address rather than the map and the time — which leaves the caller holding a live handle on the stored row and able to rewrite it without going through `UpdateUser` at all, stepping around the `Version` precondition rather than violating it. Copy the map (one level is enough; values inside it are the caller's business) and each pointed-to time both when storing and when returning. A store that reconstructs rows from a database read gets this for free; an in-memory or caching one does not. `storetest` checks it.

## Proving your stores correct

Everything above is prose, and none of it is checked by the compiler: a store that returns the wrong error, or splits an atomic check-and-mutate into a read followed by a write, satisfies every interface in this module and still breaks the guarantees the library is built on. The `storetest` package turns those contracts into an executable suite you run against your own implementation. It is supported public API, and it is the intended integration path — not an internal test helper.

```go
import (
    "testing"

    "github.com/borfast/sulis"
    "github.com/borfast/sulis/storetest"
)

func TestMyUserStore(t *testing.T) {
    storetest.RunUserStore(t, func() sulis.UserStore { return newMyUserStore(t) })
}
```

There is one `Run*` function per interface, all in the same shape:

| Interface | Suite |
| --- | --- |
| `sulis.UserStore` | `storetest.RunUserStore(t, factory)` |
| `sulis.SessionStore` | `storetest.RunSessionStore(t, factory)` |
| `sulis.TokenStore` | `storetest.RunTokenStore(t, factory)` |
| `passkey.Store` | `storetest.RunPasskeyStore(t, factory)` |
| `passkey.ChallengeStore` | `storetest.RunPasskeyChallengeStore(t, factory)` |
| `totp.Store` | `storetest.RunTOTPStore(t, factory)` |
| `recovery.Store` | `storetest.RunRecoveryStore(t, factory)` |

The factory must return a store observing no state from any earlier call — an empty database, a truncated schema, a fresh map. Every subtest calls it at least once and the concurrency subtests call it once per iteration, so make the reset cheap. Identifiers, addresses, and hashes the suite generates are unique per process run, and count assertions are always scoped to the users a subtest created, so a factory that can only truncate rather than recreate is still fine.

**Run it with `-race`.** The atomicity requirements are checked by racing goroutines through a shared start gate and asserting on the aggregate outcome: exactly one caller consumed the token, the user still has one passkey, the TOTP counter did not move backwards. Those subtests repeat many times, since a race that loses once proves nothing; pass `-short` to cut the iteration count when you are smoke-testing a slow store rather than certifying it. The suite asserts only on the documented contracts — never on storage, orderings the interfaces do not promise, or timestamp precision — so it is equally valid against SQL, key-value, and in-memory implementations.

`memstore` is the reference implementation: an in-memory version of every interface above, which passes the whole suite. It is worth reading before writing your own — each type shows where the atomic boundary has to be, with one mutex standing in for the transaction or conditional statement a database needs. It is also a working store for tests, examples, and local development:

```go
users := memstore.NewUserStore()
sessions := memstore.NewSessionStore()
tokens := memstore.NewTokenStore()
auth, err := sulis.New(users, sessions, tokens, sulis.NoSecondFactors{})
```

It is not for production: nothing survives a restart, nothing is shared between processes, and nothing is bounded except by the delete and cleanup methods.

## Security Notes

See [`SECURITY.md`](SECURITY.md) for how to report a vulnerability and the
supported-version policy, and [`docs/threat-model.md`](docs/threat-model.md)
for the full threat model — in-scope threats and their shipped mitigations,
what's explicitly out of scope, and known residual risks.

- `Token.TokenHash` stores a SHA-256 hash of a reset, magic-link, two-factor, or email-verification token. Raw tokens are returned once for delivery and should never be persisted. `Token.Email` is set for magic-link tokens issued before the user account exists, and for email-verification tokens (bound to the address they prove, so a later email change invalidates them); it is empty for password-reset and two-factor tokens.
- Session tokens are opaque bearer tokens. `SessionStore` implementations persist only `TokenHash` — `Session` has no `Token` field to accidentally persist; the raw token is returned beside the `*Session` at issuance (see `IssueSession`) and nowhere else — and perform `GetSessionByTokenHash` lookups against the hash of the presented session token rather than the raw token. `ValidateSession` likewise never returns the raw token to the caller.
- TOTP secrets (`totp.Credential.Secret`) and passkey public keys are handed to your stores as-is, **unless** you configure `totp.WithEncryptor` — see [Encrypting stored secrets](#encrypting-stored-secrets) — in which case your `totp.Store` only ever sees the configured `Encryptor`'s ciphertext. Recovery codes and all `sulis` tokens/sessions are hashed before your store ever sees them. See [Operational requirements](#operational-requirements) for what an unconfigured `Encryptor` implies for TOTP secrets specifically.
- Security events (`WithEventSink`) never carry credential material, stored hashes, submitted email addresses, or any other caller-supplied string beyond the `RequestInfo` you passed in — see [Security events](#security-events). Emission is best effort and cannot fail or slow a flow into failure; a sink that panics is contained.

## Operational requirements

These are things the library deliberately leaves to the consumer. Skipping them weakens the security properties described above.

**Rate limiting is on by default.** `sulis.New` installs an in-process `MemoryLimiter` — a token bucket that resists password guessing, reset flooding, and magic-link flooding without any wiring. It is consulted on two dimensions: per account (`"password:"+email`, `"reset:"+email`, `"magic:"+email`) and, when you pass a `RequestInfo` carrying an IP, per client address (`"password:ip:"+ip`, and so on). Per-account budgets are deliberately generous and per-IP budgets tight, so an attacker can neither rotate the email to escape throttling nor lock a victim out by exhausting the victim's own allowance.

The default is **per process**: with several instances behind a load balancer each enforces its own budget. Supply a shared implementation with `WithLimiter` for a multi-instance deployment — the interface is one method, `Allow(ctx, key) error`. `MemoryLimiter` also satisfies `totp.Limiter` and `recovery.Limiter` structurally, so one instance can guard all three; each subpackage's service still needs it passed explicitly, via `totp.WithLimiter`/`recovery.WithLimiter`, since neither imports the root package.

To turn throttling off — for instance when an upstream gateway already enforces limits — call `WithoutRateLimiting()`. That is deliberately a visible line of code rather than the consequence of not writing one.

Token-redemption calls (`ResetPassword`, `RedeemMagicLink`, `CompleteTwoFactor`, `VerifyEmail`) are deliberately **not** throttled: the guessable space there is a 256-bit random token, not a password or a six-digit code, so rate limiting does not meaningfully raise the cost of an attack. `recovery.Consume` has an 80-bit code space of its own — larger still — but, unlike these token-redemption calls, it does accept an optional `recovery.WithLimiter`, since a recovery code is meant to be a rarely-used fallback rather than a value a legitimate caller ever needs to present at volume.

**Schedule cleanup yourself.** `TokenStore.DeleteExpiredTokens` and `SessionStore.CleanExpired` exist so expired rows don't accumulate forever, but `sulis` never calls either — it runs no background workers. Run them on a periodic job (cron, a ticker goroutine, etc.). `ValidateSession` does delete a session it discovers is expired at validation time, but that's incidental to the read path, not a substitute for sweeping sessions and tokens that are never revisited.

**Cookie-mode `Authenticate` ships its own CSRF defenses — wiring them up is still yours to do.** `SessionCookie` always sets `HttpOnly`/`Secure`/`SameSite=Lax`/`Path=/` and a `__Host-`-prefixed name by default, `RequireSameOrigin` checks `Sec-Fetch-Site`/`Origin` on state-changing requests, and `IssueCSRFToken`/`RequireCSRFToken`/`VerifyCSRFToken` are a constant-time-compared double-submit token — see [Cookie sessions and CSRF](#cookie-sessions-and-csrf) for all of it, including the default `TokenSource` and the deliberate policy on requests that send neither `Sec-Fetch-Site` nor `Origin`. What's still on you: actually calling `SessionCookie`/`ClearSessionCookie` in your login/logout handlers, wrapping the routes that accept a cookie-sourced session in `RequireSameOrigin` and/or `RequireCSRFToken`, and rendering `IssueCSRFToken`'s value into your pages. None of this applies if you configure `WithTokenSource(TokenSourceBearerOnly)` and never call `SessionCookie` — a Bearer-only deployment was never CSRF-exposed.

**A `PasswordChecker` that reaches the network is your outbound dependency.** The default (`passwordcheck.NewBlocklist()`) makes no requests at all. Adding `passwordcheck.NewHIBP()` puts an HTTPS call to `api.pwnedpasswords.com` on the critical path of registration, password change, and password reset — allow it through egress filtering, watch its latency (it is bounded at 5s by default, on top of the Argon2 hash the user is already waiting for), and decide deliberately whether it fails open (the default) or closed. It is never on the login path.

**Configure `totp.WithEncryptor` before production.** By default, `totp.Service` hands your `totp.Store` a plaintext base32 secret (`Credential.Secret`) — there is no encryption unless you configure one. `totp.WithEncryptor(totp.NewAESEncryptor(key))` fixes this application-side, so a store implementation never needs its own envelope encryption to be safe: see [Encrypting stored secrets](#encrypting-stored-secrets) for the AES-256-GCM implementation, key rotation, and the fail-closed behavior on a wrong or missing key. Leaving it unconfigured means a database compromise hands an attacker every enrolled user's shared secret, usable to generate valid codes indefinitely and silently, with no work factor slowing that down the way Argon2 does for passwords.

**`CreatePasswordResetToken` cannot be used to enumerate registered addresses.** Like `Login`/`VerifyPassword`, it normalizes the unknown-address case away: an unregistered `email` returns `("", nil)`, the same shape a genuine issuance takes from the caller's perspective, rather than `ErrUserNotFound`. The unknown-address path also performs the same token generation and hashing work the known-address path does before discarding the result, so the two paths can't be distinguished by the work they perform either — only by a residual asymmetry this can't remove: the known-address path writes a token row and the unknown-address path never does, since there's no user to attach one to (the same kind of documented gap as `VerifyPassword`'s dummy-hash equalization — equal work, not a provable-equal-latency guarantee across a storage boundary). Your HTTP handler can safely return the same generic response ("if that address is registered, we've sent a reset link") unconditionally, with no flattening of its own required.

Admin tooling that has already authenticated an operator and genuinely needs to know whether an address is registered should call `CreatePasswordResetTokenStrict` instead, which returns `ErrUserNotFound` verbatim. Never wire it to a public-facing endpoint — that reopens the exact oracle `CreatePasswordResetToken` exists to close. (`CreateMagicLinkToken` doesn't have this problem at all: it never returns a not-found error, since it defers user creation to redemption.)

**Sessions are revoked on password change by default.** `RevokeSessionsOnPasswordChange` defaults to `true`, so both `ChangePassword` and `ResetPassword` delete every session belonging to the user (and purge any other outstanding password-reset tokens) as part of applying the new password. Pass `WithRevokeSessionsOnPasswordChange(false)` to opt out. Because this revokes the caller's own current session too, `ChangePassword` does not return a new one — call `IssueSessionUnchecked(ctx, userID, sulis.AuthMethodPassword)` yourself immediately afterward if you want the calling client to stay logged in; `ChangePassword` itself hands back no `Authentication`, so this is your application vouching that the same already-authenticated caller who just changed their password should stay signed in.

**New sessions are blocked for unverified accounts by default.** `RequireVerifiedEmail` defaults to `true`: `Login`, `IssueSession`, `IssueSessionUnchecked`, `CreateTwoFactorToken`, and `CompleteTwoFactor` all return `ErrEmailNotVerified` for an account whose `EmailVerifiedAt` is still nil. `Register`'s signup session and `RedeemMagicLink` (which verifies the email itself before issuing a session) are exempt. **If your application has no email verification flow wired up — no `CreateEmailVerificationToken`/`VerifyEmail`, and no magic links — you must pass `WithRequireVerifiedEmail(false)`**, or users will be able to register but never sign in again once their first session expires. Migration note: this is a behavior change for existing consumers — previously an unverified account could log in indefinitely. Either wire up verification (or magic links, which self-verify) or opt out explicitly.

## Versioning

sulis is pre-1.0 (`v0.x`) for the duration of the security-hardening plan (`docs/superpowers/plans/2026-08-17-security-hardening-v1/PLAN.md`) that closed the second-factor bypass, added the safe-by-default posture, and built the store-contract conformance suite, among everything else CHANGELOG.md's Unreleased entry lists. **Before 1.0, the public API can and does break between commits on this branch** — CHANGELOG.md's migration guide covers every break shipped so far, and there is no compatibility promise yet.

Once this plan completes and sulis tags `v1.0.0`, it adopts a [Go-1-style compatibility promise](https://go.dev/doc/go1compat) for the public API of `sulis`, `totp`, `passkey`, `recovery`, and `passwordcheck`: exported identifiers, exported types' exported fields, and documented behavior will not change incompatibly within the v1 line. A v1.x release only adds; it does not remove or repurpose anything already there, and only a v2 major version may break compatibility, following the usual Go convention of a `/v2` module path.

Two exceptions, stated up front so neither is a surprise later:

- **Store contracts may still evolve behind `storetest`.** `UserStore`, `SessionStore`, `TokenStore`, and each subpackage's `Store`/`ChallengeStore` interfaces are consumer-implemented; `storetest`'s conformance suite can still tighten a documented requirement that a compliant implementation already satisfies — the same kind of clarification this hardening pass made repeatedly (see the migration guide) — without that being a compatibility break for the interface's Go signature. It is still called out in the CHANGELOG when it happens, and a genuine signature change to a store interface is a v1-breaking change like any other.
- **`store/sql` is a separate module and versions independently.** `github.com/borfast/sulis/store/sql` (the SQLite and PostgreSQL reference implementations) is not covered by the root module's v1 promise above; it follows its own semver.

This is a compatibility promise, not a security-support policy — see [`SECURITY.md`](SECURITY.md) for which versions receive security fixes.
