# sulis

`sulis` is a small Go authentication library for consumer-owned persistence. The root package provides password-based auth, password reset, magic-link login, two-factor pending-login tokens, email verification, server-side sessions, and HTTP middleware for attaching the authenticated user and session to a request context. The `totp`, `passkey`, and `recovery` subpackages add TOTP, WebAuthn passkeys, and recovery codes as second factors or standalone credentials.

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
- `Register`, `Login`, `VerifyPassword`, `IssueSession`, `ChangePassword`, `SetInitialPassword`
- `ValidateSession`, `RevokeSession`, `RevokeAllSessions`
- `CreatePasswordResetToken`, `ResetPassword`
- `CreateMagicLinkToken`, `RedeemMagicLink`
- `CreateTwoFactorToken`, `CompleteTwoFactor`
- `CreateEmailVerificationToken`, `VerifyEmail`
- `Authenticate`, `UserFromContext`, `SessionFromContext`

Password hashes use Argon2id. Reset, magic-link, two-factor, and email-verification tokens are random, single-use, purpose-scoped, and time-limited.

## Core Flows

### Register

`Register(ctx, email, password, requestInfo)` normalizes and validates the email, checks the password against the length policy, hashes the password, creates the user, and immediately creates a new session. It returns `ErrUserAlreadyExists` if the email is already taken, `ErrInvalidEmail` for malformed/empty/overlong addresses, and `ErrPasswordTooShort`/`ErrPasswordTooLong` if the password falls outside the configured bounds. Registration does not mark the email as verified — only a redeemed magic link or a completed `VerifyEmail` does that.

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

`IssueSession(ctx, userID)` creates a new session for an already-authenticated user. It loads the user first (returning `ErrUserNotFound` for an unknown ID), then — by default — `ErrEmailNotVerified` if the account's email isn't verified yet, before creating the session; see [Operational requirements](#operational-requirements) for the `RequireVerifiedEmail` flag. Call it only after a fully completed authentication — a finished passkey ceremony, `CompleteTwoFactor`, or your own trusted flow — since it performs no credential check itself. `Login` applies the same gate before consulting the second-factor checker, so a correct password for an unverified account returns `ErrEmailNotVerified` rather than a session or a pending token.

`IssueSession` deliberately does **not** consult the `SecondFactorChecker`: it is the primitive for a login that has already cleared every factor, which is exactly what `CompleteTwoFactor` uses it for.

`ChangePassword(ctx, userID, oldPassword, newPassword, requestInfo)` is for accounts that already have a password. It consults the configured `Limiter` (key `"password:"+email`, the same key `Login`/`VerifyPassword` use) before verifying the old password, so a stolen session token can't be used to brute-force it once rate limiting is enabled. It returns `ErrInvalidCredentials` for a passwordless account or a wrong old password. The old password is re-verified against the freshly loaded user as part of the write, so a password changed by a concurrent request is never overwritten on the strength of a stale check.

`SetInitialPassword(ctx, userID, newPassword)` is for passwordless accounts created through flows such as magic link. Call it only after your application has already authenticated the user through a trusted flow; it returns `ErrInvalidCredentials` if the account already has a password.

### ValidateSession

`ValidateSession(ctx, token)` hashes the presented token, loads the session by hash, rejects expired sessions with `ErrSessionExpired` (deleting the expired record as it goes), and returns the session plus its user. The returned `Session.Token` is always empty — `ValidateSession` never echoes the raw bearer token back to the caller, since stores persist only the hash.

### Password Reset

`CreatePasswordResetToken(ctx, email, requestInfo)` creates a password-reset token and returns the raw token so the caller can deliver it out-of-band. Unlike `Login`/`VerifyPassword`, it returns `ErrUserNotFound` verbatim when the email doesn't exist — see [Operational requirements](#operational-requirements) for why that means your HTTP handler, not this method, must equalize the response.

`ResetPassword(ctx, rawToken, newPassword)` checks the password policy first (so a policy failure doesn't burn the token), then atomically consumes the token (hash + purpose, single-use), loads the user, and updates the password hash. It returns `ErrTokenInvalid` for an unknown or wrong-purpose token and `ErrTokenExpired` for an expired one. A replay's error depends on timing: redeeming the same still-live token twice (e.g. a concurrent racing request) returns `ErrTokenAlreadyUsed` for the loser; redeeming it again *after* a successful reset returns `ErrTokenInvalid` instead, because a successful reset purges the user's outstanding password-reset tokens, so the replay finds nothing to consume rather than an already-used row.

By default, both `ChangePassword` and `ResetPassword` revoke every session belonging to the user and delete any other outstanding password-reset tokens for that user — see [Operational requirements](#operational-requirements).

### Magic Link

`CreateMagicLinkToken(ctx, email)` creates a magic-link token and returns the raw token for delivery. If no user exists for the email yet, **no user row is created at this point** — only the token, carrying the email — so that requesting magic links for arbitrary addresses can't be used to flood the user store. The user is created lazily at redemption. This also means `CreateMagicLinkToken` never returns `ErrUserNotFound`, unlike `CreatePasswordResetToken`.

`RedeemMagicLink(ctx, rawToken)` atomically consumes the token, loads the user (creating a passwordless one now if the token predates the account), stamps `EmailVerifiedAt` (redeeming a magic link proves control of the mailbox), and creates a new session.

### Two-Factor

Two-factor authentication is a pending-login token sandwiched between a verified first factor and a verified second factor. `sulis` doesn't implement any second factor itself — pair it with `totp`, `recovery`, or `passkey` below — it only issues and redeems the short-lived pending token that stands in for "first factor passed, second factor pending."

Flow: `VerifyPassword` → your app checks whether the user has 2FA enabled → `CreateTwoFactorToken` → your app independently verifies the second factor (TOTP, recovery code, or passkey) → `CompleteTwoFactor(ctx, userID, rawToken)`. No session exists until `CompleteTwoFactor` succeeds; the pending token is single-use, purpose-scoped (rejected by `ResetPassword`, `RedeemMagicLink`, and `VerifyEmail`), and expires after `TwoFactorTokenDuration` (default 5 minutes).

By default, `CreateTwoFactorToken` returns `ErrEmailNotVerified` for an unverified account, failing before your app ever prompts for a second factor. `CompleteTwoFactor` re-checks the same condition as defense in depth (the token is consumed either way), against the account's *current* verification state rather than its state when the token was minted.

`CompleteTwoFactor` takes `userID` as an explicit argument and rejects the token with `ErrTokenInvalid` if it wasn't minted for that user (consuming the token either way, so a mismatched attempt also burns it). Your app must carry the `userID` obtained from `VerifyPassword` through its own server-side state across the two requests — e.g. keyed by the pending token, or in a short-lived server session — and pass that value to `CompleteTwoFactor`. **Never accept a client-supplied `userID` for this call**: if the second-factor request's `userID` came from the client instead, an attacker who can produce a *valid* second factor for their own account (their own TOTP code, their own passkey) could pair it with someone else's pending token and pass someone else's `userID`, since `sulis` only checks that the token and the userID match each other, not that the caller is who they claim.

```go
user, err := auth.VerifyPassword(ctx, email, password)
if err != nil {
    return err // ErrInvalidCredentials or ErrRateLimited
}

if !userHasTwoFactorEnabled(user) {
    session, err := auth.IssueSession(ctx, user.ID)
    return finish(user, session, err)
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
ok, err := totpSvc.Validate(ctx, user.ID, submittedCode)
if err != nil {
    // totp.ErrTOTPNotEnrolled, totp.ErrTOTPNotVerified, totp.ErrTOTPReplayed,
    // or totp.ErrTOTPRateLimited; consider falling back to a recovery code
    // via recoverySvc.Consume(ctx, user.ID, submittedRecoveryCode).
    return err
}
if !ok {
    // Wrong code: Validate returns (false, nil), not an error.
    return errors.New("invalid code")
}

// user.ID here comes from server-side state established above, never from
// the client's request.
user, session, err := auth.CompleteTwoFactor(ctx, user.ID, pending)
return finish(user, session, err)
```

### Email Verification

`CreateEmailVerificationToken(ctx, userID)` issues a single-use token proving control of the user's registered address (default TTL 24h), bound to that address: if the user's email changes before redemption, `VerifyEmail` rejects the stale token with `ErrTokenInvalid` rather than verifying the new address. `VerifyEmail(ctx, rawToken)` consumes it and stamps `User.EmailVerifiedAt`. Verification is idempotent — once set, `EmailVerifiedAt` is never overwritten by a later verification (e.g. a second magic-link redemption keeps the original timestamp). By default, an unverified `EmailVerifiedAt` also blocks new sessions elsewhere in the library — see [Operational requirements](#operational-requirements) for `RequireVerifiedEmail`.

The *first* time an account with a password gets verified (via either `VerifyEmail` or a redeemed magic link), all of that user's sessions are revoked unconditionally — regardless of `RevokeSessionsOnPasswordChange`. This closes a residual account-takeover window: an attacker who registered the victim's email with their own password before the victim ever proved mailbox control could otherwise keep a live session through the victim's later verification. Applications should additionally prompt for a password reset on this path, since the attacker's chosen password itself remains valid until changed.

## Subpackages

### `totp`

`totp` implements RFC 6238 TOTP without external dependencies. `NewService(store, issuer, opts...)` returns an error if the resolved config is out of bounds (empty/`:`-containing issuer, digits outside 6-8, period outside 15-300s, skew above 4, or secret size below 16 bytes).

It supports enrollment (`Enroll`, unverified until `ConfirmEnrollment`), validation (`Validate`), unenrollment (`Unenroll`), configurable HMAC algorithms (`SHA1`, `SHA256`, `SHA512`), configurable digit/period/skew settings, and `otpauth://` URI generation for authenticator apps.

`Validate` and `ConfirmEnrollment` enforce replay protection: each accepted code's time-step counter is persisted as `Credential.LastUsedCounter`, and a code is only accepted if its counter is strictly greater than the last one accepted for that credential. Reusing a code, or presenting an older one after a newer counter has already been accepted, returns `ErrTOTPReplayed`.

`totp.WithLimiter` configures a rate limiter (structurally identical to the root `Limiter` interface, declared separately so this package has no dependency on the root module) consulted by both `Validate` and `ConfirmEnrollment`, keyed by `"totp:"+userID`. A denied check returns `ErrTOTPRateLimited`. This is not optional in production: a 6-digit code is a 10^6 space, brute-forceable without a limiter.

The package depends on a consumer-owned `totp.Store` for saving and loading TOTP credentials.

### `passkey`

`passkey` wraps `github.com/go-webauthn/webauthn` to provide higher-level passkey registration and login helpers. It manages begin/finish WebAuthn ceremonies, persists credentials through a consumer-owned `passkey.Store`, and persists transient ceremony state through a consumer-owned `passkey.ChallengeStore`.

Besides the identified `BeginRegistration`/`FinishRegistration` and `BeginLogin`/`FinishLogin` pairs (which require the caller to already know the user), `passkey` supports **discoverable ("usernameless") login**: `BeginDiscoverableLogin(ctx)` returns the assertion options plus a `ceremonyID` that the caller must round-trip to `FinishDiscoverableLogin(ctx, ceremonyID, r)`. The user is resolved from the credential's stored owner (via the authenticator's user handle), not supplied by the caller.

Both finish paths reject a credential flagged with a sign-count anomaly by returning `ErrCloneWarning` — treat this as a signal of possible credential cloning, not a routine auth failure. On success, `FinishLogin`/`FinishDiscoverableLogin` persist the updated sign count and return the stored `Credential`; `passkey` does not create a `sulis` session for you — call `IssueSession(ctx, userID)` (directly or via the two-factor flow) after a successful finish.

Challenge/session keys are ceremony-scoped (`"register:<userID>"`, `"login:<userID>"`, `"discover:<ceremonyID>"`) so concurrent ceremonies for the same user can't clobber each other's saved challenge. A `passkey.ChallengeStore` should expire entries after roughly 5 minutes, matching the lifetime of a WebAuthn ceremony.

### `recovery`

`recovery` implements one-time recovery codes as a fallback second factor for when a user loses their TOTP device or passkey. `NewService(store, opts...)` defaults to generating 10 codes (`WithCount` to change it); each code is 10 bytes of `crypto/rand`, base32-encoded and displayed as `xxxx-xxxx-xxxx-xxxx`.

`Generate(ctx, userID)` atomically replaces the user's entire code set and returns the plaintext codes for one-time display — only their SHA-256 hashes are persisted, so the plaintext cannot be recovered later. `Consume(ctx, userID, code)` normalizes the input (case, whitespace, and dash-grouping insensitive) and atomically consumes a single matching code, returning `ErrCodeInvalid` if none matches. `Remaining` reports the unused count (useful for prompting a user to regenerate); `Disable` removes all codes for a user.

`recovery` has no built-in rate limiter — see [Operational requirements](#operational-requirements).

## Store Contracts

`sulis` does not ship a database layer. Consumers own persistence and implement these interfaces:

- `UserStore`: create, fetch, update, and delete users by ID/email. `UpdateUser` must apply the write **only** if the stored row's `version` still equals `user.Version`, incrementing it on success and returning `ErrConcurrentUpdate` otherwise:

  ```sql
  UPDATE users SET ..., version = version + 1
   WHERE id = $1 AND version = $2
  ```

  Zero rows affected means another writer won. Without this check, two flows that each read-modify-write the whole row can clobber each other, and the dangerous direction restores a password hash the user just rotated away from — silently undoing a reset. The library reloads and retries on `ErrConcurrentUpdate`, so a correct store makes the race invisible to callers.
- `SessionStore`: create sessions, load them by token-hash lookup, revoke one session, revoke all sessions for a user, and `CleanExpired`. `CleanExpired` is never called by the library itself — see [Operational requirements](#operational-requirements).
- `TokenStore`:
  - `CreateToken` persists a new token.
  - `ConsumeToken(ctx, hash, purpose)` must atomically find the unused token matching hash **and** purpose and mark it used in one operation (e.g. `UPDATE ... WHERE hash=? AND purpose=? AND used=false`), returning `ErrTokenNotFound` if nothing matches and `ErrTokenAlreadyUsed` if it was already consumed. Lookup and mark-used are not allowed to be separate steps — that would open a race where two concurrent redemptions both succeed.
  - `DeleteExpiredTokens(ctx)` deletes expired tokens; also never called by the library itself.
  - `DeleteUserTokens(ctx, userID, purpose)` deletes all of a user's tokens for a given purpose (deleting zero is not an error) — used internally to purge outstanding password-reset tokens after a successful reset/change.
- `totp.Store`: save (create or update), fetch, and delete a user's TOTP credential. `SaveTOTP` must persist `LastUsedCounter` atomically with respect to concurrent `Validate` calls, so two racing validations can't both accept the same (or an older) counter.
- `passkey.Store`: save passkey credentials, list credentials for a user, fetch a credential by WebAuthn credential ID, update sign counts, and delete credentials.
- `passkey.ChallengeStore`: store, retrieve, and delete the temporary WebAuthn session data used between begin/finish calls, keyed per-ceremony (see above) with a ~5-minute TTL.
- `recovery.Store`: `ReplaceCodes` atomically swaps a user's full code set; `ConsumeCode` must atomically find-and-delete a matching hash (same race concern as `ConsumeToken`), returning `ErrCodeNotFound` if absent; `CountCodes`; `DeleteCodes`.

These stores are part of the security boundary. They should enforce uniqueness where needed and persist enough data for expiry and revocation. Only some flows depend on specific sentinel errors from stores, such as `ErrUserNotFound`, `ErrUserAlreadyExists`, `ErrTokenNotFound`, and `recovery.ErrCodeNotFound`; other store errors are propagated or normalized by the service.

## Security Notes

- `Token.TokenHash` stores a SHA-256 hash of a reset, magic-link, two-factor, or email-verification token. Raw tokens are returned once for delivery and should never be persisted. `Token.Email` is set for magic-link tokens issued before the user account exists, and for email-verification tokens (bound to the address they prove, so a later email change invalidates them); it is empty for password-reset and two-factor tokens.
- Session tokens are opaque bearer tokens. `SessionStore` implementations persist only `TokenHash` (the root package always clears `Session.Token` before calling `CreateSession`) and perform `GetSessionByTokenHash` lookups against the hash of the presented session token rather than the raw token. `ValidateSession` likewise never returns the raw token to the caller.
- TOTP secrets (`totp.Credential.Secret`) and passkey public keys are handed to your stores as-is; recovery codes and all `sulis` tokens/sessions are hashed before your store ever sees them. See [Operational requirements](#operational-requirements) for what that implies for TOTP secrets specifically.

## Operational requirements

These are things the library deliberately leaves to the consumer. Skipping them weakens the security properties described above.

**Rate limiting is required in production.** Wire `sulis.WithLimiter` and, separately, `totp.WithLimiter` — they are independent interfaces so a single implementation can satisfy both structurally. The root limiter guards `"password:"+email` (`Login`, `VerifyPassword`, and `ChangePassword`), `"reset:"+email` (`CreatePasswordResetToken`), and `"magic:"+email` (`CreateMagicLinkToken`); the totp limiter guards `"totp:"+userID` (`Validate` and `ConfirmEnrollment`). Token-redemption calls — `ResetPassword`, `RedeemMagicLink`, `CompleteTwoFactor`, `VerifyEmail` — are deliberately **not** gated by the limiter: the guessable space there is a 256-bit random token (default `ResetTokenBytes` = 32 bytes), not a password or a 6-digit code, so rate limiting doesn't meaningfully raise the cost of an attack the way it does for a small guessable space. `recovery.Consume` also has no built-in limiter; its 80-bit codes make brute force impractical, but add rate limiting at your HTTP layer if you want defense in depth there too.

**Schedule cleanup yourself.** `TokenStore.DeleteExpiredTokens` and `SessionStore.CleanExpired` exist so expired rows don't accumulate forever, but `sulis` never calls either — it runs no background workers. Run them on a periodic job (cron, a ticker goroutine, etc.). `ValidateSession` does delete a session it discovers is expired at validation time, but that's incidental to the read path, not a substitute for sweeping sessions and tokens that are never revisited.

**Cookie-mode `Authenticate` needs CSRF defenses.** The middleware accepts a session token from either an `Authorization: Bearer` header or a `session` cookie. Bearer tokens aren't auto-attached by browsers, so they're not CSRF-exposed; cookies are. If you use the cookie path, add your own CSRF defenses — `SameSite=Strict`/`Lax` plus a synchronizer or double-submit token, or strict `Origin`/`Sec-Fetch-Site` checks. `sulis` does not add anything cookie-specific.

**Encrypt TOTP secrets at rest.** `totp.Service` hands your `totp.Store` a plaintext base32 secret (`Credential.Secret`) — there is no application-layer encryption. Encrypt it at rest (e.g. envelope encryption via a KMS) in your store implementation, since a database compromise would otherwise hand an attacker every enrolled user's shared secret, usable to generate valid codes indefinitely.

**Respond identically regardless of `CreatePasswordResetToken`'s `ErrUserNotFound`.** Unlike `Login`/`VerifyPassword`, which normalize unknown-email and wrong-password into the same `ErrInvalidCredentials` with equalized timing, `CreatePasswordResetToken` returns `ErrUserNotFound` verbatim when the email doesn't exist. Your HTTP handler must not let that distinction reach the caller — return the same generic response ("if that address is registered, we've sent a reset link") whether or not the account exists, or the endpoint becomes a user-enumeration oracle. (`CreateMagicLinkToken` doesn't have this problem: it never returns a not-found error, since it defers user creation to redemption.)

**Sessions are revoked on password change by default.** `RevokeSessionsOnPasswordChange` defaults to `true`, so both `ChangePassword` and `ResetPassword` delete every session belonging to the user (and purge any other outstanding password-reset tokens) as part of applying the new password. Pass `WithRevokeSessionsOnPasswordChange(false)` to opt out. Because this revokes the caller's own current session too, `ChangePassword` does not return a new one — call `IssueSession` yourself immediately afterward if you want the calling client to stay logged in.

**New sessions are blocked for unverified accounts by default.** `RequireVerifiedEmail` defaults to `true`: `Login`, `IssueSession`, `CreateTwoFactorToken`, and `CompleteTwoFactor` all return `ErrEmailNotVerified` for an account whose `EmailVerifiedAt` is still nil. `Register`'s signup session and `RedeemMagicLink` (which verifies the email itself before issuing a session) are exempt. **If your application has no email verification flow wired up — no `CreateEmailVerificationToken`/`VerifyEmail`, and no magic links — you must pass `WithRequireVerifiedEmail(false)`**, or users will be able to register but never sign in again once their first session expires. Migration note: this is a behavior change for existing consumers — previously an unverified account could log in indefinitely. Either wire up verification (or magic links, which self-verify) or opt out explicitly.
