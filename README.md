# sulis

`sulis` is a small Go authentication library for consumer-owned persistence. The root package provides password-based auth, password reset, magic-link login, server-side sessions, and HTTP middleware for attaching the authenticated user and session to a request context.

## Root Package

Create a service with `sulis.New(userStore, sessionStore, tokenStore, opts...)`. The root package owns the auth logic and data types:

- `User`, `Session`, and `Token`
- `Register`, `Login`, `ChangePassword`, `SetInitialPassword`
- `ValidateSession`, `RevokeSession`, `RevokeAllSessions`
- `CreatePasswordResetToken`, `ResetPassword`
- `CreateMagicLinkToken`, `RedeemMagicLink`
- `Authenticate`, `UserFromContext`, `SessionFromContext`

Password hashes use Argon2id. Reset and magic-link tokens are random, single-use, and time-limited.

## Core Flows

### Register

`Register(ctx, email, password)` hashes the password, creates the user, and immediately creates a new session. It returns `ErrUserAlreadyExists` if the email is already taken.

### Login

`Login(ctx, email, password)` loads the user by email, verifies the password hash, and creates a new session. Unknown users and wrong passwords both return `ErrInvalidCredentials`.

`ChangePassword(ctx, userID, oldPassword, newPassword)` is for accounts that already have a password. It verifies the old password before storing the new one.

`SetInitialPassword(ctx, userID, newPassword)` is for passwordless accounts created through flows such as magic link. Call it only after your application has already authenticated the user through a trusted flow.

### ValidateSession

`ValidateSession(ctx, token)` loads the session, rejects expired sessions with `ErrSessionExpired`, deletes expired session records, and returns the session plus its user.

### Password Reset

`CreatePasswordResetToken(ctx, email)` creates a password-reset token and returns the raw token so the caller can deliver it out-of-band.

`ResetPassword(ctx, rawToken, newPassword)` hashes the presented token, loads the stored token record by hash, verifies purpose, expiry, and single-use status, updates the user's password hash, and marks the token as used.

Neither `ChangePassword` nor `ResetPassword` revokes existing sessions automatically. If your application requires that behavior, call `RevokeAllSessions` yourself.

### Magic Link

`CreateMagicLinkToken(ctx, email)` creates a magic-link token and returns the raw token for delivery. If the email does not exist yet, `sulis` creates a passwordless user first.

`RedeemMagicLink(ctx, rawToken)` hashes and validates the token, marks it as used, loads the user, and creates a new session.

## Subpackages

### `totp`

`totp` implements RFC 6238 TOTP without external dependencies. It supports enrollment, enrollment confirmation, validation, unenrollment, configurable HMAC algorithms (`SHA1`, `SHA256`, `SHA512`), configurable digit/period/skew settings, and `otpauth://` URI generation for authenticator apps.

The package depends on a consumer-owned `totp.Store` for saving and loading TOTP credentials.

### `passkey`

`passkey` wraps `github.com/go-webauthn/webauthn` to provide higher-level passkey registration and login helpers. It manages begin/finish WebAuthn ceremonies, persists credentials through a consumer-owned `passkey.Store`, and persists transient ceremony state through a consumer-owned `passkey.ChallengeStore`.

## Store Contracts

`sulis` does not ship a database layer. Consumers own persistence and implement these interfaces:

- `UserStore`: create, fetch, update, and delete users by ID/email.
- `SessionStore`: create sessions, load them by token-hash lookup, revoke one session, revoke all sessions for a user, and clean expired sessions.
- `TokenStore`: create reset/magic-link tokens, load them by token hash, mark them used, and delete expired tokens.
- `totp.Store`: save, fetch, and delete a user's TOTP credential.
- `passkey.Store`: save passkey credentials, list credentials for a user, fetch a credential by WebAuthn credential ID, update sign counts, and delete credentials.
- `passkey.ChallengeStore`: store, retrieve, and delete the temporary WebAuthn session data used between begin/finish calls.

These stores are part of the security boundary. They should enforce uniqueness where needed and persist enough data for expiry and revocation. Only some flows depend on specific sentinel errors from stores, such as `ErrUserNotFound`, `ErrUserAlreadyExists`, and `ErrTokenNotFound`; other store errors are propagated or normalized by the service.

## Security Notes

- `Token.TokenHash` stores a SHA-256 hash of a reset or magic-link token. Raw reset and magic-link tokens are returned once for delivery and should never be persisted.
- `TokenStore.GetTokenByHash` is expected to look up tokens by the hash of the presented raw token.
- Session tokens are opaque bearer tokens. If a `SessionStore` persists them, it should store only a derived hash and perform `GetSessionByTokenHash` lookups against the hash of the presented session token rather than storing or querying by the raw bearer token.
