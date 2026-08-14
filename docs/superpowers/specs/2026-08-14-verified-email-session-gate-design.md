# Verified-Email Session Gate Design

## Goal

Give applications a switch that blocks new sessions for accounts whose email
address has not been verified — closing the window where an attacker who
pre-registered with someone else's email can keep signing in.

## Problem

`Register` intentionally signs the new user in right away, but nothing stops
further logins while `EmailVerifiedAt` is still nil. An attacker who registers
with a victim's email holds a working password and can log in repeatedly until
the victim happens to claim the account. Session revocation on first
verification (already shipped) kills existing sessions but does not prevent
new ones before that point.

## Approved Direction

Approach A: a config flag checked at each session-starting entry point.
Rejected alternative: gating inside `createSession`, which would force a user
load on every session (including `Register`'s) and need special-casing.

- `Config.RequireVerifiedEmail bool`, **default `true`** (secure by default;
  intentional behavior break, pre-1.0).
- `WithRequireVerifiedEmail(require bool)` option to opt out.
- New sentinel: `ErrEmailNotVerified = errors.New("sulis: email not verified")`.
- Internal helper `requireVerifiedEmail(user *User) error`: returns
  `ErrEmailNotVerified` when the flag is on and `user.EmailVerifiedAt == nil`.

## Gated Flows

All return `ErrEmailNotVerified` for unverified accounts when the flag is on:

- `Login` — checked after password verification succeeds, before session
  creation, so the error is only ever shown to someone who knows the
  password (no new enumeration surface).
- `CreateTwoFactorToken` — fails early, before the app prompts for a code.
- `CompleteTwoFactor` — defense in depth; the pending token is consumed
  either way, consistent with consume-first semantics. Check order: consume →
  userID match (`ErrTokenInvalid`) → verified check (`ErrEmailNotVerified`) →
  session.
- `IssueSession` — covers passkey logins. It now loads the user first, so it
  also returns `ErrUserNotFound` for unknown IDs (fixes a known
  inconsistency with `CreateTwoFactorToken`).

## Exempt Flows

- `Register` — the auto-session on signup stays, by explicit decision. With
  the gate on, once that first session expires the user cannot start another
  until verified.
- `RedeemMagicLink` — redemption stamps `EmailVerifiedAt` before creating the
  session, so the account is verified by the time the session is issued; this
  is the account owner's way in. No code change.
- `VerifyPassword` — pure verification, starts no session. `Login` is the
  gated wrapper.

## Error Handling

`ErrEmailNotVerified` is distinct so apps can route to "resend verification
email" UX. No wrapping; plain sentinel like the rest of the package.

## Tests

1. Gate on (default): `Login`, `CreateTwoFactorToken`, `CompleteTwoFactor`,
   and `IssueSession` each return `ErrEmailNotVerified` for an unverified user.
2. `Login` succeeds after `VerifyEmail`.
3. `RedeemMagicLink` still returns a session for a previously-unverified user.
4. `Register` still returns a session.
5. `WithRequireVerifiedEmail(false)` restores the old behavior (unverified
   login succeeds).
6. `IssueSession` with an unknown userID returns `ErrUserNotFound`.

Existing tests that `Login` on unverified accounts must be updated: verify
the account first where verification is incidental to the test, or pass
`WithRequireVerifiedEmail(false)` where unverified login is the point.

## Documentation

README: document the flag under configuration and the operational
requirements section. State loudly: **apps with no email verification flow
must set `WithRequireVerifiedEmail(false)`**, otherwise users can register
but never sign in again after the first session expires. Update the 2FA flow
description to mention the early failure from `CreateTwoFactorToken`.

## Migration Note

Consumers upgrading: unverified accounts can no longer start new sessions by
default. Either wire up `CreateEmailVerificationToken`/`VerifyEmail` (or
magic links, which self-verify) or opt out with
`WithRequireVerifiedEmail(false)`.

## Non-Goals

- No suppression of `Register`'s auto-session.
- No per-flow granularity (one flag governs all gated flows).
- No library-enforced resend/cooldown logic for verification emails.
