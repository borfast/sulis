# Security Hardening And MFA Design

Recorded retrospectively: this design came out of the 2026-08-14 security
audit, governed the plan of the same date, and was refined by the branch's
final whole-branch review. It is written to match what shipped in PR #2.

## Goal

Close the audit's security findings in the core flows and add the product
pieces the library was missing: two-factor orchestration, recovery codes,
email verification, discoverable passkey login, and rate-limit hooks.

## Problem (audit findings)

- Token redemption was check-then-mark across two store calls: concurrent
  reset/magic-link redemptions could both succeed, and `ResetPassword`
  marked the token used only after changing the password.
- Password change/reset left existing sessions and outstanding reset tokens
  alive; `ValidateSession` echoed the raw bearer token back to callers.
- `Login` returned before any Argon2 work for unknown or passwordless
  accounts (timing oracle); passwords had no length bounds (CPU DoS).
- `decodeHash` trusted the algorithm label and parameters read from stored
  hashes (tampered-row allocation DoS).
- Emails were used verbatim (case-sensitive duplicates) and
  `CreateMagicLinkToken` inserted a user row for any string before anything
  was delivered (unauthenticated table flooding).
- TOTP codes were replayable within their window, config was unvalidated
  (`Period=0` panics, `Digits>9` overflows), and secrets had no rate-limit
  protection despite a 10^6 code space.
- Passkey registration and login challenges shared one key per user
  (ceremony clobbering); `FinishLogin` discarded error detail and ignored
  the library's clone-detection warning; no usernameless login existed.
- No pending-2FA state, no recovery codes, no email verification (enabling
  pre-registration account takeover), no way to issue a session after a
  passkey login, no rate-limiting hooks anywhere.

## Approved Direction

Keep the library small and store-driven. Where correctness requires
atomicity, make it a store contract, not a convention: single atomic
operations (`ConsumeToken`, `ConsumeCode`) documented on the interface and
honored by the in-memory reference fakes. Secure defaults with explicit
opt-outs. Sentinel errors with package prefixes; raw secrets never in error
messages. Breaking API changes accepted (pre-1.0).

## Design By Area

- **Token lifecycle:** `TokenStore.ConsumeToken(ctx, hash, purpose)` atomically
  finds-and-marks the unused token; flows consume before any side effect, and
  expiry failures burn the token (safe direction). `DeleteUserTokens` supports
  post-change purges. `Token.Email` carries the address for tokens minted
  before a user exists.
- **Password flows:** `setPassword` revokes all sessions (default on,
  `WithRevokeSessionsOnPasswordChange` to opt out) and purges outstanding
  reset and pending two-factor tokens. Policy bounds: 8–1024 bytes,
  configurable. Timing equalization via a dummy hash computed at `New` with
  the configured Argon2 params. `decodeHash` validates the `argon2id` label
  and bounds every parameter before any key derivation.
- **Email handling:** `normalizeEmail` (trim, `net/mail` parse, reject
  display-name forms, lowercase, 254-char cap) at every email-accepting entry
  point. Magic-link users are created at redemption, with a
  register-race fallback.
- **TOTP:** `Credential.LastUsedCounter` rejects replays (`ErrTOTPReplayed`),
  fail-closed on persist failure; enrollment confirmation raises the counter
  monotonically; `NewService` validates issuer/digits/period/skew/secret size
  and returns an error; optional `Limiter` guards `Validate` and
  `ConfirmEnrollment`.
- **Passkeys:** challenge keys scoped by ceremony (`register:`, `login:`,
  `discover:` + random ceremony ID), ~5-minute TTL contract on
  `ChallengeStore`; clone warnings surface as `ErrCloneWarning` before any
  sign-count update; discoverable login round-trips a ceremony ID and binds
  the credential to the presented user handle.
- **MFA orchestration:** `VerifyPassword` (verification only) split from
  `IssueSession`; a short-lived single-use pending token
  (`TokenPurposeTwoFactor`, default 5 min) bridges password verification and
  `CompleteTwoFactor(ctx, userID, rawToken)`, which enforces the
  token-to-user binding so a client-supplied identity cannot bypass the
  second factor.
- **Recovery codes:** `recovery/` subpackage; 80-bit codes displayed as
  `xxxx-xxxx-xxxx-xxxx`, only SHA-256 hashes at rest, atomic
  `ConsumeCode`, full-set `ReplaceCodes`.
- **Email verification:** `User.EmailVerifiedAt`, verification tokens bound
  to the address they prove, magic-link redemption stamps verification, and
  the first verification of a passworded account revokes all existing
  sessions (pre-registration takeover mitigation). The separate
  verified-email session gate has its own spec of the same date.
- **Rate limiting:** app-provided `Limiter` consulted at guessable choke
  points (`password:`, `reset:`, `magic:`, `totp:` keys — including
  `ChangePassword`'s old-password check); high-entropy token redemption is
  deliberately exempt. Documented as a production requirement.
- **Operations:** README documents store contracts, limiter requirements,
  cleanup scheduling, CSRF for cookie mode, TOTP secret encryption at rest,
  and enumeration-safe reset responses. CI (build, vet, race tests,
  govulncheck), MIT license, dependency updates.

## Testing Strategy

TDD per task; race-detector runs on concurrency-sensitive paths (token and
recovery-code consumption, TOTP counters); every task independently
reviewed; a final adversarial whole-branch review focused on cross-flow
interactions, whose findings (2FA token purge, userID binding, email-bound
verification tokens, first-verification session revocation, TOTP store
monotonicity contract, ChangePassword limiter) were folded into the branch.

## Non-Goals

- No shipped store or limiter implementations (consumers own persistence).
- No per-flow policy engine; single flags with secure defaults.
- No OAuth/social login.
- No transactional store abstraction beyond the atomic single-call contracts.
