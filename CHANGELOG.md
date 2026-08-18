# Changelog

All notable changes to sulis are documented in this file. The format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), adapted for
a pre-1.0 project: see README.md's "Versioning" section for why this file has
no tagged version numbers yet, only one running `[Unreleased]` entry.

## [Unreleased]

This entry covers the entire `security-hardening-v1` branch (branched from
`main` at `bf18c6e`): closing every finding in
`docs/security-audit-2026-08-17.html`, making unsafe store implementations
impossible rather than merely discouraged (`storetest` + `memstore`), and
inverting every previously-unsafe default. It is deliberately one large
entry rather than many small ones — see `CONTRIBUTING.md`.

### BREAKING CHANGES

**Construction and second-factor enforcement**

- `New` now returns `(*Sulis, error)` (was `*Sulis`) and takes a required
  fourth argument, a `SecondFactorChecker`.

**Session issuance and lifecycle**

- `Session.Token` is gone. Every call that mints a session now returns the
  raw token as a separate value instead.
- `Login`, `RedeemMagicLink`, and `CompleteTwoFactor` now return
  `*LoginResult` instead of `(*User, *Session, error)`; `CompleteTwoFactor`
  also gained a `RequestInfo` parameter.
- `RevokeSession` now takes `(ctx, userID, sessionID)` — a caller can only
  revoke a session belonging to their own user ID.
- `IssueSession` now takes an `Authentication` proof instead of a bare user
  ID, and also returns the raw session token. `IssueSessionUnchecked` is
  the old unguarded shape, now under an explicit name.
- `SessionStore`: `DeleteSession` is now `(ctx, userID, id)` and MUST be
  scoped to both columns atomically. `TouchSession`, `UpdateAuthenticatedAt`,
  and `DeleteUserSessionsExcept` are new required methods.

**Password and account lifecycle**

- `CreatePasswordResetToken` returns `("", nil)` for an unknown address
  instead of propagating `ErrUserNotFound`. `CreatePasswordResetTokenStrict`
  is new, for callers that need the real answer.
- The default `MinPasswordLength` is now 12 (was 8).
- Most flows (`Register`, `Login`, `VerifyPassword`, `ChangePassword`,
  `CreatePasswordResetToken`, `CreateMagicLinkToken`, `RedeemMagicLink`, …)
  now take a `RequestInfo` parameter.
- `User` gained a `Version` field; `UserStore.UpdateUser` MUST implement
  optimistic concurrency against it and MUST enforce email uniqueness
  (`ErrUserAlreadyExists`) at the storage layer.

**Magic link**

- `CreateMagicLinkToken` now also returns a binding nonce.
  `RedeemMagicLink` requires that nonce back as a new parameter.

**TOTP**

- `totp.Service.Validate` is now error-only: `error` instead of
  `(bool, error)`.
- `totp.Store` no longer has `SaveTOTP`/`GetTOTPByUserID`/`DeleteTOTP` as
  its whole surface. It now separates a pending (unverified) enrollment
  from the active (verified) one: `GetActiveTOTP`, `GetPendingTOTP`,
  `EnrollPending`, `ReplacePending`, and `ConfirmEnrollment` are new
  required methods; `SaveTOTP`/`DeleteTOTP` remain but their contracts
  changed (see the doc comments in `totp/store.go`).

**Passkey**

- `passkey.User.Credentials` is gone. The `Service` now loads a user's
  credentials from the `Store` itself.
- `BeginLogin` now also returns a ceremony ID; `FinishLogin` (and its HTTP
  wrapper) now requires that ceremony ID as a parameter.
- `passkey.Store`: `UpdateCredentialSignCount` is replaced by
  `UpdateCredentialAfterLogin` (sign count, backup state, and last-used
  time in one call). `DeleteCredential` gained an `allowLast bool`
  parameter and MUST atomically refuse to delete a user's last remaining
  credential unless it is set.

**Recovery codes**

- `recovery.Service.Consume` now returns `(remaining int, err error)`
  instead of just `error`.

### Added

- **Second-factor enforcement**: `SecondFactorChecker`, `NoSecondFactors`,
  and `LoginResult` — no path can issue a fully-privileged session for an
  account with an enrolled second factor without that factor being checked.
- **Rate limiting is on by default**: an in-process `MemoryLimiter` guards
  password, reset, and magic-link attempts on both an account and an IP
  dimension out of the box. `WithoutRateLimiting()` opts out explicitly.
- **Password quality screening**: `passwordcheck.NewBlocklist()` (the
  no-network default) and `passwordcheck.NewHIBP()` (opt-in, fails open by
  default, `WithHIBPFailClosed()` inverts it), plus NFKC Unicode
  normalization (`golang.org/x/text`, the one approved new dependency —
  see `CONTRIBUTING.md`) so a password typed with a different Unicode
  composition still verifies.
- **Password peppering**: `WithPepper`, an HMAC-SHA256 secret mixed into
  every password before Argon2, independent of any per-user salt.
- **Automatic password rehashing**: `VerifyPassword` (and `ReAuthenticate`)
  transparently upgrade a stored hash to the configured `Argon2Params` on
  a successful verify against weaker parameters.
- **TOTP secret encryption at rest**: `totp.WithEncryptor`,
  `totp.NewAESEncryptor` (AES-256-GCM, with key rotation via a variadic
  `rotated` argument). Unconfigured, secrets are stored exactly as before
  (plaintext) — this is opt-in, see the README's "Operational
  requirements" for why you want it before production.
- **WebAuthn user verification required by default**:
  `passkey.WithUserVerification` defaults to
  `protocol.VerificationRequired`; `passkey.WithResidentKey` defaults to
  `protocol.ResidentKeyRequirementRequired`. `passkey.WithMaxCeremonyBody`
  caps ceremony response bodies (default 64 KiB) against unbounded reads.
  `UpdateCredentialAfterLogin` also tracks sign-count clone detection
  (`ErrCloneWarning`) and backup state.
- **Secure cookie sessions and CSRF defenses**: `SessionCookie`,
  `ClearSessionCookie` (`HttpOnly`/`Secure`/`SameSite=Lax`, `__Host-`
  prefixed by default), `RequireSameOrigin`, and a constant-time
  double-submit token pair, `IssueCSRFToken`/`RequireCSRFToken`/
  `VerifyCSRFToken`. `TokenSource` (`TokenSourceBoth` by default,
  `TokenSourceCookieOnly`, `TokenSourceBearerOnly`) controls which
  credential `Authenticate` accepts.
- **Account disable and lockout**: `DisableUser`/`EnableUser`,
  `User.DisabledAt`/`DisabledReason`, and an opt-in automatic lockout
  (`WithFailureLockout`) backed by `User.FailedLoginAttempts`/
  `LockedUntil`.
- **Step-up re-authentication**: `RequireRecentAuth` and `ReAuthenticate`,
  backed by `Session.AuthenticatedAt`, for gating sensitive operations
  (enrolling a second factor, removing a passkey, changing email, …)
  behind a recently-proven credential rather than a possibly-hours-old
  session.
- **Session liveness and idle expiry**: `Session.LastSeenAt`/
  `IdleExpiresAt`, `WithIdleTimeout`, throttled `TouchSession` writes, and
  `RefreshSession` (fail-closed against a revoked or disabled account).
- **`ListUserSessions`** and `SessionStore.DeleteUserSessionsExcept` for
  "where you're signed in" / "sign out everywhere else" device management.
- **Security event sink**: `EventSink`, `WithEventSink`, `NewSlogSink`, and
  a 33-constant `EventKind` taxonomy (`events.go`) covering every
  security-relevant decision the root package makes, with a documented
  no-secrets rule and a no-allocation guarantee when unconfigured.
  `recovery` ships its own independent, non-wire-compatible event sink
  (`recovery/events.go`) for the same reason (see `doc.go`'s "Security
  events" section for why they can't share one type).
- **Store-contract conformance suite**: `storetest` (one package, all
  seven store interfaces) and `memstore` (a reference in-memory
  implementation proven against it). Any store implementation — yours or
  ours — can be run through `storetest.RunUserStore`/`RunSessionStore`/…
  to prove it satisfies the documented contracts rather than merely
  compiling against the interface.
- **Reference SQL stores**: `store/sql/sqlite` (`modernc.org/sqlite`, pure
  Go, one serialized connection) and `store/sql/postgres`
  (`github.com/jackc/pgx/v5`, advisory locks on the deadlock-prone paths),
  both green against the full `storetest` suite. This is a separate Go
  module (`store/sql/go.mod`) with its own dependency graph and its own
  versioning — see README.md's "Versioning" section.
- **Fuzz targets**: `FuzzDecodeHash` and `FuzzNormalizeEmail` (root
  `fuzz_test.go`), `FuzzGenerateCode` (`totp/fuzz_test.go`, exercising the
  epoch guard), and `FuzzRecoveryCanonical` (`recovery/fuzz_test.go`,
  canonicalization/hashing).
- **Package documentation**: `doc.go` (overview, minimal end-to-end
  example, store-contract summary) and compiler-checked `Example`
  functions (`example_test.go`) for password login with a second factor,
  magic links, passkeys, password reset, and email change.
- `SECURITY.md` and `docs/threat-model.md`: how to report a vulnerability,
  the pre-1.0 supported-versions policy, and the full threat model —
  in-scope threats, shipped mitigations, explicit out-of-scope items, and
  residual risks.
- `CONTRIBUTING.md` and this file.
- A stated versioning policy in README.md (v0.x until this plan completes,
  then a Go-1-style compatibility promise at v1.0.0).

### Changed

- Sentinel errors are consistently prefixed by package: `sulis:`, `totp:`,
  `passkey:`, `recovery:`.
- CI (`ci.yml`) pins third-party Actions to a SHA and runs static analysis
  (`staticcheck`, `gosec`, `govulncheck`) in a separate job from the test
  matrix; a dedicated `postgres` job runs the PostgreSQL store's
  conformance suite against a pinned service container; a `fuzz` job
  smoke-tests the fuzz targets.
- `decodeHash` widens salt/hash lengths only after the bounds check that
  makes the conversion safe (closing a gosec G115 finding for real, not
  by suppression).
- `totp.Generate`/the internal counter derivation gained a pre-1970 epoch
  guard (`counterAt`), since `Generate` is public and takes an arbitrary
  `time.Time`.
- `RevokeSessionsOnPasswordChange` (default `true`): `ChangePassword` and
  `ResetPassword` now revoke every other session on the account and purge
  outstanding reset tokens as part of applying a new password. Every
  password-setting path also purges the account's pending two-factor and
  outstanding magic-link tokens, whatever this setting says — a magic link
  is a mailbox-derived credential a password rotation is often being
  performed to escape.
- `RequireVerifiedEmail` (default `true`): new sessions are refused for an
  account whose email isn't verified yet, except through `Register`'s own
  signup session and `RedeemMagicLink` (which verifies the email itself).
  `RefreshSession` applies the gate too, so `Register`'s exemption covers
  that one session rather than a renewable one. This is a behavior change
  for existing consumers with no verification flow wired up — pass
  `WithRequireVerifiedEmail(false)` explicitly if that's you.
- README and `doc.go` were updated by the task that changed each behavior
  described in this entry, not in a later sweep — so the README reflects
  current behavior throughout, not just at the points called out here.

### Security

Selected findings from `docs/security-audit-2026-08-17.html` this pass
closes (see `docs/threat-model.md` for the complete mapping):

- A session could be issued for an account with an enrolled second factor
  without that factor ever being checked. Closed by the required
  `SecondFactorChecker` and the `LoginResult`/`CompleteTwoFactor` flow.
- `RevokeSession` could revoke any session by ID regardless of who owned
  it. Closed by scoping it (and the store contract behind it) to the
  caller's own user ID.
- `RefreshSession` could resurrect a session whose account had since been
  disabled or revoked (a create-then-swallowed-delete ordering bug found
  during task review). Fixed with a delete-first, fail-closed ordering
  plus an explicit account-status check.
- WebAuthn authentication did not require user verification by default,
  so a passkey could authenticate on bare possession of an unlocked
  device rather than a PIN or biometric. Closed by defaulting
  `passkey.WithUserVerification` to `protocol.VerificationRequired`.
- Deleting a passkey credential raced two concurrent deletes of a user's
  last two credentials down to zero remaining credentials (a TOCTOU in
  the last-credential guard). Closed by making the guard atomic inside
  `Store.DeleteCredential`.
- A TOTP enrollment could be silently clobbered by a concurrent
  enrollment attempt landing between validation and promotion. Closed by
  making `ConfirmEnrollment`'s compare-and-promote atomic in the store.
- TOTP secrets were stored in plaintext with no way to encrypt them.
  `totp.WithEncryptor` closes this application-side.
- Password reset requests, magic-link requests, and login attempts had no
  rate limiting at all. Closed by rate limiting on by default.
- `CreatePasswordResetToken` let a caller enumerate registered email
  addresses via the response shape and timing. Closed by equalizing both
  to the same `("", nil)` shape and the same work.
- Cookie-mode sessions had no CSRF defense. Closed by `RequireSameOrigin`
  and the double-submit token helpers, plus secure cookie defaults.
- An account with no email verification flow could log in indefinitely
  even though its email was never confirmed. Closed by
  `RequireVerifiedEmail` defaulting to `true`.
- Automatic lockout bookkeeping was only cleared by a successful
  password verify, so an attacker could lock a victim out even through
  the victim's own password reset (a stronger identity proof than the
  login password itself). Closed by clearing lockout state in
  `ChangePassword`/`ResetPassword`/`SetInitialPassword` too.
- Fuzzing (`FuzzRecoveryCanonical`) found and fixed a genuine
  non-idempotency bug in `recovery.canonical`, discovered within seconds
  of the first non-seed run.
- The default minimum password length (8) was below current guidance;
  raised to 12.
- `passwordcheck.WithHIBPFailClosed()` did not reject a password when the
  HIBP range response row matching that password's suffix had a count this
  client could not parse — it silently fell through to "not found" and
  accepted the password, the one case where fail-closed's "no password
  without a completed check" promise did not actually hold. `HIBP.lookup`
  now surfaces that row as an error like any other failed lookup, so
  fail-closed rejects it via an error wrapping the newly-exported
  `passwordcheck.ErrMalformedResponse`, letting applications distinguish
  corrupted-response data from transport failures with `errors.Is` and
  build custom policy in their own `PasswordChecker` wrapper; the
  fail-open default is unchanged; a malformed row for an unrelated
  suffix is still ignored.

## Migration guide

For each breaking change above: what it used to look like, what it looks
like now, and the smallest change that gets you working again.

**`New` requires a `SecondFactorChecker` and can fail**
Was: `auth := sulis.New(users, sessions, tokens)`
Now: `auth, err := sulis.New(users, sessions, tokens, factors)`
Do this: pass a real `SecondFactorChecker` if you have second factors, or
`sulis.NoSecondFactors{}` if you don't; handle the returned `error`.

**`Session.Token` removed**
Was: `session.Token` held the raw bearer token after `CreateSession`.
Now: the raw token is a separate return value everywhere a session is
minted (`Register`, `Login`'s `LoginResult.SessionToken`, `IssueSession`,
`IssueSessionUnchecked`, …). There is no field to read it from.
Do this: capture the function's token return value at the call site
instead of reading it back off the `*Session` afterward.

**`Login`/`RedeemMagicLink` return `*LoginResult`**
Was: `user, session, err := auth.Login(ctx, email, password)`
Now: `result, err := auth.Login(ctx, email, password, ri)`
Do this: check `result.NeedsSecondFactor` first. If false, use
`result.User`/`result.Session`/`result.SessionToken`; if true, use
`result.PendingToken` with `CompleteTwoFactor`.

**`CompleteTwoFactor` returns `*LoginResult` and takes `RequestInfo`**
Was: `user, session, err := auth.CompleteTwoFactor(ctx, userID, rawToken)`
Now: `result, err := auth.CompleteTwoFactor(ctx, userID, rawToken, ri)`
Do this: pass the `RequestInfo` you have for this request, and read
`result.User`/`result.Session`/`result.SessionToken` instead of the old
positional returns — the same shape as `Login`'s `*LoginResult` above,
since completing a second factor is the other half of that same flow.
`NeedsSecondFactor` is always `false` here (there is no third factor), but
the field still exists on the returned `*LoginResult`.

**`RevokeSession` is user-scoped**
Was: `auth.RevokeSession(ctx, sessionID)`
Now: `auth.RevokeSession(ctx, userID, sessionID)`
Do this: pass the session's owning user ID (typically the caller's own,
from their validated session) — this is also what makes the call safe to
expose to end users at all.

**`IssueSession` takes an `Authentication`; `IssueSessionUnchecked` is the old shape**
Was: `session, err := auth.IssueSession(ctx, userID)`
Now: `session, token, err := auth.IssueSessionUnchecked(ctx, userID, method)`
Do this: if you have a bare user ID and no `sulis`-verified proof (e.g.
after your own passkey ceremony), call `IssueSessionUnchecked` with the
`AuthMethod` you're vouching for. `IssueSession` itself is now only
reachable with an `Authentication` this package minted internally.

**`SessionStore.DeleteSession` is user-scoped; three new required methods**
Was: `DeleteSession(ctx, id) error`.
Now: `DeleteSession(ctx, userID, id) error`, plus `TouchSession(ctx, id,
lastSeen, idleExpires) error`, `UpdateAuthenticatedAt(ctx, id, at) error`,
and `DeleteUserSessionsExcept(ctx, userID, keepSessionID) error`.
Do this: add `userID` to your `DeleteSession`'s `WHERE` clause (atomically
with the lookup), and implement the three new methods — or switch to
`memstore`/`store/sql`'s reference implementations and run `storetest`
against your own to confirm.

**`CreatePasswordResetToken` no longer errors on an unknown address**
Was: an unregistered email returned `ErrUserNotFound`.
Now: it returns `("", nil)`.
Do this: stop branching on `ErrUserNotFound` from this call; return the
same generic "if that address is registered…" response regardless. Use
`CreatePasswordResetTokenStrict` (never on a public endpoint) if you
genuinely need to know.

**Default minimum password length raised to 12**
Was: `MinPasswordLength` defaulted to 8.
Now: it defaults to 12.
Do this: nothing, unless you were relying on the old default for existing
short passwords — those still verify (this only gates new passwords), but
call `WithPasswordLengthLimits` explicitly if you need a different floor.

**`RequestInfo` threaded through most flows**
Was: e.g. `auth.Register(ctx, email, password)`.
Now: `auth.Register(ctx, email, password, ri)`.
Do this: pass `sulis.RequestInfo{IP: r.RemoteAddr, UserAgent:
r.UserAgent()}` (or `sulis.RequestInfo{}` if you have nothing to report) —
it feeds the IP dimension of rate limiting and is recorded on the session.

**`User.Version` and store-layer uniqueness/optimistic concurrency**
Was: `UserStore.UpdateUser` had no concurrency contract, and email
uniqueness was assumed rather than required.
Now: `User.Version` MUST round-trip through a compare-and-swap in
`UpdateUser` (`ErrConcurrentUpdate` on a stale write), and both
`CreateUser`/`UpdateUser` MUST return `ErrUserAlreadyExists` on an email
collision enforced at the storage layer (e.g. a `UNIQUE` index).
Do this: add a `version` column (increment on write, `WHERE version = ?`
in the update) and a unique index on the normalized email column. Run
`storetest.RunUserStore` to confirm.

**`CreateMagicLinkToken` returns a binding nonce; `RedeemMagicLink` takes it**
Was: `token, err := auth.CreateMagicLinkToken(ctx, email)` /
`user, session, err := auth.RedeemMagicLink(ctx, rawToken)`
Now: `token, nonce, err := auth.CreateMagicLinkToken(ctx, email, ri)` /
`result, err := auth.RedeemMagicLink(ctx, rawToken, nonce, ri)`
Do this: store the nonce server-side (a short-lived cookie or session tied
to the browser that requested the link — never inside the emailed link
itself) and pass it back into `RedeemMagicLink`. See README's "Binding a
magic link to its requester" for the full flow and why this closes a
link-forwarding/prefetch attack.

**`totp.Validate` is error-only**
Was: `ok, err := svc.Validate(ctx, userID, code); if err == nil && !ok { ... }`
Now: `err := svc.Validate(ctx, userID, code); if err != nil { ... }`
Do this: check `err` alone. A wrong code, a replayed code, and "not
enrolled" are now distinguishable sentinel errors instead of a single
`false`.

**`totp.Store` splits pending from active enrollments**
Was: `SaveTOTP`, `GetTOTPByUserID`, `DeleteTOTP` — one slot per user.
Now: `GetActiveTOTP`, `GetPendingTOTP`, `EnrollPending`, `ReplacePending`,
`ConfirmEnrollment(ctx, userID, pendingID, counter)`, plus the retained
`SaveTOTP`/`DeleteTOTP` with tightened contracts.
Do this: rewrite your `totp.Store` implementation against the new
interface (see `totp/store.go`'s doc comments for the exact atomicity
requirements and reference SQL), or adopt `memstore`/`store/sql`.

**`passkey.User.Credentials` removed**
Was: callers populated `passkey.User{ID, Name, DisplayName, Credentials}`.
Now: `passkey.User{ID, Name, DisplayName}` — `Service` loads credentials
from `Store` itself.
Do this: stop populating `Credentials`; nothing else changes at call sites.

**`BeginLogin`/`FinishLogin` need a ceremony ID**
Was: `assertion, err := svc.BeginLogin(ctx, user)` /
`cred, err := svc.FinishLogin(ctx, user, r)`
Now: `assertion, ceremonyID, err := svc.BeginLogin(ctx, user)` /
`cred, err := svc.FinishLogin(ctx, user, ceremonyID, r)`
Do this: hand `ceremonyID` to the client (or hold it server-side) between
the two calls and pass it back into `FinishLogin`/`FinishLoginResponse`.

**`passkey.Store` method changes**
Was: `UpdateCredentialSignCount(ctx, credentialID, signCount) error`;
`DeleteCredential(ctx, id) error`.
Now: `UpdateCredentialAfterLogin(ctx, credentialID, signCount, backupState,
lastUsedAt) error`; `DeleteCredential(ctx, userID, id, allowLast) error`,
required to atomically refuse deleting a user's last credential unless
`allowLast` is set.
Do this: rewrite your `passkey.Store` implementation against the new
method set — see `passkey/store.go`'s doc comments for the atomicity
requirement and reference SQL, or adopt `memstore`/`store/sql`.

**`recovery.Consume` returns a remaining count**
Was: `err := svc.Consume(ctx, userID, code)`
Now: `remaining, err := svc.Consume(ctx, userID, code)`
Do this: capture the extra return value if you want to show a "N codes
left" nudge; ignore it (`_`) otherwise.
