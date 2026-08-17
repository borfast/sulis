# Security Hardening v1 Implementation Plan

> **Read `PROGRESS.md` in this directory FIRST.** It holds the live task list, current position, and ratified API decisions. This file is a stable reference and does not change as work proceeds. `PROGRESS.md` is the only state file and must be updated in the same commit as every code change.

**Goal:** Close all 33 findings from `docs/security-audit-2026-08-17.html` and land every breaking API change in one pass, before tagging v1.

**Approach:** Three structural moves carry most of the risk reduction:
1. Make the library aware of second factors, so no path issues a session without consulting them.
2. Make unsafe store implementations impossible rather than discouraged — optimistic concurrency, atomic consumption, a published conformance suite.
3. Invert every unsafe default.

**Spec:** `docs/security-audit-2026-08-17.html`. Read the finding before starting the task that fixes it — the audit carries the threat model and evidence, this plan carries the work.

## Global Constraints

- Go 1.25.0 floor. Test against the two most recent Go releases.
- No new third-party dependencies in the root module or `totp/`, `passkey/`, `recovery/`. New deps live in `store/sql/` as its own module.
- Breaking changes are expected. Land them all before v1.0.0.
- Sentinel errors use the package prefix: `sulis:`, `totp:`, `passkey:`, `recovery:`.
- Raw secrets — passwords, tokens, session tokens, TOTP secrets, recovery codes — never appear in error messages, events, or logs.
- TDD per task: failing test → watch it fail → minimal implementation → watch it pass → commit.
- Every task ends green: `go build ./... && go vet ./... && go test -race ./...`.
- Commits: imperative subject line, no type prefix, body wrapped at ~72 columns. No trailers.
- Root tests extend the existing fakes in `sulis_test.go` until T401 moves them to `storetest`.
- README and `doc.go` are updated by the task that changes the behavior, not in a later sweep.

## Specification level

Phase 0–1 tasks carry concrete signatures and test names. Phase 2–7 tasks carry target signatures, required test cases, files, and acceptance criteria — but not pre-written implementation bodies, which would drift before they were reached. **Appendix A is the binding contract that keeps all 38 tasks type-consistent.** Amend it only in `PROGRESS.md`, with a reason.

---

## File Map

**Root package** — `sulis.go` (service, registration, password flows, validation), `config.go`, `user.go`, `session.go`, `token.go`, `magiclink.go`, `twofactor.go`, `emailverification.go`, `middleware.go`, `errors.go`.

**New root files** — `issue.go` (session issuance + `Authentication`), `changeemail.go`, `limiter.go`, `status.go`, `stepup.go`, `events.go`, `cookie.go`, `csrf.go`, `doc.go`.

**Subpackages** — `totp/` (gains `encrypt.go`), `passkey/` (T204 splits out `http.go`), `recovery/`.

**New packages** — `storetest/` (exported conformance suite), `memstore/` (in-memory reference stores, moved out of `sulis_test.go` in T401), `passwordcheck/` (blocklist + HIBP), `store/sql/` (separate module: Postgres + SQLite).

---

## Phase 0 — Foundations

### T001 · D2 — Harden CI

**Files:** `.github/workflows/ci.yml`, `.github/dependabot.yml` (new)

**Why first:** `govulncheck@latest` executes unpinned code in CI, and every later task is verified by this pipeline.

- [ ] Pin actions to commit SHAs; pin `govulncheck` to a version; add `permissions: contents: read`.
- [ ] Add a Go version matrix (`1.25.x`, `stable`).
- [ ] Add `gofmt -l .` gate, pinned `staticcheck`, pinned `gosec`.
- [ ] Change the test step to `go test -race -covermode=atomic -coverprofile=coverage.out -count=1 ./...`.
- [ ] Add `dependabot.yml` for `gomod` and `github-actions`, weekly.
- [ ] Fix all pre-existing `staticcheck`/`gosec` findings in this task. Suppress only with a narrow comment saying who decided and why.
- [ ] Commit.

**Done when:** CI runs pinned tools with a read-only token and the repo is clean under all gates.

---

### T002 — Ratify the target API surface

**Files:** `PROGRESS.md` (Decisions Log). No code.

15 breaking changes across 36 tasks and many sessions will drift unless the destination is written down once.

- [ ] Read Appendix A.
- [ ] Answer the four open questions at the end of Appendix A. Each has a recommendation; ask the user if unsure.
- [ ] Copy the final surface into `PROGRESS.md` under "Ratified API". Note any deviation with a one-line reason.
- [ ] Commit.

**Done when:** `PROGRESS.md` holds the complete ratified surface.

---

## Phase 1 — Close the bypasses

### T101 · A3 — Stop whole-row user writes resurrecting old credentials

**Files:** `user.go`, `errors.go`, `sulis.go:223-247`, `emailverification.go:56-75`, `sulis_test.go`

**Produces:** `User.Version uint64`; `ErrConcurrentUpdate`; `updateUserWithRetry(ctx, userID string, mutate func(*User) error) (*User, error)`. T107, T502, T504 reuse the helper — do not duplicate the retry loop.

- [ ] Write `TestConcurrentResetAndVerifyDoesNotResurrectOldHash`: add a `beforeUpdate` hook to `memUserStore` so the test can let a full `ResetPassword` land between `VerifyEmail`'s read and its write. Assert the new password verifies and the old one does not.
- [ ] Run it. It fails — the old password still verifies.
- [ ] Add `User.Version`. Document on `UpdateUser` that stores must apply only if the persisted version matches, then increment, returning `ErrConcurrentUpdate` on mismatch. Include the reference SQL in the comment.
- [ ] Add `updateUserWithRetry` (reload, mutate, update, retry up to 3× on conflict). Route `setPassword` and `stampEmailVerified` through it. Hash before the mutation so a retry does not repeat the Argon2 cost.
- [ ] Make `memUserStore` enforce versioning — it is the reference other developers read.
- [ ] Run the test, run the suite, update the README store contract, commit.

**Done when:** No library code writes a whole user row from a stale read, proven by the race test.

---

### T102 · A1 — Make session issuance aware of second factors

**Files:** `issue.go` (new), `sulis.go`, `config.go`, `errors.go`, `sulis_test.go`

**Produces:** `SecondFactorChecker`, `NoSecondFactors`, `LoginResult`, `AuthMethod` + constants, `RequestInfo`, `New(...) (*Sulis, error)`. T103, T104, T305, T502 depend on these exact names.

The core fix: today `Login` returns a privileged session on a correct password alone.

- [ ] Write three failing tests: a user with a second factor gets `NeedsSecondFactor` and a `PendingToken` but no session; a user without one gets a session; a checker error fails closed.
- [ ] Run them. They fail.
- [ ] Add the types per Appendix A. `Session`/`SessionToken` and `PendingToken` are mutually exclusive — never populate both.
- [ ] Make the checker a required argument to `New`. Return an error if nil; do not substitute a no-op, since that is the bypass being closed. Applications with no factors pass `NoSecondFactors{}` — visible and greppable.
- [ ] Move issuance into `issue.go`. `Login` → `VerifyPassword` → consult checker → pending token or session. Keep `requireVerifiedEmail` ahead of both branches.
- [ ] Run the tests, update every call site, run the suite, update the README, commit.

**Done when:** No password-authenticated path produces a session without consulting the checker. Verify by grepping `createSession` — every caller either consults the checker, or is `Register` (documented exempt) or `CompleteTwoFactor` (factor just verified).

---

### T103 · A1 — Close the magic-link 2FA bypass

**Files:** `magiclink.go`, `sulis_test.go`

**Produces:** `RedeemMagicLink(ctx, rawToken string, ri RequestInfo) (*LoginResult, error)`. T508 later adds a `bindingNonce` parameter — that is deliberate evolution, not a contradiction with Appendix A.

Currently anyone who can read the mailbox bypasses 2FA entirely, with no hook to stop it.

- [ ] Write two failing tests: a user with a second factor gets a pending token, not a session; redemption still stamps `EmailVerifiedAt` even when a factor is pending.
- [ ] Run them. They fail.
- [ ] Return `*LoginResult`. Order: consume token → resolve or create user → `stampEmailVerified` → consult checker → session or pending token. Verification must precede the branch, or a 2FA user could never verify this way.
- [ ] Run the tests, update call sites, run the suite, commit.
- [ ] README: a magic link is a full first factor and is gated by 2FA exactly like a password.

**Done when:** Magic-link redemption cannot skip an enrolled second factor.

---

### T104 · B5 — Remove `Session.Token`

**Files:** `session.go`, `issue.go`, `middleware.go`, `sulis_test.go`, `middleware_test.go`

**Produces:** `Session` with no `Token` field; `createSession(ctx, userID string, method AuthMethod) (*Session, string, error)`; `IssueSession` returning `(*Session, string, error)`.

Small now that the raw token flows through `LoginResult`. Doing it here means every store from T401 on never sees a raw token.

- [ ] Write `TestSessionStructHasNoRawTokenField` using reflection, so the field cannot be reintroduced without failing CI.
- [ ] Run it. It fails.
- [ ] Delete the field; return the raw token separately. Delete the defensive copy-and-blank in `createSession` — no longer needed, which is the point.
- [ ] Run the tests, update call sites, run the suite, update the README, commit.

**Done when:** `Session` has no `Token` field and a test guards it.

---

### T105 · A2 — Require WebAuthn user verification

**Files:** `passkey/passkey.go`, `passkey/passkey_test.go`, `passkey/testauth_test.go` (new)

**Produces:** `WithUserVerification(protocol.UserVerificationRequirement) Option`, default `protocol.VerificationRequired`.

Evidence: `AuthenticatorSelection` is left at zero, so `UserVerification` is `""`. go-webauthn gates the check on `== protocol.VerificationRequired` (`webauthn/login.go:354`, `webauthn/registration.go:149`), so a presence-only tap is accepted today.

- [ ] Build a minimal test authenticator in `testauth_test.go` (T206 reuses it) that can forge an assertion with the UV bit clear. Assert `FinishLogin` rejects it under the default.
- [ ] Run it. It fails — the UV-absent assertion is accepted.
- [ ] Add a service `Config` with `UserVerification` defaulting to required. Set `webauthn.Config.AuthenticatorSelection.UserVerification`, and pass `webauthn.WithUserVerification(...)` to `BeginLogin` and `BeginDiscoverableLogin` so the requirement reaches the finish step.
- [ ] Run the tests, run the suite, commit.
- [ ] Document: `discouraged` is only defensible when the passkey is a second factor behind a password. As a sole factor, UV is what makes it two factors.

**Done when:** A UV-absent assertion is rejected by default, proven by test.

---

### T106 · B1 — Rate limiting on by default, with an IP dimension

**Files:** `limiter.go` (new), `config.go`, `sulis.go`, `magiclink.go`, `twofactor.go`, `emailverification.go`, `limiter_test.go`

**Produces:** `NewMemoryLimiter(...)` (satisfies both `sulis.Limiter` and `totp.Limiter` structurally); `WithoutRateLimiting() Option`. `WithLimiter` stays for custom implementations.

A nil limiter is a silent no-op, so guessing runs at full speed unless the adopter reads the README.

- [ ] Write four failing tests: the default throttles per-account guessing; it throttles per-IP guessing spread across accounts; `WithoutRateLimiting` disables it; the bucket refills.
- [ ] Run them. They fail.
- [ ] Implement a token bucket keyed by string, with an injectable clock, and **bounded key cardinality** (LRU or periodic sweep) — a limiter that can be OOM'd is a denial of service, not a defense.
- [ ] Make it the default. Add `WithoutRateLimiting`. Add IP-keyed budgets at each choke point when `ri.IP != ""`: `password:ip:`, `reset:ip:`, `magic:ip:`.
- [ ] Tune the two dimensions separately: generous per-account (an attacker must not be able to lock a victim out by burning their budget), strict per-IP.
- [ ] Run the tests, run the suite, commit.
- [ ] Rewrite the README's "rate limiting is required in production" into "on by default; here is how to replace it for multi-instance, and why the default is per-process".

**Done when:** A `Sulis` built with no options throttles both dimensions, and disabling requires an explicit call.

---

### T107 · C1 — Own the email-change flow

**Files:** `changeemail.go` (new), `user.go`, `token.go`, `errors.go`, `sulis_test.go`

**Produces:** `ChangeEmail(ctx, userID, newEmail string) (string, error)`; `ConfirmEmailChange(ctx, rawToken string) (*User, error)`; `TokenPurposeEmailChange`; `User.PendingEmail`.

Nothing clears `EmailVerifiedAt` when the address changes and no method owns the change, so applications will mutate `user.Email` and keep the stamp — an unverified address treated as verified, which defeats the `RequireVerifiedEmail` gate and is the standard takeover pivot.

- [ ] Write five failing tests: `ChangeEmail` stages without changing the live address; `ConfirmEmailChange` swaps and re-stamps verification; the swap revokes sessions and purges reset tokens; a token for a superseded address is rejected; an address already in use fails before a token is issued.
- [ ] Run them. They fail.
- [ ] Implement: `ChangeEmail` normalizes, checks uniqueness, writes `PendingEmail`, issues a token bound to it. `ConfirmEmailChange` consumes, checks `token.Email == user.PendingEmail`, swaps, clears pending, re-stamps, revokes sessions, purges reset and 2FA tokens.
- [ ] Run the tests, run the suite, commit.
- [ ] Document that the caller must notify the **old** address — that notification is how a victim catches a takeover in progress. The library does not send mail.

**Done when:** The live address can only change through `ConfirmEmailChange`, which re-establishes verification from scratch.

---

## Phase 2 — Passkey hardening

One context: everything is in `passkey/`. Three Group A defects live here and coverage is the lowest (59%).

### T201 · A4 — Atomic challenge consumption

**Files:** `passkey/store.go`, `passkey/passkey.go`, `passkey/passkey_test.go`

**Produces:** `ChallengeStore` with `SaveChallenge` + `ConsumeChallenge(ctx, key string) ([]byte, error)`. `GetChallenge`/`DeleteChallenge` removed.

Get-then-`defer` Delete means two concurrent finishes with the same assertion both succeed. The only place in the library where single-use is intent rather than mechanism.

- [ ] Write a failing concurrency test: two goroutines finish the same ceremony; exactly one succeeds, the other gets `ErrChallengeExpired`.
- [ ] Run it under `-race`. It fails.
- [ ] Replace the pair with `ConsumeChallenge`, documented as atomic fetch-and-delete. Name the reference implementations: Redis `GETDEL`, SQL `DELETE ... RETURNING`.
- [ ] Key login challenges per ceremony, not per user — `BeginLogin` returns a ceremony ID like `BeginDiscoverableLogin` already does, so a second login cannot clobber the first device's challenge. Signature change; see Appendix A.
- [ ] Run the tests, update the in-memory test store, run the suite, update the README, commit.

**Done when:** A challenge can be consumed exactly once, proven by a race test.

---

### T202 · A5 — Populate `excludeCredentials` from the store

**Files:** `passkey/passkey.go`, `passkey/passkey_test.go`

`BeginLogin` loads credentials from the store; `BeginRegistration` does not, so the browser's "you already registered this key" prompt never fires.

- [ ] Write a failing test: register a credential, then assert `BeginRegistration` for that user returns options whose `ExcludeCredentials` contains it.
- [ ] Run it. It fails.
- [ ] Load credentials from the store inside `BeginRegistration`, ignoring `user.Credentials`.
- [ ] Remove `Credentials` from the exported `User` struct so it cannot be misread as an input; build the `webauthn.User` adapter internally.
- [ ] Run the tests, run the suite, commit.

**Done when:** Registration excludes existing credentials without caller cooperation.

---

### T203 · A6 — Request resident keys

**Files:** `passkey/passkey.go`, `passkey/store.go`, `passkey/passkey_test.go`

**Produces:** `WithResidentKey(protocol.ResidentKeyRequirement) Option`, default required; `Credential.Discoverable bool`.

`BeginDiscoverableLogin` exists but registration never asks for a discoverable credential, so usernameless login works only by luck — and the fallback trains users back onto the password.

- [ ] Write a failing test asserting options request `residentKey: required` and set legacy `RequireResidentKey`.
- [ ] Run it. It fails.
- [ ] Add the option, set both fields, persist `Discoverable` from the registration response.
- [ ] Run the tests, run the suite, commit.

**Done when:** Registration requests discoverable credentials by default and records what it got.

---

### T204 · A7 — Bound the ceremony body, decouple from `net/http`

**Files:** `passkey/http.go` (new), `passkey/passkey.go`, `passkey/passkey_test.go`

**Produces:** `WithMaxCeremonyBody(int64) Option` (default 64 KiB); `FinishRegistrationResponse`, `FinishLoginResponse`, `FinishDiscoverableLoginResponse` taking `[]byte`. The `*http.Request` methods become thin wrappers.

go-webauthn's `decodeBody` is a bare `json.NewDecoder(body).Decode(v)` with no limit (`protocol/decoder.go:10`). Because sulis owns the `*http.Request`, consumers have no place to wrap it.

- [ ] Write a failing test posting an oversized body; expect a bounded error.
- [ ] Run it. It fails.
- [ ] Add the byte-slice core methods, move HTTP wrappers to `http.go`, wrap `r.Body` in `http.MaxBytesReader`.
- [ ] Run the tests, run the suite, commit.

**Done when:** Oversized bodies are rejected cheaply and the core no longer requires `net/http`.

---

### T205 · C12 — Record credential metadata

**Files:** `passkey/store.go`, `passkey/passkey.go`, `passkey/passkey_test.go`

**Produces:** `Credential` gains `Name`, `Transports`, `BackupEligible`, `BackupState`, `LastUsedAt`. Store gains `DeleteCredentialsByUserID`, `RenameCredential`.

Backup flags tell you whether a passkey is cloud-synced or hardware-bound — a real policy input, currently discarded. Without `Name`/`LastUsedAt` no management UI is buildable.

- [ ] Write failing tests: flags persisted from registration; `LastUsedAt` advanced on a successful assertion; deleting the last credential rejected without an explicit override.
- [ ] Run them. They fail.
- [ ] Persist flags and transports from `waCredential.Flags`/`.Transport`. Update `LastUsedAt` in `finishLoginCredential` alongside the sign count.
- [ ] Add the last-factor deletion guard — for a passwordless account, removing the final credential is permanent lockout.
- [ ] Run the tests, run the suite, commit.

**Done when:** A management UI is buildable and last-factor deletion requires intent.

---

### T206 · D3 — Bring passkey coverage to parity

**Files:** `passkey/passkey_test.go`, `passkey/testauth_test.go`

- [ ] Extend the T105 test authenticator to forge responses with controllable flags, origins, RPID, sign counts, and user handles.
- [ ] Add cases: clone-warning rejection; origin mismatch; RPID mismatch; discoverable handler where the credential belongs to a different user than the user handle; absent/expired challenge; malformed CBOR.
- [ ] Verify the CodeGraph-flagged gaps (`issueSessionForUser`, `stampEmailVerified`'s store calls, `requireVerifiedEmail`) are genuinely exercised through their callers; add direct tests if not.
- [ ] Run coverage; confirm `passkey` is at or above the other packages. Commit.

**Done when:** Every ceremony rejection path has a test.

---

## Phase 3 — Safe defaults

### T301 · B4 — `totp.Validate` returns `error` only

**Files:** `totp/totp.go`, `totp/totp_test.go`

**Produces:** `Validate(ctx, userID, code string) error`.

An invalid code is `(false, nil)` today, so this reads as correct and is a total bypass:

```go
if _, err := totpSvc.Validate(ctx, userID, code); err != nil {
    return unauthorized(w)
}
grantSession(w, userID) // reached for every wrong code
```

- [ ] Write a failing test asserting a wrong code returns an error matching `ErrTOTPInvalid`.
- [ ] Run it. It fails.
- [ ] Change the signature. Keep `ErrTOTPReplayed` and `ErrTOTPNotVerified` distinct.
- [ ] Run the tests, update call sites and the README, run the suite, commit.

**Done when:** The bypass above is unwritable.

---

### T302 · A8 — `totp.Enroll` cannot clobber a verified factor

**Files:** `totp/totp.go`, `totp/store.go`, `totp/totp_test.go`

**Produces:** `ErrTOTPAlreadyEnrolled`; `ReplaceEnrollment(ctx, userID, accountName string) (secret, uri string, err error)`; store methods separating pending from active.

One stray call — double-submitted form, CSRF'd POST, retried request — replaces a confirmed factor with an unconfirmed one.

- [ ] Write failing tests: `Enroll` on a verified user returns `ErrTOTPAlreadyEnrolled`; a pending enrollment does not disturb the active credential; `Validate` keeps working while one is pending; `ReplaceEnrollment` explicitly supersedes.
- [ ] Run them. They fail.
- [ ] Separate pending from active in the store contract. `ConfirmEnrollment` promotes pending to active, carrying the counter forward monotonically.
- [ ] Run the tests, run the suite, commit.
- [ ] Document that enrollment endpoints require recent authentication (T501).

**Done when:** A working second factor cannot be disabled by a single request.

---

### T303 · B3 — `RevokeSession` takes a user ID

**Files:** `sulis.go`, `session.go`, `sulis_test.go`

**Produces:** `RevokeSession(ctx, userID, sessionID string) error`; `SessionStore.DeleteSession(ctx, userID, id string) error`.

- [ ] Write a failing test: revoking user B's session as user A returns `ErrSessionNotFound` and leaves it intact.
- [ ] Run it. It fails.
- [ ] Add the user ID to both signatures; scope the store delete to both columns.
- [ ] Run the tests, update call sites and the README, run the suite, commit.

**Done when:** Cross-user revocation is impossible through the public API.

---

### T304 · B2 — `CreatePasswordResetToken` stops leaking existence

**Files:** `sulis.go`, `sulis_test.go`

**Produces:** `CreatePasswordResetToken(ctx, email string, ri RequestInfo) (string, error)` returning `("", nil)` for an unknown address; `CreatePasswordResetTokenStrict` for admin tooling.

The README currently tells consumers to flatten `ErrUserNotFound` themselves. There is also a timing channel no response normalization fixes: the existing-user path generates and stores a token, the missing-user path returns immediately.

- [ ] Write failing tests: unknown address returns `("", nil)`; the unknown path performs equivalent work (assert via an instrumented store that a token was generated and discarded).
- [ ] Run them. They fail.
- [ ] Generate and discard on the unknown path, then return empty. Keep the limiter call ahead of the branch.
- [ ] Run the tests, rewrite the README warning as a description of the safe default, commit.

**Done when:** The endpoint cannot distinguish registered from unregistered addresses by result or timing.

---

### T305 · B6 — Make "already authenticated" a type

**Files:** `issue.go`, `twofactor.go`, `sulis_test.go`

**Produces:** `Authentication` (opaque, unexported fields); `IssueSession(ctx, auth Authentication) (*Session, string, error)`; `IssueSessionUnchecked(ctx, userID string, method AuthMethod) (*Session, string, error)`.

- [ ] Write a failing test asserting the zero-value `Authentication` is rejected at issuance.
- [ ] Run it. It fails.
- [ ] Add the type. Completion paths mint it. Applications with a factor sulis does not know about call `IssueSessionUnchecked`, whose name appears in their code review rather than only in our docs.
- [ ] Run the tests, update call sites and the README, run the suite, commit.

**Done when:** Minting a session for an arbitrary user ID requires a method with "Unchecked" in its name.

---

## Phase 4 — Store contracts and fuzzing

Done before Phase 5 extends the interfaces further.

### T401 · D1 — Publish a store conformance suite

**Files:** `storetest/*.go` (new), `sulis_test.go`

**Produces:** `storetest.RunUserStore(t *testing.T, factory func() sulis.UserStore)` and one `Run*` per interface. Exported — a supported part of the public API.

Highest leverage item in the audit. Atomicity of `ConsumeToken`, `ConsumeCode`, `ConsumeChallenge`, monotonicity of `SaveTOTP`, and version checking on `UpdateUser` are all prose today, and every adopter hand-writes the SQL.

- [ ] Write the suite for `TokenStore` first, including N goroutines consuming the same token with exactly one winner.
- [ ] Run it against `memTokenStore`, then deliberately break the fake's atomicity and confirm the suite catches it. A conformance suite that cannot fail is decoration.
- [ ] Extend to every interface, each atomicity and monotonicity requirement race-hammered under `-race`.
- [ ] Move the in-memory fakes out of `sulis_test.go` into a `memstore` package so the suite has a reference implementation and adopters have something to read.
- [ ] Document it in the README as the supported integration path, with the five-line example.
- [ ] Run the suite, commit.

**Done when:** An adopter can prove their store compliant in five lines, and the suite demonstrably fails on a non-atomic implementation.

---

### T402 · D4 — Fuzz the parsers

**Files:** `fuzz_test.go`, `totp/fuzz_test.go`, `recovery/fuzz_test.go`, `testdata/fuzz/**`

Four hand-rolled parsers with no fuzzing: `decodeHash` (`password.go:60`), `normalizeEmail`, `recovery.canonical`, and the base32 decode in `generateCode`.

- [ ] `FuzzDecodeHash` — no panic; `hashPassword` output always decodes.
- [ ] `FuzzNormalizeEmail` — no panic; idempotent; any accepted address is lowercase and trimmed.
- [ ] `FuzzRecoveryCanonical` — no panic; idempotent.
- [ ] `FuzzGenerateCode` — no panic; output is always exactly `Digits` ASCII digits.
- [ ] Run each for 60s, check in crashers and a seed corpus, fix what they surface.
- [ ] Add a 10s smoke run to CI, commit.

**Done when:** All four parsers have fuzz targets with checked-in corpora.

---

## Phase 5 — Complete the feature set

Each task that adds a store method extends the T401 suite in the same commit.

### T501 · C7 — Step-up authentication

**Files:** `stepup.go` (new), `session.go`, `issue.go`, `errors.go`, `sulis_test.go`, `storetest/session.go`

**Produces:** `Session.AuthenticatedAt`, `Session.Method`; `RequireRecentAuth(ctx, session *Session, maxAge time.Duration) error`; `ErrReauthRequired`; `ReAuthenticate(ctx, session *Session, password string, ri RequestInfo) error`.

Enrolling TOTP, adding or removing a passkey, disabling 2FA, changing email, and regenerating recovery codes should require proving ownership now, not holding a cookie from this morning.

- [ ] Write failing tests: a session older than `maxAge` returns `ErrReauthRequired`; `ReAuthenticate` refreshes the stamp without minting a new session or rotating the token; a wrong password does not refresh it.
- [ ] Run them. They fail.
- [ ] Record `AuthenticatedAt` and `Method` at issuance; add the check and the re-auth flow.
- [ ] Extend the conformance suite. Run the suite.
- [ ] README: enumerate explicitly which operations should be gated, so adopters do not guess. Commit.

**Done when:** Applications can require recent authentication without inventing it.

---

### T502 · C5 — Account disable and lockout

**Files:** `status.go` (new), `user.go`, `sulis.go`, `issue.go`, `errors.go`, `sulis_test.go`, `storetest/user.go`

**Produces:** `User.DisabledAt`, `User.LockedUntil`; `DisableUser(ctx, userID, reason string) error`; `EnableUser`; `ErrAccountDisabled`, `ErrAccountLocked`.

There is no way to take an account out of service: delete its sessions and the next correct password mints a new one.

- [ ] Write failing tests: a disabled user cannot authenticate; existing sessions die immediately via `ValidateSession`; a locked account recovers when `LockedUntil` passes; `DisableUser` revokes sessions.
- [ ] Run them. They fail.
- [ ] Check status in `VerifyPassword`, every issuance path, and `ValidateSession`. The `ValidateSession` check matters most — without it, disabling leaves live sessions working for the full session lifetime.
- [ ] Add optional automatic lockout after N failures with exponential backoff. Default it **off**: attacker-triggered lockout is itself a denial of service. Prefer long backoff over a hard lock.
- [ ] Extend the conformance suite, run the suite, commit.

**Done when:** Disabling an account immediately invalidates every existing session.

---

### T503 · C10 — Session visibility and lifecycle

**Files:** `session.go`, `issue.go`, `middleware.go`, `config.go`, `sulis_test.go`, `storetest/session.go`

**Produces:** `Session.LastSeenAt`, `IdleExpiresAt`, `IP`, `UserAgent`; `ListUserSessions`; `SessionStore.TouchSession`, `DeleteUserSessionsExcept`; `RefreshSession`; `WithIdleTimeout(d) Option`.

No list operation means no "where you're signed in" screen — the control that lets a user evict an intruder themselves.

- [ ] Write failing tests: sessions carry their `RequestInfo`; `ListUserSessions` returns them with no token material; an idle session past `IdleExpiresAt` fails validation before `ExpiresAt`; `RefreshSession` rotates the token while preserving the row and `AuthenticatedAt`.
- [ ] Run them. They fail.
- [ ] Populate metadata at issuance; touch on validation; add idle timeout and refresh. Throttle the touch write (only when `LastSeenAt` is older than an interval) and document the cost — otherwise it is a write per request.
- [ ] Assert no listing path exposes `TokenHash`.
- [ ] Extend the conformance suite, run the suite, commit.

**Done when:** A device-management UI is buildable and idle sessions expire.

---

### T504 · C3 — Rehash on login

**Files:** `password.go`, `sulis.go`, `password_test.go`, `sulis_test.go`

**Produces:** internal `needsRehash(encoded string, want Argon2Params) bool`. No public signature change.

`verifyPassword` reads cost parameters out of the stored hash and never compares them to the configured ones, so raising `Argon2Params` is silently cosmetic for the installed base.

- [ ] Write failing tests: a weaker stored hash is upgraded on successful login; the upgrade uses `updateUserWithRetry`; a failed login never rehashes; a store error during rehash does not fail the login (the user authenticated correctly).
- [ ] Run them. They fail.
- [ ] Implement `needsRehash`; wire it into the successful-verification path.
- [ ] Emit an event. If T509 has not landed, leave a `// TODO(T509)` marker and wire it there rather than inventing a second mechanism.
- [ ] Run the suite, document the upgrade path, commit.

**Done when:** Raising `Argon2Params` measurably upgrades stored hashes as users log in.

---

### T505 · C2 — Password quality beyond length

**Files:** `passwordcheck/*.go` (new), `sulis.go`, `config.go`, `errors.go`, tests

**Produces:** `PasswordChecker` interface; `WithPasswordChecker(PasswordChecker) Option`; `ErrPasswordCompromised`; `passwordcheck.NewBlocklist()`, `passwordcheck.NewHIBP(...)`.

Length-only means `password123` passes. NIST SP 800-63B expects comparison against known-compromised values.

- [ ] Write failing tests: a blocklisted password is rejected from all four password-setting paths; the HIBP client sends only a 5-character SHA-1 prefix and never the password or full hash; a network failure honors the configured fail-open/fail-closed setting.
- [ ] Run them. They fail.
- [ ] Implement the blocklist with an embedded common-password list via `embed`.
- [ ] Implement the HIBP k-anonymity client on stdlib `net/http`. Assert in a test that the outbound request carries only the prefix.
- [ ] **NFKC normalization needs `golang.org/x/text`, which violates the no-new-dependencies rule.** Either implement the narrow normalization, get the user's approval for the dependency, or defer it. Record the decision in `PROGRESS.md`. Do not silently add the dependency.
- [ ] Raise the default minimum length to 12 while the API is already breaking.
- [ ] Run the suite, update the README, commit.

**Done when:** Common and breached passwords are rejected by default, and HIBP provably never transmits the password.

---

### T506 · C4 — Encrypt TOTP secrets; offer a pepper

**Files:** `totp/encrypt.go` (new), `totp/totp.go`, `totp/store.go`, `password.go`, `config.go`, tests

**Produces:** `totp.Encryptor`; `totp.NewAESEncryptor(key []byte)`; `totp.WithEncryptor(Encryptor) Option`; `sulis.WithPepper([]byte) Option`.

`Credential.Secret` reaches the store as base32 plaintext. Unlike a password hash there is no work factor: a leak yields every enrolled secret, usable indefinitely and silently.

- [ ] Write failing tests: with an encryptor, the stored value is not and does not contain the base32 secret; round trip recovers it; a key-ID prefix allows decrypting with an older key; a wrong key fails closed rather than returning garbage.
- [ ] Run them. They fail.
- [ ] Implement AES-256-GCM, random nonce per encryption, key-ID prefix for rotation.
- [ ] Encrypt inside the totp package so stores only see ciphertext — the protection must not depend on the store author.
- [ ] Add `WithPepper` (HMAC-SHA256 before Argon2). Document that losing it makes every hash unverifiable, and that it protects against database-only leaks, not full application compromise.
- [ ] Run the suite, update the README, commit.

**Done when:** A configured encryptor means no plaintext TOTP secret reaches a store.

---

### T507 · C6 — Cookie and CSRF helpers

**Files:** `cookie.go`, `csrf.go` (new), `middleware.go`, `config.go`, tests

**Produces:** `SessionCookie`, `ClearSessionCookie`, `RequireSameOrigin(allowed []string)`, double-submit CSRF helpers, `TokenSource` + `WithTokenSource`, `WithCookieName`.

The middleware reads a cookie the library never sets and offers no CSRF defense. Because a Bearer header is accepted on the same handlers, a defense predicated on "we only accept cookies here" does not hold.

- [ ] Write failing tests: the cookie has `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, `__Host-` prefixed name; `TokenSourceCookieOnly` rejects a Bearer header and vice versa; `RequireSameOrigin` rejects cross-site `Sec-Fetch-Site` and unlisted `Origin` on state-changing methods while allowing safe ones; the double-submit comparison is constant time.
- [ ] Run them. They fail.
- [ ] Implement. `__Host-` requires `Secure` and `Path=/` and forbids `Domain` — enforce the combination rather than allowing an invalid cookie.
- [ ] Add `WWW-Authenticate` and `Cache-Control: no-store` to the 401 path while in the file.
- [ ] Run the suite, rewrite the README CSRF section from "add your own" to "here is what we ship and what remains yours", commit.

**Done when:** An adopter gets a correct session cookie and a working CSRF defense without writing either.

---

### T508 · C8 — Split magic-link TTL; bind links to the requester

**Files:** `magiclink.go`, `config.go`, `token.go`, `sulis_test.go`

**Produces:** `CreateMagicLinkToken(...) (token, bindingNonce string, err error)`; `RedeemMagicLink(ctx, rawToken, bindingNonce string, ri RequestInfo)`; `WithMagicLinkDuration` (default 15m); `WithMagicLinkBinding` (default true).

One `TokenDuration` governs both flows, so a magic link — a full credential sent in cleartext, often forwarded, scanned, or prefetched — lives as long as a password reset.

- [ ] Write failing tests: the default magic-link TTL is 15m and independent of `TokenDuration`; a missing or wrong binding nonce is rejected when binding is on; redemption works without one when binding is off; the nonce is stored hashed.
- [ ] Run them. They fail.
- [ ] Add the duration and the nonce. Store its hash alongside the token; require it at redemption. The application sets it as a short-lived `HttpOnly` cookie at request time, so a forwarded link is useless in another browser.
- [ ] Default binding on, but keep it optional and document the trade-off: some users legitimately open mail on a different device.
- [ ] Document the prefetch hazard — recommend an explicit confirmation click so mail scanners cannot consume the single-use token.
- [ ] Run the suite, update the README, commit.

**Done when:** A forwarded magic link cannot sign anyone in.

---

### T509 · C9 — Security event sink

**Files:** `events.go` (new), every flow file, `events_test.go`

**Produces:** `EventKind` constants; `Event`; `EventSink` with `Emit(ctx, e Event)`; `WithEventSink(EventSink) Option`; `NewSlogSink(*slog.Logger)`.

Failed logins, limiter trips, factor changes, recovery-code use, and new-device sign-ins are all unobservable today.

- [ ] Write failing tests: each decision point emits the expected kind and outcome; **no event payload contains a raw password, token, session token, TOTP secret, or recovery code** (scan every emitted event against the known secret values); a nil sink is a no-op.
- [ ] Run them. They fail.
- [ ] Define the taxonomy; emit from every decision point, including T504's rehash.
- [ ] Add the `slog` adapter so wiring is one line.
- [ ] Run the suite, document the taxonomy, commit.

**Done when:** Every security-relevant decision is observable and no event leaks a secret.

---

### T510 · C11 — Wire recovery codes into the 2FA lifecycle

**Files:** `recovery/recovery.go`, `recovery/store.go`, `recovery/recovery_test.go`

**Produces:** `Consume(ctx, userID, code string) (remaining int, err error)`; `WithLimiter(Limiter) Option`.

The primitives are sound; the lifecycle is missing.

- [ ] Write failing tests: `Consume` reports the remaining count; a limiter is consulted and its error normalized; codes are purged when the last factor is removed.
- [ ] Run them. They fail.
- [ ] Change the signature, add the limiter, add the purge hook.
- [ ] Document the expected sequence: a consumed code should revoke other sessions, emit an event, and push the user to re-enroll a real factor. The library cannot do this for you because it cannot know your product — say so.
- [ ] Run the suite, commit.

**Done when:** Applications know how many codes remain, and codes cannot outlive the factor they back up.

---

## Phase 6 — Reference stores

Last, so the schema is written once against interfaces that have stopped moving.

### T601 · D1 — SQLite reference store

**Files:** `store/sql/go.mod`, `store/sql/sqlite/*.go`, `schema.sql`, tests

- [ ] Create the nested module with its own `go.mod`, so drivers never enter the core's dependency graph.
- [ ] Write the schema with the constraints the contracts imply: unique lowercase email, unique token hash, unique session token hash, the `version` column, and indexes on every lookup column.
- [ ] Implement the stores: `UPDATE ... WHERE version = ?` for user writes, `DELETE ... RETURNING` (or a transaction) for atomic consumption, a conditional update for TOTP counter monotonicity.
- [ ] Run the full `storetest` suite against it — it must pass unmodified. That is the acceptance criterion.
- [ ] Add the nested module to CI, commit.

---

### T602 · D1 — Postgres reference store

**Files:** `store/sql/postgres/*.go`, `schema.sql`, tests

- [ ] Port the schema to Postgres types (`timestamptz`, `bytea`, `citext` or a lowercase unique index for email).
- [ ] Implement the stores using `DELETE ... RETURNING`.
- [ ] Run `storetest` against a real Postgres in CI via a service container. Skip cleanly when no database URL is set, so contributors without Postgres can still run the suite.
- [ ] Commit.

---

## Phase 7 — Release readiness

### T701 · D5 — `SECURITY.md` and threat model

**Files:** `SECURITY.md`, `docs/threat-model.md`

- [ ] Write `SECURITY.md`: reporting channel (GitHub private vulnerability reporting), a response-time commitment you can keep, supported-version policy.
- [ ] Write the threat model. In scope: credential guessing, token theft and replay, enumeration, database compromise, session hijacking, 2FA bypass, CSRF on the cookie path. Out of scope: application XSS, compromised hosts, malicious store implementations, phishing beyond WebAuthn origin-binding, and mailbox compromise — state plainly that magic links and resets are only as strong as the user's mailbox.
- [ ] Link both from the README, commit.

---

### T702 · D6 — Package docs and examples

**Files:** `doc.go`, `example_test.go`

The root package has no doc comment, so pkg.go.dev is bare.

- [ ] Write `doc.go`: overview, minimal end-to-end example, store-contract summary, pointer to operational requirements.
- [ ] Write compiler-checked `Example` functions for password login with 2FA, magic link, passkey registration and login, password reset, email change. These are what people copy, so they must show the secure path.
- [ ] Run `go test ./...` and `go vet ./...`, commit.

---

### T703 · D7 — Contribution, changelog, versioning

**Files:** `CONTRIBUTING.md`, `CHANGELOG.md`, `README.md`

- [ ] `CONTRIBUTING.md`: TDD expectation, commit convention, no-new-dependencies rule, requirement that store changes extend `storetest`.
- [ ] `CHANGELOG.md`: the whole hardening pass, with a prominent breaking-changes section and a migration guide.
- [ ] State the versioning policy in the README: v0.x until this plan completes, then v1.0.0 with a stated compatibility commitment.
- [ ] Commit.

---

### T704 — Final verification sweep

- [ ] Re-read the audit finding by finding. Confirm each of the 33 is closed, deliberately deferred with a reason, or obsoleted. Write all 33 dispositions into `PROGRESS.md`.
- [ ] Run the full gate: `gofmt -l .`, `go vet`, `staticcheck`, `gosec`, `go test -race -covermode=atomic -count=1 ./...`, `govulncheck`, and the nested module's suite.
- [ ] Grep for any path where a password, raw token, session token, TOTP secret, or recovery code could reach an error string, event, or log line.
- [ ] Read the README end to end as a newcomer; fix anything that no longer matches behavior.
- [ ] Decide on an external review and record the decision in `PROGRESS.md`.
- [ ] Tag v1.0.0 only after the user approves. Commit.

**Done when:** All 33 findings have a recorded disposition and the full gate is green.

---

## Appendix A — Target API surface

Ratified in T002. Later tasks must match these names and types, or amend them in `PROGRESS.md` with a reason.

### Types

```go
type AuthMethod string

const (
	AuthMethodPassword     AuthMethod = "password"
	AuthMethodMagicLink    AuthMethod = "magic_link"
	AuthMethodPasskey      AuthMethod = "passkey"
	AuthMethodTwoFactor    AuthMethod = "two_factor"
	AuthMethodRecoveryCode AuthMethod = "recovery_code"
)

// RequestInfo carries per-request caller context for IP-dimension rate
// limiting and session metadata. The zero value is valid.
type RequestInfo struct {
	IP        string
	UserAgent string
}

// SecondFactorChecker reports whether a user has an enrolled second factor.
// Required by New — there is no default, because defaulting it is the bypass.
type SecondFactorChecker interface {
	HasSecondFactor(ctx context.Context, userID string) (bool, error)
}

// NoSecondFactors is an explicit declaration that an application has none.
type NoSecondFactors struct{}

// LoginResult is the outcome of first-factor authentication. Exactly one of
// (Session, SessionToken) or PendingToken is populated.
type LoginResult struct {
	User              *User
	Session           *Session
	SessionToken      string
	NeedsSecondFactor bool
	PendingToken      string
}

// Authentication is opaque proof that a user completed authentication.
// Only this package can construct a valid one.
type Authentication struct {
	userID string
	method AuthMethod
	at     time.Time
}
```

### Functions

```go
func New(users UserStore, sessions SessionStore, tokens TokenStore,
	factors SecondFactorChecker, opts ...Option) (*Sulis, error)

func (s *Sulis) Register(ctx context.Context, email, password string, ri RequestInfo) (*User, *Session, string, error)
func (s *Sulis) Login(ctx context.Context, email, password string, ri RequestInfo) (*LoginResult, error)
func (s *Sulis) VerifyPassword(ctx context.Context, email, password string, ri RequestInfo) (*User, error)
func (s *Sulis) ReAuthenticate(ctx context.Context, session *Session, password string, ri RequestInfo) error

func (s *Sulis) IssueSession(ctx context.Context, auth Authentication) (*Session, string, error)
func (s *Sulis) IssueSessionUnchecked(ctx context.Context, userID string, method AuthMethod) (*Session, string, error)

func (s *Sulis) ValidateSession(ctx context.Context, token string) (*Session, *User, error)
func (s *Sulis) RefreshSession(ctx context.Context, session *Session) (*Session, string, error)
func (s *Sulis) ListUserSessions(ctx context.Context, userID string) ([]Session, error)
func (s *Sulis) RevokeSession(ctx context.Context, userID, sessionID string) error
func (s *Sulis) RevokeAllSessions(ctx context.Context, userID string) error
func (s *Sulis) RequireRecentAuth(ctx context.Context, session *Session, maxAge time.Duration) error

func (s *Sulis) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string, ri RequestInfo) error
func (s *Sulis) SetInitialPassword(ctx context.Context, userID, newPassword string) error
func (s *Sulis) CreatePasswordResetToken(ctx context.Context, email string, ri RequestInfo) (string, error)
func (s *Sulis) CreatePasswordResetTokenStrict(ctx context.Context, email string, ri RequestInfo) (string, error)
func (s *Sulis) ResetPassword(ctx context.Context, rawToken, newPassword string) error

func (s *Sulis) CreateMagicLinkToken(ctx context.Context, email string, ri RequestInfo) (token, bindingNonce string, err error)
func (s *Sulis) RedeemMagicLink(ctx context.Context, rawToken, bindingNonce string, ri RequestInfo) (*LoginResult, error)

func (s *Sulis) CreateTwoFactorToken(ctx context.Context, userID string) (string, error)
func (s *Sulis) CompleteTwoFactor(ctx context.Context, userID, rawToken string, ri RequestInfo) (*LoginResult, error)

func (s *Sulis) CreateEmailVerificationToken(ctx context.Context, userID string) (string, error)
func (s *Sulis) VerifyEmail(ctx context.Context, rawToken string) (*User, error)
func (s *Sulis) ChangeEmail(ctx context.Context, userID, newEmail string) (string, error)
func (s *Sulis) ConfirmEmailChange(ctx context.Context, rawToken string) (*User, error)

func (s *Sulis) DisableUser(ctx context.Context, userID, reason string) error
func (s *Sulis) EnableUser(ctx context.Context, userID string) error

func (s *Sulis) SessionCookie(rawToken string, expires time.Time) *http.Cookie
func (s *Sulis) ClearSessionCookie() *http.Cookie
func (s *Sulis) Authenticate(next http.Handler) http.Handler
func RequireSameOrigin(allowed []string) func(http.Handler) http.Handler
```

### Store interfaces

```go
type UserStore interface {
	CreateUser(ctx context.Context, user *User) error
	GetUserByID(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	// UpdateUser applies the write only if the persisted version equals
	// user.Version, then increments it. Returns ErrConcurrentUpdate on
	// mismatch. See README for reference SQL.
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id string) error
}

type SessionStore interface {
	CreateSession(ctx context.Context, session *Session) error
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
	ListUserSessions(ctx context.Context, userID string) ([]Session, error)
	TouchSession(ctx context.Context, id string, lastSeen time.Time, idleExpires *time.Time) error
	DeleteSession(ctx context.Context, userID, id string) error
	DeleteUserSessions(ctx context.Context, userID string) error
	DeleteUserSessionsExcept(ctx context.Context, userID, keepSessionID string) error
	CleanExpired(ctx context.Context) error
}
```

`TokenStore` gains only `TokenPurposeEmailChange`. `passkey.ChallengeStore` becomes `SaveChallenge` + `ConsumeChallenge`. `totp.Store` separates pending from active. `recovery.Store` is unchanged.

### New sentinel errors

```go
ErrConcurrentUpdate    = errors.New("sulis: concurrent update")
ErrAccountDisabled     = errors.New("sulis: account disabled")
ErrAccountLocked       = errors.New("sulis: account locked")
ErrReauthRequired      = errors.New("sulis: recent authentication required")
ErrPasswordCompromised = errors.New("sulis: password appears in a breach corpus")
ErrEmailChangePending  = errors.New("sulis: email change already pending")

ErrTOTPAlreadyEnrolled = errors.New("totp: already enrolled")
```

### Open questions for T002

1. `RequestInfo` as an explicit parameter or a context value? **Recommend explicit** — per-IP limiting should be visible in the signature; a context value is silently droppable.
2. `User.Version` optimistic concurrency or narrow per-column setters? **Recommend `Version`** — one concept instead of seven interface methods, protects future fields, fails loudly.
3. `store/sql` as a separate nested module or the same module? **Recommend separate** — SQL drivers should never enter the dependency graph of someone using their own store.
4. Should `New` return an error? **Recommend yes** — it now validates config, and a panic in a constructor is worse.

---

## Appendix B — Finding-to-task map

| Finding | Severity | Task |
|---|---|---|
| A1 — no 2FA awareness in session issuance | Critical | T102, T103 |
| A2 — WebAuthn UV never enforced | High | T105 |
| A3 — whole-row `UpdateUser` lost updates | High | T101 |
| A4 — challenges not atomically consumed | Medium | T201 |
| A5 — no `excludeCredentials` | Medium | T202 |
| A6 — resident keys never requested | Medium | T203 |
| A7 — unbounded ceremony body | Medium | T204 |
| A8 — `Enroll` destroys verified enrollment | Medium | T302 |
| B1 — rate limiting off by default | High | T106 |
| B2 — reset enumeration oracle | Medium | T304 |
| B3 — `RevokeSession` ownership | Medium | T303 |
| B4 — `Validate` returns `(bool, error)` | Medium | T301 |
| B5 — `Session.Token` on persisted struct | Low | T104 |
| B6 — `IssueSession` guarded by comment | Low | T305 |
| C1 — no `ChangeEmail` | High | T107 |
| C2 — no breach/blocklist check | Medium | T505 |
| C3 — no rehash-on-login | Medium | T504 |
| C4 — plaintext TOTP secrets, no pepper | Medium | T506 |
| C5 — no lockout or disable | Medium | T502 |
| C6 — no cookie or CSRF helpers | Medium | T507 |
| C7 — no step-up primitive | Medium | T501 |
| C8 — magic-link TTL and binding | Medium | T508 |
| C9 — no event hook | Low | T509 |
| C10 — no session listing | Low | T503 |
| C11 — recovery lifecycle | Low | T510 |
| C12 — passkey metadata | Low | T205 |
| D1 — reference stores and conformance suite | Low | T401, T601, T602 |
| D2 — CI hardening | Low | T001 |
| D3 — passkey coverage | Low | T206 |
| D4 — no fuzz targets | Low | T402 |
| D5 — no `SECURITY.md` or threat model | Low | T701 |
| D6 — no package doc | Low | T702 |
| D7 — versioning and changelog | Low | T703 |
