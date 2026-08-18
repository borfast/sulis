# Security Hardening v1 — Progress

**This is the state file. Read it first, update it in every commit.**

Plan: `PLAN.md` (same directory) · Audit: `docs/security-audit-2026-08-17.html`

---

## Session protocol

### Starting a session

1. Read this file. Do not read `PLAN.md` end to end — it is long.
2. Run `git log --oneline -5` and `git status`. If they disagree with "Current position" below, trust git and fix this file first.
3. Find the first task not marked `[x]`. Read only that task's section in `PLAN.md`.
4. Read "Ratified API" and "Decisions" below. They override `PLAN.md` Appendix A where they differ.
5. Start work.

### During a session

Update this file **in the same commit as the code**. Never commit code without updating it — a commit that advances the work but leaves this file stale is what breaks the next session.

On every commit:
- Tick the task's checkbox, or set its status to `in-progress`.
- Update "Current position".
- Add a line to "Session log".
- Add any API or design decision to "Decisions". If it contradicts `PLAN.md` Appendix A, say so explicitly.

### Ending a session

Leave the tree in one of two states, and say which in "Current position":

- **GREEN** — `go build ./... && go vet ./... && go test -race ./...` all pass. Preferred.
- **RED (mid-TDD)** — a deliberately failing test exists. Name the exact test and the expected failure in "Current position", so the next session knows the red is intentional.

Never end a session with uncommitted work. If a task is half done, commit it as `in-progress` with a note describing what is done and what is next.

### Verification command

```
go build ./... && go vet ./... && go test -race -count=1 ./...
```

After T001, also: `gofmt -l .`, `staticcheck ./...`, `gosec ./...`.

### Commit style

Imperative subject, no type prefix, body wrapped at ~72 columns explaining *why*. No trailers.

```
Gate new sessions on verified email by default

Add RequireVerifiedEmail (default true) and ErrEmailNotVerified, gating
Login, IssueSession, CreateTwoFactorToken, and CompleteTwoFactor on
EmailVerifiedAt. Register and magic-link redemption stay exempt.
```

---

## Current position

**Branch:** `security-hardening-v1` (branched from `main` at `bf18c6e`). All work happens here; not yet pushed.
**Status:** T001, T002, T101–T107 done. Phase 1 complete.
**Next task:** T201 — atomic passkey challenge consumption (first task of Phase 2).
**Tree:** GREEN. `gofmt`, `go build`, `go vet`, `staticcheck`, `gosec`, `govulncheck`, and `go test -race -count=1 ./...` all pass locally. Coverage: 84.6% root, 61.6% passkey, 92.1% recovery, 86.1% totp.
**Blockers:** None. CI has not run on GitHub yet — the branch is unpushed, so the workflow is verified locally only. Push and confirm the workflow is green before relying on it.

**Carry-forward for whoever picks this up:**
- All 9 completed tasks are committed; the working tree is clean apart from pre-existing untracked files (`.claude/`, `.codegraph/`, `AGENTS.md`, `CLAUDE.md`).
- **T206 owes an end-to-end test.** T105 verified that user verification is requested and recorded in session data, not that a UV-absent assertion is rejected. That needs a forging test authenticator, which T206 must build. Do not close T206 without it.
- Every finding fixed so far was mutation-tested — the regression test was confirmed to fail when the fix is reverted. Keep doing that for the security-critical ones; a test that cannot fail is decoration.

---

## Task list

38 tasks, 7 phases. `[ ]` todo · `[~]` in progress · `[x]` done.

### Phase 0 — Foundations
- [x] **T001** · D2 · Harden CI (pin tools, scope token, add staticcheck/gosec/gofmt gates)
- [x] **T002** · Ratify the target API surface into "Ratified API" below

### Phase 1 — Close the bypasses
- [x] **T101** · A3 · Stop whole-row user writes resurrecting old credentials
- [x] **T102** · A1 · Make session issuance aware of second factors
- [x] **T103** · A1 · Close the magic-link 2FA bypass
- [x] **T104** · B5 · Remove `Session.Token`
- [x] **T105** · A2 · Require WebAuthn user verification
- [x] **T106** · B1 · Rate limiting on by default, with an IP dimension
- [x] **T107** · C1 · Own the email-change flow

### Phase 2 — Passkey hardening
- [ ] **T201** · A4 · Atomic challenge consumption
- [ ] **T202** · A5 · Populate `excludeCredentials` from the store
- [ ] **T203** · A6 · Request resident keys
- [ ] **T204** · A7 · Bound the ceremony body, decouple from `net/http`
- [ ] **T205** · C12 · Record credential metadata
- [ ] **T206** · D3 · Bring passkey coverage to parity

### Phase 3 — Safe defaults
- [ ] **T301** · B4 · `totp.Validate` returns `error` only
- [ ] **T302** · A8 · `totp.Enroll` cannot clobber a verified factor
- [ ] **T303** · B3 · `RevokeSession` takes a user ID
- [ ] **T304** · B2 · `CreatePasswordResetToken` stops leaking existence
- [ ] **T305** · B6 · Make "already authenticated" a type

### Phase 4 — Store contracts and fuzzing
- [ ] **T401** · D1 · Publish a store conformance suite
- [ ] **T402** · D4 · Fuzz the parsers

### Phase 5 — Complete the feature set
- [ ] **T501** · C7 · Step-up authentication
- [ ] **T502** · C5 · Account disable and lockout
- [ ] **T503** · C10 · Session visibility and lifecycle
- [ ] **T504** · C3 · Rehash on login
- [ ] **T505** · C2 · Password quality beyond length
- [ ] **T506** · C4 · Encrypt TOTP secrets; offer a pepper
- [ ] **T507** · C6 · Cookie and CSRF helpers
- [ ] **T508** · C8 · Split magic-link TTL; bind links to the requester
- [ ] **T509** · C9 · Security event sink
- [ ] **T510** · C11 · Wire recovery codes into the 2FA lifecycle

### Phase 6 — Reference stores
- [ ] **T601** · D1 · SQLite reference store
- [ ] **T602** · D1 · Postgres reference store

### Phase 7 — Release readiness
- [ ] **T701** · D5 · `SECURITY.md` and threat model
- [ ] **T702** · D6 · Package docs and examples
- [ ] **T703** · D7 · Contribution, changelog, versioning
- [ ] **T704** · Final verification sweep

---

## Ratified API

**Ratified 2026-08-18 (T002): `PLAN.md` Appendix A is adopted as written, with the four questions answered below.**

Appendix A stays the single source of truth for signatures — it is not copied here, so there is nothing to drift. Any later amendment goes in the Decisions table below, marked as overriding Appendix A.

| # | Question | Decision | Reason |
|---|---|---|---|
| 1 | `RequestInfo` explicit param or context value? | **Explicit param** | Per-IP rate limiting must be visible in the signature. A context value is silently droppable, and the failure is invisible — the limiter just never sees an IP. |
| 2 | `User.Version` optimistic concurrency or per-column setters? | **`Version`** | One concept instead of seven interface methods. Protects fields added later (T502's `DisabledAt`, T107's `PendingEmail`) without further interface churn, and fails loudly rather than silently losing a write. |
| 3 | `store/sql` separate module or same module? | **Separate nested module** | SQL drivers must not enter the dependency graph of someone using their own store. Preserves the no-new-dependencies rule for the core. |
| 4 | Should `New` return an error? | **Yes** | It now validates config (nil `SecondFactorChecker`, bad Argon2 params). A panic in a constructor is worse, and returning an error matches `totp.NewService` and `passkey.NewService`. |

### Consequences to hold across sessions

- `New` gains a required 4th argument before `opts`. Applications with no second factor pass `sulis.NoSecondFactors{}` — an explicit, greppable declaration rather than a default.
- Every store implementing `UserStore` must honour the version precondition. `storetest` (T401) enforces it.
- `RequestInfo` is threaded through `Login`, `VerifyPassword`, `ChangePassword`, `CreatePasswordResetToken`, `CreateMagicLinkToken`, `RedeemMagicLink`, `CompleteTwoFactor`, and `ReAuthenticate`. Zero value is valid, so tests stay short.
- Raw session tokens are returned beside the `*Session`, never on it (T104).

### Known deferrals

None outstanding. (The NFKC dependency question was resolved on 2026-08-18 — see the Decisions table.)

---

## Decisions

Append as work proceeds. Each entry: task, decision, one-line reason. Mark anything that contradicts `PLAN.md` Appendix A.

| Task | Decision | Reason |
|---|---|---|
| — | Commits use no trailers | User preference, 2026-08-17 |
| — | Plan split into `PLAN.md` (stable) + `PROGRESS.md` (state) | Sessions restart often; one state file avoids divergence |
| T505 | **`golang.org/x/text` approved** — user authorised it 2026-08-18. Amends the Global Constraints in `PLAN.md` | NFKC normalization is needed so a password typed with different Unicode composition still verifies. Hand-rolling it would be worse than depending on the semi-official module that implements the spec. Do **not** treat this as a general relaxation: it is a one-module carve-out, and everything else still obeys the no-new-dependencies rule |
| — | Work on branch `security-hardening-v1`, not `main` | Long breaking-change series; keeps `main` releasable |
| — | `git config user.name/email` set repo-locally to match existing history | No identity was configured; used `Raúl Santos <4837+borfast@users.noreply.github.com>` from prior commits |
| T001 | Actions upgraded v4/v5 → v7, SHA-pinned | Pinning stale majors trades one risk for another; Dependabot keeps them current |
| T001 | Analyzers run in a separate `analyze` job, not the test matrix | Avoids running them twice per Go version |
| T001 | `decodeHash` widens salt/hash lengths *after* the bounds check | Real fix for gosec G115: the conversion is now provably in range |
| T001 | Added `counterAt` epoch guard in `totp` | Real fix: `Generate` is public and takes an arbitrary time; pre-1970 times wrapped `uint64` |
| T001 | 3 `#nosec` suppressions, each with an inline reason | G115 ×2 (bounds enforced 3 lines above, invisible to gosec), G101 (purpose enum, not a credential), G505 (HMAC-SHA1 is required by RFC 6238 and unaffected by SHA-1 collisions) |
| T001 | `GO-2026-5932` (x/crypto/openpgp) accepted, not actioned | Unreachable — sulis imports only `x/crypto/argon2`; no fix exists upstream |
| T101 | `setPassword` signature changed to `(ctx, userID, newPassword string, guard func(*User) error)` | Extends Appendix A (internal, so not a public break). The guard re-runs on each retry, so `ChangePassword`'s old-password check and `SetInitialPassword`'s passwordless check hold against current state, not the caller's first read |
| T101 | `ChangePassword` re-verifies the old password inside the update | A concurrent change must not be overwritten on the strength of a stale check. Costs an extra Argon2 run only on an actual conflict |
| T101 | `stampEmailVerified` reads `hadPassword` from the reloaded row | A password set between the caller's read and this write still triggers the session revocation it is there to guarantee |
| T102 | **Deviates from PLAN.md T102:** the checker is wired into `Login` only, NOT `IssueSession` | `IssueSession` is the post-all-factors primitive that `CompleteTwoFactor` calls. Consulting the checker there would demand a second factor again after it was just verified — an infinite loop. T305 replaces its `userID` argument with an `Authentication` proof, which is the real guard |
| T102 | `RequestInfo` threaded in this task rather than T106 | Otherwise T106 re-touches the same ~35 call sites for no benefit. The parameters are accepted and documented now, and consumed by the limiter in T106 |
| T102 | `New` also validates `MinPasswordLength <= MaxPasswordLength` | Free to add now that it returns an error; an inverted range would otherwise reject every password |
| T102 | `LoginResult.SessionToken` populated from `Session.Token` until T104 | Keeps `LoginResult` correct from the start, so T104 is a pure deletion of the struct field |
| T104 | `CompleteTwoFactor` returns `*LoginResult` and takes `RequestInfo` (Appendix A shape, landed early) | It had to change anyway to surface the raw token; returning `LoginResult` avoids a fourth return value and a second churn |
| T104 | `Register` returns `(*User, *Session, string, error)` rather than a `LoginResult` | Registration is exempt from the second-factor gate by design, so a result type implying a 2FA branch would mislead |
| T106 | Per-prefix budgets with longest-prefix matching, rather than one budget for all keys | Per-account must stay generous (an attacker must not lock a victim out) while per-IP stays tight; one budget cannot serve both |
| T106 | `MemoryLimiter` caps tracked keys (default 100k) and evicts full buckets first | A limiter that can be driven out of memory is a denial of service, not a defence. Full buckets carry no state, so they are free to drop |
| T105 | **Scope split from PLAN.md T105:** the test asserts UV is *requested and recorded in session data*, not end-to-end rejection of a UV-absent assertion | go-webauthn's enforcement is driven entirely by `session.UserVerification == VerificationRequired`, so that is the library behaviour we control. End-to-end rejection needs a forging test authenticator, which **T206 must build** — do not close T206 without it |
| T107 | `ChangeEmail`'s uniqueness check runs once before staging; `ConfirmEmailChange`'s re-runs inside the `updateUserWithRetry` closure, against the freshly loaded row, on every attempt | Staging doesn't make an address live, so a race there is harmless. Confirmation is where the address actually becomes live, so that check must hold against current state, not the state read before the retry loop started — matching `updateUserWithRetry`'s existing re-establish-invariants contract |
| T107 | `stampEmailVerified` (idempotent, no-op if already verified) is not reused by `ConfirmEmailChange` | Confirmation must re-stamp unconditionally with a fresh timestamp even though `EmailVerifiedAt` was already non-nil for the old address — idempotent semantics would make it a no-op and leave the old address's stamp in place for the new one |
| T107 (fix round 1) | `UserStore` GoDoc now states email uniqueness MUST be enforced at the storage layer, with `CreateUser`/`UpdateUser` returning `ErrUserAlreadyExists` on violation | `Version` only guards a lost update on a single row; two different rows racing to claim the same address (e.g. two accounts both confirming a change to the same staged address) can't be prevented above the store interface. `ConfirmEmailChange`'s own `GetUserByEmail` re-check is a best-effort early rejection, not the guarantee — found in code review |

---

## Deferred

Anything consciously not done, so T704 can account for it. Empty is good.

| Item | Task | Reason | Revisit? |
|---|---|---|---|
| `UserStore.UpdateUser` email-uniqueness enforcement isn't tested against real store implementations | T401 | The in-memory test double now enforces it (T107 fix round 1: `memUserStore.UpdateUser` in `sulis_test.go`), so `sulis`'s own tests hold, but the store conformance suite is what will hold real SQL/etc. implementations to the same contract | Yes — T401 must add a dedicated test asserting `UpdateUser` rejects a write whose email collides with a different user's live row |

---

## Session log

Newest last. One line per commit: date, task, what landed.

| Date | Task | What landed |
|---|---|---|
| 2026-08-17 | — | Audit written (`docs/security-audit-2026-08-17.html`), plan and progress files created |
| 2026-08-17 | T001 | CI hardened: SHA-pinned actions, `permissions: contents: read`, Go matrix (1.25.x + stable), gofmt gate, pinned staticcheck/gosec/govulncheck, atomic coverage, Dependabot. Fixed 7 gosec findings (2 real fixes in `password.go` and `totp/totp.go`, 3 suppressed with reasons) |
| 2026-08-18 | T002 | Appendix A ratified as written; four open questions answered (explicit `RequestInfo`, `User.Version`, separate `store/sql` module, `New` returns an error). NFKC dependency question deferred to T505 |
| 2026-08-18 | T101 | `User.Version` optimistic concurrency + `ErrConcurrentUpdate`; `updateUserWithRetry` helper; `setPassword` and `stampEmailVerified` no longer write whole rows from stale reads; `setPassword` takes a re-checked guard; regression test proves the resurrection bug is fixed |
| 2026-08-18 | T102 | `SecondFactorChecker` (required by `New`), `NoSecondFactors`, `LoginResult`, `AuthMethod`, `RequestInfo`; `New` returns an error; `Login` returns `*LoginResult` and fails closed on checker errors; `createSession` moved to `issue.go`. Mutation-tested: the A1 regression test fails if the check is bypassed |
| 2026-08-18 | T103 | `RedeemMagicLink` returns `*LoginResult` and routes through `completeFirstFactor`, closing the mailbox-access-defeats-2FA bypass. Verification is stamped before the branch so a 2FA user can still verify by magic link |
| 2026-08-18 | T104 | `Session.Token` removed; raw token returned beside the session by `createSession`, `Register`, `IssueSession`. `CompleteTwoFactor` now returns `*LoginResult`. Reflection test guards the field |
| 2026-08-18 | T105 | `passkey.NewService` takes options; `WithUserVerification` defaults to `required` and is set on the RP config and both login ceremonies. Mutation-tested: without it the session records UV `""` |
| 2026-08-18 | T106 | `MemoryLimiter` token bucket is now the default; `WithoutRateLimiting()` to opt out; per-account and per-IP budgets wired into password, reset and magic-link choke points; key tracking bounded |
| 2026-08-18 | T107 | `changeemail.go`: `ChangeEmail`/`ConfirmEmailChange`, `User.PendingEmail`, `TokenPurposeEmailChange`. Confirmation swaps the address, clears `PendingEmail`, re-stamps `EmailVerifiedAt` with a fresh timestamp, and revokes all sessions plus purges password-reset and two-factor tokens. Mutation-tested: reverting the session/token purge or the `token.Email == PendingEmail` check each fail the corresponding regression test. Phase 1 complete |
| 2026-08-18 | T107 (fix round 1) | Closed a cross-account race review found: two accounts confirming the same staged address could both pass `ConfirmEmailChange`'s `GetUserByEmail` pre-check before either write landed, since `Version` only guards one row. `UserStore` GoDoc now mandates storage-layer email-uniqueness enforcement (`ErrUserAlreadyExists` from `CreateUser`/`UpdateUser`); `memUserStore.UpdateUser` (test double) now enforces it; new test `TestConfirmEmailChangeAbortsIfAnotherAccountWinsTheRace` interleaves two confirmations via the existing `beforeUpdate` hook. Mutation-tested: reverting the test-store enforcement fails only that test |

---

## Finding dispositions

*Filled in T704.* All 33 audit findings, each marked closed, deferred (with reason), or obsoleted.
