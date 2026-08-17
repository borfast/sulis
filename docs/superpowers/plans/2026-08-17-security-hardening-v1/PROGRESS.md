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

**Status:** Not started — plan written, no code changed.
**Next task:** T001 (harden CI).
**Tree:** GREEN. Baseline at commit `bf18c6e`: build, vet, and `go test -race -cover ./...` all pass. Coverage 84.1% root, 59.0% passkey, 92.1% recovery, 87.6% totp.
**Blockers:** None.

---

## Task list

38 tasks, 7 phases. `[ ]` todo · `[~]` in progress · `[x]` done.

### Phase 0 — Foundations
- [ ] **T001** · D2 · Harden CI (pin tools, scope token, add staticcheck/gosec/gofmt gates)
- [ ] **T002** · Ratify the target API surface into "Ratified API" below

### Phase 1 — Close the bypasses
- [ ] **T101** · A3 · Stop whole-row user writes resurrecting old credentials
- [ ] **T102** · A1 · Make session issuance aware of second factors
- [ ] **T103** · A1 · Close the magic-link 2FA bypass
- [ ] **T104** · B5 · Remove `Session.Token`
- [ ] **T105** · A2 · Require WebAuthn user verification
- [ ] **T106** · B1 · Rate limiting on by default, with an IP dimension
- [ ] **T107** · C1 · Own the email-change flow

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

*Filled by T002. Until then, `PLAN.md` Appendix A is the working proposal.*

Four questions to answer in T002:

| # | Question | Recommendation | Decided |
|---|---|---|---|
| 1 | `RequestInfo` explicit param or context value? | Explicit param | — |
| 2 | `User.Version` optimistic concurrency or per-column setters? | `Version` | — |
| 3 | `store/sql` separate module or same module? | Separate | — |
| 4 | Should `New` return an error? | Yes | — |

---

## Decisions

Append as work proceeds. Each entry: task, decision, one-line reason. Mark anything that contradicts `PLAN.md` Appendix A.

| Task | Decision | Reason |
|---|---|---|
| — | Commits use no trailers | User preference, 2026-08-17 |
| — | Plan split into `PLAN.md` (stable) + `PROGRESS.md` (state) | Sessions restart often; one state file avoids divergence |

---

## Deferred

Anything consciously not done, so T704 can account for it. Empty is good.

| Item | Task | Reason | Revisit? |
|---|---|---|---|
| — | — | — | — |

---

## Session log

Newest last. One line per commit: date, task, what landed.

| Date | Task | What landed |
|---|---|---|
| 2026-08-17 | — | Audit written (`docs/security-audit-2026-08-17.html`), plan and progress files created |

---

## Finding dispositions

*Filled in T704.* All 33 audit findings, each marked closed, deferred (with reason), or obsoleted.
