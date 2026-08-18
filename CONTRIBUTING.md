# Contributing to sulis

sulis is a Go authentication library where almost every line touches a
security property. These rules exist to keep that property provably true
after your change, not just true today.

## Reporting a vulnerability

**Do not open a GitHub issue for a security report.** See
[`SECURITY.md`](SECURITY.md) and use GitHub's private vulnerability
reporting for this repository. Everything below is about contributing code
and docs — bugs, features, and cleanups — not about disclosing a flaw.

## Test-driven development

Write the failing test first, watch it fail for the reason you expect, then
write the minimal implementation that makes it pass. This applies to every
change, not only bug fixes: a new option, a new store method, a new event —
the test that pins the behavior exists before the code that satisfies it.

For a security property specifically — a guard, a fail-closed branch, an
atomicity requirement, a "this must never appear in an error/event/log"
claim — passing is not enough evidence that the test exercises the
property. **Mutation-test it**: temporarily revert or remove the fix (skip
the check, widen the guard, drop the atomic operation) and confirm the test
you just wrote actually fails without it. Then put the fix back. A test
that stays green whether or not the property holds is not testing the
property; it is decoration. This project's own history is full of these —
e.g. reverting a guard to prove a regression test bites before trusting a
fuzz target, or independently re-running a fix-round's mutation check
during scoped review — and a PR introducing a security-relevant test
should say, in the description or a commit message, what breaking change
you made to confirm it fails, not merely that it currently passes.

Run the full local gate before committing:

```
gofmt -l .
go build ./...
go vet ./...
go test -race -count=1 ./...
```

If you touched `store/sql` (a separate nested module, its own `go.mod`),
repeat the same commands with `store/sql` as the working directory —
`./...` does not cross a nested module boundary.

## Commit style

Imperative subject line, no type prefix (no `feat:`/`fix:`/`chore:`), body
wrapped at ~72 columns explaining *why* the change was made, not a
restatement of the diff. No trailers — this project does not add
`Co-Authored-By` or similar lines. This has been the convention for every
commit on this branch; keep it that way.

```
Gate new sessions on verified email by default

Add RequireVerifiedEmail (default true) and ErrEmailNotVerified, gating
Login, IssueSession, CreateTwoFactorToken, and CompleteTwoFactor on
EmailVerifiedAt. Register and magic-link redemption stay exempt.
```

One logical change per commit. If a task needs a follow-up fix after
review, that is a new commit, not an amend of the one being reviewed.

## No new dependencies without approval

The root module and the `totp`, `passkey`, and `recovery` subpackages take
on **no new third-party dependency without explicit maintainer approval**,
requested and recorded before the code that needs it lands. This is not a
soft preference: every dependency is a piece of this library's own trust
boundary that consumers inherit whether or not they ever call into it.

The one precedent so far is `golang.org/x/text`, approved for NFKC password
normalization (a security-relevant piece of Unicode handling not worth
hand-rolling badly) and pinned to exactly the one module needed. That
approval is a **carve-out for that one module**, not a general relaxation
of the rule — it does not extend to "another `x/...` module is probably
fine too." Propose the dependency, state what it's for and why the standard
library or an existing dependency can't do the job, and get a yes before
writing code against it.

`store/sql` (the SQLite and PostgreSQL reference store implementations) is
its own module with its own `go.mod` precisely so it can take on the
database drivers a reference implementation needs — `modernc.org/sqlite`,
`github.com/jackc/pgx/v5`, and so on — without pulling any of that into the
root module's dependency graph. New dependencies there still want a
maintainer's sign-off, but the bar is "does a reference SQL store need
this," not "can the root module avoid it."

## Store contracts: extend `storetest` in the same commit

`UserStore`, `SessionStore`, `TokenStore`, and each subpackage's own
`Store`/`ChallengeStore` interface are consumer-implemented — sulis ships
no database driver. Every requirement one of these interfaces states in its
doc comment (an atomic check-and-mutate, a scoping rule, an error sentinel
on a specific failure) is a contract a consumer's implementation must
satisfy, and `storetest`'s conformance suite is what proves an
implementation actually satisfies it instead of merely compiling against
the interface.

If your change adds a method to one of these interfaces, changes what an
existing method must guarantee, or adds/changes an error sentinel a store
must return, it is **not done until the same commit also**:

- extends `storetest`'s conformance suite (`storetest/*.go`) with subtests
  that would fail against an implementation missing the new requirement;
- updates `memstore` (the reference in-memory implementation) to satisfy
  it, so `memstore` keeps being proof the suite is satisfiable, not just
  written;
- if `store/sql` already implements the interface, updates
  `store/sql/sqlite` and `store/sql/postgres` too, in the same PR even
  though that module builds separately.

A store-contract change that lands without a `storetest` subtest is a
requirement that exists only in a doc comment — unenforceable, and the
exact gap this project's own store-contract work (see
`docs/superpowers/plans/2026-08-17-security-hardening-v1/PROGRESS.md`,
Decisions rows for T401/T601/T602) was written to close.

## Where to look before you start

- `README.md` — every flow, every default, and why each default is what it
  is.
- `docs/threat-model.md` — what sulis defends against and what is
  explicitly out of scope.
- `CHANGELOG.md` — what changed and why, including migration notes for
  every breaking change so far.
- Each store interface's own doc comment (`session.go`, `user.go`,
  `token.go`, and the subpackages' `store.go` files) — the atomicity and
  scoping requirements a store implementation must meet, with reference SQL
  where the requirement is non-obvious.
