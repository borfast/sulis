# Independent security review scope

This document briefs an independent reviewer before the v1 review of
`sulis`. It describes the security boundaries the library claims, points to
the code and tests that implement those claims, and provides the record for
findings and their dispositions. The reviewer should test the claims against
the implementation and against realistic consumer wiring; this is a review
of judgement, failure modes, and composition, not a request to re-document
the API.

## Product boundary and existing material

`sulis` owns authentication decisions, token and session lifecycle, WebAuthn
and TOTP integrations, and HTTP cookie/CSRF middleware. Consumers own the
HTTP router, templates and frontend, secrets and key management, database
schema and store implementations, and the decision to wire optional defenses
such as rate limiting, TOTP encryption, same-origin checks, and CSRF checks.
Assess those integration boundaries explicitly: a consumer can satisfy every
library API contract while still deploying an unsafe flow.

Start with these documents and tests:

- [`docs/threat-model.md`](threat-model.md) states the in-scope threats,
  shipped defenses, out-of-scope assumptions, and residual risks. Treat it as
  the library's security claims, not as evidence that the claims are correct.
- [`docs/security-audit-2026-08-17.html`](security-audit-2026-08-17.html)
  contains the earlier audit and its finding history. Check that its fixes
  remain true after subsequent changes.
- [`SECURITY.md`](../SECURITY.md) defines vulnerability reporting, supported
  versions, and the boundary between a library defect and a consumer/store
  integration issue.
- The [`storetest`](../storetest) conformance suite is the executable contract
  for consumer-owned stores. In particular, its concurrency tests are the
  evidence for atomicity requirements; passing ordinary happy-path tests is
  not sufficient.
- [`README.md`](../README.md) describes the supported wiring and operational
  requirements. Verify examples and prose against the current code, but use
  the source and tests as the final authority.

The review should include the root module and the nested `store/sql` module,
including both the SQLite and PostgreSQL implementations. A finding may be a
code defect, a store-contract violation, an unsafe default or option, an
incorrect security claim, or a consumer integration hazard that needs clearer
documentation.

## Focus areas

### 1. WebAuthn ceremonies

Review the complete registration, identified-login, and discoverable-login
flows in [`passkey/passkey.go`](../passkey/passkey.go) and its HTTP wrappers in
[`passkey/http.go`](../passkey/http.go), together with the passkey store and
challenge-store implementations.

Check at least:

- authenticator-data flags, especially user presence, user verification,
  backup eligibility/state, and sign-count handling;
- origin and RP-ID validation, including configuration with multiple allowed
  origins and the distinction between an origin and an RP ID;
- challenge generation, ceremony-key scoping, expiry, and single-use
  consumption; a failed verification is intended to burn the challenge;
- credential-to-user binding in discoverable login and identified login;
- clone detection and the treatment of sign-count anomalies; and
- atomic persistence of the updated sign count, backup state, and last-used
  time after a successful ceremony.

The default service requires user verification and resident keys. Review every
allowed override (`WithUserVerification`, `WithResidentKey`) in the context of
the caller's chosen flow. Constructors now reject incomplete stores and
WebAuthn configuration early; verify that this prevents unsafe partial setup
without creating a bypass in a later ceremony. The library returns a verified
passkey result but does not mint a root-package session automatically; review
the hand-off to `IssueSessionUnchecked` and the two-factor flow as an explicit
trust boundary.

### 2. Session and token transitions

Trace state transitions through [`issue.go`](../issue.go),
[`session.go`](../session.go), and [`stepup.go`](../stepup.go), then follow
their store calls and error handling. Review issuance after password, magic
link, TOTP, recovery-code, and passkey authentication; pending-token to
session completion; refresh; revocation; re-authentication; and account
disable/lock and email-verification gates.

Pay particular attention to:

- when a raw token is created, hashed, persisted, consumed, or exposed to the
  caller, and whether a failure can leave a token or session reusable;
- whether every transition checks current account status and required email or
  second-factor state rather than trusting a stale `User` or `Session` value;
- refresh ordering and revocation semantics, including stale sessions and
  preservation of session metadata;
- `RequireRecentAuth` and `ReAuthenticate`, including the deliberate
  in-place update of the caller's session and its documented concurrency
  responsibility;
- error mapping and information leaks: not-found, already-used, invalid,
  expired, disabled, locked, and rate-limited paths must not accidentally
  become account or token oracles; and
- event emissions and logs must not contain passwords, raw bearer tokens,
  recovery codes, binding nonces, or equivalent secrets.

Treat `Authentication` and `IssueSessionUnchecked` as separate trust levels.
The latter is intentionally an escape hatch for a ceremony verified outside
the root package, so the review should ask whether each caller has actually
completed all required checks before invoking it.

### 3. SQLite and PostgreSQL atomicity, locking, and errors

Review [`store/sql/sqlite`](../store/sql/sqlite),
[`store/sql/postgres`](../store/sql/postgres), and the interfaces and comments
they implement in the root and subpackages. Compare both backends with the
same `storetest` suite and inspect transaction boundaries, affected-row
checks, isolation assumptions, and error translation.

The important contracts include single-operation consumption of tokens,
challenges, and recovery codes; optimistic user updates; membership-scoped
session and credential deletion; atomic TOTP enrollment/promotion and
credential bookkeeping; and preservation of independent copies on reads.
Verify that SQLite's locking and PostgreSQL's transaction behavior provide the
same result under concurrent calls, including rollback and context
cancellation. Check that unique, foreign-key, serialization, and missing-row
conditions map to the documented Sulis sentinel errors without hiding an
unexpected database failure.

One recent path deserves focused adversarial testing: `recovery.Store.ConsumeCode`
now returns the remaining count from the same consumption operation. The
PostgreSQL implementation takes a per-user advisory lock using
`advisoryClassRecovery` so concurrent callers receive honest, distinct counts.
This code has only run in CI so far. Exercise concurrent consumption of
distinct codes and the same code, rollback/error paths, lock key scoping, and
behavior when another transaction is active. Confirm that SQLite provides the
same observable contract without relying on PostgreSQL-only behavior. The
tests in `storetest/recovery.go` (especially the concurrent count cases) are
the minimum contract, not a substitute for reviewing the SQL.

### 4. Browser cookies, same-origin, and CSRF

Review [`cookie.go`](../cookie.go), [`csrf.go`](../csrf.go),
[`config.go`](../config.go), and the corresponding tests and README guidance.
Check the complete browser behavior, not just the values in an `http.Cookie`:

- default `__Host-session` and `__Host-csrf_token` names, `Secure`, `Path=/`,
  absent `Domain`, `HttpOnly`, and `SameSite=Lax` attributes;
- what `SameSite=Lax` does and does not protect, including top-level
  navigations and same-site cross-origin requests;
- `RequireSameOrigin`'s Fetch Metadata and `Origin` fallback, its safe-method
  behavior, allowlist matching, and what missing headers mean for non-browser
  clients;
- the double-submit comparison, constant-time equality, header/form
  precedence, and the fact that the CSRF cookie is intentionally readable by
  same-origin script; and
- whether middleware is actually applied to every cookie-authenticated,
  state-changing route in a representative consumer application.

`WithCookieName` and `WithCSRFCookieName` intentionally allow a deployment to
drop the `__Host-` prefix. This is a material security tradeoff, not a
cosmetic rename. In particular, dropping it from the CSRF cookie permits a
hostile sibling subdomain to inject a cookie and defeat the bare double-submit
check. `RequireSameOrigin` does not repair that case because the sibling
request is still same-site. The relevant warning is in [`config.go`](../config.go)
and [`docs/threat-model.md`](threat-model.md); verify that the API, tests, and
consumer-facing documentation make this consequence hard to miss.

Also consider development and deployment scheme mismatches. Safari refuses to
store a cookie carrying `Secure` when it is set over plain HTTP, including on
`localhost` and `127.0.0.1` ([WebKit bug 232088](https://bugs.webkit.org/show_bug.cgi?id=232088)).
This was measured on Safari 26.6.2: all four Sulis cookies were dropped while
a non-`Secure` control was stored. It is not a library defect and must not be
“fixed” by weakening production cookie attributes; local development against
the real cookie flow needs HTTPS at the browser boundary. The README's
[Local development](../README.md#local-development) section has the tracked
TLS guidance, and the review should check that it does not become a production
configuration.

## Recent changes to examine closely

The following are deliberately called out so they receive judgement beyond a
routine regression run:

1. Recovery-code consumption now returns its remaining count atomically, and
   PostgreSQL serializes a user's consumption with `advisoryClassRecovery`.
   This path is new and has only run in CI; test races, retries, cancellation,
   and lock interactions directly.
2. Custom session and CSRF cookie names can remove the `__Host-` protection.
   Evaluate the sibling-subdomain cookie-injection scenario and the limits of
   `RequireSameOrigin`, as described above.
3. `totp.NewService` and `passkey.NewService` now reject incomplete or unsafe
   configuration at construction instead of deferring failure until a
   ceremony. Check both rejection coverage and whether valid deployments,
   including explicit second-factor-only configurations, remain safe.
4. Safari's refusal to store Secure cookies set over plain HTTP (including on
   localhost and 127.0.0.1) is a consumer-development constraint, not a
   library defect. Verify that no production guidance asks users to disable
   `Secure` or the `__Host-` guarantees; the tracked README's
   [Local development](../README.md#local-development) section should remain
   the source of the HTTPS workaround.

## Review method and evidence

For each suspected issue, reproduce it with a focused test or a minimal
consumer harness where possible. Run the root and `store/sql` test suites with
the race detector, and run the storetest conformance suites against both
backends. Record the exact commit, configuration, database version, browser
assumptions, and whether the result requires an unsafe consumer choice. A
passing test is evidence for a contract; it is not proof that the contract is
the right security property.

Reviewers should distinguish:

- a defect in Sulis's code or documented contract;
- a store implementation that fails a Sulis contract;
- a consumer that failed to wire an explicitly required defense; and
- a residual risk that is understood and accepted by the project.

The last two can still merit documentation or an API change even when they
are not library vulnerabilities.

## Findings and dispositions

Add one row for every finding, including findings that are accepted or
confirmed as residual risk. Keep the wording specific enough that a later
reviewer can reproduce the original concern.

| ID | Finding | Severity | Evidence / affected flow | Repo response | Where the fix landed | Status |
| --- | --- | --- | --- | --- | --- | --- |
| SR-001 | _Describe the security property that fails and the trigger._ | Critical / High / Medium / Low | _Test, trace, configuration, or browser/database setup._ | _Fix, documentation, mitigation, or rationale._ | _Commit, PR, file, or “none”._ | Open |

Use the following status vocabulary consistently: `open`, `fixed`,
`verified`, `deferred`, or `accepted, not fixed`. **“Accepted, not fixed” is a
legitimate outcome and must still be recorded with the reasoning, affected
deployments, and any compensating control.** Acceptance does not mean the
finding was overlooked; it means the project consciously judged the residual
risk against its stated scope and release policy.

When a fix is made, link the commit or pull request and add the regression
test or other evidence that closes the finding. When a finding is deferred,
name the milestone or decision that will revisit it rather than leaving an
unbounded promise.
