# Dependency policy and rationale

This document records why Sulis accepts the dependencies that handle secrets,
untrusted protocol input, or persisted authentication state. It covers both the
root module and the independently versioned `store/sql` module. The versions
below are the versions selected by `go.mod` on 2026-09-17; `go.mod` and
`store/sql/go.mod` remain the source of truth.

The inventory is deliberately about runtime code. Test-only modules and CI
tools do not ship in an application that imports Sulis. They are still pinned
by `go.sum` or an explicit tool version and are reviewed by Dependabot and CI.

## Automated policy

Pull requests run GitHub's dependency-review action over runtime, development,
and unknown dependency scopes. It rejects every newly introduced known
vulnerability, starting at `low` severity, and every known license outside this
permissive allow-list:

- Apache-2.0
- BSD-2-Clause
- BSD-3-Clause
- ISC
- MIT

An unfamiliar license therefore requires a deliberate policy change and code
review. GitHub reports an undetected license but cannot fail on it, so reviewers
must resolve unknown licenses before merging. Dependency review complements
Dependabot, `govulncheck`, `gosec`, checksum verification through `go.sum`, and
full-SHA action pins; none substitutes for reviewing what privileged code does.

At this review, `govulncheck v1.7.0` found no reachable vulnerability in either
module. It did report three module-level advisories in `golang.org/x/crypto`
`v0.55.0`: two in the unimported `ssh` package (fixed in `v0.56.0`) and one
warning that the unimported `openpgp` package is unsafe and unmaintained. Sulis
imports neither package. This distinction explains the current result; it does
not excuse delaying a compatible `x/crypto` update.

When updating this file, use `go list -deps` for both modules. A module can be
security-sensitive even when Sulis does not import it directly: WebAuthn and
database drivers compile parsers and codecs that consume attacker-controlled
bytes on Sulis's behalf.

## Root module

### Passwords and normalization

| Module | Why it is present and where it runs | Posture, alternatives, and decision |
| --- | --- | --- |
| [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) | Direct dependency. `password.go` uses `argon2` (and its `blake2b` implementation) to hash passwords. The WebAuthn stack also uses `ocsp` while validating attestations. | Maintained by the Go project and covered by the Go vulnerability database. Replacing Argon2id with a local implementation would increase cryptographic risk; another standard password KDF would change stored hashes and policy. Keep it pinned and migrate only with an explicit password-hash upgrade plan. |
| [`golang.org/x/text`](https://pkg.go.dev/golang.org/x/text) | Direct dependency. `password.go` applies Unicode NFKC normalization before policy checks and hashing. | Maintained by the Go project. Hand-written Unicode normalization is not credible; accepting raw code-point variants would make password policy and storage disagree. The standard-library subset does not provide NFKC, so the dependency stays. |
| [`golang.org/x/sys`](https://pkg.go.dev/golang.org/x/sys) | Indirect through `x/crypto` and the WebAuthn stack. It provides CPU and OS primitives used by cryptographic and certificate code. | Maintained by the Go project and version-selected with the other `x/*` modules. The alternative is for upstream libraries to duplicate platform-specific code. Sulis should follow compatible upstream updates rather than replace it. |

The local `passwordcheck` package uses the standard library for its HIBP range
request and SHA-1 prefix calculation; it adds no external runtime dependency.
Its embedded common-password corpus comes from SecLists, with provenance and a
checksum recorded beside the embed in `passwordcheck/blocklist.go`.

### WebAuthn

[`github.com/go-webauthn/webauthn`](https://github.com/go-webauthn/webauthn)
is a direct dependency used by `passkey/passkey.go` and `passkey/store.go` for
registration and authentication ceremonies, origin and RP-ID validation,
credential parsing, signature verification, and clone-counter handling. It is
the largest externally maintained security boundary in the root module. The
project publishes signed, immutable releases and the selected `v0.17.4` release
was current when reviewed. Implementing WebAuthn locally would mean owning a
large, evolving browser and authenticator protocol; the realistic alternative
is another established WebAuthn implementation, which would still require a
full ceremony-level audit and migration. The current library stays because its
API matches Sulis's server-side model and it receives active security and
dependency maintenance.

Its compiled runtime dependency family is:

| Module | Actual role in Sulis's path | Posture, alternatives, and decision |
| --- | --- | --- |
| [`github.com/fxamacker/cbor/v2`](https://github.com/fxamacker/cbor) | WebAuthn's `protocol/webauthncbor` decodes authenticator-controlled CBOR and `webauthncose` represents COSE keys. | The codec documents resource limits and malformed-input handling and has undergone published and private security assessment. A different CBOR codec or a local CTAP subset would replace one subtle parser with another; retain the upstream-selected codec and keep parser-facing tests and vulnerability scanning. |
| [`github.com/x448/float16`](https://github.com/x448/float16) | Indirect through `fxamacker/cbor`; it converts IEEE-754 binary16 values encountered by the CBOR codec. The chain is `passkey` → `go-webauthn` → `fxamacker/cbor` → `float16`. It does **not** implement credential signatures, key validation, randomness, password hashing, or any other cryptographic decision. | This is a small MIT-licensed package split out of `fxamacker/cbor`. Its upstream test suite claims exhaustive coverage of all 65,536 float16 inputs and all 2³² float32 conversions, plus 100% statement coverage. Its small maintainer base is a continuity risk, but the narrow API, exhaustive conversion tests, absence of I/O or unsafe code, and use by the assessed CBOR codec make that risk acceptable. Alternatives are vendoring the same conversion code, maintaining a fork, or replacing the CBOR codec; each transfers maintenance to Sulis without reducing the parsing surface. Keep it indirect, pinned, and monitored. |
| [`github.com/go-viper/mapstructure/v2`](https://github.com/go-viper/mapstructure) | WebAuthn decodes Android SafetyNet claims and FIDO metadata into typed structures with it. | The maintained v2 fork has shipped fixes for malformed-input disclosure issues; the selected `v2.5.0` is newer than the affected `<=v2.3.0` range of GHSA-2464-8j7c-4cjm. Manual claim decoding is possible but would diverge from upstream ceremony validation. Retain and scan it. |
| [`github.com/go-webauthn/x`](https://github.com/go-webauthn/x) | Supplies ASN.1 handling for COSE keys and revocation helpers for WebAuthn metadata. | Maintained alongside `go-webauthn`, which avoids cross-project compatibility drift. Standard-library ASN.1 plus local revocation code is possible, but would make Sulis responsible for protocol edge cases already owned upstream. |
| [`github.com/golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt) | Parses and validates Android SafetyNet and metadata JWTs inside `go-webauthn`. | Mature, versioned implementation with a public security policy. A local JWT parser would be a high-risk substitution; disabling those attestation formats would be a product-level decision. Keep the upstream-selected major version and apply advisories promptly. |
| [`github.com/google/go-tpm`](https://github.com/google/go-tpm) | Parses TPM structures and verifies TPM attestation data in `go-webauthn/protocol`. | Maintained in Google's Go TPM project. Sulis could reject TPM attestations to remove it, but accepting TPM while replacing the parser locally would be riskier. Retain while those attestations remain supported. |
| [`github.com/google/uuid`](https://github.com/google/uuid) | Represents authenticator and metadata identifiers and creates WebAuthn session/user identifiers within `go-webauthn`. | Small, widely used, BSD-licensed implementation maintained under Google's organization. Standard-library byte arrays could replace it only through an upstream API rewrite; keep it indirect. |
| [`github.com/tinylib/msgp`](https://github.com/tinylib/msgp) | Generated WebAuthn code serializes credential, authenticator, and session structures with MessagePack. | The generated format belongs to the upstream WebAuthn API. Replacing the generator/runtime would require maintaining generated compatibility code in Sulis, so the upstream-selected dependency remains. |
| [`github.com/philhofer/fwd`](https://github.com/philhofer/fwd) | Buffering helper used by `tinylib/msgp`; Sulis does not call it directly. | Narrow, pure-Go helper inherited with MessagePack. Removing it requires changing `msgp` or its generated output; monitor it with the parent dependency. |

`float16` deserves explicit attention because its repository is less prominent
than the WebAuthn and CBOR projects. Trust here does not come from popularity.
It comes from the limited responsibility described above, inspectable code,
exhaustive conversion tests, permissive license, module checksums, and the fact
that Sulis never uses a decoded floating-point value to authorize a user. A
future CBOR or WebAuthn update that removes it should allow `go mod tidy` to
remove the explicit indirect requirement; Sulis should not start importing it
directly.

## `store/sql` module

The SQL module is separate so applications with their own stores do not inherit
either database driver. Its direct dependencies execute SQL, parse database
files or server messages, and persist authentication state, so updates require
the `storetest` conformance suite and the store-specific concurrency tests.

### PostgreSQL driver family

| Module | Why it is present and where it runs | Posture, alternatives, and decision |
| --- | --- | --- |
| [`github.com/jackc/pgx/v5`](https://github.com/jackc/pgx) | Direct dependency. `store/sql/postgres/postgres.go` registers `pgx`'s `database/sql` driver and inspects `pgconn.PgError` for safe constraint mapping. It handles PostgreSQL authentication, TLS, wire messages, and values. | Actively maintained stable major with a documented version policy. `v5.10.0` includes explicit hardening against malicious-server messages and authentication downgrade. `lib/pq` is effectively maintenance-only and would lose pgx's current hardening; a custom driver is unjustifiable. Keep pgx and review connection security in consuming deployments. |
| [`github.com/jackc/pgpassfile`](https://github.com/jackc/pgpassfile) | Indirect pgx support for PostgreSQL password files. | Maintained in the pgx ecosystem. Sulis does not invoke it directly, but pgx connection-string behavior can reach it. Reimplementing connection discovery locally would create incompatible security behavior; retain with pgx. |
| [`github.com/jackc/pgservicefile`](https://github.com/jackc/pgservicefile) | Indirect pgx parser for PostgreSQL service configuration. | Same ownership and rationale as pgx. Applications can avoid service files through explicit DSNs, but removing the parser requires forking the driver. |
| [`github.com/jackc/puddle/v2`](https://github.com/jackc/puddle) | Indirect pgx connection-pool primitive. | Maintained by the pgx author and versioned with pgx's needs. Sulis uses `database/sql`, but the compiled pgx stack still includes it. A replacement only makes sense upstream. |
| [`golang.org/x/sync`](https://pkg.go.dev/golang.org/x/sync) | Indirect synchronization primitives used by pgx and SQL dependencies. | Go-project module with a narrow concurrency role. Local equivalents add race and cancellation risk; retain at the version selected by the module graph. |

### SQLite driver family

| Module | Why it is present and where it runs | Posture, alternatives, and decision |
| --- | --- | --- |
| [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite) | Direct dependency. `store/sql/sqlite/sqlite.go` registers a CGo-free transpilation of SQLite and uses its error codes for constraint mapping. It parses database pages and executes every SQLite query. | Actively tracks upstream SQLite and publishes a detailed changelog, platform matrix, and tagged releases. The CGo-free build is valuable to library consumers, but the generated surface is large and updates can carry SQLite or transpiler changes. `mattn/go-sqlite3` is the mature CGo alternative; `ncruces/go-sqlite3` is a WebAssembly-derived alternative. Retain modernc while cross-platform, CGo-free builds and conformance tests remain priorities. |
| [`modernc.org/libc`](https://pkg.go.dev/modernc.org/libc) | Runtime layer required by the transpiled SQLite engine. | Large generated/platform-specific dependency maintained with modernc. The SQLite project warns consumers to use the version it pins; Sulis should update `sqlite` and `libc` together through `go mod tidy`, never bump `libc` alone. Switching SQLite drivers is the meaningful alternative. |
| [`modernc.org/mathutil`](https://pkg.go.dev/modernc.org/mathutil) | Numeric helpers used by the transpiled SQLite/libc stack. | Small modernc support module. It is not an independent Sulis design choice; replacing it means forking the driver family. |
| [`modernc.org/memory`](https://pkg.go.dev/modernc.org/memory) | Memory-management support for modernc's transpiled C runtime. | Security-sensitive because malformed database input can exercise allocation paths. It is maintained in the same ecosystem and should move with `sqlite`/`libc`; a different SQLite driver is the practical alternative. |
| [`github.com/remyoudompheng/bigfft`](https://github.com/remyoudompheng/bigfft) | Large-integer/FFT helper pulled by modernc numeric code. | Narrow, pure-Go transitive helper. Sulis has no direct API dependency; replacing it would mean changing modernc's implementation, so monitor it with that family. |
| [`github.com/dustin/go-humanize`](https://github.com/dustin/go-humanize) | Formatting and size helper compiled into the modernc stack. | Mature, small MIT-licensed helper. It is not on an authorization boundary by itself; retain as an implementation detail of the driver. |
| [`github.com/mattn/go-isatty`](https://github.com/mattn/go-isatty) | Terminal-detection helper inherited from modernc tooling/runtime support. | Small MIT-licensed package with no Sulis calls. Removal belongs upstream; dependency review and checksums cover changes meanwhile. |
| [`github.com/ncruces/go-strftime`](https://github.com/ncruces/go-strftime) | Implements SQLite-compatible date formatting for the modernc driver. | Focused, versioned helper in the SQLite ecosystem. A local formatter risks SQL behavior drift; keep the driver's selected implementation. |

The SQL module also repeats the WebAuthn family because its passkey stores use
`go-webauthn/protocol` types. Those modules have the same rationale as in the
root module and should normally resolve to the same versions through the local
`replace github.com/borfast/sulis => ../..` directive used during development.

## Review procedure

For a dependency change:

1. Confirm why the module is in each graph with `go mod why -m` and confirm the
   compiled packages with `go list -deps` in both module roots.
2. Read upstream release notes, security advisories, ownership changes, and any
   new native code, code generation, network access, or parsing surface.
3. Run `go mod tidy` in the affected module and review both `go.mod` and
   `go.sum`; an unexplained new indirect dependency blocks the change.
4. Run `govulncheck`, `gosec`, the race-enabled tests, and the SQL conformance
   tests. A clean scanner result does not waive source or behavior review.
5. Update this document when the role, risk, maintainer posture, or chosen
   alternative changes.
