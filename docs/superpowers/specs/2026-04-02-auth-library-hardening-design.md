# Auth Library Hardening Design

## Goal

Harden the core session and token flows, remove a broken passwordless edge case, add focused passkey regression coverage, and document the storage and security contracts expected from library consumers.

## Approved Scope

1. Core hardening in the root `sulis` package.
2. Initial `passkey` package tests for challenge lifecycle and error mapping.
3. A root `README.md` that explains the library surface and storage expectations.

## Chosen Approach

The implementation keeps the library small and store-driven, but makes the token-handling contracts explicit.

For sessions, raw bearer tokens will only exist at issue time. Persisted sessions will store a hash, and validation will hash the presented token before store lookup. This keeps the current bearer-token model while reducing the blast radius of a session-store leak.

For password changes, passwordless users will be allowed to set an initial password by calling `ChangePassword` with an empty `oldPassword`. Existing password users will still need to present the current password.

For token validation, not-found cases will still normalize to `ErrTokenInvalid`, but actual store failures will be returned so operational issues are visible to callers.

## Package-Level Design

### Root package

- Extend `Session` so stores can persist a `TokenHash` while newly issued sessions can still return the raw `Token` to the caller.
- Update `SessionStore` lookup semantics to query by token hash.
- Add an explicit `ErrTokenNotFound` sentinel so store implementations can distinguish missing tokens from backend failures.
- Switch internal not-found checks to `errors.Is`.
- Add root-package tests for the new storage and error-handling behavior.

### Passkey package

- Add narrow, store-backed tests that cover:
  - challenge persistence on registration start,
  - `ErrPasskeyNotFound` when login is started with no credentials,
  - `ErrChallengeExpired` when finish endpoints are called without saved challenge state.
- Avoid full browser/WebAuthn ceremony tests; the goal is to verify the package’s own logic and store contracts.

### Documentation

- Add a root `README.md` with:
  - package overview,
  - root auth flows,
  - TOTP and passkey extension overview,
  - storage responsibilities for user/session/token stores,
  - security notes for hashed reset tokens and hashed persisted session tokens.

## Testing Strategy

- Root package: add behavior tests first, then implement the minimal production changes to make them pass.
- Passkey package: add direct unit tests around fake stores and missing challenge cases.
- Final verification: `go test ./...`, `go test -cover ./...`, and `go vet ./...`.

## Non-Goals

- No transactional store abstraction changes.
- No broader auth API redesign.
- No full WebAuthn end-to-end browser ceremony coverage.
