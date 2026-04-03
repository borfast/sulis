# Auth Library Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden core auth token handling, add passkey regression coverage, and document the library’s security/storage contracts.

**Architecture:** Keep the library store-driven and minimal. Tighten the core `sulis` package by hashing persisted session tokens and improving error semantics, add targeted passkey tests around challenge handling, and document the resulting contracts in a concise top-level README.

**Tech Stack:** Go 1.24, standard library, `golang.org/x/crypto/argon2`, `github.com/go-webauthn/webauthn`

---

### Task 1: Harden Core Session And Token Flows

**Files:**
- Modify: `session.go`
- Modify: `sulis.go`
- Modify: `errors.go`
- Modify: `magiclink.go`
- Modify: `sulis_test.go`

- [ ] **Step 1: Write failing tests in `sulis_test.go`**

```go
func TestRegisterStoresSessionTokenHash(t *testing.T) { /* assert returned token differs from stored TokenHash */ }
func TestValidateSessionUsesTokenHashLookup(t *testing.T) { /* assert validation succeeds with presented raw token */ }
func TestChangePasswordAllowsPasswordlessUpgrade(t *testing.T) { /* magic-link user + empty old password succeeds */ }
func TestResetPasswordPropagatesLookupFailures(t *testing.T) { /* non-not-found token store error bubbles up */ }
func TestCreateMagicLinkTokenAcceptsWrappedUserNotFound(t *testing.T) { /* wrapped ErrUserNotFound still creates user */ }
```

- [ ] **Step 2: Run the focused root-package tests and verify RED**

Run: `go test ./...`

Expected: the new tests fail because the current code stores raw session tokens, rejects passwordless upgrades, and hides store errors.

- [ ] **Step 3: Implement the minimal production changes**

```go
type Session struct {
	ID        string
	UserID    string
	Token     string // raw token, only populated when issuing a new session
	TokenHash string // persisted lookup value for stores
	ExpiresAt time.Time
	CreatedAt time.Time
	Metadata  map[string]any
}

type SessionStore interface {
	CreateSession(ctx context.Context, session *Session) error
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteUserSessions(ctx context.Context, userID string) error
	CleanExpired(ctx context.Context) error
}
```

Implement `createSession` so it stores `hashToken(raw)` in `TokenHash` and returns the raw token in the session returned to callers. Hash the presented bearer token inside `ValidateSession` before store lookup. Add `ErrTokenNotFound`, map only not-found token lookups to `ErrTokenInvalid`, and allow `ChangePassword(..., "", newPassword)` when the user currently has no password hash.

- [ ] **Step 4: Re-run the root-package tests and verify GREEN**

Run: `go test ./...`

Expected: all root and existing package tests pass.

- [ ] **Step 5: Self-review for scope and API clarity**

Confirm the changes stay limited to token/session hardening and do not redesign unrelated auth flows.

### Task 2: Add Passkey Regression Tests

**Files:**
- Create: `passkey/passkey_test.go`
- Modify: `passkey/passkey.go` (only if tests expose a package bug)

- [ ] **Step 1: Write failing tests for the package-owned behavior**

```go
func TestBeginRegistrationSavesChallenge(t *testing.T) { /* fake challenge store records session data */ }
func TestBeginLoginWithoutCredentialsReturnsErrPasskeyNotFound(t *testing.T) { /* empty store */ }
func TestFinishRegistrationWithoutChallengeReturnsErrChallengeExpired(t *testing.T) { /* no saved challenge */ }
func TestFinishLoginWithoutChallengeReturnsErrChallengeExpired(t *testing.T) { /* no saved challenge */ }
```

- [ ] **Step 2: Run passkey tests and verify RED**

Run: `go test ./passkey`

Expected: test file compiles against missing coverage or exposes small package issues.

- [ ] **Step 3: Make the minimal code changes needed for GREEN**

Keep the package API unchanged unless the tests reveal a real defect. Prefer store fakes in tests over deep WebAuthn mocking.

- [ ] **Step 4: Re-run passkey tests and verify GREEN**

Run: `go test ./passkey`

Expected: targeted passkey tests pass.

- [ ] **Step 5: Self-review for overreach**

Confirm the task added coverage for package logic without trying to simulate full browser/WebAuthn ceremonies.

### Task 3: Add Top-Level Documentation

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write the README**

Include:
- package overview,
- core auth flows (`Register`, `Login`, `ValidateSession`, password reset, magic link),
- TOTP and passkey package overview,
- store responsibilities,
- security notes about hashed persisted session tokens and hashed reset/magic-link tokens.

- [ ] **Step 2: Check the README against the implemented code**

Verify the storage-contract wording matches the updated `SessionStore`, `TokenStore`, and `ChangePassword` behavior.

- [ ] **Step 3: Run full verification after docs land**

Run: `go test ./... && go vet ./...`

Expected: code remains green after documentation changes.

- [ ] **Step 4: Self-review for concision and accuracy**

Keep the README concrete and brief; avoid promising features the code does not provide.
