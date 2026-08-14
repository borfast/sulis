# Verified-Email Session Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Block new sessions for unverified accounts by default, per the approved spec `docs/superpowers/specs/2026-08-14-verified-email-session-gate-design.md`.

**Architecture:** One config flag (`RequireVerifiedEmail`, default true) checked by a tiny helper at each session-starting entry point: `Login`, `CreateTwoFactorToken`, `CompleteTwoFactor`, `IssueSession`. `Register`, `RedeemMagicLink`, and `VerifyPassword` stay exempt by design.

**Tech Stack:** Go 1.25, standard library only.

## Global Constraints

- No new dependencies.
- New sentinel uses the `sulis:` prefix; raw secrets never in error messages.
- TDD: failing tests → RED → implement → GREEN.
- `go test ./... && go vet ./...` green before committing.
- Commit subject: plain imperative, no type prefix.

---

### Task 1: Verified-Email Session Gate

**Files:**
- Modify: `config.go`, `errors.go`, `sulis.go`, `twofactor.go`
- Modify: `sulis_test.go` (new tests + updating existing tests that log in on unverified accounts)
- Modify: `README.md`

**Interfaces:**
- Consumes: `User.EmailVerifiedAt *time.Time`, `VerifyEmail`, `stampEmailVerified`, `consumeToken`, `createSession`, `newTestEnv`.
- Produces: `Config.RequireVerifiedEmail bool` (default `true`) + `WithRequireVerifiedEmail(require bool)`; `ErrEmailNotVerified`; gated `Login`/`CreateTwoFactorToken`/`CompleteTwoFactor`/`IssueSession`; `IssueSession` now returns `ErrUserNotFound` for unknown IDs.

- [ ] **Step 1: Write failing tests**

```go
func TestUnverifiedAccountCannotStartNewSessions(t *testing.T) {
	// Register (auto-session OK), then with default config assert:
	// Login -> ErrEmailNotVerified; CreateTwoFactorToken -> ErrEmailNotVerified;
	// CompleteTwoFactor (token minted via WithRequireVerifiedEmail(false) env or
	// direct store seeding) -> ErrEmailNotVerified; IssueSession -> ErrEmailNotVerified.
}
func TestLoginSucceedsAfterEmailVerification(t *testing.T)    // VerifyEmail then Login -> session
func TestRedeemMagicLinkStillSignsInUnverifiedUser(t *testing.T) // magic link self-verifies -> session
func TestRegisterStillReturnsSession(t *testing.T)            // auto-session unaffected by default-on gate
func TestWithRequireVerifiedEmailFalseRestoresOldBehavior(t *testing.T) // unverified Login succeeds
func TestIssueSessionUnknownUserReturnsErrUserNotFound(t *testing.T)
```

For the `CompleteTwoFactor` case: mint the pending token while the gate would allow it (e.g. build the env with `WithRequireVerifiedEmail(false)`, create the token, then use a second env sharing the same stores with the default config — or simpler, seed the token via the store fake). Assert check order per spec: consume → userID match → verified check.

- [ ] **Step 2: Run `go test ./...` — verify RED**

- [ ] **Step 3: Implement**

```go
// errors.go
ErrEmailNotVerified = errors.New("sulis: email not verified")
```

```go
// config.go
RequireVerifiedEmail bool // block new sessions for unverified accounts (default: true)
// defaultConfig: RequireVerifiedEmail: true

// WithRequireVerifiedEmail sets whether new sessions are blocked until the
// account's email is verified. Register's signup session and magic-link
// redemption (which verifies the email itself) are always exempt.
func WithRequireVerifiedEmail(require bool) Option {
	return func(c *Config) { c.RequireVerifiedEmail = require }
}
```

```go
// sulis.go
func (s *Sulis) requireVerifiedEmail(user *User) error {
	if s.cfg.RequireVerifiedEmail && user.EmailVerifiedAt == nil {
		return ErrEmailNotVerified
	}
	return nil
}
```

Gate points:
- `Login`: after `VerifyPassword` succeeds, before session creation.
- `IssueSession`: load the user with `GetUserByID` (propagating `ErrUserNotFound`), then check, then `createSession`.
- `CreateTwoFactorToken`: after the existing `GetUserByID`, before `createTokenForUser`.
- `CompleteTwoFactor`: after the userID match, before `createSession`.

- [ ] **Step 4: Update existing tests broken by the default flip**

Where verification is incidental to the test, verify the account first (set `EmailVerifiedAt` on the stored user via the fake, or run `VerifyEmail`); where unverified login IS the point, pass `WithRequireVerifiedEmail(false)`. Do not weaken any assertion.

- [ ] **Step 5: Run `go test ./... && go vet ./...` — verify GREEN**

- [ ] **Step 6: Update README.md**

Document the flag in the configuration list and Operational Requirements: default on; **apps with no email verification flow must set `WithRequireVerifiedEmail(false)`** or users can register but never sign in again after the first session expires; magic-link apps need no change (redemption self-verifies). Mention `CreateTwoFactorToken`'s early failure in the 2FA flow section and add a migration note for upgraders.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "Gate new sessions on verified email by default"
```
