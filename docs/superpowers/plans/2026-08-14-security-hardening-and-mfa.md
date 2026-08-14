# Security Hardening And MFA Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the security gaps found in the 2026-08-14 audit (non-atomic token use, TOTP replay, timing oracles, enumeration, passkey challenge clobbering) and add the missing product pieces: 2FA orchestration, recovery codes, email verification, discoverable passkey login, and rate-limit hooks.

**Architecture:** Keep the library small and store-driven. Security fixes tighten existing flows in place; new features reuse the existing `Token` machinery (2FA pending, email verification) or follow the established subpackage pattern (`recovery/`). Store interfaces change where atomicity must be a contract, not a hope.

**Tech Stack:** Go 1.24, standard library, `golang.org/x/crypto/argon2`, `github.com/go-webauthn/webauthn`

## Global Constraints

- Go 1.24.7 floor. No new third-party dependencies; stdlib + existing deps only.
- Breaking API changes are allowed (pre-1.0, no external consumers) — this repo's precedent from the 2026-04-03 password API split.
- New sentinel errors use the package prefix convention: `sulis:`, `totp:`, `passkey:`, `recovery:`.
- Raw secrets (passwords, raw tokens, TOTP secrets, recovery codes) must never appear in error messages.
- TDD per task: failing test → RED → minimal implementation → GREEN.
- After every task: `go test ./... && go vet ./...` must be green before committing.
- Commit subjects: plain imperative, no type prefix (matches repo history).
- Root-package tests use the existing fakes in `sulis_test.go` (`memUserStore`, `memSessionStore`, `memTokenStore`, `newTestSulis`); extend them rather than inventing new ones.

Tasks are ordered so the tree is green after each one. Phases 2–5 depend on Phase 1 refactors (`consumeToken`, `createTokenForUser`) but are otherwise independent of each other.

---

## Phase 1 — Core hardening (root package)

### Task 1: Atomic Token Consumption

Two concurrent `ResetPassword` calls with the same token can both pass the current check-then-mark sequence, and `ResetPassword` marks the token used *after* changing the password. Replace the pattern with an atomic store operation, consumed before any effect.

**Files:**
- Modify: `token.go`
- Modify: `sulis.go`
- Modify: `magiclink.go`
- Test: `sulis_test.go`

**Interfaces:**
- Produces: `TokenStore.ConsumeToken(ctx, hash string, purpose TokenPurpose) (*Token, error)` (replaces `GetTokenByHash` + `MarkTokenUsed`); internal `(s *Sulis) consumeToken(ctx, rawToken string, purpose TokenPurpose) (*Token, error)` used by every later token-based flow.

- [ ] **Step 1: Write failing tests**

Update `memTokenStore` to implement `ConsumeToken` under its mutex (lookup by hash+purpose, reject used, mark used, return copy). Add:

```go
func TestResetPasswordConsumesTokenBeforePasswordChange(t *testing.T) {
	// store fake that fails UpdateUser: token must already be used afterwards,
	// so a second ResetPassword with the same token returns ErrTokenAlreadyUsed.
}

func TestConcurrentResetPasswordSingleWinner(t *testing.T) {
	// launch 2 goroutines calling ResetPassword with the same raw token via
	// sync.WaitGroup; assert exactly one nil error and one ErrTokenAlreadyUsed.
}

func TestConsumeTokenWrongPurposeIsInvalid(t *testing.T) {
	// reset token presented to RedeemMagicLink -> ErrTokenInvalid,
	// and the token is still usable for ResetPassword afterwards.
}
```

- [ ] **Step 2: Run `go test ./...` — verify RED** (new tests fail; existing `MarkTokenUsed` tests still compile until Step 3 removes the method)

- [ ] **Step 3: Implement**

```go
// token.go
type TokenStore interface {
	CreateToken(ctx context.Context, token *Token) error
	// ConsumeToken atomically finds the unused token matching hash AND purpose
	// and marks it used, returning it. Lookup and mark MUST be one atomic
	// operation (e.g. UPDATE ... WHERE hash=? AND purpose=? AND used=false).
	// Returns ErrTokenNotFound if no token matches hash+purpose;
	// ErrTokenAlreadyUsed if it exists but was already consumed.
	ConsumeToken(ctx context.Context, hash string, purpose TokenPurpose) (*Token, error)
	DeleteExpiredTokens(ctx context.Context) error
}
```

```go
// sulis.go — replaces validateToken; expiry is checked after consumption so
// failures burn the token (safe direction).
func (s *Sulis) consumeToken(ctx context.Context, rawToken string, purpose TokenPurpose) (*Token, error) {
	token, err := s.tokens.ConsumeToken(ctx, hashToken(rawToken), purpose)
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			return nil, ErrTokenInvalid
		}
		return nil, err // ErrTokenAlreadyUsed and store failures propagate
	}
	if time.Now().After(token.ExpiresAt) {
		return nil, ErrTokenExpired
	}
	return token, nil
}
```

`ResetPassword`: `consumeToken` → `GetUserByID` → `setPassword`; drop the trailing `MarkTokenUsed`. `RedeemMagicLink`: `consumeToken` → `GetUserByID` → `createSession`; drop `MarkTokenUsed`. Delete `validateToken` and the `MarkTokenUsed` interface method; update fakes and any test using them.

- [ ] **Step 4: Run `go test ./... && go vet ./...` — verify GREEN**

- [ ] **Step 5: Commit** — `git commit -m "Make token consumption atomic and consume before side effects"`

### Task 2: Revoke Sessions And Stale Tokens On Password Change

A password reset that leaves an attacker's stolen session alive defeats the point of resetting. Also stop re-attaching the raw bearer token in `ValidateSession` — raw tokens should exist only at issue time (per the 2026-04-02 design).

**Files:**
- Modify: `token.go` (interface), `config.go`, `sulis.go`
- Test: `sulis_test.go`

**Interfaces:**
- Consumes: `consumeToken` from Task 1.
- Produces: `TokenStore.DeleteUserTokens(ctx, userID string, purpose TokenPurpose) error`; `Config.RevokeSessionsOnPasswordChange bool` (default `true`) + `WithRevokeSessionsOnPasswordChange(bool)`.

- [ ] **Step 1: Write failing tests**

```go
func TestResetPasswordRevokesAllSessions(t *testing.T)        // old session invalid after reset
func TestChangePasswordRevokesAllSessions(t *testing.T)       // same for ChangePassword
func TestResetPasswordDeletesOutstandingResetTokens(t *testing.T) // second live reset token no longer redeemable
func TestWithRevokeSessionsOnPasswordChangeFalseKeepsSessions(t *testing.T)
func TestValidateSessionDoesNotEchoRawToken(t *testing.T)     // returned Session.Token == ""
```

Add a test env helper the later tasks reuse:

```go
func newTestEnv(opts ...Option) (*Sulis, *memUserStore, *memSessionStore, *memTokenStore)
```

- [ ] **Step 2: Run `go test ./...` — verify RED**

- [ ] **Step 3: Implement**

Add `DeleteUserTokens` to `TokenStore` + `memTokenStore`. In `setPassword`, after `UpdateUser` succeeds:

```go
if s.cfg.RevokeSessionsOnPasswordChange {
	if err := s.sessions.DeleteUserSessions(ctx, user.ID); err != nil {
		return err
	}
}
return s.tokens.DeleteUserTokens(ctx, user.ID, TokenPurposePasswordReset)
```

In `ValidateSession`, remove `validated.Token = token`.

- [ ] **Step 4: Run `go test ./... && go vet ./...` — verify GREEN**

- [ ] **Step 5: Commit** — `git commit -m "Revoke sessions and stale reset tokens on password change"`

### Task 3: Login Timing Equalization And Password Length Policy

`Login` returns before any Argon2 work for unknown emails and passwordless users — response time reveals account existence. Passwords also have no length bounds (no minimum; no maximum = CPU-DoS via huge Argon2 inputs).

**Files:**
- Modify: `sulis.go`, `config.go`, `errors.go`
- Test: `sulis_test.go`, `password_test.go`

**Interfaces:**
- Produces: `Config.MinPasswordLength` (default 8), `Config.MaxPasswordLength` (default 1024, bytes) + `WithPasswordLengthLimits(min, max int)`; `ErrPasswordTooShort`, `ErrPasswordTooLong`; unexported `Sulis.dummyHash`.

- [ ] **Step 1: Write failing tests**

```go
func TestLoginUnknownUserStillRunsArgon2(t *testing.T) {
	// wrap verification indirectly: time Login for unknown email vs known email
	// with wrong password; assert unknown-email duration >= 50% of known-email
	// duration (coarse bound — catches the early return without being flaky).
}
func TestLoginPasswordlessUserReturnsInvalidCredentials(t *testing.T) // unchanged behavior, now with dummy verify
func TestRegisterRejectsShortPassword(t *testing.T)  // 7 chars -> ErrPasswordTooShort
func TestRegisterRejectsHugePassword(t *testing.T)   // 1025 bytes -> ErrPasswordTooLong
func TestPolicyAppliesToChangeSetInitialAndReset(t *testing.T) // all three reject "short"
```

- [ ] **Step 2: Run `go test ./...` — verify RED**

- [ ] **Step 3: Implement**

In `New`, after building cfg: `s.dummyHash, _ = hashPassword("sulis-timing-equalization-dummy", cfg.Argon2)` (crypto/rand cannot fail on Go ≥1.24). In `Login`, on the `ErrUserNotFound` and empty-`PasswordHash` paths, run `_, _ = verifyPassword(password, s.dummyHash)` before returning `ErrInvalidCredentials`.

```go
func (s *Sulis) checkPasswordPolicy(password string) error {
	if len(password) < s.cfg.MinPasswordLength {
		return ErrPasswordTooShort
	}
	if len(password) > s.cfg.MaxPasswordLength {
		return ErrPasswordTooLong
	}
	return nil
}
```

Call it at the top of `Register`, `ChangePassword` (new password), `SetInitialPassword`, and `ResetPassword` (before consuming the token, so a policy failure does not burn it).

- [ ] **Step 4: Run `go test ./... && go vet ./...` — verify GREEN**

- [ ] **Step 5: Commit** — `git commit -m "Equalize login timing and enforce password length bounds"`

### Task 4: Harden Argon2 Hash Decoding

`decodeHash` never checks the algorithm label and trusts parameters read from the stored hash — a tampered DB row could trigger a multi-GiB allocation on verify.

**Files:**
- Modify: `password.go`
- Test: `password_test.go`

- [ ] **Step 1: Write failing tests**

```go
func TestDecodeHashRejectsWrongAlgorithm(t *testing.T)   // "$argon2i$..." -> error
func TestDecodeHashRejectsOversizedMemory(t *testing.T)  // m=4294967295 -> error, no allocation
func TestDecodeHashRejectsZeroParams(t *testing.T)       // t=0 or p=0 -> error
func TestDecodeHashRejectsBadSaltOrKeySize(t *testing.T) // 4-byte salt / 8-byte key -> error
```

- [ ] **Step 2: Run `go test ./password_test.go` (via `go test ./...`) — verify RED**

- [ ] **Step 3: Implement** — in `decodeHash`, after splitting:

```go
if parts[1] != "argon2id" {
	return params, nil, nil, fmt.Errorf("sulis: unsupported algorithm %q", parts[1])
}
```

After parsing params and decoding salt/hash:

```go
switch {
case params.Parallelism == 0,
	params.Iterations == 0 || params.Iterations > 1024,
	params.Memory < 8*uint32(params.Parallelism) || params.Memory > 1<<22, // 4 GiB cap
	len(salt) < 8 || len(salt) > 64,
	len(hash) < 16 || len(hash) > 128:
	return params, nil, nil, fmt.Errorf("sulis: hash parameters out of bounds")
}
```

- [ ] **Step 4: Run `go test ./... && go vet ./...` — verify GREEN**

- [ ] **Step 5: Commit** — `git commit -m "Validate algorithm label and parameter bounds when decoding hashes"`

### Task 5: Email Normalization And Deferred Magic-Link User Creation

Emails are used verbatim (`Foo@x.com` ≠ `foo@x.com`), and `CreateMagicLinkToken` inserts a user row for any string before anything is delivered — an unauthenticated flooding vector. Create the user at redemption time instead.

**Files:**
- Modify: `sulis.go`, `magiclink.go`, `token.go`, `errors.go`
- Test: `sulis_test.go`

**Interfaces:**
- Produces: `normalizeEmail(email string) (string, error)`; `ErrInvalidEmail`; `Token.Email string` field; `createTokenForUser(ctx, userID string, purpose TokenPurpose, ttl time.Duration) (string, error)` (reused by Tasks 11 and 13).

- [ ] **Step 1: Write failing tests**

```go
func TestEmailsAreNormalized(t *testing.T)              // Register "Foo@X.com " then Login "foo@x.com" works
func TestRegisterRejectsInvalidEmail(t *testing.T)      // "not-an-email", "a b@c.d", 255+ chars -> ErrInvalidEmail
func TestCreateMagicLinkTokenDoesNotCreateUser(t *testing.T) // unknown email: token issued, user store still empty
func TestRedeemMagicLinkCreatesPasswordlessUser(t *testing.T) // redemption creates user with normalized email
func TestRedeemMagicLinkRacesWithRegister(t *testing.T) // user registered between create and redeem: redeem logs into that account
```

- [ ] **Step 2: Run `go test ./...` — verify RED**

- [ ] **Step 3: Implement**

```go
// sulis.go
func normalizeEmail(email string) (string, error) {
	email = strings.TrimSpace(email)
	if email == "" || len(email) > 254 {
		return "", ErrInvalidEmail
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email { // rejects "Name <a@b>" forms
		return "", ErrInvalidEmail
	}
	return strings.ToLower(email), nil
}
```

Apply at the top of `Register`, `Login`, `CreatePasswordResetToken`, `CreateMagicLinkToken`. Split `createToken` into `createTokenForUser(ctx, userID, purpose, ttl)`; `CreatePasswordResetToken` = normalize → `GetUserByEmail` → `createTokenForUser(user.ID, TokenPurposePasswordReset, s.cfg.TokenDuration)`.

`CreateMagicLinkToken`: normalize; `GetUserByEmail`; if found, `createTokenForUser`; if `ErrUserNotFound`, create the token directly with `UserID: ""` and `Email: email` (no user row). `RedeemMagicLink`:

```go
token, err := s.consumeToken(ctx, rawToken, TokenPurposeMagicLink)
// ...
var user *User
if token.UserID != "" {
	user, err = s.users.GetUserByID(ctx, token.UserID)
} else {
	user, err = s.getOrCreatePasswordlessUser(ctx, token.Email)
}
```

`getOrCreatePasswordlessUser`: `GetUserByEmail`; on `ErrUserNotFound` create the passwordless user; if `CreateUser` returns `ErrUserAlreadyExists` (race), `GetUserByEmail` again.

- [ ] **Step 4: Run `go test ./... && go vet ./...` — verify GREEN**

- [ ] **Step 5: Commit** — `git commit -m "Normalize emails and defer magic-link user creation to redemption"`

---

## Phase 2 — TOTP hardening

### Task 6: TOTP Replay Protection

A valid TOTP code currently works for its whole window (±skew). RFC 6238 §5.2 requires rejecting reuse of the same time step.

**Files:**
- Modify: `totp/totp.go`, `totp/store.go`
- Test: `totp/totp_test.go`

**Interfaces:**
- Produces: `Credential.LastUsedCounter uint64`; `ErrTOTPReplayed`; internal `matchCode(secret, code string, t time.Time) (counter uint64, ok bool)`.

- [ ] **Step 1: Write failing tests**

```go
func TestValidateRejectsReplayedCode(t *testing.T) {
	// enroll+confirm with code A at time T; Validate(code for T) -> false, ErrTOTPReplayed
	// (confirmation already consumed that counter)
}
func TestValidateAcceptsNextWindowCode(t *testing.T)   // code for T+period validates after code for T
func TestValidateRejectsOlderWindowAfterNewer(t *testing.T) // once T+period used, code for T fails
func TestValidatePersistsLastUsedCounter(t *testing.T) // memTOTPStore credential updated on success
```

- [ ] **Step 2: Run `go test ./totp` — verify RED**

- [ ] **Step 3: Implement**

Replace `validateCode` with `matchCode`, which returns the matched counter (`uint64(shifted.Unix()) / cfg.Period`). In `ConfirmEnrollment`: on match, set `Verified = true`, `LastUsedCounter = counter`, save. In `Validate`:

```go
counter, ok := s.matchCode(cred.Secret, code, time.Now())
if !ok {
	return false, nil
}
if counter <= cred.LastUsedCounter {
	return false, ErrTOTPReplayed
}
cred.LastUsedCounter = counter
if err := s.store.SaveTOTP(ctx, cred); err != nil {
	return false, err // fail closed if the counter cannot be persisted
}
return true, nil
```

Document on `Store.SaveTOTP` that implementations should persist `LastUsedCounter` atomically with respect to concurrent validates.

- [ ] **Step 4: Run `go test ./... && go vet ./...` — verify GREEN**

- [ ] **Step 5: Commit** — `git commit -m "Reject replayed TOTP codes by tracking the last used counter"`

### Task 7: TOTP Config Validation

`Period=0` divides by zero; `Digits>9` overflows the uint32 modulus. Validate at construction.

**Files:**
- Modify: `totp/totp.go`
- Test: `totp/totp_test.go`

**Interfaces:**
- Produces: `NewService(store Store, issuer string, opts ...Option) (*Service, error)` — breaking signature change; update all call sites in tests.

- [ ] **Step 1: Write failing tests**

```go
func TestNewServiceRejectsInvalidConfig(t *testing.T) {
	// table test: Digits 5 and 9, Period 0 and 301, Skew 5, SecretSize 15,
	// empty issuer, issuer containing ":" -> all return error
}
func TestNewServiceAcceptsDefaults(t *testing.T)
```

- [ ] **Step 2: Run `go test ./totp` — verify RED (won't compile until signature changes)**

- [ ] **Step 3: Implement** — after applying options in `NewService`:

```go
switch {
case cfg.Issuer == "" || strings.Contains(cfg.Issuer, ":"):
	return nil, fmt.Errorf("totp: issuer must be non-empty and contain no ':'")
case cfg.Digits < 6 || cfg.Digits > 8:
	return nil, fmt.Errorf("totp: digits must be 6-8, got %d", cfg.Digits)
case cfg.Period < 15 || cfg.Period > 300:
	return nil, fmt.Errorf("totp: period must be 15-300 seconds, got %d", cfg.Period)
case cfg.Skew > 4:
	return nil, fmt.Errorf("totp: skew must be at most 4, got %d", cfg.Skew)
case cfg.SecretSize < 16:
	return nil, fmt.Errorf("totp: secret size must be at least 16 bytes, got %d", cfg.SecretSize)
}
```

- [ ] **Step 4: Run `go test ./... && go vet ./...` — verify GREEN**

- [ ] **Step 5: Commit** — `git commit -m "Validate TOTP configuration at service construction"`

---

## Phase 3 — Passkey hardening

### Task 8: Scope Challenges By Ceremony, Surface Clone Detection, Keep Error Detail

Registration and login challenges share the key `userID`, so concurrent ceremonies clobber each other. `FinishLogin` also swallows the underlying error and ignores the library's `CloneWarning` (stolen/cloned authenticator signal).

**Files:**
- Modify: `passkey/passkey.go`
- Test: `passkey/passkey_test.go`

**Interfaces:**
- Produces: `ErrCloneWarning`; challenge keys become `"register:"+userID` / `"login:"+userID` (documented on `ChallengeStore`).

- [ ] **Step 1: Write failing tests**

```go
func TestRegistrationAndLoginChallengesDoNotClobber(t *testing.T) {
	// BeginRegistration then BeginLogin for same user: fakeChallengeStore holds
	// both "register:<id>" and "login:<id>" entries.
}
func TestFinishLoginWrapsUnderlyingError(t *testing.T) {
	// bad assertion body: errors.Is(err, ErrChallengeFailed) AND err.Error()
	// contains detail beyond the sentinel text.
}
func TestFinishLoginRejectsClonedAuthenticator(t *testing.T) {
	// exercise via a helper that injects CloneWarning (extract the post-Finish
	// handling into finishLoginCredential(ctx, waCred) for testability):
	// returns ErrCloneWarning and does NOT call UpdateCredentialSignCount.
}
```

- [ ] **Step 2: Run `go test ./passkey` — verify RED**

- [ ] **Step 3: Implement**

```go
func challengeKey(kind, id string) string { return kind + ":" + id }
```

Use `challengeKey("register", string(user.ID))` in Begin/FinishRegistration and `challengeKey("login", ...)` in Begin/FinishLogin. Extract the post-`wa.FinishLogin` logic:

```go
func (s *Service) finishLoginCredential(ctx context.Context, waCred *webauthn.Credential) (*Credential, error) {
	if waCred.Authenticator.CloneWarning {
		return nil, ErrCloneWarning
	}
	if err := s.store.UpdateCredentialSignCount(ctx, waCred.ID, waCred.Authenticator.SignCount); err != nil {
		return nil, err
	}
	return s.store.GetCredentialByID(ctx, waCred.ID)
}
```

Replace `return nil, ErrChallengeFailed` with `return nil, fmt.Errorf("%w: %v", ErrChallengeFailed, err)`. Document on `ChallengeStore` that keys are opaque strings and entries should expire after ~5 minutes.

- [ ] **Step 4: Run `go test ./... && go vet ./...` — verify GREEN**

- [ ] **Step 5: Commit** — `git commit -m "Scope passkey challenges by ceremony and surface clone warnings"`

### Task 9: Discoverable (Usernameless) Passkey Login

`BeginLogin` requires knowing the user first; passkeys' main draw is "sign in with a passkey" with no identifier typed.

**Files:**
- Modify: `passkey/passkey.go`
- Test: `passkey/passkey_test.go`

**Interfaces:**
- Consumes: `challengeKey`, `finishLoginCredential` from Task 8; `Store.GetCredentialByID`.
- Produces: `BeginDiscoverableLogin(ctx) (*protocol.CredentialAssertion, string, error)` (second return is a ceremony ID the caller must echo back); `FinishDiscoverableLogin(ctx, ceremonyID string, r *http.Request) (*Credential, error)`.

- [ ] **Step 1: Write failing tests**

```go
func TestBeginDiscoverableLoginSavesChallengeUnderCeremonyID(t *testing.T) // key "discover:<ceremonyID>" in fake store
func TestBeginDiscoverableLoginReturnsUniqueCeremonyIDs(t *testing.T)      // two calls, two distinct IDs, two entries
func TestFinishDiscoverableLoginWithoutChallengeReturnsErrChallengeExpired(t *testing.T)
```

- [ ] **Step 2: Run `go test ./passkey` — verify RED**

- [ ] **Step 3: Implement**

```go
func (s *Service) BeginDiscoverableLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	assertion, sessionData, err := s.wa.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", fmt.Errorf("passkey: begin discoverable login: %w", err)
	}
	data, err := json.Marshal(sessionData)
	if err != nil {
		return nil, "", fmt.Errorf("passkey: marshaling session: %w", err)
	}
	ceremonyID := generateID()
	if err := s.challenges.SaveChallenge(ctx, challengeKey("discover", ceremonyID), data); err != nil {
		return nil, "", err
	}
	return assertion, ceremonyID, nil
}

func (s *Service) FinishDiscoverableLogin(ctx context.Context, ceremonyID string, r *http.Request) (*Credential, error) {
	key := challengeKey("discover", ceremonyID)
	data, err := s.challenges.GetChallenge(ctx, key)
	if err != nil {
		return nil, ErrChallengeExpired
	}
	defer s.challenges.DeleteChallenge(ctx, key)

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		return nil, fmt.Errorf("passkey: unmarshaling session: %w", err)
	}

	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		cred, err := s.store.GetCredentialByID(ctx, rawID)
		if err != nil {
			return nil, ErrPasskeyNotFound
		}
		if cred.UserID != string(userHandle) {
			return nil, ErrChallengeFailed
		}
		return &User{ID: userHandle, Credentials: []Credential{*cred}}, nil
	}

	waCred, err := s.wa.FinishDiscoverableLogin(handler, sessionData, r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChallengeFailed, err)
	}
	return s.finishLoginCredential(ctx, waCred)
}
```

- [ ] **Step 4: Run `go test ./... && go vet ./...` — verify GREEN**

- [ ] **Step 5: Commit** — `git commit -m "Add discoverable passkey login"`

---

## Phase 4 — Features

### Task 10: Split Verification From Session Issuance

There is currently no public way to issue a sulis session after a passkey login, and no way to verify a password without creating a session (needed for the 2FA flow).

**Files:**
- Modify: `sulis.go`
- Test: `sulis_test.go`

**Interfaces:**
- Produces: `VerifyPassword(ctx, email, password string) (*User, error)` (all of Login's checks, dummy-hash timing included, no session); `IssueSession(ctx, userID string) (*Session, error)`.

- [ ] **Step 1: Write failing tests**

```go
func TestVerifyPasswordDoesNotCreateSession(t *testing.T) // session store stays empty
func TestVerifyPasswordWrongPasswordReturnsInvalidCredentials(t *testing.T)
func TestIssueSessionReturnsValidatableSession(t *testing.T) // IssueSession -> ValidateSession round-trip
func TestLoginStillReturnsUserAndSession(t *testing.T)       // Login == VerifyPassword + IssueSession
```

- [ ] **Step 2: Run `go test ./...` — verify RED**

- [ ] **Step 3: Implement** — move Login's body into `VerifyPassword`; `Login` becomes `VerifyPassword` + `createSession`. `IssueSession` is a public wrapper over `createSession` with a doc comment: *"Callers MUST invoke this only after fully authenticating the user (e.g. a finished passkey ceremony or completed 2FA)."*

- [ ] **Step 4: Run `go test ./... && go vet ./...` — verify GREEN**

- [ ] **Step 5: Commit** — `git commit -m "Split password verification from session issuance"`

### Task 11: Two-Factor Pending Login Flow

Nothing represents "password verified, second factor pending". Reuse the token machinery: a short-lived, single-use pending token bridges the two steps.

**Files:**
- Modify: `sulis.go` (new file `twofactor.go` for the two methods), `token.go`, `config.go`
- Test: `sulis_test.go`

**Interfaces:**
- Consumes: `createTokenForUser` (Task 5), `consumeToken` (Task 1), `createSession`.
- Produces: `TokenPurposeTwoFactor = "two_factor"`; `Config.TwoFactorTokenDuration` (default 5 min) + `WithTwoFactorTokenDuration(d)`; `CreateTwoFactorToken(ctx, userID string) (string, error)`; `CompleteTwoFactor(ctx, rawToken string) (*User, *Session, error)`.

Intended app flow (goes in the README in Task 16): `VerifyPassword` → app checks its own "user has 2FA" flag → `CreateTwoFactorToken` → app verifies TOTP/recovery code/passkey → `CompleteTwoFactor` → session.

- [ ] **Step 1: Write failing tests**

```go
func TestTwoFactorFlowIssuesSessionOnlyAfterCompletion(t *testing.T) // no session until CompleteTwoFactor
func TestTwoFactorTokenIsSingleUse(t *testing.T)                     // second CompleteTwoFactor -> ErrTokenAlreadyUsed
func TestTwoFactorTokenExpires(t *testing.T)                         // WithTwoFactorTokenDuration(-time.Second) -> ErrTokenExpired
func TestTwoFactorTokenRejectedByOtherFlows(t *testing.T)            // ResetPassword with a 2FA token -> ErrTokenInvalid
```

- [ ] **Step 2: Run `go test ./...` — verify RED**

- [ ] **Step 3: Implement**

```go
// twofactor.go
func (s *Sulis) CreateTwoFactorToken(ctx context.Context, userID string) (string, error) {
	if _, err := s.users.GetUserByID(ctx, userID); err != nil {
		return "", err
	}
	return s.createTokenForUser(ctx, userID, TokenPurposeTwoFactor, s.cfg.TwoFactorTokenDuration)
}

func (s *Sulis) CompleteTwoFactor(ctx context.Context, rawToken string) (*User, *Session, error) {
	token, err := s.consumeToken(ctx, rawToken, TokenPurposeTwoFactor)
	if err != nil {
		return nil, nil, err
	}
	user, err := s.users.GetUserByID(ctx, token.UserID)
	if err != nil {
		return nil, nil, err
	}
	session, err := s.createSession(ctx, user.ID)
	if err != nil {
		return nil, nil, err
	}
	return user, session, nil
}
```

- [ ] **Step 4: Run `go test ./... && go vet ./...` — verify GREEN**

- [ ] **Step 5: Commit** — `git commit -m "Add two-factor pending login flow"`

### Task 12: Recovery Codes Package

Standard companion to 2FA: without recovery codes, a lost phone means lockout or a support-driven bypass.

**Files:**
- Create: `recovery/recovery.go`, `recovery/store.go`
- Test: `recovery/recovery_test.go`

**Interfaces:**
- Produces (package `recovery`):

```go
var (
	ErrCodeInvalid  = errors.New("recovery: invalid code")
	ErrCodeNotFound = errors.New("recovery: code not found") // returned by stores
)

type Store interface {
	// ReplaceCodes atomically replaces the user's full code set.
	ReplaceCodes(ctx context.Context, userID string, hashes []string) error
	// ConsumeCode atomically deletes the code matching userID+hash.
	// Returns ErrCodeNotFound if absent. Lookup and delete MUST be atomic.
	ConsumeCode(ctx context.Context, userID, hash string) error
	CountCodes(ctx context.Context, userID string) (int, error)
	DeleteCodes(ctx context.Context, userID string) error
}

func NewService(store Store, opts ...Option) *Service // WithCount(n int), default 10
func (s *Service) Generate(ctx context.Context, userID string) ([]string, error)
func (s *Service) Consume(ctx context.Context, userID, code string) error
func (s *Service) Remaining(ctx context.Context, userID string) (int, error)
func (s *Service) Disable(ctx context.Context, userID string) error
```

- [ ] **Step 1: Write failing tests** (with an in-memory `memStore` fake, mutex-guarded)

```go
func TestGenerateReturnsFormattedCodesAndStoresOnlyHashes(t *testing.T) // "xxxx-xxxx-xxxx-xxxx", store holds 64-char hex
func TestGenerateReplacesPreviousSet(t *testing.T)                      // old codes stop working
func TestConsumeAcceptsSloppyInput(t *testing.T)                        // uppercase, no dashes, surrounding spaces
func TestConsumeIsSingleUse(t *testing.T)                               // second Consume -> ErrCodeInvalid
func TestConcurrentConsumeSingleWinner(t *testing.T)                    // 2 goroutines, same code, exactly one nil error
func TestRemainingCounts(t *testing.T)
```

- [ ] **Step 2: Run `go test ./recovery` — verify RED**

- [ ] **Step 3: Implement**

Each code: 10 bytes from `crypto/rand` → base32 no-padding (16 chars) → displayed lowercase as `xxxx-xxxx-xxxx-xxxx`. Canonical form for hashing: strip `-` and spaces, uppercase. Hash: SHA-256 hex of the canonical form.

```go
func canonical(code string) string {
	code = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	return strings.ReplaceAll(code, " ", "")
}

func hashCode(code string) string {
	h := sha256.Sum256([]byte(canonical(code)))
	return hex.EncodeToString(h[:])
}

func (s *Service) Consume(ctx context.Context, userID, code string) error {
	err := s.store.ConsumeCode(ctx, userID, hashCode(code))
	if errors.Is(err, ErrCodeNotFound) {
		return ErrCodeInvalid
	}
	return err
}
```

- [ ] **Step 4: Run `go test ./... && go vet ./...` — verify GREEN**

- [ ] **Step 5: Commit** — `git commit -m "Add recovery codes package"`

### Task 13: Email Verification

Unverified emails enable pre-registration account takeover: an attacker registers with the victim's email + a password; the victim later magic-links into that attacker-seeded account.

**Files:**
- Modify: `user.go`, `sulis.go`, `magiclink.go`, `token.go`, `config.go`
- Test: `sulis_test.go`

**Interfaces:**
- Consumes: `createTokenForUser`, `consumeToken`.
- Produces: `User.EmailVerifiedAt *time.Time`; `TokenPurposeEmailVerification = "email_verification"`; `Config.EmailVerificationTokenDuration` (default 24h) + `WithEmailVerificationTokenDuration(d)`; `CreateEmailVerificationToken(ctx, userID string) (string, error)`; `VerifyEmail(ctx, rawToken string) (*User, error)`.

- [ ] **Step 1: Write failing tests**

```go
func TestVerifyEmailStampsEmailVerifiedAt(t *testing.T)
func TestVerifyEmailTokenIsSingleUse(t *testing.T)
func TestRedeemMagicLinkStampsEmailVerified(t *testing.T)      // magic link proves inbox ownership
func TestRegisterLeavesEmailUnverified(t *testing.T)           // EmailVerifiedAt nil after Register
```

- [ ] **Step 2: Run `go test ./...` — verify RED**

- [ ] **Step 3: Implement**

```go
func (s *Sulis) VerifyEmail(ctx context.Context, rawToken string) (*User, error) {
	token, err := s.consumeToken(ctx, rawToken, TokenPurposeEmailVerification)
	if err != nil {
		return nil, err
	}
	user, err := s.users.GetUserByID(ctx, token.UserID)
	if err != nil {
		return nil, err
	}
	return user, s.stampEmailVerified(ctx, user)
}

func (s *Sulis) stampEmailVerified(ctx context.Context, user *User) error {
	if user.EmailVerifiedAt != nil {
		return nil
	}
	now := time.Now()
	user.EmailVerifiedAt = &now
	user.UpdatedAt = now
	return s.users.UpdateUser(ctx, user)
}
```

`CreateEmailVerificationToken`: `GetUserByID` → `createTokenForUser(userID, TokenPurposeEmailVerification, s.cfg.EmailVerificationTokenDuration)`. In `RedeemMagicLink`, call `stampEmailVerified` after resolving the user, before `createSession`.

- [ ] **Step 4: Run `go test ./... && go vet ./...` — verify GREEN**

- [ ] **Step 5: Commit** — `git commit -m "Add email verification flow"`

### Task 14: Rate-Limiting Hooks

The library cannot rate-limit by itself (no IP/state knowledge), but it can guarantee the app's limiter is consulted at every guessable choke point — critical for TOTP (10^6 code space).

**Files:**
- Modify: `config.go`, `errors.go`, `sulis.go`, `magiclink.go`, `totp/totp.go`
- Test: `sulis_test.go`, `totp/totp_test.go`

**Interfaces:**
- Produces (root): `Limiter interface { Allow(ctx context.Context, key string) error }`; `Config.Limiter Limiter` + `WithLimiter(l Limiter)`; `ErrRateLimited`. (totp): identical `Limiter` interface declared locally (no root import; structural typing lets one implementation satisfy both), `Config.Limiter` + `WithLimiter`.

- [ ] **Step 1: Write failing tests**

```go
// root: a fakeLimiter records keys and returns an error when told to.
func TestLoginConsultsLimiterWithNormalizedEmailKey(t *testing.T) // key "password:foo@x.com" for input "Foo@X.com"
func TestDeniedLimiterReturnsErrRateLimited(t *testing.T)         // Login, CreatePasswordResetToken, CreateMagicLinkToken
func TestNilLimiterIsNoOp(t *testing.T)

// totp:
func TestValidateConsultsLimiterBeforeCheckingCode(t *testing.T)  // denied -> (false, error), code never evaluated
```

- [ ] **Step 2: Run `go test ./...` — verify RED**

- [ ] **Step 3: Implement**

```go
// sulis.go
func (s *Sulis) allow(ctx context.Context, key string) error {
	if s.cfg.Limiter == nil {
		return nil
	}
	if err := s.cfg.Limiter.Allow(ctx, key); err != nil {
		return ErrRateLimited
	}
	return nil
}
```

Guard points (after email normalization, before any store lookup): `VerifyPassword` → `"password:"+email`; `CreatePasswordResetToken` → `"reset:"+email`; `CreateMagicLinkToken` → `"magic:"+email`. In `totp.Service.Validate` and `ConfirmEnrollment`, first line: limiter check with key `"totp:"+userID`, returning the limiter error. High-entropy token redemption (`ResetPassword`, `RedeemMagicLink`, `CompleteTwoFactor`) and recovery codes (80-bit) are not guarded — not guessable online; document this reasoning in Task 16.

- [ ] **Step 4: Run `go test ./... && go vet ./...` — verify GREEN**

- [ ] **Step 5: Commit** — `git commit -m "Add rate-limiter hooks at guessable authentication choke points"`

---

## Phase 5 — Housekeeping

### Task 15: Dependencies, CI, LICENSE, gitignore

**Files:**
- Create: `.github/workflows/ci.yml`, `LICENSE`
- Modify: `go.mod`, `go.sum`, `.gitignore`

- [ ] **Step 1: Update dependencies** — `go get -u ./... && go mod tidy`. Verify `github.com/golang-jwt/jwt/v5` lands at ≥ v5.2.2 (memory-allocation advisory fixed there) and `go build ./... && go test ./...` stay green.

- [ ] **Step 2: Add CI**

```yaml
name: CI
on:
  push: { branches: [main] }
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version-file: go.mod }
      - run: go build ./...
      - run: go vet ./...
      - run: go test -race -cover ./...
      - run: go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

- [ ] **Step 3: Add LICENSE** — MIT, `Copyright (c) 2026 Raúl Santos`. (License choice is the owner's call; MIT is the plan default — swap before publishing if preferred.)

- [ ] **Step 4: Fix `.gitignore`** — uncomment the `.idea/` and `.vscode/` lines.

- [ ] **Step 5: Backfill middleware tests** — `middleware.go` has zero coverage. Create `middleware_test.go` using `net/http/httptest` and `newTestEnv`:

```go
func TestAuthenticateAttachesUserAndSession(t *testing.T) {
	// Register, then GET with "Authorization: Bearer <session.Token>" through
	// s.Authenticate(handler); handler asserts UserFromContext and
	// SessionFromContext both return ok=true with the right IDs.
}
func TestAuthenticateAcceptsSessionCookie(t *testing.T)      // cookie "session=<token>" -> 200
func TestAuthenticateRejectsMissingToken(t *testing.T)       // no header, no cookie -> 401, handler not called
func TestAuthenticateRejectsInvalidToken(t *testing.T)       // garbage bearer token -> 401
func TestAuthenticateBearerTakesPrecedenceOverCookie(t *testing.T) // valid cookie + invalid bearer -> 401
```

- [ ] **Step 6: Run `go test ./... && go vet ./...`, then commit** — `git commit -m "Update dependencies, add CI, LICENSE, IDE ignores, and middleware tests"`

### Task 16: README Security And Operations Documentation

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Document the new surface** — sections for: two-factor flow (the `VerifyPassword` → `CreateTwoFactorToken` → verify factor → `CompleteTwoFactor` sequence, with a code example), recovery codes, email verification, discoverable passkey login (including the ceremony-ID round-trip), `IssueSession` after passkey login, and the updated store contracts (`ConsumeToken`/`ConsumeCode` atomicity requirements, `DeleteUserTokens`, `LastUsedCounter`, ceremony-scoped challenge keys with ~5-minute TTL).

- [ ] **Step 2: Add an "Operational requirements" section**, one short paragraph each:
  - Rate limiting is **required** in production: wire `WithLimiter` (root and totp); explain the key scheme and why token redemption is exempt.
  - Schedule `DeleteExpiredTokens` and `CleanExpired` yourself; the library never calls them.
  - Cookie-mode `Authenticate` needs CSRF defenses (SameSite + token or same-origin checks); the middleware accepts both bearer headers and cookies.
  - Encrypt TOTP secrets at rest in your `totp.Store`; the library hands you plaintext base32.
  - `CreatePasswordResetToken` returns `ErrUserNotFound` — respond identically to callers whether or not the account exists, or you build an enumeration oracle.
  - Sessions are revoked on password change/reset by default (`WithRevokeSessionsOnPasswordChange(false)` to opt out); issue a fresh session after `ChangePassword`.

- [ ] **Step 3: Check every claim against the code** (method names, defaults, error names), run `go test ./... && go vet ./...`, commit — `git commit -m "Document MFA flows, store contracts, and operational requirements"`
