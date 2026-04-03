# Password API Split Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split password bootstrapping from password changing by making `ChangePassword` strict again and adding `SetInitialPassword` for passwordless accounts.

**Architecture:** Keep the change inside the root `sulis` package. Add one new public method and a small private helper in `sulis.go`, update root tests in `sulis_test.go` to enforce the new API boundary, and then update `README.md` so the public docs match the behavior.

**Tech Stack:** Go 1.24, standard library, `golang.org/x/crypto/argon2`

---

## File Map

- `sulis.go`: owns the public password API and should contain both `ChangePassword` and the new `SetInitialPassword` method, plus one small private helper for writing the new password hash.
- `sulis_test.go`: owns root-package behavior tests and should verify both positive and negative password flows using public methods.
- `README.md`: documents the public API and should clearly explain when to use `Register`, `ChangePassword`, and `SetInitialPassword`.

### Task 1: Add `SetInitialPassword`

**Files:**
- Modify: `sulis.go:95-126`
- Modify: `sulis_test.go:612-662`

- [ ] **Step 1: Write the failing tests for the new explicit bootstrap API**

Add these tests to `sulis_test.go` near the current passwordless-password tests:

```go
func TestSetInitialPassword(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	if _, err := s.CreateMagicLinkToken(ctx, "bob@example.com"); err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	user, err := s.users.GetUserByEmail(ctx, "bob@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if user.PasswordHash != "" {
		t.Fatal("expected passwordless user")
	}

	if err := s.SetInitialPassword(ctx, user.ID, "new-password"); err != nil {
		t.Fatalf("SetInitialPassword: %v", err)
	}

	_, _, err = s.Login(ctx, "bob@example.com", "new-password")
	if err != nil {
		t.Fatalf("Login with initial password: %v", err)
	}
}

func TestSetInitialPasswordRejectsExistingPassword(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	user, _, err := s.Register(ctx, "alice@example.com", "password123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	err = s.SetInitialPassword(ctx, user.ID, "new-password")
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `go test ./... -run 'TestSetInitialPassword|TestSetInitialPasswordRejectsExistingPassword'`

Expected: FAIL with a compile error like `s.SetInitialPassword undefined`.

- [ ] **Step 3: Add `SetInitialPassword` and the shared password-writing helper**

Modify `sulis.go` so the new method exists and both password-writing paths can share one helper:

```go
func (s *Sulis) SetInitialPassword(ctx context.Context, userID, newPassword string) error {
	user, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.PasswordHash != "" {
		return ErrInvalidCredentials
	}
	return s.setPassword(ctx, user, newPassword)
}

func (s *Sulis) setPassword(ctx context.Context, user *User, newPassword string) error {
	hash, err := hashPassword(newPassword, s.cfg.Argon2)
	if err != nil {
		return fmt.Errorf("sulis: hashing new password: %w", err)
	}

	user.PasswordHash = hash
	user.UpdatedAt = time.Now()
	return s.users.UpdateUser(ctx, user)
}
```

Put `SetInitialPassword` immediately below `ChangePassword` so the public password APIs stay together. Keep `setPassword` private.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run: `go test ./... -run 'TestSetInitialPassword|TestSetInitialPasswordRejectsExistingPassword'`

Expected: PASS.

- [ ] **Step 5: Commit Task 1**

```bash
git add sulis.go sulis_test.go
git commit -m "feat: add initial password setup API"
```

### Task 2: Make `ChangePassword` Strict Again

**Files:**
- Modify: `sulis.go:95-126`
- Modify: `sulis_test.go:251-273`
- Modify: `sulis_test.go:612-662`

- [ ] **Step 1: Replace the passwordless `ChangePassword` tests with a strict rejection test**

Remove the current passwordless bootstrap assumptions and add this test in `sulis_test.go`:

```go
func TestChangePasswordRejectsPasswordlessUser(t *testing.T) {
	s := newTestSulis()
	ctx := context.Background()

	if _, err := s.CreateMagicLinkToken(ctx, "bob@example.com"); err != nil {
		t.Fatalf("CreateMagicLinkToken: %v", err)
	}

	user, err := s.users.GetUserByEmail(ctx, "bob@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}

	err = s.ChangePassword(ctx, user.ID, "", "new-password")
	if err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}
```

Keep the existing `TestChangePassword` success case for password-based users unchanged.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `go test ./... -run 'TestChangePassword$|TestChangePasswordRejectsPasswordlessUser|TestSetInitialPassword'`

Expected: FAIL because `ChangePassword` still allows the passwordless bootstrap path.

- [ ] **Step 3: Simplify `ChangePassword` so it always requires an existing password**

Replace the current passwordless branch in `sulis.go` with this stricter version:

```go
func (s *Sulis) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	user, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.PasswordHash == "" {
		return ErrInvalidCredentials
	}

	ok, err := verifyPassword(oldPassword, user.PasswordHash)
	if err != nil {
		return fmt.Errorf("sulis: verifying old password: %w", err)
	}
	if !ok {
		return ErrInvalidCredentials
	}

	return s.setPassword(ctx, user, newPassword)
}
```

Also update the comment above `ChangePassword` so it no longer mentions passwordless bootstrap.

- [ ] **Step 4: Run the focused tests and then the full suite**

Run: `go test ./... -run 'TestChangePassword$|TestChangePasswordRejectsPasswordlessUser|TestSetInitialPassword|TestSetInitialPasswordRejectsExistingPassword'`
Expected: PASS.

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 5: Commit Task 2**

```bash
git add sulis.go sulis_test.go
git commit -m "refactor: split password bootstrap from password changes"
```

### Task 3: Update Public Documentation And Re-Verify

**Files:**
- Modify: `README.md:7-46`

- [ ] **Step 1: Update the public API list and flow descriptions in `README.md`**

Make these concrete edits:

```md
- `Register`, `Login`, `ChangePassword`, `SetInitialPassword`
```

Replace the current `ChangePassword` paragraph under `### Login` with:

```md
`ChangePassword(ctx, userID, oldPassword, newPassword)` is for accounts that already have a password. It verifies the old password before storing the new one.

`SetInitialPassword(ctx, userID, newPassword)` is for passwordless accounts created through flows such as magic link. Call it only after your application has already authenticated the user through a trusted flow.
```

Keep the existing note that password changes and resets do not revoke sessions automatically.

- [ ] **Step 2: Re-read the password API in `sulis.go` and verify the README matches it**

Check these points manually:
- `ChangePassword` no longer supports `oldPassword == ""` bootstrap
- `SetInitialPassword` exists and only works for passwordless users
- `Register` remains the password-first path
- magic link may still create passwordless users

- [ ] **Step 3: Run final verification commands**

Run: `go test ./...`
Expected: PASS.

Run: `go vet ./...`
Expected: no output and exit 0.

- [ ] **Step 4: Commit Task 3**

```bash
git add README.md
git commit -m "docs: clarify password change and bootstrap APIs"
```
