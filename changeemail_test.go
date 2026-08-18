package sulis

import (
	"context"
	"testing"
	"time"
)

// countTokensByPurpose reports how many tokens of the given purpose the store
// holds, for tests asserting that a flow issued (or refused to issue) one.
func countTokensByPurpose(ts *memTokenStore, purpose TokenPurpose) int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	n := 0
	for _, t := range ts.tokens {
		if t.Purpose == purpose {
			n++
		}
	}
	return n
}

// stampVerifiedAt sets EmailVerifiedAt to a specific instant on the stored
// user, so a test can prove a later re-stamp produced a *new* timestamp rather
// than reusing the old one.
func stampVerifiedAt(t *testing.T, users *memUserStore, userID string, at time.Time) {
	t.Helper()
	ctx := context.Background()
	u, err := users.GetUserByID(ctx, userID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	u.EmailVerifiedAt = &at
	if err := users.UpdateUser(ctx, u); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
}

// TestChangeEmailStagesWithoutChangingLiveAddress asserts that requesting an
// email change does not touch the live address or its verification stamp: the
// new address is only staged until control of it is proven.
func TestChangeEmailStagesWithoutChangingLiveAddress(t *testing.T) {
	s, users, _, tokens := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	rawToken, err := s.ChangeEmail(ctx, user.ID, "New@Example.com")
	if err != nil {
		t.Fatalf("ChangeEmail: %v", err)
	}
	if rawToken == "" {
		t.Fatal("expected a raw token to deliver to the new address")
	}

	stored, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if stored.Email != "alice@example.com" {
		t.Fatalf("live address changed before confirmation: %q", stored.Email)
	}
	if stored.PendingEmail != "new@example.com" {
		t.Fatalf("expected normalized pending address, got %q", stored.PendingEmail)
	}
	if stored.EmailVerifiedAt == nil {
		t.Fatal("staging a change must not clear verification of the live address")
	}
	if n := countTokensByPurpose(tokens, TokenPurposeEmailChange); n != 1 {
		t.Fatalf("expected 1 email-change token, got %d", n)
	}
}

// TestConfirmEmailChangeSwapsAddressAndReStampsVerification asserts that
// confirmation makes the staged address live, clears the staging slot, and
// establishes verification afresh from the proof just presented.
func TestConfirmEmailChangeSwapsAddressAndReStampsVerification(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	oldStamp := time.Now().Add(-time.Hour)
	stampVerifiedAt(t, users, user.ID, oldStamp)

	rawToken, err := s.ChangeEmail(ctx, user.ID, "new@example.com")
	if err != nil {
		t.Fatalf("ChangeEmail: %v", err)
	}

	changed, err := s.ConfirmEmailChange(ctx, rawToken)
	if err != nil {
		t.Fatalf("ConfirmEmailChange: %v", err)
	}
	if changed.Email != "new@example.com" {
		t.Fatalf("expected returned user to carry the new address, got %q", changed.Email)
	}
	if changed.PendingEmail != "" {
		t.Fatalf("expected pending address cleared, got %q", changed.PendingEmail)
	}
	if changed.EmailVerifiedAt == nil || !changed.EmailVerifiedAt.After(oldStamp) {
		t.Fatalf("expected verification re-stamped after %v, got %v", oldStamp, changed.EmailVerifiedAt)
	}

	stored, err := users.GetUserByEmail(ctx, "new@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail(new): %v", err)
	}
	if stored.ID != user.ID {
		t.Fatalf("expected the new address to resolve to the same user")
	}
	if _, err := users.GetUserByEmail(ctx, "alice@example.com"); err != ErrUserNotFound {
		t.Fatalf("expected the old address to be free, got %v", err)
	}
}

// TestConfirmEmailChangeRevokesSessionsAndPurgesResetTokens asserts that the
// swap invalidates everything the old address could still reach: live sessions
// and any outstanding password-reset token delivered to it.
func TestConfirmEmailChangeRevokesSessionsAndPurgesResetTokens(t *testing.T) {
	s, users, sessions, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	if _, err := s.Login(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{}); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if sessions.count() == 0 {
		t.Fatal("expected a live session before the change")
	}

	resetToken, err := s.CreatePasswordResetToken(ctx, "alice@example.com", RequestInfo{})
	if err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	rawToken, err := s.ChangeEmail(ctx, user.ID, "new@example.com")
	if err != nil {
		t.Fatalf("ChangeEmail: %v", err)
	}
	if _, err := s.ConfirmEmailChange(ctx, rawToken); err != nil {
		t.Fatalf("ConfirmEmailChange: %v", err)
	}

	if n := sessions.count(); n != 0 {
		t.Fatalf("expected all sessions revoked by the swap, got %d", n)
	}
	if err := s.ResetPassword(ctx, resetToken, "brand-new-password"); err != ErrTokenInvalid {
		t.Fatalf("expected the outstanding reset token to be purged, got %v", err)
	}
}

// TestConfirmEmailChangePurgesTwoFactorTokens asserts that a pending 2FA login,
// minted against the account as it was before the change, cannot be completed
// afterwards.
func TestConfirmEmailChangePurgesTwoFactorTokens(t *testing.T) {
	s, users, _, _, factors := newTestEnvWithFactors(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)
	factors.enroll(user.ID)

	res, err := s.Login(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !res.NeedsSecondFactor {
		t.Fatal("expected a pending second factor")
	}

	rawToken, err := s.ChangeEmail(ctx, user.ID, "new@example.com")
	if err != nil {
		t.Fatalf("ChangeEmail: %v", err)
	}
	if _, err := s.ConfirmEmailChange(ctx, rawToken); err != nil {
		t.Fatalf("ConfirmEmailChange: %v", err)
	}

	if _, err := s.CompleteTwoFactor(ctx, user.ID, res.PendingToken, RequestInfo{}); err != ErrTokenInvalid {
		t.Fatalf("expected the pending 2FA token to be purged, got %v", err)
	}
}

// TestConfirmEmailChangeRejectsTokenForSupersededAddress asserts that staging a
// second address invalidates the first one's token. Without this, a token
// delivered to an address the user has since abandoned could still take over
// the account's identity.
func TestConfirmEmailChangeRejectsTokenForSupersededAddress(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	firstToken, err := s.ChangeEmail(ctx, user.ID, "typo@example.com")
	if err != nil {
		t.Fatalf("ChangeEmail(first): %v", err)
	}
	secondToken, err := s.ChangeEmail(ctx, user.ID, "correct@example.com")
	if err != nil {
		t.Fatalf("ChangeEmail(second): %v", err)
	}

	if _, err := s.ConfirmEmailChange(ctx, firstToken); err != ErrTokenInvalid {
		t.Fatalf("expected ErrTokenInvalid for the superseded address, got %v", err)
	}
	stored, err := users.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if stored.Email != "alice@example.com" {
		t.Fatalf("superseded token changed the live address to %q", stored.Email)
	}

	changed, err := s.ConfirmEmailChange(ctx, secondToken)
	if err != nil {
		t.Fatalf("ConfirmEmailChange(second): %v", err)
	}
	if changed.Email != "correct@example.com" {
		t.Fatalf("expected the current staged address to win, got %q", changed.Email)
	}
}

// TestChangeEmailRejectsAddressAlreadyInUse asserts that an address belonging
// to another account is refused before any token is issued, so the flow cannot
// be used to send mail to an address the requester does not own.
func TestChangeEmailRejectsAddressAlreadyInUse(t *testing.T) {
	s, users, _, tokens := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	alice, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register(alice): %v", err)
	}
	if _, _, _, err := s.Register(ctx, "bob@example.com", "correct-battery-staple", RequestInfo{}); err != nil {
		t.Fatalf("Register(bob): %v", err)
	}

	if _, err := s.ChangeEmail(ctx, alice.ID, "BOB@example.com"); err != ErrUserAlreadyExists {
		t.Fatalf("expected ErrUserAlreadyExists, got %v", err)
	}

	if n := countTokensByPurpose(tokens, TokenPurposeEmailChange); n != 0 {
		t.Fatalf("expected no token issued for a taken address, got %d", n)
	}
	stored, err := users.GetUserByID(ctx, alice.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if stored.PendingEmail != "" {
		t.Fatalf("expected nothing staged, got %q", stored.PendingEmail)
	}
}

// TestChangeEmailRejectsCurrentAddress asserts that staging the address the
// account already holds is refused: there is nothing to prove and nothing to
// change.
func TestChangeEmailRejectsCurrentAddress(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := s.ChangeEmail(ctx, user.ID, "Alice@Example.com"); err != ErrUserAlreadyExists {
		t.Fatalf("expected ErrUserAlreadyExists, got %v", err)
	}
}

// TestChangeEmailRejectsInvalidEmail asserts the new address is validated
// before anything is staged.
func TestChangeEmailRejectsInvalidEmail(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if _, err := s.ChangeEmail(ctx, user.ID, "not-an-address"); err != ErrInvalidEmail {
		t.Fatalf("expected ErrInvalidEmail, got %v", err)
	}
}

// TestConfirmEmailChangeRejectsAddressTakenSinceStaging asserts the uniqueness
// check is re-run at confirmation time. Staging does not reserve an address, so
// another account may have claimed it in the meantime.
func TestConfirmEmailChangeRejectsAddressTakenSinceStaging(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	alice, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register(alice): %v", err)
	}
	verifyUserEmail(t, users, alice.ID)

	rawToken, err := s.ChangeEmail(ctx, alice.ID, "contested@example.com")
	if err != nil {
		t.Fatalf("ChangeEmail: %v", err)
	}

	if _, _, _, err := s.Register(ctx, "contested@example.com", "correct-battery-staple", RequestInfo{}); err != nil {
		t.Fatalf("Register(claimant): %v", err)
	}

	if _, err := s.ConfirmEmailChange(ctx, rawToken); err != ErrUserAlreadyExists {
		t.Fatalf("expected ErrUserAlreadyExists at confirmation, got %v", err)
	}
	stored, err := users.GetUserByID(ctx, alice.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if stored.Email != "alice@example.com" {
		t.Fatalf("expected the live address untouched, got %q", stored.Email)
	}
}

// TestConfirmEmailChangeAbortsIfAnotherAccountWinsTheRace asserts the real
// guarantee behind ConfirmEmailChange's cross-account race: when two
// accounts stage the same address and race to confirm it, the loser's write
// is rejected and its live address is left untouched. Unlike
// TestConfirmEmailChangeRejectsAddressTakenSinceStaging (which proves the
// sequential case, resolved by the in-library GetUserByEmail pre-check),
// this interleaves the two confirmations so both pre-checks observe the
// address as free before either write lands — only UserStore.UpdateUser's
// own uniqueness enforcement (see user.go) can catch that, since Version
// only guards a single row and these are two different rows.
func TestConfirmEmailChangeAbortsIfAnotherAccountWinsTheRace(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	alice, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register(alice): %v", err)
	}
	verifyUserEmail(t, users, alice.ID)
	bob, _, _, err := s.Register(ctx, "bob@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register(bob): %v", err)
	}
	verifyUserEmail(t, users, bob.ID)

	aliceToken, err := s.ChangeEmail(ctx, alice.ID, "shared@example.com")
	if err != nil {
		t.Fatalf("ChangeEmail(alice): %v", err)
	}
	bobToken, err := s.ChangeEmail(ctx, bob.ID, "shared@example.com")
	if err != nil {
		t.Fatalf("ChangeEmail(bob): %v", err)
	}

	// Right before alice's confirmation writes, let bob's confirmation run to
	// completion and claim the address first. Both accounts' GetUserByEmail
	// pre-checks see the address as unclaimed at read time; the race is only
	// closed by whichever write reaches the store second.
	users.beforeUpdate = func(u *User) {
		if u.ID != alice.ID {
			return
		}
		if _, err := s.ConfirmEmailChange(ctx, bobToken); err != nil {
			t.Fatalf("ConfirmEmailChange(bob): %v", err)
		}
	}

	if _, err := s.ConfirmEmailChange(ctx, aliceToken); err != ErrUserAlreadyExists {
		t.Fatalf("expected ErrUserAlreadyExists for the losing confirmation, got %v", err)
	}

	stored, err := users.GetUserByID(ctx, alice.ID)
	if err != nil {
		t.Fatalf("GetUserByID(alice): %v", err)
	}
	if stored.Email != "alice@example.com" {
		t.Fatalf("expected alice's live address untouched by the losing confirmation, got %q", stored.Email)
	}

	winner, err := users.GetUserByEmail(ctx, "shared@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail(shared): %v", err)
	}
	if winner.ID != bob.ID {
		t.Fatalf("expected bob to hold the contested address, got user %q", winner.ID)
	}
}

// TestEmailChangeTokensArePurposeScoped asserts an email-change token cannot be
// spent on another flow, and that another flow's token cannot confirm a change.
func TestEmailChangeTokensArePurposeScoped(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	changeToken, err := s.ChangeEmail(ctx, user.ID, "new@example.com")
	if err != nil {
		t.Fatalf("ChangeEmail: %v", err)
	}
	if _, err := s.VerifyEmail(ctx, changeToken); err != ErrTokenInvalid {
		t.Fatalf("expected an email-change token to be rejected by VerifyEmail, got %v", err)
	}

	verificationToken, err := s.CreateEmailVerificationToken(ctx, user.ID)
	if err != nil {
		t.Fatalf("CreateEmailVerificationToken: %v", err)
	}
	if _, err := s.ConfirmEmailChange(ctx, verificationToken); err != ErrTokenInvalid {
		t.Fatalf("expected a verification token to be rejected by ConfirmEmailChange, got %v", err)
	}
}
