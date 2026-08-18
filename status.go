package sulis

import (
	"context"
	"time"
)

// DisableUser marks userID as disabled, effective immediately: it stamps
// User.DisabledAt and records reason (caller-supplied context — sulis never
// inspects it, see User.DisabledReason), then revokes every existing
// session for the account.
//
// The write that marks the account disabled happens BEFORE the session
// revocation, not after, and revocation is best treated as an optimization
// for immediate cutoff rather than the mechanism disabling actually depends
// on: even if DeleteUserSessions itself failed, every one of those sessions
// would still die on its very next use, because ValidateSession checks
// DisabledAt on every call. Without that check, disabling would leave live
// sessions working for the remainder of their natural lifetime — this is
// why ValidateSession's own check is the one piece of this feature that
// matters most.
//
// Returns ErrUserNotFound if no such user exists.
func (s *Sulis) DisableUser(ctx context.Context, userID, reason string) error {
	now := time.Now()
	user, err := s.updateUserWithRetry(ctx, userID, func(u *User) error {
		u.DisabledAt = &now
		u.DisabledReason = reason
		u.UpdatedAt = now
		return nil
	})
	if err != nil {
		return err
	}
	return s.sessions.DeleteUserSessions(ctx, user.ID)
}

// EnableUser reverses a previous DisableUser call: DisabledAt and
// DisabledReason are reset to their zero values, and authentication works
// again on the next attempt. It does not touch LockedUntil or
// FailedLoginAttempts — those belong to the separate automatic-lockout
// mechanism (see WithFailureLockout), and an operator re-enabling a
// manually disabled account is not the same event as a lockout window
// expiring; EnableUser should not silently forgive an in-progress lockout
// the operator may not even know about. It also does not restore any
// session DisableUser revoked — the account can simply start new ones.
//
// Returns ErrUserNotFound if no such user exists.
func (s *Sulis) EnableUser(ctx context.Context, userID string) error {
	_, err := s.updateUserWithRetry(ctx, userID, func(u *User) error {
		u.DisabledAt = nil
		u.DisabledReason = ""
		u.UpdatedAt = time.Now()
		return nil
	})
	return err
}

// accountStatus reports whether user may authenticate right now: nil if the
// account is clear, ErrAccountDisabled if DisabledAt is set, or
// ErrAccountLocked if LockedUntil is set and still in the future.
//
// Every session-issuance path must call this — completeFirstFactor (the
// choke point shared by Login and RedeemMagicLink), issueSessionForUser
// (IssueSession/IssueSessionUnchecked), and CompleteTwoFactor all do.
// VerifyPassword also calls it, but only AFTER the password has already
// verified: an unauthenticated caller who has not proven the password must
// not be able to use a distinct error to learn that an account exists and
// is disabled or locked. See the README's "Account disable and lockout"
// section for the full reasoning, including why ValidateSession checks only
// DisabledAt and not LockedUntil.
func (s *Sulis) accountStatus(user *User) error {
	if user.DisabledAt != nil {
		return ErrAccountDisabled
	}
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return ErrAccountLocked
	}
	return nil
}

// recordFailedLogin is called by VerifyPassword after a wrong password for
// a real (non-passwordless, non-unknown) user, and only when automatic
// lockout (WithFailureLockout) is configured. It increments
// FailedLoginAttempts and, once the configured threshold is reached, sets
// LockedUntil to an exponentially growing backoff from now — recomputed and
// pushed out again on every further failure while still locked, so
// continued guessing keeps extending the deadline rather than reaching it
// once and stopping.
//
// Any error is swallowed rather than returned: this is best-effort
// bookkeeping, and a write failure here must not turn a correctly detected
// wrong password into a different error for the caller, who is about to
// receive ErrInvalidCredentials regardless.
func (s *Sulis) recordFailedLogin(ctx context.Context, userID string) {
	now := time.Now()
	_, _ = s.updateUserWithRetry(ctx, userID, func(u *User) error {
		u.FailedLoginAttempts++
		if u.FailedLoginAttempts >= s.cfg.FailureLockoutThreshold {
			excess := u.FailedLoginAttempts - s.cfg.FailureLockoutThreshold
			until := now.Add(lockoutBackoff(s.cfg.FailureLockoutBaseBackoff, s.cfg.FailureLockoutMaxBackoff, excess))
			u.LockedUntil = &until
		}
		u.UpdatedAt = now
		return nil
	})
}

// clearFailedLogins resets the automatic-lockout bookkeeping after a
// password has just verified correctly outside any active lockout window —
// VerifyPassword's success path calls it so the account doesn't carry a
// stale failure count or a lockout stamp forward into the future. Swallows
// errors for the same reason recordFailedLogin does: the caller is about to
// receive a successful result, and a bookkeeping failure here must not turn
// that into an error instead.
func (s *Sulis) clearFailedLogins(ctx context.Context, userID string) {
	_, _ = s.updateUserWithRetry(ctx, userID, func(u *User) error {
		u.FailedLoginAttempts = 0
		u.LockedUntil = nil
		u.UpdatedAt = time.Now()
		return nil
	})
}

// lockoutBackoff computes the automatic-lockout duration for excess
// failures beyond the configured threshold: base, doubling with every
// additional failure, capped at max. excess is clamped to keep the shift
// from overflowing time.Duration's underlying int64; any overflow that
// still slipped through (a zero or negative result) also clamps to max
// rather than producing a lockout shorter than intended — the failure mode
// a wraparound would otherwise cause is exactly backwards from what a
// lockout is for.
func lockoutBackoff(base, max time.Duration, excess int) time.Duration {
	if excess < 0 {
		excess = 0
	}
	if excess > 32 {
		excess = 32
	}
	backoff := base << uint(excess)
	if backoff <= 0 || backoff > max {
		backoff = max
	}
	return backoff
}
