package sulis

import (
	"context"
	"fmt"
	"time"
)

// RequireRecentAuth returns ErrReauthRequired if session's AuthenticatedAt is
// older than maxAge, and nil otherwise. It does not touch any store: it is a
// pure check against the *Session the caller already holds (typically the
// one ValidateSession just returned), so gating an endpoint with it costs no
// extra round trip.
//
// A session issued before this field existed, or otherwise never stamped,
// reads back with the zero time for AuthenticatedAt. time.Since of the zero
// time is on the order of two thousand years, which is older than any
// realistic maxAge, so such a session always fails this check — fail closed,
// not "treat an absent stamp as fresh."
//
// Gate security-relevant account changes behind this rather than a bare
// session: enrolling or replacing a TOTP factor (totp.Service.Enroll,
// ReplaceEnrollment), adding or removing a passkey, disabling two-factor
// authentication, changing email (ChangeEmail), and regenerating recovery
// codes should all require proving the credential again, not merely holding
// a cookie from hours ago. See the README's "Step-up authentication"
// section for the full list and example wiring.
func (s *Sulis) RequireRecentAuth(ctx context.Context, session *Session, maxAge time.Duration) error {
	if time.Since(session.AuthenticatedAt) > maxAge {
		return ErrReauthRequired
	}
	return nil
}

// ReAuthenticate verifies password for the user who owns session and, on
// success, stamps session's AuthenticatedAt with the current time — both on
// the stored session and on the *Session the caller passed in, so neither a
// reload nor a fresh ValidateSession call is needed to observe the refresh.
// It mints no new session and does not rotate the session's token: the
// session's ID and TokenHash are exactly what they were before the call.
// This is the write side of the step-up gate RequireRecentAuth checks.
//
// Like VerifyPassword, it is rate-limited on both the account dimension
// (key "password:"+email, the same budget Login/VerifyPassword/
// ChangePassword share, since a stolen session token attempting to
// brute-force the password here is exactly the risk those guard) and the IP
// dimension, and it equalizes response timing for a passwordless account by
// running the same Argon2 work against an internal dummy hash rather than
// returning early. Returns ErrInvalidCredentials for a passwordless account
// or a wrong password — in neither case is AuthenticatedAt touched.
//
// A successful verification here can also upgrade the stored hash, exactly
// like VerifyPassword's success path: if the hash is weaker than the
// currently configured Argon2Params, it is re-hashed with the plaintext
// just verified and written back, best-effort (see password.go's
// needsRehash and sulis.go's rehashPassword). This is deliberate, not an
// oversight left over from T504: ReAuthenticate is a real password
// comparison against a real stored hash, so it upgrades the same as any
// other one — see the T504 (fix round 1) Decisions row.
//
// Also returns ErrAccountDisabled/ErrAccountLocked via accountStatus,
// checked right after loading the user and before spending an Argon2
// verification on a call that cannot succeed either way. Unlike
// VerifyPassword's oracle-ordering concern (an unauthenticated caller must
// not learn account status without proving a password first),
// ReAuthenticate has no equivalent exposure to guard against: the caller
// already holds a valid *Session for this exact account — proof enough
// that the account exists — so checking status before the password costs
// nothing extra in exchange for not refreshing AuthenticatedAt on a
// disabled or locked account's already-held session. This closes the gap
// the T501 Decisions row deferred: see PROGRESS.md.
func (s *Sulis) ReAuthenticate(ctx context.Context, session *Session, password string, ri RequestInfo) error {
	user, err := s.users.GetUserByID(ctx, session.UserID)
	if err != nil {
		return err
	}

	if err := s.allow(ctx, "password:"+user.Email); err != nil {
		return err
	}
	if err := s.allowIP(ctx, "password:", ri); err != nil {
		return err
	}

	if err := s.accountStatus(user); err != nil {
		return err
	}

	if user.PasswordHash == "" {
		// Passwordless user: verify against the dummy hash for the same
		// reason VerifyPassword does — so response timing doesn't reveal
		// that this account has no password to check.
		_, _ = verifyPassword(password, s.dummyHash)
		return ErrInvalidCredentials
	}

	ok, err := verifyPassword(password, user.PasswordHash)
	if err != nil {
		return fmt.Errorf("sulis: verifying password: %w", err)
	}
	if !ok {
		return ErrInvalidCredentials
	}

	// The password just verified, so this is exactly the same
	// weaker-than-configured-hash opportunity VerifyPassword's success path
	// upgrades (see password.go's needsRehash and sulis.go's rehashPassword)
	// — best-effort and swallowed on failure for the same reason: the caller
	// already proved they know the password, so only the cost of the next
	// comparison is at stake, not this call's correctness.
	if needsRehash(user.PasswordHash, s.cfg.Argon2) {
		s.rehashPassword(ctx, user, password)
	}

	now := time.Now()
	if err := s.sessions.UpdateAuthenticatedAt(ctx, session.ID, now); err != nil {
		return err
	}
	session.AuthenticatedAt = now
	return nil
}
