package sulis

import "errors"

var (
	// User errors.
	ErrUserNotFound      = errors.New("sulis: user not found")
	ErrUserAlreadyExists = errors.New("sulis: user already exists")
	// ErrConcurrentUpdate is returned by UserStore.UpdateUser when the write
	// was built from a stale read and another writer won the race.
	ErrConcurrentUpdate = errors.New("sulis: concurrent update")

	// Credential errors.
	ErrInvalidCredentials = errors.New("sulis: invalid credentials")

	// Authentication errors.
	//
	// ErrNotAuthenticated is returned by IssueSession when given the zero
	// value Authentication{} (or any Authentication not obtained by
	// completing a factor sulis itself verified, since nothing outside this
	// package can construct one otherwise). It means there is no proof of
	// authentication to act on, not that a specific credential was wrong.
	ErrNotAuthenticated = errors.New("sulis: not authenticated")

	// Session errors.
	ErrSessionNotFound = errors.New("sulis: session not found")
	ErrSessionExpired  = errors.New("sulis: session expired")

	// ErrReauthRequired is returned by RequireRecentAuth when a session's
	// AuthenticatedAt is older than the caller's maxAge. It means the
	// session is otherwise valid — ValidateSession would still accept it —
	// but too stale to authorize a step-up-gated operation without proving
	// the credential again via ReAuthenticate.
	ErrReauthRequired = errors.New("sulis: recent authentication required")

	// Token errors.
	ErrTokenInvalid     = errors.New("sulis: invalid token")
	ErrTokenNotFound    = errors.New("sulis: token not found")
	ErrTokenExpired     = errors.New("sulis: token expired")
	ErrTokenAlreadyUsed = errors.New("sulis: token already used")

	// Password policy errors.
	ErrPasswordTooShort = errors.New("sulis: password too short")
	ErrPasswordTooLong  = errors.New("sulis: password too long")

	// Email validation errors.
	ErrInvalidEmail = errors.New("sulis: invalid email")

	// Email verification errors.
	ErrEmailNotVerified = errors.New("sulis: email not verified")

	// Rate limiting.
	ErrRateLimited = errors.New("sulis: rate limited")

	// Account status errors.
	//
	// ErrAccountDisabled is returned once a credential has verified for an
	// account DisableUser marked disabled — VerifyPassword checks this only
	// after a successful password verification, so a caller who has not
	// proven the password cannot use it to learn whether an account exists
	// and is disabled. ValidateSession also returns it for a pre-existing
	// session belonging to a disabled account, so disabling takes effect on
	// every live session immediately rather than only on the next login.
	ErrAccountDisabled = errors.New("sulis: account disabled")
	// ErrAccountLocked is returned the same way — only after a credential
	// has verified — for an account whose LockedUntil (set by the optional
	// automatic lockout; see WithFailureLockout) has not yet passed. Unlike
	// ErrAccountDisabled, it is not checked by ValidateSession: a lockout
	// throttles new authentication attempts, it does not invalidate a
	// session already issued before the lockout began.
	ErrAccountLocked = errors.New("sulis: account locked")
)
