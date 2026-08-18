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
)
