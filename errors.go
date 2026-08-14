package sulis

import "errors"

var (
	// User errors.
	ErrUserNotFound      = errors.New("sulis: user not found")
	ErrUserAlreadyExists = errors.New("sulis: user already exists")

	// Credential errors.
	ErrInvalidCredentials = errors.New("sulis: invalid credentials")

	// Session errors.
	ErrSessionNotFound = errors.New("sulis: session not found")
	ErrSessionExpired  = errors.New("sulis: session expired")

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

	// Rate limiting.
	ErrRateLimited = errors.New("sulis: rate limited")
)
