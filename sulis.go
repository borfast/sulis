package sulis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
)

// Sulis is the main authentication service. It coordinates user registration,
// login, password reset, and session management.
type Sulis struct {
	users     UserStore
	sessions  SessionStore
	tokens    TokenStore
	cfg       Config
	dummyHash string // used to equalize Login timing for unknown/passwordless users
}

// New creates a new Sulis instance with the given stores and options.
func New(users UserStore, sessions SessionStore, tokens TokenStore, opts ...Option) *Sulis {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	s := &Sulis{
		users:    users,
		sessions: sessions,
		tokens:   tokens,
		cfg:      cfg,
	}
	// crypto/rand cannot fail on Go >= 1.24, so ignoring the error here is safe.
	s.dummyHash, _ = hashPassword("sulis-timing-equalization-dummy", cfg.Argon2)
	return s
}

// Register creates a new user with the given email and password, and returns
// a new session. Returns ErrUserAlreadyExists if the email is already taken.
func (s *Sulis) Register(ctx context.Context, email, password string) (*User, *Session, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return nil, nil, err
	}

	if err := s.checkPasswordPolicy(password); err != nil {
		return nil, nil, err
	}

	hash, err := hashPassword(password, s.cfg.Argon2)
	if err != nil {
		return nil, nil, fmt.Errorf("sulis: hashing password: %w", err)
	}

	now := time.Now()
	user := &User{
		ID:           generateID(),
		Email:        email,
		PasswordHash: hash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.users.CreateUser(ctx, user); err != nil {
		return nil, nil, err
	}

	session, err := s.createSession(ctx, user.ID)
	if err != nil {
		return nil, nil, err
	}

	return user, session, nil
}

// Login authenticates a user with email and password and returns a new session.
// Returns ErrInvalidCredentials if the email or password is wrong.
func (s *Sulis) Login(ctx context.Context, email, password string) (*User, *Session, error) {
	user, err := s.VerifyPassword(ctx, email, password)
	if err != nil {
		return nil, nil, err
	}

	session, err := s.IssueSession(ctx, user.ID)
	if err != nil {
		return nil, nil, err
	}

	return user, session, nil
}

// VerifyPassword checks an email and password against the stored credentials
// without creating a session. Returns ErrInvalidCredentials if the email or
// password is wrong. Like Login, it equalizes response timing for
// unknown-user and passwordless-user cases by running the same Argon2 work
// against a dummy hash.
func (s *Sulis) VerifyPassword(ctx context.Context, email, password string) (*User, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return nil, err
	}

	user, err := s.users.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Run the same Argon2 work a real verification would, so the
			// response time doesn't reveal whether the account exists.
			_, _ = verifyPassword(password, s.dummyHash)
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if user.PasswordHash == "" {
		// Passwordless user: verify against the dummy hash for the same reason.
		_, _ = verifyPassword(password, s.dummyHash)
		return nil, ErrInvalidCredentials
	}

	ok, err := verifyPassword(password, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("sulis: verifying password: %w", err)
	}
	if !ok {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}

// IssueSession creates a new session for the given user ID.
//
// Callers MUST invoke this only after fully authenticating the user (e.g. a
// finished passkey ceremony or completed 2FA).
func (s *Sulis) IssueSession(ctx context.Context, userID string) (*Session, error) {
	return s.createSession(ctx, userID)
}

// ChangePassword changes a user's password after verifying the old password.
// The length policy applies only to the new password; the old one was
// already validated when it was set.
func (s *Sulis) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	if err := s.checkPasswordPolicy(newPassword); err != nil {
		return err
	}

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

// SetInitialPassword sets the first password for a passwordless user.
func (s *Sulis) SetInitialPassword(ctx context.Context, userID, newPassword string) error {
	if err := s.checkPasswordPolicy(newPassword); err != nil {
		return err
	}

	user, err := s.users.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.PasswordHash != "" {
		return ErrInvalidCredentials
	}
	return s.setPassword(ctx, user, newPassword)
}

// checkPasswordPolicy enforces the configured minimum and maximum password
// length. Lengths are measured in bytes.
func (s *Sulis) checkPasswordPolicy(password string) error {
	if len(password) < s.cfg.MinPasswordLength {
		return ErrPasswordTooShort
	}
	if len(password) > s.cfg.MaxPasswordLength {
		return ErrPasswordTooLong
	}
	return nil
}

func (s *Sulis) setPassword(ctx context.Context, user *User, newPassword string) error {
	hash, err := hashPassword(newPassword, s.cfg.Argon2)
	if err != nil {
		return fmt.Errorf("sulis: hashing new password: %w", err)
	}

	user.PasswordHash = hash
	user.UpdatedAt = time.Now()
	if err := s.users.UpdateUser(ctx, user); err != nil {
		return err
	}

	if s.cfg.RevokeSessionsOnPasswordChange {
		if err := s.sessions.DeleteUserSessions(ctx, user.ID); err != nil {
			return err
		}
	}
	return s.tokens.DeleteUserTokens(ctx, user.ID, TokenPurposePasswordReset)
}

// CreatePasswordResetToken generates a password reset token for the given email.
// The raw token is returned so the consumer can deliver it (e.g. via email).
// Returns ErrUserNotFound if the email does not exist.
func (s *Sulis) CreatePasswordResetToken(ctx context.Context, email string) (string, error) {
	email, err := normalizeEmail(email)
	if err != nil {
		return "", err
	}

	user, err := s.users.GetUserByEmail(ctx, email)
	if err != nil {
		return "", err
	}

	return s.createTokenForUser(ctx, user.ID, TokenPurposePasswordReset, s.cfg.TokenDuration)
}

// ResetPassword resets a user's password using a raw reset token. The
// password policy is checked before the token is consumed, so a policy
// failure does not burn the token.
func (s *Sulis) ResetPassword(ctx context.Context, rawToken, newPassword string) error {
	if err := s.checkPasswordPolicy(newPassword); err != nil {
		return err
	}

	token, err := s.consumeToken(ctx, rawToken, TokenPurposePasswordReset)
	if err != nil {
		return err
	}

	user, err := s.users.GetUserByID(ctx, token.UserID)
	if err != nil {
		return err
	}

	return s.setPassword(ctx, user, newPassword)
}

// ValidateSession validates a session token and returns the session and user.
// Returns ErrSessionNotFound or ErrSessionExpired on failure.
func (s *Sulis) ValidateSession(ctx context.Context, token string) (*Session, *User, error) {
	tokenHash := hashSessionToken(token)
	session, err := s.sessions.GetSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, nil, err
	}
	validated := *session

	if time.Now().After(validated.ExpiresAt) {
		_ = s.sessions.DeleteSession(ctx, validated.ID)
		return nil, nil, ErrSessionExpired
	}

	user, err := s.users.GetUserByID(ctx, validated.UserID)
	if err != nil {
		return nil, nil, err
	}

	return &validated, user, nil
}

// RevokeSession deletes a single session.
func (s *Sulis) RevokeSession(ctx context.Context, sessionID string) error {
	return s.sessions.DeleteSession(ctx, sessionID)
}

// RevokeAllSessions deletes all sessions for a user.
func (s *Sulis) RevokeAllSessions(ctx context.Context, userID string) error {
	return s.sessions.DeleteUserSessions(ctx, userID)
}

// createSession creates a new session for the given user.
func (s *Sulis) createSession(ctx context.Context, userID string) (*Session, error) {
	token, err := generateSessionToken(s.cfg.SessionTokenBytes)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	session := &Session{
		ID:        generateID(),
		UserID:    userID,
		Token:     token,
		TokenHash: hashSessionToken(token),
		ExpiresAt: now.Add(s.cfg.SessionDuration),
		CreatedAt: now,
	}

	persisted := *session
	persisted.Token = ""

	if err := s.sessions.CreateSession(ctx, &persisted); err != nil {
		return nil, err
	}

	return session, nil
}

// createTokenForUser generates a token for the given user, purpose, and TTL.
func (s *Sulis) createTokenForUser(ctx context.Context, userID string, purpose TokenPurpose, ttl time.Duration) (string, error) {
	raw, hashed, err := generateRawToken(s.cfg.ResetTokenBytes)
	if err != nil {
		return "", fmt.Errorf("sulis: generating token: %w", err)
	}

	now := time.Now()
	token := &Token{
		ID:        generateID(),
		UserID:    userID,
		TokenHash: hashed,
		Purpose:   purpose,
		ExpiresAt: now.Add(ttl),
		CreatedAt: now,
	}

	if err := s.tokens.CreateToken(ctx, token); err != nil {
		return "", err
	}

	return raw, nil
}

// consumeToken atomically consumes a raw token for the given purpose. Expiry
// is checked after consumption so failures burn the token (safe direction).
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

// generateID creates a random hex-encoded ID.
func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// normalizeEmail trims surrounding whitespace, validates the result as a
// single RFC 5322 address (rejecting display-name forms like "Name <a@b>"),
// and lowercases it for consistent storage and comparison. Returns
// ErrInvalidEmail for empty, overlong (>254 bytes), or malformed input.
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
