package sulis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Sulis is the main authentication service. It coordinates user registration,
// login, password reset, and session management.
type Sulis struct {
	users    UserStore
	sessions SessionStore
	tokens   TokenStore
	cfg      Config
}

// New creates a new Sulis instance with the given stores and options.
func New(users UserStore, sessions SessionStore, tokens TokenStore, opts ...Option) *Sulis {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Sulis{
		users:    users,
		sessions: sessions,
		tokens:   tokens,
		cfg:      cfg,
	}
}

// Register creates a new user with the given email and password, and returns
// a new session. Returns ErrUserAlreadyExists if the email is already taken.
func (s *Sulis) Register(ctx context.Context, email, password string) (*User, *Session, error) {
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
	user, err := s.users.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, nil, ErrInvalidCredentials
		}
		return nil, nil, err
	}

	if user.PasswordHash == "" {
		return nil, nil, ErrInvalidCredentials
	}

	ok, err := verifyPassword(password, user.PasswordHash)
	if err != nil {
		return nil, nil, fmt.Errorf("sulis: verifying password: %w", err)
	}
	if !ok {
		return nil, nil, ErrInvalidCredentials
	}

	session, err := s.createSession(ctx, user.ID)
	if err != nil {
		return nil, nil, err
	}

	return user, session, nil
}

// ChangePassword changes a user's password after verifying the old password.
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

// SetInitialPassword sets the first password for a passwordless user.
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

// CreatePasswordResetToken generates a password reset token for the given email.
// The raw token is returned so the consumer can deliver it (e.g. via email).
// Returns ErrUserNotFound if the email does not exist.
func (s *Sulis) CreatePasswordResetToken(ctx context.Context, email string) (string, error) {
	return s.createToken(ctx, email, TokenPurposePasswordReset)
}

// ResetPassword resets a user's password using a raw reset token.
func (s *Sulis) ResetPassword(ctx context.Context, rawToken, newPassword string) error {
	token, err := s.validateToken(ctx, rawToken, TokenPurposePasswordReset)
	if err != nil {
		return err
	}

	user, err := s.users.GetUserByID(ctx, token.UserID)
	if err != nil {
		return err
	}

	if err := s.setPassword(ctx, user, newPassword); err != nil {
		return err
	}

	return s.tokens.MarkTokenUsed(ctx, token.ID)
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
	validated.Token = token

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

// createToken generates a token for the given email and purpose.
func (s *Sulis) createToken(ctx context.Context, email string, purpose TokenPurpose) (string, error) {
	user, err := s.users.GetUserByEmail(ctx, email)
	if err != nil {
		return "", err
	}

	raw, hashed, err := generateRawToken(s.cfg.ResetTokenBytes)
	if err != nil {
		return "", fmt.Errorf("sulis: generating token: %w", err)
	}

	now := time.Now()
	token := &Token{
		ID:        generateID(),
		UserID:    user.ID,
		TokenHash: hashed,
		Purpose:   purpose,
		ExpiresAt: now.Add(s.cfg.TokenDuration),
		CreatedAt: now,
	}

	if err := s.tokens.CreateToken(ctx, token); err != nil {
		return "", err
	}

	return raw, nil
}

// validateToken validates a raw token for the given purpose.
func (s *Sulis) validateToken(ctx context.Context, rawToken string, purpose TokenPurpose) (*Token, error) {
	hashed := hashToken(rawToken)
	token, err := s.tokens.GetTokenByHash(ctx, hashed)
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			return nil, ErrTokenInvalid
		}
		return nil, err
	}

	if token.Purpose != purpose {
		return nil, ErrTokenInvalid
	}
	if token.Used {
		return nil, ErrTokenAlreadyUsed
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
