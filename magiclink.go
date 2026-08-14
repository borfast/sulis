package sulis

import (
	"context"
	"errors"
	"time"
)

// CreateMagicLinkToken generates a magic link token for the given email.
// If no user exists for the email, one is created (passwordless user).
// The raw token is returned so the consumer can deliver it (e.g. via email).
func (s *Sulis) CreateMagicLinkToken(ctx context.Context, email string) (string, error) {
	// Ensure a user exists for this email; create one if not.
	_, err := s.users.GetUserByEmail(ctx, email)
	if err != nil {
		if !errors.Is(err, ErrUserNotFound) {
			return "", err
		}
		now := time.Now()
		user := &User{
			ID:        generateID(),
			Email:     email,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := s.users.CreateUser(ctx, user); err != nil {
			return "", err
		}
	}

	return s.createToken(ctx, email, TokenPurposeMagicLink)
}

// RedeemMagicLink validates a magic link token and returns the user and a new session.
func (s *Sulis) RedeemMagicLink(ctx context.Context, rawToken string) (*User, *Session, error) {
	token, err := s.consumeToken(ctx, rawToken, TokenPurposeMagicLink)
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
