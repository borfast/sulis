// Package passkey implements WebAuthn-based passkey registration and authentication.
//
// It wraps github.com/go-webauthn/webauthn to provide a higher-level API
// with pluggable storage for credentials and challenges.
package passkey

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	ErrPasskeyNotFound  = errors.New("passkey: credential not found")
	ErrChallengeFailed  = errors.New("passkey: challenge verification failed")
	ErrChallengeExpired = errors.New("passkey: challenge expired or not found")
)

// WebAuthnConfig holds the configuration for the WebAuthn relying party.
type WebAuthnConfig struct {
	RPDisplayName string   // human-readable name, e.g. "My Application"
	RPID          string   // relying party ID, e.g. "example.com"
	RPOrigins     []string // allowed origins, e.g. ["https://example.com"]
}

// User adapts a consumer's user type to the webauthn.User interface.
// Consumers create this from their own user type when calling Service methods.
type User struct {
	ID          []byte
	Name        string
	DisplayName string
	Credentials []Credential
}

func (u *User) WebAuthnID() []byte                         { return u.ID }
func (u *User) WebAuthnName() string                       { return u.Name }
func (u *User) WebAuthnDisplayName() string                { return u.DisplayName }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return toWebAuthnCreds(u.Credentials) }

// Service manages WebAuthn passkey registration and authentication.
type Service struct {
	wa         *webauthn.WebAuthn
	store      Store
	challenges ChallengeStore
}

// NewService creates a new passkey service with the given stores and configuration.
func NewService(store Store, challenges ChallengeStore, cfg WebAuthnConfig) (*Service, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: initializing webauthn: %w", err)
	}

	return &Service{
		wa:         wa,
		store:      store,
		challenges: challenges,
	}, nil
}

// BeginRegistration starts the WebAuthn registration ceremony.
// Returns the credential creation options to send to the client.
func (s *Service) BeginRegistration(ctx context.Context, user *User) (*protocol.CredentialCreation, error) {
	creation, sessionData, err := s.wa.BeginRegistration(user)
	if err != nil {
		return nil, fmt.Errorf("passkey: begin registration: %w", err)
	}

	data, err := json.Marshal(sessionData)
	if err != nil {
		return nil, fmt.Errorf("passkey: marshaling session: %w", err)
	}

	if err := s.challenges.SaveChallenge(ctx, string(user.ID), data); err != nil {
		return nil, err
	}

	return creation, nil
}

// FinishRegistration completes the WebAuthn registration ceremony.
// The http.Request must contain the authenticator's response body.
func (s *Service) FinishRegistration(ctx context.Context, user *User, r *http.Request) (*Credential, error) {
	data, err := s.challenges.GetChallenge(ctx, string(user.ID))
	if err != nil {
		return nil, ErrChallengeExpired
	}
	defer s.challenges.DeleteChallenge(ctx, string(user.ID))

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		return nil, fmt.Errorf("passkey: unmarshaling session: %w", err)
	}

	waCredential, err := s.wa.FinishRegistration(user, sessionData, r)
	if err != nil {
		return nil, fmt.Errorf("passkey: finish registration: %w", err)
	}

	cred := &Credential{
		ID:              generateID(),
		UserID:          string(user.ID),
		CredentialID:    waCredential.ID,
		PublicKey:       waCredential.PublicKey,
		AttestationType: waCredential.AttestationType,
		AAGUID:          waCredential.Authenticator.AAGUID,
		SignCount:       waCredential.Authenticator.SignCount,
		CreatedAt:       time.Now(),
	}

	if err := s.store.SaveCredential(ctx, cred); err != nil {
		return nil, err
	}

	return cred, nil
}

// BeginLogin starts the WebAuthn authentication ceremony.
// Returns the credential assertion options to send to the client.
func (s *Service) BeginLogin(ctx context.Context, user *User) (*protocol.CredentialAssertion, error) {
	// Load credentials from store.
	creds, err := s.store.GetCredentialsByUserID(ctx, string(user.ID))
	if err != nil {
		return nil, err
	}
	if len(creds) == 0 {
		return nil, ErrPasskeyNotFound
	}
	user.Credentials = creds

	assertion, sessionData, err := s.wa.BeginLogin(user)
	if err != nil {
		return nil, fmt.Errorf("passkey: begin login: %w", err)
	}

	data, err := json.Marshal(sessionData)
	if err != nil {
		return nil, fmt.Errorf("passkey: marshaling session: %w", err)
	}

	if err := s.challenges.SaveChallenge(ctx, string(user.ID), data); err != nil {
		return nil, err
	}

	return assertion, nil
}

// FinishLogin completes the WebAuthn authentication ceremony.
// The http.Request must contain the authenticator's response body.
// Returns the credential that was used for authentication.
func (s *Service) FinishLogin(ctx context.Context, user *User, r *http.Request) (*Credential, error) {
	// Load credentials from store.
	creds, err := s.store.GetCredentialsByUserID(ctx, string(user.ID))
	if err != nil {
		return nil, err
	}
	user.Credentials = creds

	data, err := s.challenges.GetChallenge(ctx, string(user.ID))
	if err != nil {
		return nil, ErrChallengeExpired
	}
	defer s.challenges.DeleteChallenge(ctx, string(user.ID))

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		return nil, fmt.Errorf("passkey: unmarshaling session: %w", err)
	}

	waCredential, err := s.wa.FinishLogin(user, sessionData, r)
	if err != nil {
		return nil, ErrChallengeFailed
	}

	// Update sign count.
	if err := s.store.UpdateCredentialSignCount(ctx, waCredential.ID, waCredential.Authenticator.SignCount); err != nil {
		return nil, err
	}

	// Find and return the matching credential.
	storedCred, err := s.store.GetCredentialByID(ctx, waCredential.ID)
	if err != nil {
		return nil, err
	}

	return storedCred, nil
}

// toWebAuthnCreds converts our Credential type to the webauthn library's type.
func toWebAuthnCreds(creds []Credential) []webauthn.Credential {
	result := make([]webauthn.Credential, len(creds))
	for i, c := range creds {
		result[i] = webauthn.Credential{
			ID:              c.CredentialID,
			PublicKey:       c.PublicKey,
			AttestationType: c.AttestationType,
			Authenticator: webauthn.Authenticator{
				AAGUID:    c.AAGUID,
				SignCount: c.SignCount,
			},
		}
	}
	return result
}

func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
