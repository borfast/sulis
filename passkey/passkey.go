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
	ErrCloneWarning     = errors.New("passkey: credential clone detected (sign count anomaly)")
)

// WebAuthnConfig holds the configuration for the WebAuthn relying party.
type WebAuthnConfig struct {
	RPDisplayName string   // human-readable name, e.g. "My Application"
	RPID          string   // relying party ID, e.g. "example.com"
	RPOrigins     []string // allowed origins, e.g. ["https://example.com"]
}

// serviceConfig holds the tunable ceremony parameters.
type serviceConfig struct {
	userVerification protocol.UserVerificationRequirement
}

// Option configures a passkey Service.
type Option func(*serviceConfig)

// WithUserVerification sets whether the authenticator must verify the user —
// a PIN, a biometric — rather than merely confirming that someone is present.
//
// The default is protocol.VerificationRequired, and it should stay there for a
// passwordless passkey: user verification is what makes the credential two
// factors ("something you have" plus "something you are") instead of bare
// possession of an unlocked device. protocol.VerificationDiscouraged is only
// defensible when the passkey is a SECOND factor behind a verified password.
//
// This must be set for the check to happen at all: go-webauthn only verifies
// the UV flag when the ceremony's session data says VerificationRequired.
func WithUserVerification(uv protocol.UserVerificationRequirement) Option {
	return func(c *serviceConfig) { c.userVerification = uv }
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
	cfg        serviceConfig
}

// NewService creates a new passkey service with the given stores and configuration.
func NewService(store Store, challenges ChallengeStore, cfg WebAuthnConfig, opts ...Option) (*Service, error) {
	sc := serviceConfig{userVerification: protocol.VerificationRequired}
	for _, opt := range opts {
		opt(&sc)
	}
	switch sc.userVerification {
	case protocol.VerificationRequired, protocol.VerificationPreferred, protocol.VerificationDiscouraged:
	default:
		return nil, fmt.Errorf("passkey: invalid user verification requirement %q", sc.userVerification)
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: sc.userVerification,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: initializing webauthn: %w", err)
	}

	return &Service{
		wa:         wa,
		store:      store,
		challenges: challenges,
		cfg:        sc,
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

	if err := s.challenges.SaveChallenge(ctx, challengeKey("register", string(user.ID)), data); err != nil {
		return nil, err
	}

	return creation, nil
}

// FinishRegistration completes the WebAuthn registration ceremony.
// The http.Request must contain the authenticator's response body.
func (s *Service) FinishRegistration(ctx context.Context, user *User, r *http.Request) (*Credential, error) {
	key := challengeKey("register", string(user.ID))
	data, err := s.challenges.GetChallenge(ctx, key)
	if err != nil {
		return nil, ErrChallengeExpired
	}
	defer s.challenges.DeleteChallenge(ctx, key)

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

	assertion, sessionData, err := s.wa.BeginLogin(user, webauthn.WithUserVerification(s.cfg.userVerification))
	if err != nil {
		return nil, fmt.Errorf("passkey: begin login: %w", err)
	}

	data, err := json.Marshal(sessionData)
	if err != nil {
		return nil, fmt.Errorf("passkey: marshaling session: %w", err)
	}

	if err := s.challenges.SaveChallenge(ctx, challengeKey("login", string(user.ID)), data); err != nil {
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

	key := challengeKey("login", string(user.ID))
	data, err := s.challenges.GetChallenge(ctx, key)
	if err != nil {
		return nil, ErrChallengeExpired
	}
	defer s.challenges.DeleteChallenge(ctx, key)

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		return nil, fmt.Errorf("passkey: unmarshaling session: %w", err)
	}

	waCredential, err := s.wa.FinishLogin(user, sessionData, r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChallengeFailed, err)
	}

	return s.finishLoginCredential(ctx, waCredential)
}

// BeginDiscoverableLogin starts a usernameless ("discoverable") WebAuthn
// authentication ceremony: the caller does not need to know the user's
// identity up front, since the authenticator itself supplies it during
// FinishDiscoverableLogin.
// Returns the credential assertion options to send to the client and a
// ceremony ID that the caller must round-trip to FinishDiscoverableLogin.
func (s *Service) BeginDiscoverableLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	assertion, sessionData, err := s.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(s.cfg.userVerification))
	if err != nil {
		return nil, "", fmt.Errorf("passkey: begin discoverable login: %w", err)
	}
	data, err := json.Marshal(sessionData)
	if err != nil {
		return nil, "", fmt.Errorf("passkey: marshaling session: %w", err)
	}
	ceremonyID := generateID()
	if err := s.challenges.SaveChallenge(ctx, challengeKey("discover", ceremonyID), data); err != nil {
		return nil, "", err
	}
	return assertion, ceremonyID, nil
}

// FinishDiscoverableLogin completes a usernameless WebAuthn authentication
// ceremony started by BeginDiscoverableLogin. ceremonyID must be the value
// returned by the matching BeginDiscoverableLogin call. The user is resolved
// from the credential's stored owner rather than being supplied by the
// caller.
// The http.Request must contain the authenticator's response body.
// Returns the credential that was used for authentication.
func (s *Service) FinishDiscoverableLogin(ctx context.Context, ceremonyID string, r *http.Request) (*Credential, error) {
	key := challengeKey("discover", ceremonyID)
	data, err := s.challenges.GetChallenge(ctx, key)
	if err != nil {
		return nil, ErrChallengeExpired
	}
	defer s.challenges.DeleteChallenge(ctx, key)

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		return nil, fmt.Errorf("passkey: unmarshaling session: %w", err)
	}

	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		cred, err := s.store.GetCredentialByID(ctx, rawID)
		if err != nil {
			return nil, ErrPasskeyNotFound
		}
		if cred.UserID != string(userHandle) {
			return nil, ErrChallengeFailed
		}
		return &User{ID: userHandle, Credentials: []Credential{*cred}}, nil
	}

	waCred, err := s.wa.FinishDiscoverableLogin(handler, sessionData, r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChallengeFailed, err)
	}
	return s.finishLoginCredential(ctx, waCred)
}

// finishLoginCredential applies the post-verification checks and bookkeeping
// for a successfully verified assertion: it rejects credentials flagged as
// possibly cloned, then persists the updated sign count and returns the
// stored credential.
func (s *Service) finishLoginCredential(ctx context.Context, waCred *webauthn.Credential) (*Credential, error) {
	if waCred.Authenticator.CloneWarning {
		return nil, ErrCloneWarning
	}

	if err := s.store.UpdateCredentialSignCount(ctx, waCred.ID, waCred.Authenticator.SignCount); err != nil {
		return nil, err
	}

	return s.store.GetCredentialByID(ctx, waCred.ID)
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

// challengeKey scopes a challenge store key by ceremony kind ("register" or
// "login") so that concurrent registration and login ceremonies for the same
// user do not overwrite each other's saved challenge.
func challengeKey(kind, id string) string {
	return kind + ":" + id
}

func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
