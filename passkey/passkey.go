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
	residentKey      protocol.ResidentKeyRequirement
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

// WithResidentKey sets whether registration asks the authenticator to create
// a client-side discoverable ("resident key") credential — the kind
// BeginDiscoverableLogin's usernameless login depends on being able to find
// without the relying party supplying a credential ID first.
//
// The default is protocol.ResidentKeyRequirementRequired, and it should stay
// there for any Service that offers BeginDiscoverableLogin: a passkey that
// isn't discoverable can't be found by usernameless login, so registration
// would silently produce credentials the feature can't use, and the
// fallback to typing a username trains users back onto the thing passkeys
// are meant to replace. Use protocol.ResidentKeyRequirementPreferred or
// ...Discouraged only when usernameless login is not offered and every
// caller of BeginLogin always supplies an identified user first.
func WithResidentKey(rk protocol.ResidentKeyRequirement) Option {
	return func(c *serviceConfig) { c.residentKey = rk }
}

// User identifies a consumer's user account to the passkey Service.
// Consumers create this from their own user type when calling Service
// methods.
type User struct {
	ID          []byte
	Name        string
	DisplayName string
}

// webauthnUser adapts a *User plus a store-loaded credential list to the
// webauthn.User interface expected by github.com/go-webauthn/webauthn.
// Service builds this internally for every ceremony so the credential list
// always reflects what the store has on record; User itself carries no
// Credentials field, so a caller cannot smuggle in a stale or fabricated
// list.
type webauthnUser struct {
	user        *User
	credentials []Credential
}

func (u *webauthnUser) WebAuthnID() []byte          { return u.user.ID }
func (u *webauthnUser) WebAuthnName() string        { return u.user.Name }
func (u *webauthnUser) WebAuthnDisplayName() string { return u.user.DisplayName }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	return toWebAuthnCreds(u.credentials)
}

// Service manages WebAuthn passkey registration and authentication.
type Service struct {
	wa         *webauthn.WebAuthn
	store      Store
	challenges ChallengeStore
	cfg        serviceConfig
}

// NewService creates a new passkey service with the given stores and configuration.
func NewService(store Store, challenges ChallengeStore, cfg WebAuthnConfig, opts ...Option) (*Service, error) {
	sc := serviceConfig{
		userVerification: protocol.VerificationRequired,
		residentKey:      protocol.ResidentKeyRequirementRequired,
	}
	for _, opt := range opts {
		opt(&sc)
	}
	switch sc.userVerification {
	case protocol.VerificationRequired, protocol.VerificationPreferred, protocol.VerificationDiscouraged:
	default:
		return nil, fmt.Errorf("passkey: invalid user verification requirement %q", sc.userVerification)
	}
	switch sc.residentKey {
	case protocol.ResidentKeyRequirementRequired, protocol.ResidentKeyRequirementPreferred, protocol.ResidentKeyRequirementDiscouraged:
	default:
		return nil, fmt.Errorf("passkey: invalid resident key requirement %q", sc.residentKey)
	}

	// The legacy requireResidentKey boolean is for authenticators that
	// predate the residentKey string enum; only "required" maps to true —
	// go-webauthn's own WithResidentKeyRequirement option follows the same
	// rule (protocol.ResidentKeyRequired only for the Required case).
	requireResidentKey := protocol.ResidentKeyNotRequired()
	if sc.residentKey == protocol.ResidentKeyRequirementRequired {
		requireResidentKey = protocol.ResidentKeyRequired()
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification:   sc.userVerification,
			ResidentKey:        sc.residentKey,
			RequireResidentKey: requireResidentKey,
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
// Returns the credential creation options to send to the client. The
// options' excludeCredentials list is populated from the store's existing
// credentials for this user, so the authenticator can tell the browser
// "you already registered this key" instead of silently creating a
// duplicate credential.
func (s *Service) BeginRegistration(ctx context.Context, user *User) (*protocol.CredentialCreation, error) {
	creds, err := s.store.GetCredentialsByUserID(ctx, string(user.ID))
	if err != nil {
		return nil, err
	}

	waUser := &webauthnUser{user: user, credentials: creds}
	exclude := webauthn.Credentials(toWebAuthnCreds(creds)).CredentialDescriptors()

	// credProps is requested regardless of the configured ResidentKey
	// requirement: it's how the client reports back whether the credential
	// it actually created is discoverable (see Credential.Discoverable),
	// which is worth knowing even under "preferred" or "discouraged".
	creation, sessionData, err := s.wa.BeginRegistration(waUser,
		webauthn.WithExclusions(exclude),
		webauthn.WithExtensions(protocol.AuthenticationExtensions{"credProps": true}),
	)
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
//
// The challenge is consumed before verification runs, so a failed
// verification still burns it — the safe direction, same policy as sulis's
// consumeToken: a rejected registration cannot be retried against the same
// challenge.
func (s *Service) FinishRegistration(ctx context.Context, user *User, r *http.Request) (*Credential, error) {
	key := challengeKey("register", string(user.ID))
	data, err := s.challenges.ConsumeChallenge(ctx, key)
	if err != nil {
		return nil, ErrChallengeExpired
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		return nil, fmt.Errorf("passkey: unmarshaling session: %w", err)
	}

	// Parsed directly (rather than via s.wa.FinishRegistration, which
	// discards the parsed response) so ClientExtensionResults is available
	// below to populate Credential.Discoverable.
	parsedResponse, err := protocol.ParseCredentialCreationResponse(r)
	if err != nil {
		return nil, fmt.Errorf("passkey: parsing registration response: %w", err)
	}

	waUser := &webauthnUser{user: user}
	waCredential, err := s.wa.CreateCredential(waUser, sessionData, parsedResponse)
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
		Discoverable:    credPropsResidentKey(parsedResponse.ClientExtensionResults),
		CreatedAt:       time.Now(),
	}

	if err := s.store.SaveCredential(ctx, cred); err != nil {
		return nil, err
	}

	return cred, nil
}

// BeginLogin starts the WebAuthn authentication ceremony.
// Returns the credential assertion options to send to the client and a
// ceremony ID that the caller must round-trip to FinishLogin. The challenge
// is keyed by this ceremony ID rather than by user ID so that a second login
// ceremony started for the same user (e.g. from a different device) cannot
// clobber the first ceremony's saved challenge.
func (s *Service) BeginLogin(ctx context.Context, user *User) (*protocol.CredentialAssertion, string, error) {
	// Load credentials from store.
	creds, err := s.store.GetCredentialsByUserID(ctx, string(user.ID))
	if err != nil {
		return nil, "", err
	}
	if len(creds) == 0 {
		return nil, "", ErrPasskeyNotFound
	}
	waUser := &webauthnUser{user: user, credentials: creds}

	assertion, sessionData, err := s.wa.BeginLogin(waUser, webauthn.WithUserVerification(s.cfg.userVerification))
	if err != nil {
		return nil, "", fmt.Errorf("passkey: begin login: %w", err)
	}

	data, err := json.Marshal(sessionData)
	if err != nil {
		return nil, "", fmt.Errorf("passkey: marshaling session: %w", err)
	}

	ceremonyID := generateID()
	if err := s.challenges.SaveChallenge(ctx, challengeKey("login", ceremonyID), data); err != nil {
		return nil, "", err
	}

	return assertion, ceremonyID, nil
}

// FinishLogin completes the WebAuthn authentication ceremony started by
// BeginLogin. ceremonyID must be the value returned by the matching
// BeginLogin call.
// The http.Request must contain the authenticator's response body.
// Returns the credential that was used for authentication.
//
// The challenge is consumed before verification runs, so a failed
// verification still burns it — the safe direction, same policy as sulis's
// consumeToken: a rejected assertion cannot be retried against the same
// challenge.
func (s *Service) FinishLogin(ctx context.Context, user *User, ceremonyID string, r *http.Request) (*Credential, error) {
	// Load credentials from store.
	creds, err := s.store.GetCredentialsByUserID(ctx, string(user.ID))
	if err != nil {
		return nil, err
	}
	waUser := &webauthnUser{user: user, credentials: creds}

	key := challengeKey("login", ceremonyID)
	data, err := s.challenges.ConsumeChallenge(ctx, key)
	if err != nil {
		return nil, ErrChallengeExpired
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		return nil, fmt.Errorf("passkey: unmarshaling session: %w", err)
	}

	waCredential, err := s.wa.FinishLogin(waUser, sessionData, r)
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
//
// The challenge is consumed before verification runs, so a failed
// verification still burns it — the safe direction, same policy as sulis's
// consumeToken: a rejected assertion cannot be retried against the same
// challenge.
func (s *Service) FinishDiscoverableLogin(ctx context.Context, ceremonyID string, r *http.Request) (*Credential, error) {
	key := challengeKey("discover", ceremonyID)
	data, err := s.challenges.ConsumeChallenge(ctx, key)
	if err != nil {
		return nil, ErrChallengeExpired
	}

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
		return &webauthnUser{user: &User{ID: userHandle}, credentials: []Credential{*cred}}, nil
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

// credPropsResidentKey reports whether the client's "credProps" extension
// output says the credential just created is client-side discoverable
// (credProps.rk). See Credential.Discoverable for why this — rather than
// anything on the finished waCredential itself — is the signal used, and
// for its reliability caveats.
func credPropsResidentKey(ext protocol.AuthenticationExtensionsClientOutputs) bool {
	credProps, ok := ext["credProps"].(map[string]any)
	if !ok {
		return false
	}
	rk, _ := credProps["rk"].(bool)
	return rk
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

// challengeKey scopes a challenge store key by ceremony kind ("register",
// "login", or "discover") so that concurrent registration and login
// ceremonies for the same user do not overwrite each other's saved challenge.
func challengeKey(kind, id string) string {
	return kind + ":" + id
}

func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
