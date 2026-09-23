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
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	ErrPasskeyNotFound  = errors.New("passkey: credential not found")
	ErrChallengeFailed  = errors.New("passkey: challenge verification failed")
	ErrChallengeExpired = errors.New("passkey: challenge expired or not found")
	ErrCloneWarning     = errors.New("passkey: credential clone detected (sign count anomaly)")

	// ErrCeremonyBodyTooLarge is returned when a ceremony response body
	// exceeds the configured WithMaxCeremonyBody limit. See that option's
	// GoDoc for why the cap exists.
	ErrCeremonyBodyTooLarge = errors.New("passkey: ceremony response body too large")

	// ErrLastCredential is returned by Service.DeleteCredential (via the
	// atomic guard in Store.DeleteCredential) when id names the only
	// credential userID has registered and DeleteOptions.AllowLast was not
	// set. See DeleteOptions for why this package can't decide that on its
	// own, and Store.DeleteCredential for why the guard must be atomic.
	ErrLastCredential = errors.New("passkey: cannot delete the account's last credential without DeleteOptions.AllowLast")
)

// defaultMaxCeremonyBody is WithMaxCeremonyBody's default: generous enough
// for any real WebAuthn attestation/assertion response (which run at most a
// few KiB, even with a large X.509 attestation certificate chain) while
// still bounding how much of a request body sulis will read or hold in
// memory for a single ceremony.
const defaultMaxCeremonyBody = 64 * 1024

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
	maxCeremonyBody  int64
	EventSink        EventSink
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

// WithMaxCeremonyBody caps how many bytes of a ceremony response body
// FinishRegistration, FinishLogin, and FinishDiscoverableLogin (and their
// []byte-taking counterparts) will read or accept, in bytes. max must be > 0.
//
// The default is 64 KiB. go-webauthn's own body decoding
// (protocol.decodeBody, in its unexported decoder.go) is a bare
// json.NewDecoder(body).Decode(v) with no limit at all — an attacker who can
// reach a Finish endpoint could otherwise send an arbitrarily large body and
// have it read fully into memory before any validation runs. Because sulis
// owns the *http.Request in the http.go wrappers, it can — and does — impose
// this limit itself via http.MaxBytesReader; the same limit is also enforced
// in the []byte-taking core methods so a caller that bypasses net/http
// entirely gets the same bound.
func WithMaxCeremonyBody(max int64) Option {
	return func(c *serviceConfig) { c.maxCeremonyBody = max }
}

// WithEventSink routes passkey security and operational events to sink. The
// default is nil: no sink, no events, and no work beyond the nil check. The
// event taxonomy is intentionally local to this package; applications that
// want one stream across sulis, recovery, and passkey can adapt each package's
// Event value at their boundary without coupling the packages together.
func WithEventSink(sink EventSink) Option {
	return func(c *serviceConfig) { c.EventSink = sink }
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

// NewService creates a new passkey service with the given stores and
// configuration.
//
// Every argument it cannot work without is checked here rather than at the
// first ceremony. go-webauthn's own constructor accepts an empty RPID and an
// empty RPDisplayName without complaint, so before these checks a service
// built from an incomplete config looked healthy and failed later, during a
// registration or login a real user was waiting on.
func NewService(store Store, challenges ChallengeStore, cfg WebAuthnConfig, opts ...Option) (*Service, error) {
	switch {
	case store == nil:
		return nil, fmt.Errorf("passkey: store must not be nil")
	case challenges == nil:
		return nil, fmt.Errorf("passkey: challenge store must not be nil")
	case cfg.RPID == "":
		return nil, fmt.Errorf("passkey: RPID must not be empty")
	case cfg.RPDisplayName == "":
		return nil, fmt.Errorf("passkey: RPDisplayName must not be empty")
	case len(cfg.RPOrigins) == 0:
		return nil, fmt.Errorf("passkey: RPOrigins must list at least one allowed origin")
	}

	sc := serviceConfig{
		userVerification: protocol.VerificationRequired,
		residentKey:      protocol.ResidentKeyRequirementRequired,
		maxCeremonyBody:  defaultMaxCeremonyBody,
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
	if sc.maxCeremonyBody <= 0 {
		return nil, fmt.Errorf("passkey: invalid max ceremony body %d (must be > 0)", sc.maxCeremonyBody)
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
		s.emit(ctx, Event{Kind: EventStoreFailed, UserID: string(user.ID), Operation: "get_credentials"})
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
		webauthn.WithExtensions(webauthn.WithExtensionCredProps()),
	)
	if err != nil {
		return nil, fmt.Errorf("passkey: begin registration: %w", err)
	}

	data, err := json.Marshal(sessionData)
	if err != nil {
		return nil, fmt.Errorf("passkey: marshaling session: %w", err)
	}

	if err := s.challenges.SaveChallenge(ctx, challengeKey("register", string(user.ID)), data); err != nil {
		s.emit(ctx, Event{Kind: EventStoreFailed, UserID: string(user.ID), Operation: "save_challenge"})
		return nil, err
	}

	return creation, nil
}

// FinishRegistrationResponse completes the WebAuthn registration ceremony
// from the raw response body — the []byte-taking core that FinishRegistration
// (in http.go) wraps for net/http callers, and the entry point for callers
// that don't use net/http at all.
//
// body must not exceed the Service's configured WithMaxCeremonyBody limit
// (default 64 KiB); a larger body is rejected up front, before the challenge
// is consumed or any JSON parsing happens, with ErrCeremonyBodyTooLarge.
//
// The challenge is consumed before verification runs, so a failed
// verification still burns it — the safe direction, same policy as sulis's
// consumeToken: a rejected registration cannot be retried against the same
// challenge.
func (s *Service) FinishRegistrationResponse(ctx context.Context, user *User, body []byte) (*Credential, error) {
	if err := s.checkCeremonyBodySize(body); err != nil {
		return nil, err
	}

	key := challengeKey("register", string(user.ID))
	data, err := s.challenges.ConsumeChallenge(ctx, key)
	if err != nil {
		s.emit(ctx, Event{Kind: EventRegistrationChallengeExpired, UserID: string(user.ID), Diagnostic: "challenge_expired"})
		return nil, ErrChallengeExpired
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		s.emit(ctx, Event{Kind: EventRegistrationRejected, UserID: string(user.ID), Diagnostic: "session_data"})
		return nil, fmt.Errorf("passkey: unmarshaling session: %w", err)
	}

	// Parsed directly (rather than via s.wa.FinishRegistration, which
	// discards the parsed response) so ClientExtensionResults is available
	// below to populate Credential.Discoverable.
	parsedResponse, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		s.emit(ctx, Event{Kind: EventRegistrationRejected, UserID: string(user.ID), Diagnostic: diagnosticCategory(err)})
		return nil, fmt.Errorf("passkey: parsing registration response: %w", err)
	}

	waUser := &webauthnUser{user: user}
	waCredential, err := s.wa.CreateCredential(waUser, sessionData, parsedResponse)
	if err != nil {
		s.emit(ctx, Event{Kind: EventRegistrationRejected, UserID: string(user.ID), Diagnostic: diagnosticCategory(err)})
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
		Transports:      waCredential.Transport,
		BackupEligible:  waCredential.Flags.BackupEligible,
		BackupState:     waCredential.Flags.BackupState,
		CreatedAt:       time.Now(),
	}

	if err := s.store.SaveCredential(ctx, cred); err != nil {
		s.emit(ctx, Event{Kind: EventStoreFailed, UserID: string(user.ID), Operation: "save_credential"})
		return nil, err
	}

	s.emit(ctx, Event{Kind: EventRegistrationSucceeded, UserID: string(user.ID)})
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
		s.emit(ctx, Event{Kind: EventStoreFailed, UserID: string(user.ID), Operation: "get_credentials"})
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
		s.emit(ctx, Event{Kind: EventStoreFailed, UserID: string(user.ID), Operation: "save_challenge"})
		return nil, "", err
	}

	return assertion, ceremonyID, nil
}

// FinishLoginResponse completes the WebAuthn authentication ceremony started
// by BeginLogin, from the raw response body — the []byte-taking core that
// FinishLogin (in http.go) wraps for net/http callers, and the entry point
// for callers that don't use net/http at all. ceremonyID must be the value
// returned by the matching BeginLogin call.
//
// body must not exceed the Service's configured WithMaxCeremonyBody limit
// (default 64 KiB); a larger body is rejected up front, before the challenge
// is consumed or any JSON parsing happens, with ErrCeremonyBodyTooLarge.
//
// Returns the credential that was used for authentication.
//
// The challenge is consumed before verification runs, so a failed
// verification still burns it — the safe direction, same policy as sulis's
// consumeToken: a rejected assertion cannot be retried against the same
// challenge.
func (s *Service) FinishLoginResponse(ctx context.Context, user *User, ceremonyID string, body []byte) (*Credential, error) {
	if err := s.checkCeremonyBodySize(body); err != nil {
		return nil, err
	}

	// Load credentials from store.
	creds, err := s.store.GetCredentialsByUserID(ctx, string(user.ID))
	if err != nil {
		s.emit(ctx, Event{Kind: EventStoreFailed, UserID: string(user.ID), Operation: "get_credentials"})
		return nil, err
	}
	waUser := &webauthnUser{user: user, credentials: creds}

	key := challengeKey("login", ceremonyID)
	data, err := s.challenges.ConsumeChallenge(ctx, key)
	if err != nil {
		s.emit(ctx, Event{Kind: EventLoginChallengeExpired, UserID: string(user.ID), Diagnostic: "challenge_expired"})
		return nil, ErrChallengeExpired
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		s.emit(ctx, Event{Kind: EventLoginRejected, UserID: string(user.ID), Diagnostic: "session_data"})
		return nil, fmt.Errorf("passkey: unmarshaling session: %w", err)
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		s.emit(ctx, Event{Kind: EventLoginRejected, UserID: string(user.ID), Diagnostic: diagnosticCategory(err)})
		return nil, fmt.Errorf("%w: %w", ErrChallengeFailed, err)
	}

	waCredential, err := s.wa.ValidateLogin(waUser, sessionData, parsedResponse)
	if err != nil {
		s.emit(ctx, Event{Kind: EventLoginRejected, UserID: string(user.ID), Diagnostic: diagnosticCategory(err)})
		return nil, fmt.Errorf("%w: %w", ErrChallengeFailed, err)
	}

	return s.finishLoginCredential(ctx, string(user.ID), waCredential)
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
		s.emit(ctx, Event{Kind: EventStoreFailed, Operation: "save_challenge"})
		return nil, "", err
	}
	return assertion, ceremonyID, nil
}

// FinishDiscoverableLoginResponse completes a usernameless WebAuthn
// authentication ceremony started by BeginDiscoverableLogin, from the raw
// response body — the []byte-taking core that FinishDiscoverableLogin (in
// http.go) wraps for net/http callers, and the entry point for callers that
// don't use net/http at all. ceremonyID must be the value returned by the
// matching BeginDiscoverableLogin call. The user is resolved from the
// credential's stored owner rather than being supplied by the caller.
//
// body must not exceed the Service's configured WithMaxCeremonyBody limit
// (default 64 KiB); a larger body is rejected up front, before the challenge
// is consumed or any JSON parsing happens, with ErrCeremonyBodyTooLarge.
//
// Returns the credential that was used for authentication.
//
// The challenge is consumed before verification runs, so a failed
// verification still burns it — the safe direction, same policy as sulis's
// consumeToken: a rejected assertion cannot be retried against the same
// challenge.
func (s *Service) FinishDiscoverableLoginResponse(ctx context.Context, ceremonyID string, body []byte) (*Credential, error) {
	if err := s.checkCeremonyBodySize(body); err != nil {
		return nil, err
	}

	key := challengeKey("discover", ceremonyID)
	data, err := s.challenges.ConsumeChallenge(ctx, key)
	if err != nil {
		s.emit(ctx, Event{Kind: EventLoginChallengeExpired, Diagnostic: "challenge_expired"})
		return nil, ErrChallengeExpired
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		s.emit(ctx, Event{Kind: EventLoginRejected, Diagnostic: "session_data"})
		return nil, fmt.Errorf("passkey: unmarshaling session: %w", err)
	}

	var resolvedUserID string
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		cred, err := s.store.GetCredentialByID(ctx, rawID)
		if err != nil {
			s.emit(ctx, Event{Kind: EventStoreFailed, Operation: "get_credential"})
			return nil, ErrPasskeyNotFound
		}
		if cred.UserID != string(userHandle) {
			return nil, ErrChallengeFailed
		}
		resolvedUserID = cred.UserID
		return &webauthnUser{user: &User{ID: userHandle}, credentials: []Credential{*cred}}, nil
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		s.emit(ctx, Event{Kind: EventLoginRejected, Diagnostic: diagnosticCategory(err)})
		return nil, fmt.Errorf("%w: %w", ErrChallengeFailed, err)
	}

	waCred, err := s.wa.ValidateDiscoverableLogin(handler, sessionData, parsedResponse)
	if err != nil {
		s.emit(ctx, Event{Kind: EventLoginRejected, UserID: resolvedUserID, Diagnostic: diagnosticCategory(err)})
		return nil, fmt.Errorf("%w: %w", ErrChallengeFailed, err)
	}
	return s.finishLoginCredential(ctx, resolvedUserID, waCred)
}

// finishLoginCredential applies the post-verification checks and bookkeeping
// for a successfully verified assertion: it rejects credentials flagged as
// possibly cloned, then persists the updated sign count, backup state, and
// last-used timestamp, and returns the stored credential.
func (s *Service) finishLoginCredential(ctx context.Context, userID string, waCred *webauthn.Credential) (*Credential, error) {
	if waCred.Authenticator.CloneWarning {
		s.emit(ctx, Event{Kind: EventCloneWarning, UserID: userID, Diagnostic: "clone_warning"})
		return nil, ErrCloneWarning
	}

	if err := s.store.UpdateCredentialAfterLogin(ctx, waCred.ID, waCred.Authenticator.SignCount, waCred.Flags.BackupState, time.Now()); err != nil {
		s.emit(ctx, Event{Kind: EventStoreFailed, UserID: userID, Operation: "update_credential_after_login"})
		return nil, err
	}

	cred, err := s.store.GetCredentialByID(ctx, waCred.ID)
	if err != nil {
		s.emit(ctx, Event{Kind: EventStoreFailed, UserID: userID, Operation: "get_credential"})
		return nil, err
	}
	s.emit(ctx, Event{Kind: EventLoginSucceeded, UserID: userID})
	return cred, nil
}

// DeleteOptions configures Service.DeleteCredential.
type DeleteOptions struct {
	// AllowLast permits removing a user's only remaining credential.
	// passkey has no visibility into whether userID's application account
	// has any other way to authenticate (a password, another second
	// factor) — it only knows about its own credentials — so the caller
	// must set this to true only after establishing, through its own
	// re-authentication or explicit confirmation flow, that removing the
	// account's last passkey is intentional and the account will remain
	// reachable afterward.
	AllowLast bool
}

// DeleteCredential removes the credential identified by id (a Credential.ID
// value — the store's own opaque ID, not the raw WebAuthn
// Credential.CredentialID) after confirming it belongs to userID.
//
// Deleting a user's only remaining credential is rejected with
// ErrLastCredential unless opts.AllowLast is set — see DeleteOptions for why
// this package can't make that call on its own and what the caller must
// establish before setting it. The guard only ever sees passkey's own
// credential count for userID: it has no way to know whether the account
// has a password or another second factor, so a caller whose account can
// only ever authenticate via passkey must set AllowLast with particular
// care.
//
// This method is a thin wrapper: the guard itself — the membership check,
// the remaining-count check, and the removal — is implemented entirely by
// Store.DeleteCredential as one atomic operation. It does not live here as
// a separate "load, check, then delete" sequence, because that would
// reopen exactly the race the guard exists to close: two concurrent calls
// for two different credentials of the same last-two-credential user could
// each load the pre-deletion count before either delete lands, both pass a
// Service-level check, and both succeed — see Store.DeleteCredential's
// GoDoc for the full reasoning and reference implementations.
func (s *Service) DeleteCredential(ctx context.Context, userID, id string, opts DeleteOptions) error {
	err := s.store.DeleteCredential(ctx, userID, id, opts.AllowLast)
	if err == nil {
		s.emit(ctx, Event{Kind: EventCredentialDeleted, UserID: userID})
		return nil
	}
	if errors.Is(err, ErrPasskeyNotFound) || errors.Is(err, ErrLastCredential) {
		s.emit(ctx, Event{Kind: EventCredentialDeletionRejected, UserID: userID, Diagnostic: deletionDiagnostic(err)})
	} else {
		s.emit(ctx, Event{Kind: EventStoreFailed, UserID: userID, Operation: "delete_credential"})
	}
	return err
}

// checkCeremonyBodySize rejects a ceremony response body larger than the
// Service's configured WithMaxCeremonyBody limit. Callers run this before
// consuming a challenge or attempting any JSON parsing, so an oversized body
// is rejected cheaply rather than after work has already been spent on it —
// and, for FinishRegistrationResponse/FinishLoginResponse/
// FinishDiscoverableLoginResponse specifically, without burning the
// caller's still-valid challenge.
func (s *Service) checkCeremonyBodySize(body []byte) error {
	if int64(len(body)) > s.cfg.maxCeremonyBody {
		return fmt.Errorf("%w: %d bytes exceeds the %d byte limit", ErrCeremonyBodyTooLarge, len(body), s.cfg.maxCeremonyBody)
	}
	return nil
}

// credPropsResidentKey reports whether the client's "credProps" extension
// output says the credential just created is client-side discoverable
// (credProps.rk). See Credential.Discoverable for why this — rather than
// anything on the finished waCredential itself — is the signal used, and
// for its reliability caveats.
// go-webauthn v0.18 models the outputs as a struct rather than a map, and
// both pointers are meaningful: a nil CredProps means the client said
// nothing, while a non-nil RK of false means it said the credential is not
// discoverable. Both answer this question with false.
func credPropsResidentKey(ext protocol.AuthenticationExtensionsClientOutputs) bool {
	if ext.CredProps == nil || ext.CredProps.RK == nil {
		return false
	}
	return *ext.CredProps.RK
}

// toWebAuthnCreds converts our Credential type to the webauthn library's
// type.
//
// Flags and Transport are carried over deliberately, not just for
// completeness: go-webauthn's own login verification
// (webauthn.validateLogin, invoked via wa.ValidateLogin/
// wa.ValidateDiscoverableLogin) compares the credential's Flags.BackupEligible
// bit against the fresh assertion's — a mismatch fails the login with
// "Backup Eligible flag inconsistency detected". Since BackupEligible is
// re-derived from the signed authenticator data on every ceremony (see
// Credential.BackupEligible), the value fed back in here must match what
// was last persisted, or a genuinely backup-eligible credential's next
// login would always fail this check.
func toWebAuthnCreds(creds []Credential) []webauthn.Credential {
	result := make([]webauthn.Credential, len(creds))
	for i, c := range creds {
		result[i] = webauthn.Credential{
			ID:              c.CredentialID,
			PublicKey:       c.PublicKey,
			AttestationType: c.AttestationType,
			Transport:       c.Transports,
			Flags: webauthn.CredentialFlags{
				BackupEligible: c.BackupEligible,
				BackupState:    c.BackupState,
			},
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
