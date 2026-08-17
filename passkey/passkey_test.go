package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestBeginRegistrationSavesChallenge(t *testing.T) {
	t.Parallel()

	store := &fakeStore{}
	challenges := newFakeChallengeStore()
	service := newTestService(t, store, challenges)
	user := &User{
		ID:          []byte("user-1"),
		Name:        "user@example.com",
		DisplayName: "User One",
	}

	creation, err := service.BeginRegistration(context.Background(), user)
	if err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}
	if creation == nil {
		t.Fatal("BeginRegistration() returned nil creation")
	}

	session := mustLoadSavedSession(t, challenges, challengeKey("register", string(user.ID)))
	if session.Challenge == "" {
		t.Fatal("saved session data has empty challenge")
	}
	if string(session.UserID) != string(user.ID) {
		t.Fatalf("saved session user ID = %q, want %q", session.UserID, user.ID)
	}
}

func TestBeginLoginSavesChallenge(t *testing.T) {
	t.Parallel()

	store := &fakeStore{credentialsByUser: map[string][]Credential{
		"user-1": {
			{CredentialID: []byte("credential-1")},
		},
	}}
	challenges := newFakeChallengeStore()
	service := newTestService(t, store, challenges)
	user := &User{
		ID:          []byte("user-1"),
		Name:        "user@example.com",
		DisplayName: "User One",
	}

	assertion, err := service.BeginLogin(context.Background(), user)
	if err != nil {
		t.Fatalf("BeginLogin() error = %v", err)
	}
	if assertion == nil {
		t.Fatal("BeginLogin() returned nil assertion")
	}

	session := mustLoadSavedSession(t, challenges, challengeKey("login", string(user.ID)))
	if session.Challenge == "" {
		t.Fatal("saved session data has empty challenge")
	}
	if string(session.UserID) != string(user.ID) {
		t.Fatalf("saved session user ID = %q, want %q", session.UserID, user.ID)
	}
}

func TestBeginLoginReturnsErrPasskeyNotFoundWhenUserHasNoCredentials(t *testing.T) {
	t.Parallel()

	store := &fakeStore{}
	challenges := newFakeChallengeStore()
	service := newTestService(t, store, challenges)
	user := &User{ID: []byte("user-1")}

	assertion, err := service.BeginLogin(context.Background(), user)
	if !errors.Is(err, ErrPasskeyNotFound) {
		t.Fatalf("BeginLogin() error = %v, want %v", err, ErrPasskeyNotFound)
	}
	if assertion != nil {
		t.Fatalf("BeginLogin() assertion = %#v, want nil", assertion)
	}
	if len(challenges.saved) != 0 {
		t.Fatalf("BeginLogin() saved %d challenges, want 0", len(challenges.saved))
	}
	if store.getCredentialsCalls != 1 {
		t.Fatalf("GetCredentialsByUserID() calls = %d, want 1", store.getCredentialsCalls)
	}
	if got := store.lastUserID; got != string(user.ID) {
		t.Fatalf("GetCredentialsByUserID() user ID = %q, want %q", got, user.ID)
	}
}

func TestFinishRegistrationReturnsErrChallengeExpiredWhenChallengeMissing(t *testing.T) {
	t.Parallel()

	store := &fakeStore{}
	challenges := newFakeChallengeStore()
	service := newTestService(t, store, challenges)
	user := &User{ID: []byte("user-1")}

	cred, err := service.FinishRegistration(context.Background(), user, httptestNewRequest(t))
	if !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("FinishRegistration() error = %v, want %v", err, ErrChallengeExpired)
	}
	if cred != nil {
		t.Fatalf("FinishRegistration() credential = %#v, want nil", cred)
	}
}

func TestFinishLoginReturnsErrChallengeExpiredWhenChallengeMissing(t *testing.T) {
	t.Parallel()

	store := &fakeStore{credentialsByUser: map[string][]Credential{
		"user-1": {
			{CredentialID: []byte("credential-1")},
		},
	}}
	challenges := newFakeChallengeStore()
	service := newTestService(t, store, challenges)
	user := &User{ID: []byte("user-1")}

	cred, err := service.FinishLogin(context.Background(), user, httptestNewRequest(t))
	if !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("FinishLogin() error = %v, want %v", err, ErrChallengeExpired)
	}
	if cred != nil {
		t.Fatalf("FinishLogin() credential = %#v, want nil", cred)
	}
	if store.getCredentialsCalls != 1 {
		t.Fatalf("GetCredentialsByUserID() calls = %d, want 1", store.getCredentialsCalls)
	}
}

func TestRegistrationAndLoginChallengesDoNotClobber(t *testing.T) {
	t.Parallel()

	store := &fakeStore{credentialsByUser: map[string][]Credential{
		"user-1": {
			{CredentialID: []byte("credential-1")},
		},
	}}
	challenges := newFakeChallengeStore()
	service := newTestService(t, store, challenges)
	user := &User{
		ID:          []byte("user-1"),
		Name:        "user@example.com",
		DisplayName: "User One",
	}

	if _, err := service.BeginRegistration(context.Background(), user); err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}
	if _, err := service.BeginLogin(context.Background(), user); err != nil {
		t.Fatalf("BeginLogin() error = %v", err)
	}

	registerData, ok := challenges.saved["register:user-1"]
	if !ok || len(registerData) == 0 {
		t.Fatalf("expected non-empty challenge saved under %q, saved keys = %v", "register:user-1", keysOf(challenges.saved))
	}
	loginData, ok := challenges.saved["login:user-1"]
	if !ok || len(loginData) == 0 {
		t.Fatalf("expected non-empty challenge saved under %q, saved keys = %v", "login:user-1", keysOf(challenges.saved))
	}
	if len(challenges.saved) != 2 {
		t.Fatalf("challenges.saved has %d entries, want 2 (got keys = %v)", len(challenges.saved), keysOf(challenges.saved))
	}
}

func TestFinishLoginWrapsUnderlyingError(t *testing.T) {
	t.Parallel()

	store := &fakeStore{credentialsByUser: map[string][]Credential{
		"user-1": {
			{CredentialID: []byte("credential-1")},
		},
	}}
	challenges := newFakeChallengeStore()
	service := newTestService(t, store, challenges)
	user := &User{ID: []byte("user-1")}

	if _, err := service.BeginLogin(context.Background(), user); err != nil {
		t.Fatalf("BeginLogin() error = %v", err)
	}

	badRequest, err := http.NewRequest(http.MethodPost, "https://example.com", strings.NewReader("not valid json"))
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}
	badRequest.Header.Set("Content-Type", "application/json")

	cred, err := service.FinishLogin(context.Background(), user, badRequest)
	if !errors.Is(err, ErrChallengeFailed) {
		t.Fatalf("FinishLogin() error = %v, want errors.Is(err, ErrChallengeFailed)", err)
	}
	if cred != nil {
		t.Fatalf("FinishLogin() credential = %#v, want nil", cred)
	}
	if got, sentinel := err.Error(), ErrChallengeFailed.Error(); len(got) <= len(sentinel) {
		t.Fatalf("FinishLogin() error = %q, want detail beyond bare sentinel %q", got, sentinel)
	}
}

func TestFinishLoginRejectsClonedAuthenticator(t *testing.T) {
	t.Parallel()

	store := &fakeStore{}
	service := newTestService(t, store, newFakeChallengeStore())
	waCred := &webauthn.Credential{
		ID: []byte("credential-1"),
		Authenticator: webauthn.Authenticator{
			CloneWarning: true,
			SignCount:    42,
		},
	}

	cred, err := service.finishLoginCredential(context.Background(), waCred)
	if !errors.Is(err, ErrCloneWarning) {
		t.Fatalf("finishLoginCredential() error = %v, want %v", err, ErrCloneWarning)
	}
	if cred != nil {
		t.Fatalf("finishLoginCredential() credential = %#v, want nil", cred)
	}
	if store.updateSignCountCalls != 0 {
		t.Fatalf("UpdateCredentialSignCount() calls = %d, want 0", store.updateSignCountCalls)
	}
}

func TestBeginDiscoverableLoginSavesChallengeUnderCeremonyID(t *testing.T) {
	t.Parallel()

	store := &fakeStore{}
	challenges := newFakeChallengeStore()
	service := newTestService(t, store, challenges)

	assertion, ceremonyID, err := service.BeginDiscoverableLogin(context.Background())
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin() error = %v", err)
	}
	if assertion == nil {
		t.Fatal("BeginDiscoverableLogin() returned nil assertion")
	}
	if ceremonyID == "" {
		t.Fatal("BeginDiscoverableLogin() returned empty ceremony ID")
	}

	session := mustLoadSavedSession(t, challenges, challengeKey("discover", ceremonyID))
	if session.Challenge == "" {
		t.Fatal("saved session data has empty challenge")
	}
}

func TestBeginDiscoverableLoginReturnsUniqueCeremonyIDs(t *testing.T) {
	t.Parallel()

	store := &fakeStore{}
	challenges := newFakeChallengeStore()
	service := newTestService(t, store, challenges)

	_, ceremonyID1, err := service.BeginDiscoverableLogin(context.Background())
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin() error = %v", err)
	}
	_, ceremonyID2, err := service.BeginDiscoverableLogin(context.Background())
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin() error = %v", err)
	}

	if ceremonyID1 == ceremonyID2 {
		t.Fatalf("BeginDiscoverableLogin() returned identical ceremony IDs: %q", ceremonyID1)
	}
	if len(challenges.saved) != 2 {
		t.Fatalf("challenges.saved has %d entries, want 2 (got keys = %v)", len(challenges.saved), keysOf(challenges.saved))
	}
}

func TestFinishDiscoverableLoginWithoutChallengeReturnsErrChallengeExpired(t *testing.T) {
	t.Parallel()

	store := &fakeStore{}
	challenges := newFakeChallengeStore()
	service := newTestService(t, store, challenges)

	cred, err := service.FinishDiscoverableLogin(context.Background(), "missing-ceremony-id", httptestNewRequest(t))
	if !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("FinishDiscoverableLogin() error = %v, want %v", err, ErrChallengeExpired)
	}
	if cred != nil {
		t.Fatalf("FinishDiscoverableLogin() credential = %#v, want nil", cred)
	}
}

func keysOf(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

type fakeStore struct {
	credentialsByUser    map[string][]Credential
	credentialByID       map[string]*Credential
	getCredentialsCalls  int
	lastUserID           string
	updateSignCountCalls int
}

func (f *fakeStore) SaveCredential(context.Context, *Credential) error { return nil }

func (f *fakeStore) GetCredentialsByUserID(_ context.Context, userID string) ([]Credential, error) {
	f.getCredentialsCalls++
	f.lastUserID = userID
	if f.credentialsByUser == nil {
		return nil, nil
	}
	return f.credentialsByUser[userID], nil
}

func (f *fakeStore) GetCredentialByID(_ context.Context, credentialID []byte) (*Credential, error) {
	if f.credentialByID == nil {
		return nil, errors.New("credential not found")
	}
	cred, ok := f.credentialByID[string(credentialID)]
	if !ok {
		return nil, errors.New("credential not found")
	}
	return cred, nil
}

func (f *fakeStore) UpdateCredentialSignCount(context.Context, []byte, uint32) error {
	f.updateSignCountCalls++
	return nil
}

func (f *fakeStore) DeleteCredential(context.Context, string) error { return nil }

type fakeChallengeStore struct {
	saved map[string][]byte
}

func newFakeChallengeStore() *fakeChallengeStore {
	return &fakeChallengeStore{saved: make(map[string][]byte)}
}

func (f *fakeChallengeStore) SaveChallenge(_ context.Context, userID string, sessionData []byte) error {
	f.saved[userID] = append([]byte(nil), sessionData...)
	return nil
}

func (f *fakeChallengeStore) GetChallenge(_ context.Context, userID string) ([]byte, error) {
	data, ok := f.saved[userID]
	if !ok {
		return nil, errors.New("challenge not found")
	}
	return append([]byte(nil), data...), nil
}

func (f *fakeChallengeStore) DeleteChallenge(_ context.Context, userID string) error {
	delete(f.saved, userID)
	return nil
}

func newTestService(t *testing.T, store Store, challenges ChallengeStore) *Service {
	t.Helper()

	service, err := NewService(store, challenges, WebAuthnConfig{
		RPDisplayName: "Sulis Test",
		RPID:          "example.com",
		RPOrigins:     []string{"https://example.com"},
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	return service
}

func httptestNewRequest(t *testing.T) *http.Request {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, "https://example.com", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}
	return req
}

func mustLoadSavedSession(t *testing.T, challenges ChallengeStore, key string) webauthn.SessionData {
	t.Helper()

	data, err := challenges.GetChallenge(context.Background(), key)
	if err != nil {
		t.Fatalf("GetChallenge() error = %v", err)
	}
	if len(data) == 0 {
		t.Fatal("GetChallenge() returned empty challenge data")
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(data, &session); err != nil {
		t.Fatalf("saved challenge is not valid session data: %v", err)
	}

	return session
}

// TestUserVerificationIsRequiredByDefault is the regression test for audit
// finding A2. NewService left webauthn.Config.AuthenticatorSelection at its
// zero value, so UserVerification was "" — and go-webauthn only checks the UV
// flag when the ceremony's session data says VerificationRequired. A
// presence-only tap was therefore accepted, reducing a passwordless passkey
// from two factors to bare possession.
func TestUserVerificationIsRequiredByDefault(t *testing.T) {
	store := &fakeStore{credentialsByUser: map[string][]Credential{
		"user-1": {{ID: "c1", UserID: "user-1", CredentialID: []byte("cred-1")}},
	}}
	challenges := newFakeChallengeStore()
	svc := newTestService(t, store, challenges)
	ctx := context.Background()
	user := &User{ID: []byte("user-1"), Name: "alice", DisplayName: "Alice"}

	t.Run("registration", func(t *testing.T) {
		creation, err := svc.BeginRegistration(ctx, user)
		if err != nil {
			t.Fatalf("BeginRegistration: %v", err)
		}
		if got := creation.Response.AuthenticatorSelection.UserVerification; got != protocol.VerificationRequired {
			t.Errorf("client options request UV %q, want %q", got, protocol.VerificationRequired)
		}
		session := mustLoadSavedSession(t, challenges, "register:user-1")
		if session.UserVerification != protocol.VerificationRequired {
			t.Errorf("session records UV %q, want %q — go-webauthn only enforces the flag when it is %q",
				session.UserVerification, protocol.VerificationRequired, protocol.VerificationRequired)
		}
	})

	t.Run("login", func(t *testing.T) {
		assertion, err := svc.BeginLogin(ctx, user)
		if err != nil {
			t.Fatalf("BeginLogin: %v", err)
		}
		if got := assertion.Response.UserVerification; got != protocol.VerificationRequired {
			t.Errorf("client options request UV %q, want %q", got, protocol.VerificationRequired)
		}
		session := mustLoadSavedSession(t, challenges, "login:user-1")
		if session.UserVerification != protocol.VerificationRequired {
			t.Errorf("session records UV %q, want %q", session.UserVerification, protocol.VerificationRequired)
		}
	})

	t.Run("discoverable login", func(t *testing.T) {
		assertion, ceremonyID, err := svc.BeginDiscoverableLogin(ctx)
		if err != nil {
			t.Fatalf("BeginDiscoverableLogin: %v", err)
		}
		if got := assertion.Response.UserVerification; got != protocol.VerificationRequired {
			t.Errorf("client options request UV %q, want %q", got, protocol.VerificationRequired)
		}
		session := mustLoadSavedSession(t, challenges, "discover:"+ceremonyID)
		if session.UserVerification != protocol.VerificationRequired {
			t.Errorf("session records UV %q, want %q", session.UserVerification, protocol.VerificationRequired)
		}
	})
}

// TestWithUserVerificationOverridesDefault covers the escape hatch for
// passkeys used strictly as a second factor behind a verified password.
func TestWithUserVerificationOverridesDefault(t *testing.T) {
	challenges := newFakeChallengeStore()
	svc, err := NewService(&fakeStore{}, challenges, WebAuthnConfig{
		RPDisplayName: "Test",
		RPID:          "example.com",
		RPOrigins:     []string{"https://example.com"},
	}, WithUserVerification(protocol.VerificationDiscouraged))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	user := &User{ID: []byte("user-1"), Name: "alice", DisplayName: "Alice"}
	if _, err := svc.BeginRegistration(context.Background(), user); err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	session := mustLoadSavedSession(t, challenges, "register:user-1")
	if session.UserVerification != protocol.VerificationDiscouraged {
		t.Errorf("session records UV %q, want %q", session.UserVerification, protocol.VerificationDiscouraged)
	}
}

func TestNewServiceRejectsUnknownUserVerification(t *testing.T) {
	_, err := NewService(&fakeStore{}, newFakeChallengeStore(), WebAuthnConfig{
		RPDisplayName: "Test",
		RPID:          "example.com",
		RPOrigins:     []string{"https://example.com"},
	}, WithUserVerification(protocol.UserVerificationRequirement("sometimes")))
	if err == nil {
		t.Fatal("expected an unknown user verification requirement to be rejected")
	}
}
