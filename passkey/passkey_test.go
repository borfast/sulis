package passkey

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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

// TestBeginRegistrationExcludesExistingCredentials is the regression test for
// audit finding A5: BeginRegistration never consulted the store, so the
// browser's "you already registered this key" prompt never fired and users
// could create duplicate credentials for the same authenticator.
func TestBeginRegistrationExcludesExistingCredentials(t *testing.T) {
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

	creation, err := service.BeginRegistration(context.Background(), user)
	if err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}

	exclude := creation.Response.CredentialExcludeList
	if len(exclude) != 1 {
		t.Fatalf("CredentialExcludeList has %d entries, want 1 (got %#v)", len(exclude), exclude)
	}
	if string(exclude[0].CredentialID) != "credential-1" {
		t.Fatalf("CredentialExcludeList[0].CredentialID = %q, want %q", exclude[0].CredentialID, "credential-1")
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

	assertion, ceremonyID, err := service.BeginLogin(context.Background(), user)
	if err != nil {
		t.Fatalf("BeginLogin() error = %v", err)
	}
	if assertion == nil {
		t.Fatal("BeginLogin() returned nil assertion")
	}
	if ceremonyID == "" {
		t.Fatal("BeginLogin() returned empty ceremony ID")
	}

	session := mustLoadSavedSession(t, challenges, challengeKey("login", ceremonyID))
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

	assertion, ceremonyID, err := service.BeginLogin(context.Background(), user)
	if !errors.Is(err, ErrPasskeyNotFound) {
		t.Fatalf("BeginLogin() error = %v, want %v", err, ErrPasskeyNotFound)
	}
	if assertion != nil {
		t.Fatalf("BeginLogin() assertion = %#v, want nil", assertion)
	}
	if ceremonyID != "" {
		t.Fatalf("BeginLogin() ceremony ID = %q, want empty", ceremonyID)
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

	cred, err := service.FinishLogin(context.Background(), user, "missing-ceremony-id", httptestNewRequest(t))
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
	_, ceremonyID, err := service.BeginLogin(context.Background(), user)
	if err != nil {
		t.Fatalf("BeginLogin() error = %v", err)
	}

	registerData, ok := challenges.saved["register:user-1"]
	if !ok || len(registerData) == 0 {
		t.Fatalf("expected non-empty challenge saved under %q, saved keys = %v", "register:user-1", keysOf(challenges.saved))
	}
	loginKey := challengeKey("login", ceremonyID)
	loginData, ok := challenges.saved[loginKey]
	if !ok || len(loginData) == 0 {
		t.Fatalf("expected non-empty challenge saved under %q, saved keys = %v", loginKey, keysOf(challenges.saved))
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

	_, ceremonyID, err := service.BeginLogin(context.Background(), user)
	if err != nil {
		t.Fatalf("BeginLogin() error = %v", err)
	}

	badRequest, err := http.NewRequest(http.MethodPost, "https://example.com", strings.NewReader("not valid json"))
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}
	badRequest.Header.Set("Content-Type", "application/json")

	cred, err := service.FinishLogin(context.Background(), user, ceremonyID, badRequest)
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
	if store.updateAfterLoginCalls != 0 {
		t.Fatalf("UpdateCredentialAfterLogin() calls = %d, want 0", store.updateAfterLoginCalls)
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

// TestFinishDiscoverableLoginConsumesChallengeExactlyOnce is the regression
// test for audit finding A4: get-then-defer-delete lets two concurrent
// finishes of the same ceremony both read the challenge before either
// deletes it, so both proceed past the "challenge expired" gate. Exactly one
// of the two racing calls must be told the challenge is gone
// (ErrChallengeExpired); the other may fail verification for its own
// reasons, but it must not also be told the challenge was missing.
//
// Both goroutines are released from a shared start gate on every iteration
// to make the race as tight as possible, and the property is checked across
// many iterations rather than once, since a single run can get lucky.
func TestFinishDiscoverableLoginConsumesChallengeExactlyOnce(t *testing.T) {
	const iterations = 200

	for i := 0; i < iterations; i++ {
		store := &fakeStore{}
		challenges := newFakeChallengeStore()
		service := newTestService(t, store, challenges)

		_, ceremonyID, err := service.BeginDiscoverableLogin(context.Background())
		if err != nil {
			t.Fatalf("iteration %d: BeginDiscoverableLogin() error = %v", i, err)
		}

		const racers = 2
		start := make(chan struct{})
		errs := make([]error, racers)
		var wg sync.WaitGroup
		wg.Add(racers)
		for g := 0; g < racers; g++ {
			g := g
			go func() {
				defer wg.Done()
				badRequest, err := http.NewRequest(http.MethodPost, "https://example.com", strings.NewReader("not valid json"))
				if err != nil {
					errs[g] = err
					return
				}
				badRequest.Header.Set("Content-Type", "application/json")
				<-start
				_, errs[g] = service.FinishDiscoverableLogin(context.Background(), ceremonyID, badRequest)
			}()
		}
		close(start)
		wg.Wait()

		var expiredCount, otherCount int
		for _, err := range errs {
			switch {
			case errors.Is(err, ErrChallengeExpired):
				expiredCount++
			case err != nil:
				otherCount++
			default:
				t.Fatalf("iteration %d: FinishDiscoverableLogin() unexpectedly succeeded with a malformed request", i)
			}
		}
		if expiredCount != 1 || otherCount != 1 {
			t.Fatalf("iteration %d: got %d ErrChallengeExpired and %d other errors among %d racers, want exactly 1 and 1 (single-use challenge violated)",
				i, expiredCount, otherCount, racers)
		}
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
	mu sync.Mutex

	credentialsByUser     map[string][]Credential
	credentialByID        map[string]*Credential
	getCredentialsCalls   int
	saveCredentialCalls   int
	lastUserID            string
	updateAfterLoginCalls int

	// Injected failures. Each is returned by the corresponding method
	// instead of doing its normal work, so tests can cover the store-error
	// branches of every ceremony without a second, differently-broken
	// Store implementation per case. The call counter is still incremented
	// first, so a test can tell "failed" from "never reached".
	saveCredentialErr    error
	getCredentialsErr    error
	getCredentialByIDErr error
	updateAfterLoginErr  error

	deleteCredentialCalls int
	deletedCredentialID   string

	deleteCredentialsByUserIDCalls int
	deletedUserID                  string
}

// seed registers cred in both of fakeStore's lookup maps, as a store would
// hold it after a completed registration ceremony. It exists so a login test
// can start from an existing credential without first running (and having to
// keep valid) a whole registration.
func (f *fakeStore) seed(cred Credential) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.store(cred)
}

// store records cred in both lookup maps. Callers must hold f.mu.
func (f *fakeStore) store(cred Credential) {
	if f.credentialsByUser == nil {
		f.credentialsByUser = make(map[string][]Credential)
	}
	if f.credentialByID == nil {
		f.credentialByID = make(map[string]*Credential)
	}
	f.credentialsByUser[cred.UserID] = append(f.credentialsByUser[cred.UserID], cred)
	stored := cred
	f.credentialByID[string(cred.CredentialID)] = &stored
}

// SaveCredential persists the credential in both lookup maps, so a
// registration ceremony can be followed by a login ceremony against the
// credential it just created — the round trip a real deployment performs and
// the only way to prove the two halves agree on what was stored.
func (f *fakeStore) SaveCredential(_ context.Context, cred *Credential) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.saveCredentialCalls++
	if f.saveCredentialErr != nil {
		return f.saveCredentialErr
	}
	f.store(*cred)
	return nil
}

func (f *fakeStore) GetCredentialsByUserID(_ context.Context, userID string) ([]Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.getCredentialsCalls++
	f.lastUserID = userID
	if f.getCredentialsErr != nil {
		return nil, f.getCredentialsErr
	}
	if f.credentialsByUser == nil {
		return nil, nil
	}
	return append([]Credential(nil), f.credentialsByUser[userID]...), nil
}

func (f *fakeStore) GetCredentialByID(_ context.Context, credentialID []byte) (*Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.getCredentialByIDErr != nil {
		return nil, f.getCredentialByIDErr
	}
	if f.credentialByID == nil {
		return nil, errors.New("credential not found")
	}
	cred, ok := f.credentialByID[string(credentialID)]
	if !ok {
		return nil, errors.New("credential not found")
	}
	return cred, nil
}

// UpdateCredentialAfterLogin mutates the credentialByID entry in place, when
// one is registered under credentialID, so that a subsequent
// GetCredentialByID call — exactly what finishLoginCredential makes right
// after this one — observes the update, the same as a real store would. The
// by-user list is updated to match, so a second login ceremony for the same
// user reads the advanced sign count rather than a stale one and the
// clone-detection check sees what a real store would have shown it.
func (f *fakeStore) UpdateCredentialAfterLogin(_ context.Context, credentialID []byte, signCount uint32, backupState bool, lastUsedAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.updateAfterLoginCalls++
	if f.updateAfterLoginErr != nil {
		return f.updateAfterLoginErr
	}
	if f.credentialByID == nil {
		return nil
	}
	cred, ok := f.credentialByID[string(credentialID)]
	if !ok {
		return nil
	}
	cred.SignCount = signCount
	cred.BackupState = backupState
	cred.LastUsedAt = &lastUsedAt

	for _, creds := range f.credentialsByUser {
		for i := range creds {
			if bytes.Equal(creds[i].CredentialID, credentialID) {
				creds[i].SignCount = signCount
				creds[i].BackupState = backupState
				creds[i].LastUsedAt = &lastUsedAt
			}
		}
	}
	return nil
}

// DeleteCredential implements the atomic last-credential guard documented on
// Store.DeleteCredential: the membership check, the remaining-count check,
// and the removal from both lookup maps all happen while holding f.mu, so
// two concurrent calls for two different credentials belonging to the same
// last-two-credential user cannot both observe count==2 before either
// removal lands (see TestDeleteCredentialGuardIsAtomicUnderConcurrentDeletes).
func (f *fakeStore) DeleteCredential(_ context.Context, userID, id string, allowLast bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.deleteCredentialCalls++

	creds := f.credentialsByUser[userID]
	idx := -1
	for i, c := range creds {
		if c.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		return ErrPasskeyNotFound
	}
	if len(creds) <= 1 && !allowLast {
		return ErrLastCredential
	}

	removed := creds[idx]
	f.credentialsByUser[userID] = append(append([]Credential(nil), creds[:idx]...), creds[idx+1:]...)
	delete(f.credentialByID, string(removed.CredentialID))
	f.deletedCredentialID = id
	return nil
}

// DeleteCredentialsByUserID removes every credential fakeStore has on record
// for userID from both of its lookup maps, mirroring what a real store's
// equivalent bulk delete would do.
func (f *fakeStore) DeleteCredentialsByUserID(_ context.Context, userID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.deleteCredentialsByUserIDCalls++
	f.deletedUserID = userID
	if f.credentialsByUser == nil {
		return nil
	}
	for _, c := range f.credentialsByUser[userID] {
		delete(f.credentialByID, string(c.CredentialID))
	}
	delete(f.credentialsByUser, userID)
	return nil
}

// RenameCredential looks id up across every user's credential list (fakeStore
// has no separate by-ID index keyed by Credential.ID) and sets Name, or
// returns ErrPasskeyNotFound if no credential has that ID — matching the
// contract documented on Store.RenameCredential.
func (f *fakeStore) RenameCredential(_ context.Context, id, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for userID, creds := range f.credentialsByUser {
		for i := range creds {
			if creds[i].ID == id {
				creds[i].Name = name
				f.credentialsByUser[userID] = creds
				return nil
			}
		}
	}
	return ErrPasskeyNotFound
}

type fakeChallengeStore struct {
	mu    sync.Mutex
	saved map[string][]byte

	// saveErr, when set, is returned by SaveChallenge instead of storing
	// anything, so tests can cover each Begin* method's persistence-failure
	// branch.
	saveErr error
}

func newFakeChallengeStore() *fakeChallengeStore {
	return &fakeChallengeStore{saved: make(map[string][]byte)}
}

func (f *fakeChallengeStore) SaveChallenge(_ context.Context, key string, sessionData []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.saveErr != nil {
		return f.saveErr
	}
	f.saved[key] = append([]byte(nil), sessionData...)
	return nil
}

// ConsumeChallenge implements ChallengeStore atomically: the read and the
// delete happen under the same lock, so two concurrent callers can never
// both observe the challenge as present.
func (f *fakeChallengeStore) ConsumeChallenge(_ context.Context, key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.saved[key]
	if !ok {
		return nil, errors.New("challenge not found")
	}
	delete(f.saved, key)
	return append([]byte(nil), data...), nil
}

// peekChallenge returns the challenge data saved under key without consuming
// it, for tests that want to inspect what BeginX saved without going through
// a Finish call. It is not part of the ChallengeStore interface.
func (f *fakeChallengeStore) peekChallenge(key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := f.saved[key]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), data...), true
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

func mustLoadSavedSession(t *testing.T, challenges *fakeChallengeStore, key string) webauthn.SessionData {
	t.Helper()

	data, ok := challenges.peekChallenge(key)
	if !ok {
		t.Fatalf("no challenge saved under %q", key)
	}
	if len(data) == 0 {
		t.Fatal("saved challenge data is empty")
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
		assertion, ceremonyID, err := svc.BeginLogin(ctx, user)
		if err != nil {
			t.Fatalf("BeginLogin: %v", err)
		}
		if got := assertion.Response.UserVerification; got != protocol.VerificationRequired {
			t.Errorf("client options request UV %q, want %q", got, protocol.VerificationRequired)
		}
		session := mustLoadSavedSession(t, challenges, challengeKey("login", ceremonyID))
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

// TestResidentKeyIsRequiredByDefault is the regression test for audit finding
// A6: BeginRegistration never asked for a discoverable ("resident key")
// credential, so BeginDiscoverableLogin (usernameless login) only worked
// when an authenticator happened to create a discoverable credential anyway
// — and the fallback to identified login trains users back onto knowing
// (and typing) a username, undermining the point of passkeys.
func TestResidentKeyIsRequiredByDefault(t *testing.T) {
	store := &fakeStore{}
	challenges := newFakeChallengeStore()
	svc := newTestService(t, store, challenges)
	user := &User{ID: []byte("user-1"), Name: "alice", DisplayName: "Alice"}

	creation, err := svc.BeginRegistration(context.Background(), user)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	sel := creation.Response.AuthenticatorSelection
	if sel.ResidentKey != protocol.ResidentKeyRequirementRequired {
		t.Errorf("ResidentKey = %q, want %q", sel.ResidentKey, protocol.ResidentKeyRequirementRequired)
	}
	if sel.RequireResidentKey == nil || !*sel.RequireResidentKey {
		t.Errorf("RequireResidentKey = %v, want a non-nil pointer to true — older authenticators that don't understand residentKey fall back to this legacy boolean", sel.RequireResidentKey)
	}
}

// TestBeginRegistrationRequestsCredPropsExtension is the regression test for
// the client-reported discoverable-credential signal: without asking for the
// "credProps" extension, the browser has no reason to report back whether
// the credential it created is client-side discoverable, and
// Credential.Discoverable could never be populated from a real client.
func TestBeginRegistrationRequestsCredPropsExtension(t *testing.T) {
	t.Parallel()

	store := &fakeStore{}
	challenges := newFakeChallengeStore()
	service := newTestService(t, store, challenges)
	user := &User{ID: []byte("user-1"), Name: "alice", DisplayName: "Alice"}

	creation, err := service.BeginRegistration(context.Background(), user)
	if err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}

	rk, ok := creation.Response.Extensions["credProps"].(bool)
	if !ok || !rk {
		t.Fatalf("Extensions[%q] = %#v, want true", "credProps", creation.Response.Extensions["credProps"])
	}
}

// TestWithResidentKeyOverridesDefault covers the escape hatch for callers
// that do not offer usernameless login and so have no use for a discoverable
// credential.
func TestWithResidentKeyOverridesDefault(t *testing.T) {
	challenges := newFakeChallengeStore()
	svc, err := NewService(&fakeStore{}, challenges, WebAuthnConfig{
		RPDisplayName: "Test",
		RPID:          "example.com",
		RPOrigins:     []string{"https://example.com"},
	}, WithResidentKey(protocol.ResidentKeyRequirementPreferred))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	user := &User{ID: []byte("user-1"), Name: "alice", DisplayName: "Alice"}
	creation, err := svc.BeginRegistration(context.Background(), user)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	sel := creation.Response.AuthenticatorSelection
	if sel.ResidentKey != protocol.ResidentKeyRequirementPreferred {
		t.Errorf("ResidentKey = %q, want %q", sel.ResidentKey, protocol.ResidentKeyRequirementPreferred)
	}
	if sel.RequireResidentKey == nil || *sel.RequireResidentKey {
		t.Errorf("RequireResidentKey = %v, want a non-nil pointer to false when residency is merely preferred", sel.RequireResidentKey)
	}
}

func TestNewServiceRejectsUnknownResidentKey(t *testing.T) {
	_, err := NewService(&fakeStore{}, newFakeChallengeStore(), WebAuthnConfig{
		RPDisplayName: "Test",
		RPID:          "example.com",
		RPOrigins:     []string{"https://example.com"},
	}, WithResidentKey(protocol.ResidentKeyRequirement("sometimes")))
	if err == nil {
		t.Fatal("expected an unknown resident key requirement to be rejected")
	}
}

// TestFinishRegistrationRejectsOversizedBody is the regression test for audit
// finding A7: go-webauthn's decodeBody (protocol/decoder.go) is a bare
// json.NewDecoder(body).Decode(v) with no size limit, so an attacker who can
// reach FinishRegistration could send an arbitrarily large body and have it
// read fully into memory before any validation runs. The default 64 KiB cap
// must reject an oversized body cheaply — before the challenge is even
// consumed — not after an unbounded read.
func TestFinishRegistrationRejectsOversizedBody(t *testing.T) {
	t.Parallel()

	store := &fakeStore{}
	challenges := newFakeChallengeStore()
	service := newTestService(t, store, challenges)
	user := &User{ID: []byte("user-1"), Name: "user@example.com", DisplayName: "User One"}

	if _, err := service.BeginRegistration(context.Background(), user); err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}

	oversized := bytes.Repeat([]byte("a"), defaultMaxCeremonyBody+1)
	req, err := http.NewRequest(http.MethodPost, "https://example.com", bytes.NewReader(oversized))
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}

	cred, err := service.FinishRegistration(context.Background(), user, req)
	if !errors.Is(err, ErrCeremonyBodyTooLarge) {
		t.Fatalf("FinishRegistration() error = %v, want errors.Is(err, ErrCeremonyBodyTooLarge)", err)
	}
	if cred != nil {
		t.Fatalf("FinishRegistration() credential = %#v, want nil", cred)
	}

	// The challenge saved by BeginRegistration must still be there: an
	// oversized body is rejected before the challenge is consumed, so a
	// retry with a correctly sized request against the same ceremony can
	// still succeed.
	if _, ok := challenges.peekChallenge(challengeKey("register", string(user.ID))); !ok {
		t.Fatal("challenge was consumed by a rejected oversized body, want it left intact")
	}
}

// constantByteReader is an io.Reader that supplies an endless stream of a
// single repeated byte — used, wrapped in an io.LimitReader as a safety net,
// to prove FinishRegistration's http.MaxBytesReader cap actually stops
// reading the request body at the limit rather than reading it in full and
// only rejecting it afterward.
type constantByteReader byte

func (b constantByteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(b)
	}
	return len(p), nil
}

// countingReader records how many bytes have been pulled through it.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// TestFinishRegistrationCapsBodyReadRatherThanReadingItAll is the sharper
// regression test for audit finding A7's "not an unbounded read" half:
// TestFinishRegistrationRejectsOversizedBody proves the *outcome* (a bounded
// error), but it uses a body that is already fully materialized in memory
// as a []byte before the request is even built, so it would still pass even
// if FinishRegistration read the whole body first and only checked its
// length afterward — which is exactly the unbounded-read behavior the cap
// is supposed to prevent. This test proves the *read itself* stops at the
// limit: the source is a ten-times-oversized body backed by a reader that
// never allocates its output up front, and the assertion is on how many
// bytes were actually pulled through it, not just on the error returned.
func TestFinishRegistrationCapsBodyReadRatherThanReadingItAll(t *testing.T) {
	t.Parallel()

	store := &fakeStore{}
	challenges := newFakeChallengeStore()
	service := newTestService(t, store, challenges)
	user := &User{ID: []byte("user-1"), Name: "user@example.com", DisplayName: "User One"}

	if _, err := service.BeginRegistration(context.Background(), user); err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}

	const hugeBody = 10 * defaultMaxCeremonyBody
	source := &countingReader{r: io.LimitReader(constantByteReader('a'), hugeBody)}

	req, err := http.NewRequest(http.MethodPost, "https://example.com", source)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}
	req.ContentLength = -1 // unknown length: don't let net/http short-circuit on it

	cred, err := service.FinishRegistration(context.Background(), user, req)
	if !errors.Is(err, ErrCeremonyBodyTooLarge) {
		t.Fatalf("FinishRegistration() error = %v, want errors.Is(err, ErrCeremonyBodyTooLarge)", err)
	}
	if cred != nil {
		t.Fatalf("FinishRegistration() credential = %#v, want nil", cred)
	}
	if source.n > defaultMaxCeremonyBody+1 {
		t.Fatalf("read %d bytes from the request body, want at most %d+1 — the cap must stop the read at the limit instead of reading the full (10x oversized) body before rejecting it",
			source.n, defaultMaxCeremonyBody)
	}
}

// TestFinishRegistrationResponseRejectsOversizedBody covers the []byte core
// method directly: a caller that never goes through net/http (and so never
// benefits from http.MaxBytesReader) must still be bounded by the same
// limit.
func TestFinishRegistrationResponseRejectsOversizedBody(t *testing.T) {
	t.Parallel()

	store := &fakeStore{}
	challenges := newFakeChallengeStore()
	service := newTestService(t, store, challenges)
	user := &User{ID: []byte("user-1")}

	oversized := bytes.Repeat([]byte("a"), defaultMaxCeremonyBody+1)
	cred, err := service.FinishRegistrationResponse(context.Background(), user, oversized)
	if !errors.Is(err, ErrCeremonyBodyTooLarge) {
		t.Fatalf("FinishRegistrationResponse() error = %v, want errors.Is(err, ErrCeremonyBodyTooLarge)", err)
	}
	if cred != nil {
		t.Fatalf("FinishRegistrationResponse() credential = %#v, want nil", cred)
	}
}

// TestFinishLoginResponseRejectsOversizedBody is FinishRegistrationResponse's
// counterpart for the login ceremony's []byte core method.
func TestFinishLoginResponseRejectsOversizedBody(t *testing.T) {
	t.Parallel()

	store := &fakeStore{}
	challenges := newFakeChallengeStore()
	service := newTestService(t, store, challenges)
	user := &User{ID: []byte("user-1")}

	oversized := bytes.Repeat([]byte("a"), defaultMaxCeremonyBody+1)
	cred, err := service.FinishLoginResponse(context.Background(), user, "missing-ceremony-id", oversized)
	if !errors.Is(err, ErrCeremonyBodyTooLarge) {
		t.Fatalf("FinishLoginResponse() error = %v, want errors.Is(err, ErrCeremonyBodyTooLarge)", err)
	}
	if cred != nil {
		t.Fatalf("FinishLoginResponse() credential = %#v, want nil", cred)
	}
}

// TestFinishDiscoverableLoginResponseRejectsOversizedBody is
// FinishRegistrationResponse's counterpart for the discoverable-login
// ceremony's []byte core method.
func TestFinishDiscoverableLoginResponseRejectsOversizedBody(t *testing.T) {
	t.Parallel()

	store := &fakeStore{}
	challenges := newFakeChallengeStore()
	service := newTestService(t, store, challenges)

	oversized := bytes.Repeat([]byte("a"), defaultMaxCeremonyBody+1)
	cred, err := service.FinishDiscoverableLoginResponse(context.Background(), "missing-ceremony-id", oversized)
	if !errors.Is(err, ErrCeremonyBodyTooLarge) {
		t.Fatalf("FinishDiscoverableLoginResponse() error = %v, want errors.Is(err, ErrCeremonyBodyTooLarge)", err)
	}
	if cred != nil {
		t.Fatalf("FinishDiscoverableLoginResponse() credential = %#v, want nil", cred)
	}
}

// TestWithMaxCeremonyBodyOverridesDefault covers the escape hatch for callers
// who want a tighter (or looser) limit than the 64 KiB default.
func TestWithMaxCeremonyBodyOverridesDefault(t *testing.T) {
	t.Parallel()

	challenges := newFakeChallengeStore()
	svc, err := NewService(&fakeStore{}, challenges, WebAuthnConfig{
		RPDisplayName: "Test",
		RPID:          "example.com",
		RPOrigins:     []string{"https://example.com"},
	}, WithMaxCeremonyBody(10))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	user := &User{ID: []byte("user-1")}
	_, err = svc.FinishRegistrationResponse(context.Background(), user, []byte("12345678901")) // 11 bytes > 10
	if !errors.Is(err, ErrCeremonyBodyTooLarge) {
		t.Fatalf("FinishRegistrationResponse() error = %v, want errors.Is(err, ErrCeremonyBodyTooLarge)", err)
	}
}

func TestNewServiceRejectsNonPositiveMaxCeremonyBody(t *testing.T) {
	t.Parallel()

	_, err := NewService(&fakeStore{}, newFakeChallengeStore(), WebAuthnConfig{
		RPDisplayName: "Test",
		RPID:          "example.com",
		RPOrigins:     []string{"https://example.com"},
	}, WithMaxCeremonyBody(0))
	if err == nil {
		t.Fatal("expected a non-positive max ceremony body to be rejected")
	}
}

// registrationSpecVectorNoneES256 returns the W3C WebAuthn spec test vector
// for a "none"-attestation ES256 registration
// (https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-none-es256), adapted
// to optionally carry a top-level "clientExtensionResults.credProps.rk"
// value and/or a "response.transports" list — both are client (browser)
// reported values, not part of the signed attestation object, so either can
// be added or omitted independently of the rest of the fixture. Pass a nil
// credPropsRK to simulate a client that omits the credProps extension
// entirely (e.g. an older browser); pass a nil transports to simulate a
// client that omits the transports list.
//
// The fixture's signed authenticator data (part of the attestation object,
// not client-reported) has both the Backup Eligible and Backup State flags
// set, independent of either of the above.
//
// The fixture's RP ID is "example.org" (baked into the authenticator data's
// RP ID hash) and its origin is "https://example.org" (baked into the
// client data JSON): callers must configure the Service with that RPID and
// origin for verification to succeed.
func registrationSpecVectorNoneES256(t *testing.T, credPropsRK *bool, transports []string) (body []byte, challenge string, credentialID []byte) {
	t.Helper()

	const (
		attestationObjectHex = "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"
		clientDataJSONHex    = "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d"
		credentialIDHex      = "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4" //nolint:gosec
		challengeHex         = "00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130"
	)

	credentialID, err := hex.DecodeString(credentialIDHex)
	if err != nil {
		t.Fatalf("decode credential ID: %v", err)
	}
	challengeBytes, err := hex.DecodeString(challengeHex)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	challenge = base64.RawURLEncoding.EncodeToString(challengeBytes)

	attObjBytes, err := hex.DecodeString(attestationObjectHex)
	if err != nil {
		t.Fatalf("decode attestation object: %v", err)
	}
	cdjBytes, err := hex.DecodeString(clientDataJSONHex)
	if err != nil {
		t.Fatalf("decode client data JSON: %v", err)
	}

	id := base64.RawURLEncoding.EncodeToString(credentialID)
	attestationResponse := map[string]any{
		"attestationObject": base64.RawURLEncoding.EncodeToString(attObjBytes),
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(cdjBytes),
	}
	if transports != nil {
		attestationResponse["transports"] = transports
	}
	response := map[string]any{
		"id":       id,
		"rawId":    id,
		"type":     "public-key",
		"response": attestationResponse,
	}
	if credPropsRK != nil {
		response["clientExtensionResults"] = map[string]any{
			"credProps": map[string]any{"rk": *credPropsRK},
		}
	}

	body, err = json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}

	return body, challenge, credentialID
}

// seedRegistrationChallenge saves session data directly into challenges,
// bypassing BeginRegistration, so a FinishRegistration test can supply a
// fixed spec-vector challenge instead of the random one BeginRegistration
// would generate.
func seedRegistrationChallenge(t *testing.T, challenges *fakeChallengeStore, user *User, challenge string, rpID string) {
	t.Helper()

	sessionData := webauthn.SessionData{
		Challenge:        challenge,
		RelyingPartyID:   rpID,
		UserID:           user.ID,
		UserVerification: protocol.VerificationDiscouraged, // the spec vector's authenticator data has no UV flag set
		CredParams:       webauthn.CredentialParametersDefault(),
	}
	data, err := json.Marshal(sessionData)
	if err != nil {
		t.Fatalf("marshal session data: %v", err)
	}
	if err := challenges.SaveChallenge(context.Background(), challengeKey("register", string(user.ID)), data); err != nil {
		t.Fatalf("SaveChallenge: %v", err)
	}
}

// TestFinishRegistrationRecordsDiscoverableWhenCredPropsSaysResidentKey is
// part of the regression coverage for audit finding A6: recording
// Discoverable is pointless if it is never actually populated from a real
// client response.
func TestFinishRegistrationRecordsDiscoverableWhenCredPropsSaysResidentKey(t *testing.T) {
	t.Parallel()

	rk := true
	body, challenge, credentialID := registrationSpecVectorNoneES256(t, &rk, nil)

	store := &fakeStore{}
	challenges := newFakeChallengeStore()
	service, err := NewService(store, challenges, WebAuthnConfig{
		RPDisplayName: "Sulis Test",
		RPID:          "example.org",
		RPOrigins:     []string{"https://example.org"},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	user := &User{ID: []byte("test-user-id"), Name: "alice", DisplayName: "Alice"}
	seedRegistrationChallenge(t, challenges, user, challenge, "example.org")

	req, err := http.NewRequest(http.MethodPost, "https://example.org", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}

	cred, err := service.FinishRegistration(context.Background(), user, req)
	if err != nil {
		t.Fatalf("FinishRegistration() error = %v", err)
	}
	if !bytes.Equal(cred.CredentialID, credentialID) {
		t.Errorf("CredentialID = %x, want %x", cred.CredentialID, credentialID)
	}
	if !cred.Discoverable {
		t.Error("Discoverable = false, want true when the client's credProps.rk = true")
	}
}

// TestFinishRegistrationRecordsNotDiscoverableWhenCredPropsAbsent covers the
// documented fallback: a client that omits the credProps extension entirely
// (e.g. an older browser) must not be recorded as discoverable by default.
func TestFinishRegistrationRecordsNotDiscoverableWhenCredPropsAbsent(t *testing.T) {
	t.Parallel()

	body, challenge, _ := registrationSpecVectorNoneES256(t, nil, nil)

	store := &fakeStore{}
	challenges := newFakeChallengeStore()
	service, err := NewService(store, challenges, WebAuthnConfig{
		RPDisplayName: "Sulis Test",
		RPID:          "example.org",
		RPOrigins:     []string{"https://example.org"},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	user := &User{ID: []byte("test-user-id"), Name: "alice", DisplayName: "Alice"}
	seedRegistrationChallenge(t, challenges, user, challenge, "example.org")

	req, err := http.NewRequest(http.MethodPost, "https://example.org", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}

	cred, err := service.FinishRegistration(context.Background(), user, req)
	if err != nil {
		t.Fatalf("FinishRegistration() error = %v", err)
	}
	if cred.Discoverable {
		t.Error("Discoverable = true, want false when the client omits credProps")
	}
}

// TestFinishRegistrationRecordsBackupFlags is part of the regression coverage
// for audit finding C12: BackupEligible/BackupState were discarded even
// though go-webauthn already verifies them from the signed authenticator
// data. The W3C "none ES256" spec vector's authenticator data has both the
// Backup Eligible and Backup State bits set, so — unlike Discoverable's
// client-reported credProps signal — this is a verified property of the
// response itself.
func TestFinishRegistrationRecordsBackupFlags(t *testing.T) {
	t.Parallel()

	body, challenge, _ := registrationSpecVectorNoneES256(t, nil, nil)

	store := &fakeStore{}
	challenges := newFakeChallengeStore()
	service, err := NewService(store, challenges, WebAuthnConfig{
		RPDisplayName: "Sulis Test",
		RPID:          "example.org",
		RPOrigins:     []string{"https://example.org"},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	user := &User{ID: []byte("test-user-id"), Name: "alice", DisplayName: "Alice"}
	seedRegistrationChallenge(t, challenges, user, challenge, "example.org")

	req, err := http.NewRequest(http.MethodPost, "https://example.org", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}

	cred, err := service.FinishRegistration(context.Background(), user, req)
	if err != nil {
		t.Fatalf("FinishRegistration() error = %v", err)
	}
	if !cred.BackupEligible {
		t.Error("BackupEligible = false, want true (spec vector's authenticator data has the BE bit set)")
	}
	if !cred.BackupState {
		t.Error("BackupState = false, want true (spec vector's authenticator data has the BS bit set)")
	}
}

// TestFinishRegistrationRecordsTransports covers Credential.Transports: the
// client's reported transport list (the registration response's
// "response.transports" field) must be persisted from waCredential.Transport.
func TestFinishRegistrationRecordsTransports(t *testing.T) {
	t.Parallel()

	body, challenge, _ := registrationSpecVectorNoneES256(t, nil, []string{"usb", "internal"})

	store := &fakeStore{}
	challenges := newFakeChallengeStore()
	service, err := NewService(store, challenges, WebAuthnConfig{
		RPDisplayName: "Sulis Test",
		RPID:          "example.org",
		RPOrigins:     []string{"https://example.org"},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	user := &User{ID: []byte("test-user-id"), Name: "alice", DisplayName: "Alice"}
	seedRegistrationChallenge(t, challenges, user, challenge, "example.org")

	req, err := http.NewRequest(http.MethodPost, "https://example.org", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}

	cred, err := service.FinishRegistration(context.Background(), user, req)
	if err != nil {
		t.Fatalf("FinishRegistration() error = %v", err)
	}
	want := []protocol.AuthenticatorTransport{protocol.USB, protocol.Internal}
	if !slices.Equal(cred.Transports, want) {
		t.Errorf("Transports = %v, want %v", cred.Transports, want)
	}
}

// TestFinishRegistrationRecordsNoTransportsWhenOmitted covers the case where
// the client's response doesn't include a transports list at all.
func TestFinishRegistrationRecordsNoTransportsWhenOmitted(t *testing.T) {
	t.Parallel()

	body, challenge, _ := registrationSpecVectorNoneES256(t, nil, nil)

	store := &fakeStore{}
	challenges := newFakeChallengeStore()
	service, err := NewService(store, challenges, WebAuthnConfig{
		RPDisplayName: "Sulis Test",
		RPID:          "example.org",
		RPOrigins:     []string{"https://example.org"},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	user := &User{ID: []byte("test-user-id"), Name: "alice", DisplayName: "Alice"}
	seedRegistrationChallenge(t, challenges, user, challenge, "example.org")

	req, err := http.NewRequest(http.MethodPost, "https://example.org", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}

	cred, err := service.FinishRegistration(context.Background(), user, req)
	if err != nil {
		t.Fatalf("FinishRegistration() error = %v", err)
	}
	if len(cred.Transports) != 0 {
		t.Errorf("Transports = %v, want none", cred.Transports)
	}
}

// TestToWebAuthnCredsPreservesBackupFlagsAndTransport is the regression test
// for a non-obvious consequence of persisting BackupEligible/BackupState:
// every ceremony rebuilds its webauthn.User from the store's credential list
// via toWebAuthnCreds, and go-webauthn's own login verification
// (webauthn.validateLogin) compares the credential's stored BackupEligible
// bit against the fresh assertion's bit, rejecting the login with "Backup
// Eligible flag inconsistency detected" on any mismatch. If toWebAuthnCreds
// silently dropped these fields, the zero-value Flags it produced would
// never match a real client whose credential is genuinely backup-eligible,
// so every login after the first would be rejected.
func TestToWebAuthnCredsPreservesBackupFlagsAndTransport(t *testing.T) {
	t.Parallel()

	creds := []Credential{{
		CredentialID:   []byte("credential-1"),
		BackupEligible: true,
		BackupState:    true,
		Transports:     []protocol.AuthenticatorTransport{protocol.USB, protocol.Internal},
	}}

	got := toWebAuthnCreds(creds)
	if len(got) != 1 {
		t.Fatalf("toWebAuthnCreds() returned %d credentials, want 1", len(got))
	}
	if !got[0].Flags.BackupEligible {
		t.Error("Flags.BackupEligible = false, want true")
	}
	if !got[0].Flags.BackupState {
		t.Error("Flags.BackupState = false, want true")
	}
	want := []protocol.AuthenticatorTransport{protocol.USB, protocol.Internal}
	if !slices.Equal(got[0].Transport, want) {
		t.Errorf("Transport = %v, want %v", got[0].Transport, want)
	}
}

// TestFinishLoginCredentialAdvancesLastUsedAtAndBackupState is the
// regression test for the finish-login half of finding C12. go-webauthn's
// own storage guidance (webauthn package doc, "Storage" section) says
// BackupState must be written back on every successful login — it can flip
// independently of BackupEligible over a credential's lifetime — and
// LastUsedAt is new bookkeeping a management UI needs; sign count alone is
// not enough.
func TestFinishLoginCredentialAdvancesLastUsedAtAndBackupState(t *testing.T) {
	t.Parallel()

	store := &fakeStore{credentialByID: map[string]*Credential{
		"credential-1": {ID: "c1", UserID: "user-1", CredentialID: []byte("credential-1")},
	}}
	service := newTestService(t, store, newFakeChallengeStore())

	waCred := &webauthn.Credential{
		ID: []byte("credential-1"),
		Flags: webauthn.CredentialFlags{
			BackupEligible: true,
			BackupState:    true,
		},
		Authenticator: webauthn.Authenticator{SignCount: 7},
	}

	before := time.Now()
	cred, err := service.finishLoginCredential(context.Background(), waCred)
	if err != nil {
		t.Fatalf("finishLoginCredential() error = %v", err)
	}
	if cred.SignCount != 7 {
		t.Errorf("SignCount = %d, want 7", cred.SignCount)
	}
	if !cred.BackupState {
		t.Error("BackupState = false, want true")
	}
	if cred.LastUsedAt == nil {
		t.Fatal("LastUsedAt = nil, want a timestamp")
	}
	if cred.LastUsedAt.Before(before) {
		t.Errorf("LastUsedAt = %v, want at or after %v", cred.LastUsedAt, before)
	}
	if store.updateAfterLoginCalls != 1 {
		t.Errorf("UpdateCredentialAfterLogin() calls = %d, want 1", store.updateAfterLoginCalls)
	}
}

// TestDeleteCredentialRejectsLastCredentialWithoutOverride is the regression
// test for the last-factor deletion guard (finding C12): passkey has no
// visibility into whether userID's account has any other way to
// authenticate, so removing a user's only remaining credential must require
// the caller to say so explicitly via DeleteOptions.AllowLast.
func TestDeleteCredentialRejectsLastCredentialWithoutOverride(t *testing.T) {
	t.Parallel()

	store := &fakeStore{credentialsByUser: map[string][]Credential{
		"user-1": {{ID: "cred-1", UserID: "user-1", CredentialID: []byte("credential-1")}},
	}}
	service := newTestService(t, store, newFakeChallengeStore())

	err := service.DeleteCredential(context.Background(), "user-1", "cred-1", DeleteOptions{})
	if !errors.Is(err, ErrLastCredential) {
		t.Fatalf("DeleteCredential() error = %v, want %v", err, ErrLastCredential)
	}
	if store.deletedCredentialID != "" {
		t.Errorf("deleted credential ID = %q, want none (rejected)", store.deletedCredentialID)
	}
	remaining, err := store.GetCredentialsByUserID(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("GetCredentialsByUserID() error = %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("user-1 has %d credentials remaining, want 1 (rejected deletion must not remove anything)", len(remaining))
	}
}

// TestDeleteCredentialAllowsLastCredentialWithOverride covers the override:
// once the caller has established (through its own re-auth/confirmation
// flow) that removing the account's last credential is intentional, the
// same call must succeed.
func TestDeleteCredentialAllowsLastCredentialWithOverride(t *testing.T) {
	t.Parallel()

	store := &fakeStore{credentialsByUser: map[string][]Credential{
		"user-1": {{ID: "cred-1", UserID: "user-1", CredentialID: []byte("credential-1")}},
	}}
	service := newTestService(t, store, newFakeChallengeStore())

	err := service.DeleteCredential(context.Background(), "user-1", "cred-1", DeleteOptions{AllowLast: true})
	if err != nil {
		t.Fatalf("DeleteCredential() error = %v, want nil", err)
	}
	if store.deletedCredentialID != "cred-1" {
		t.Errorf("deleted credential ID = %q, want %q", store.deletedCredentialID, "cred-1")
	}
	remaining, err := store.GetCredentialsByUserID(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("GetCredentialsByUserID() error = %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("user-1 has %d credentials remaining, want 0", len(remaining))
	}
}

// TestDeleteCredentialAllowsNonLastCredentialWithoutOverride covers the
// common case: deleting one of several credentials never needs the override.
func TestDeleteCredentialAllowsNonLastCredentialWithoutOverride(t *testing.T) {
	t.Parallel()

	store := &fakeStore{credentialsByUser: map[string][]Credential{
		"user-1": {
			{ID: "cred-1", UserID: "user-1", CredentialID: []byte("credential-1")},
			{ID: "cred-2", UserID: "user-1", CredentialID: []byte("credential-2")},
		},
	}}
	service := newTestService(t, store, newFakeChallengeStore())

	if err := service.DeleteCredential(context.Background(), "user-1", "cred-1", DeleteOptions{}); err != nil {
		t.Fatalf("DeleteCredential() error = %v, want nil", err)
	}
	if store.deletedCredentialID != "cred-1" {
		t.Errorf("deleted credential ID = %q, want %q", store.deletedCredentialID, "cred-1")
	}
	remaining, err := store.GetCredentialsByUserID(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("GetCredentialsByUserID() error = %v", err)
	}
	if len(remaining) != 1 || remaining[0].ID != "cred-2" {
		t.Fatalf("user-1 credentials = %v, want only cred-2 remaining", remaining)
	}
}

// TestDeleteCredentialReturnsErrPasskeyNotFoundForUnknownCredential covers a
// credentialID that doesn't belong to (or exist for) userID at all — this
// must fail with ErrPasskeyNotFound before the last-credential guard is even
// consulted, and regardless of AllowLast.
func TestDeleteCredentialReturnsErrPasskeyNotFoundForUnknownCredential(t *testing.T) {
	t.Parallel()

	store := &fakeStore{credentialsByUser: map[string][]Credential{
		"user-1": {{ID: "cred-1", UserID: "user-1", CredentialID: []byte("credential-1")}},
	}}
	service := newTestService(t, store, newFakeChallengeStore())

	err := service.DeleteCredential(context.Background(), "user-1", "does-not-exist", DeleteOptions{AllowLast: true})
	if !errors.Is(err, ErrPasskeyNotFound) {
		t.Fatalf("DeleteCredential() error = %v, want %v", err, ErrPasskeyNotFound)
	}
	if store.deletedCredentialID != "" {
		t.Errorf("deleted credential ID = %q, want none", store.deletedCredentialID)
	}
}

// TestDeleteCredentialGuardIsAtomicUnderConcurrentDeletes is the regression
// test for a TOCTOU race a review found in the last-factor guard: a
// get-count-then-delete guard implemented as two separate operations lets
// two concurrent callers, each deleting one of a user's last two
// credentials, both observe count==2 before either deletion lands — both
// then pass the guard with AllowLast==false, and both succeed, leaving the
// user with zero credentials. That is exactly the lockout state
// DeleteOptions.AllowLast exists to prevent, reached through the guarded
// path. Store.DeleteCredential's contract requires the membership check,
// the remaining-count check, and the removal to be one atomic operation for
// exactly this reason (the same requirement ChallengeStore.ConsumeChallenge,
// TokenStore.ConsumeToken, and recovery.Store.ConsumeCode already place on
// their own check-and-mutate operations).
//
// Modeled on T201's TestFinishDiscoverableLoginConsumesChallengeExactlyOnce:
// both goroutines are released from a shared start gate on every iteration
// to make the race as tight as possible, and the property is checked across
// many iterations since a single run can get lucky.
func TestDeleteCredentialGuardIsAtomicUnderConcurrentDeletes(t *testing.T) {
	const iterations = 200

	for i := 0; i < iterations; i++ {
		store := &fakeStore{credentialsByUser: map[string][]Credential{
			"user-1": {
				{ID: "cred-1", UserID: "user-1", CredentialID: []byte("credential-1")},
				{ID: "cred-2", UserID: "user-1", CredentialID: []byte("credential-2")},
			},
		}}
		service := newTestService(t, store, newFakeChallengeStore())

		const racers = 2
		ids := [racers]string{"cred-1", "cred-2"}
		start := make(chan struct{})
		errs := make([]error, racers)
		var wg sync.WaitGroup
		wg.Add(racers)
		for g := 0; g < racers; g++ {
			g := g
			go func() {
				defer wg.Done()
				<-start
				errs[g] = service.DeleteCredential(context.Background(), "user-1", ids[g], DeleteOptions{})
			}()
		}
		close(start)
		wg.Wait()

		var succeeded, rejected int
		for _, err := range errs {
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, ErrLastCredential):
				rejected++
			default:
				t.Fatalf("iteration %d: DeleteCredential() unexpected error = %v", i, err)
			}
		}
		if succeeded != 1 || rejected != 1 {
			t.Fatalf("iteration %d: got %d succeeded and %d rejected among %d racers, want exactly 1 and 1 (atomic last-credential guard violated)",
				i, succeeded, rejected, racers)
		}

		remaining, err := store.GetCredentialsByUserID(context.Background(), "user-1")
		if err != nil {
			t.Fatalf("iteration %d: GetCredentialsByUserID() error = %v", i, err)
		}
		if len(remaining) != 1 {
			t.Fatalf("iteration %d: user-1 has %d credentials remaining, want exactly 1 (zero would be the lockout the guard exists to prevent)", i, len(remaining))
		}
	}
}

// TestFakeStoreRenameCredentialUpdatesNameOrReturnsErrPasskeyNotFound
// exercises the Store.RenameCredential contract documented on the interface:
// a caller-supplied Name is set on success, and an unknown id is rejected
// with ErrPasskeyNotFound rather than silently succeeding or panicking.
func TestFakeStoreRenameCredentialUpdatesNameOrReturnsErrPasskeyNotFound(t *testing.T) {
	t.Parallel()

	store := &fakeStore{credentialsByUser: map[string][]Credential{
		"user-1": {{ID: "cred-1", UserID: "user-1", CredentialID: []byte("credential-1")}},
	}}

	if err := store.RenameCredential(context.Background(), "cred-1", "My YubiKey"); err != nil {
		t.Fatalf("RenameCredential() error = %v, want nil", err)
	}
	if got := store.credentialsByUser["user-1"][0].Name; got != "My YubiKey" {
		t.Errorf("Name = %q, want %q", got, "My YubiKey")
	}

	err := store.RenameCredential(context.Background(), "missing-id", "x")
	if !errors.Is(err, ErrPasskeyNotFound) {
		t.Fatalf("RenameCredential() error = %v, want %v", err, ErrPasskeyNotFound)
	}
}

// TestFakeStoreDeleteCredentialsByUserIDRemovesOnlyThatUsersCredentials
// exercises the Store.DeleteCredentialsByUserID contract: every credential
// for the named user is gone, and other users' credentials are untouched.
func TestFakeStoreDeleteCredentialsByUserIDRemovesOnlyThatUsersCredentials(t *testing.T) {
	t.Parallel()

	store := &fakeStore{credentialsByUser: map[string][]Credential{
		"user-1": {
			{ID: "cred-1", CredentialID: []byte("credential-1")},
			{ID: "cred-2", CredentialID: []byte("credential-2")},
		},
		"user-2": {{ID: "cred-3", CredentialID: []byte("credential-3")}},
	}}

	if err := store.DeleteCredentialsByUserID(context.Background(), "user-1"); err != nil {
		t.Fatalf("DeleteCredentialsByUserID() error = %v, want nil", err)
	}
	if got := store.credentialsByUser["user-1"]; len(got) != 0 {
		t.Errorf("user-1 credentials = %v, want none", got)
	}
	if got := store.credentialsByUser["user-2"]; len(got) != 1 {
		t.Errorf("user-2 credentials = %v, want 1 untouched", got)
	}
}

// errStoreFailure stands in for any failure a real Store might return —
// a dropped database connection, a timeout, a constraint violation. What
// matters is only that it is a distinct sentinel the tests can match with
// errors.Is, so an assertion proves the store's error reached the caller
// rather than being swallowed and replaced with something generic.
var errStoreFailure = errors.New("store unavailable")

// TestBeginRegistrationPropagatesCredentialLookupFailure covers the store
// error path T202 opened but did not test: BeginRegistration reads the user's
// existing credentials to build excludeCredentials, and a failure there must
// abort the ceremony rather than silently proceeding with an empty exclusion
// list — which would quietly reintroduce exactly the duplicate-credential
// problem T202 fixed.
func TestBeginRegistrationPropagatesCredentialLookupFailure(t *testing.T) {
	t.Parallel()

	store := &fakeStore{getCredentialsErr: errStoreFailure}
	challenges := newFakeChallengeStore()
	service := newTestService(t, store, challenges)

	creation, err := service.BeginRegistration(context.Background(), &User{ID: []byte("user-1")})
	if !errors.Is(err, errStoreFailure) {
		t.Fatalf("BeginRegistration() error = %v, want errors.Is(err, errStoreFailure)", err)
	}
	if creation != nil {
		t.Fatalf("BeginRegistration() creation = %#v, want nil", creation)
	}
	if len(challenges.saved) != 0 {
		t.Fatalf("BeginRegistration() saved %d challenges, want 0 — an aborted ceremony must not leave a challenge behind", len(challenges.saved))
	}
}

// TestBeginLoginPropagatesCredentialLookupFailure is BeginRegistration's
// counterpart. The distinction that matters here is against
// ErrPasskeyNotFound: a store that is broken must not be reported as a user
// who has no passkey, since a caller would reasonably route the latter to a
// "register a passkey" flow.
func TestBeginLoginPropagatesCredentialLookupFailure(t *testing.T) {
	t.Parallel()

	store := &fakeStore{getCredentialsErr: errStoreFailure}
	challenges := newFakeChallengeStore()
	service := newTestService(t, store, challenges)

	assertion, ceremonyID, err := service.BeginLogin(context.Background(), &User{ID: []byte("user-1")})
	if !errors.Is(err, errStoreFailure) {
		t.Fatalf("BeginLogin() error = %v, want errors.Is(err, errStoreFailure)", err)
	}
	if errors.Is(err, ErrPasskeyNotFound) {
		t.Error("BeginLogin() reported ErrPasskeyNotFound for a store failure — a broken store must not look like a user without a passkey")
	}
	if assertion != nil || ceremonyID != "" {
		t.Fatalf("BeginLogin() = (%#v, %q), want (nil, \"\")", assertion, ceremonyID)
	}
}

// TestFinishLoginResponsePropagatesCredentialLookupFailure covers the same
// lookup on the finish side, which happens before the challenge is consumed.
func TestFinishLoginResponsePropagatesCredentialLookupFailure(t *testing.T) {
	t.Parallel()

	store := &fakeStore{getCredentialsErr: errStoreFailure}
	challenges := newFakeChallengeStore()
	service := newTestService(t, store, challenges)

	_, err := service.FinishLoginResponse(context.Background(), &User{ID: []byte("user-1")}, "ceremony-1", []byte("{}"))
	if !errors.Is(err, errStoreFailure) {
		t.Fatalf("FinishLoginResponse() error = %v, want errors.Is(err, errStoreFailure)", err)
	}
	if errors.Is(err, ErrChallengeExpired) {
		t.Error("FinishLoginResponse() reported ErrChallengeExpired for a store failure — the two must stay distinguishable")
	}
}

// TestBeginCeremoniesPropagateChallengeSaveFailure covers the other
// persistence dependency every Begin* method has. A ceremony whose challenge
// could not be stored is unfinishable, so returning the options anyway would
// hand the caller a ceremony guaranteed to fail later with
// ErrChallengeExpired — a confusing way to report a storage outage.
func TestBeginCeremoniesPropagateChallengeSaveFailure(t *testing.T) {
	t.Parallel()

	user := &User{ID: []byte("user-1"), Name: "alice", DisplayName: "Alice"}

	newService := func(t *testing.T) *Service {
		t.Helper()
		store := &fakeStore{credentialsByUser: map[string][]Credential{
			"user-1": {{ID: "cred-1", UserID: "user-1", CredentialID: []byte("credential-1")}},
		}}
		return newTestService(t, store, &fakeChallengeStore{saved: map[string][]byte{}, saveErr: errStoreFailure})
	}

	t.Run("registration", func(t *testing.T) {
		t.Parallel()
		if _, err := newService(t).BeginRegistration(context.Background(), user); !errors.Is(err, errStoreFailure) {
			t.Fatalf("BeginRegistration() error = %v, want errors.Is(err, errStoreFailure)", err)
		}
	})

	t.Run("login", func(t *testing.T) {
		t.Parallel()
		if _, _, err := newService(t).BeginLogin(context.Background(), user); !errors.Is(err, errStoreFailure) {
			t.Fatalf("BeginLogin() error = %v, want errors.Is(err, errStoreFailure)", err)
		}
	})

	t.Run("discoverable login", func(t *testing.T) {
		t.Parallel()
		if _, _, err := newService(t).BeginDiscoverableLogin(context.Background()); !errors.Is(err, errStoreFailure) {
			t.Fatalf("BeginDiscoverableLogin() error = %v, want errors.Is(err, errStoreFailure)", err)
		}
	})
}

// TestFinishRegistrationResponsePropagatesSaveFailure covers the last store
// call in the registration ceremony. A credential that verified but could not
// be persisted must surface as an error: reporting success would tell the
// caller a passkey exists that no later login will ever find.
func TestFinishRegistrationResponsePropagatesSaveFailure(t *testing.T) {
	t.Parallel()

	body, challenge, _ := registrationSpecVectorNoneES256(t, nil, nil)

	store := &fakeStore{saveCredentialErr: errStoreFailure}
	challenges := newFakeChallengeStore()
	service, err := NewService(store, challenges, WebAuthnConfig{
		RPDisplayName: "Sulis Test",
		RPID:          "example.org",
		RPOrigins:     []string{"https://example.org"},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	user := &User{ID: []byte("test-user-id"), Name: "alice", DisplayName: "Alice"}
	seedRegistrationChallenge(t, challenges, user, challenge, "example.org")

	cred, err := service.FinishRegistrationResponse(context.Background(), user, body)
	if !errors.Is(err, errStoreFailure) {
		t.Fatalf("FinishRegistrationResponse() error = %v, want errors.Is(err, errStoreFailure)", err)
	}
	if cred != nil {
		t.Fatalf("FinishRegistrationResponse() credential = %#v, want nil", cred)
	}
}

// TestFinishLoginCredentialPropagatesUpdateFailure covers the bookkeeping
// write that follows a verified assertion. The sign count, backup state, and
// last-used timestamp must be persisted before a login is reported as
// successful — if that write fails and the login succeeds anyway, the sign
// count never advances and clone detection is silently disabled for that
// credential from then on.
func TestFinishLoginCredentialPropagatesUpdateFailure(t *testing.T) {
	t.Parallel()

	store := &fakeStore{
		credentialByID:      map[string]*Credential{"credential-1": {ID: "c1", UserID: "user-1", CredentialID: []byte("credential-1")}},
		updateAfterLoginErr: errStoreFailure,
	}
	service := newTestService(t, store, newFakeChallengeStore())

	waCred := &webauthn.Credential{ID: []byte("credential-1"), Authenticator: webauthn.Authenticator{SignCount: 7}}

	cred, err := service.finishLoginCredential(context.Background(), waCred)
	if !errors.Is(err, errStoreFailure) {
		t.Fatalf("finishLoginCredential() error = %v, want errors.Is(err, errStoreFailure)", err)
	}
	if cred != nil {
		t.Fatalf("finishLoginCredential() credential = %#v, want nil", cred)
	}
}

// TestFinishLoginCredentialPropagatesReloadFailure covers the final read: the
// credential is re-fetched so the caller receives the row as persisted, and a
// failure there must not be reported as a successful login with a nil
// credential.
func TestFinishLoginCredentialPropagatesReloadFailure(t *testing.T) {
	t.Parallel()

	store := &fakeStore{
		credentialByID:       map[string]*Credential{"credential-1": {ID: "c1", UserID: "user-1", CredentialID: []byte("credential-1")}},
		getCredentialByIDErr: errStoreFailure,
	}
	service := newTestService(t, store, newFakeChallengeStore())

	waCred := &webauthn.Credential{ID: []byte("credential-1"), Authenticator: webauthn.Authenticator{SignCount: 7}}

	if _, err := service.finishLoginCredential(context.Background(), waCred); !errors.Is(err, errStoreFailure) {
		t.Fatalf("finishLoginCredential() error = %v, want errors.Is(err, errStoreFailure)", err)
	}
}

// TestFinishCeremoniesRejectCorruptSessionData covers a challenge store that
// returns something that is not session data — a truncated write, a
// serialization change, a key collision with another subsystem. Each Finish*
// method must fail rather than proceeding with a zero-valued
// webauthn.SessionData, whose empty Challenge and empty UserVerification
// would disable both the challenge match and the user-verification check.
func TestFinishCeremoniesRejectCorruptSessionData(t *testing.T) {
	t.Parallel()

	const corrupt = "this is not session data"
	user := &User{ID: []byte("user-1")}
	ctx := context.Background()

	t.Run("registration", func(t *testing.T) {
		t.Parallel()

		challenges := newFakeChallengeStore()
		service := newTestService(t, &fakeStore{}, challenges)
		if err := challenges.SaveChallenge(ctx, challengeKey("register", string(user.ID)), []byte(corrupt)); err != nil {
			t.Fatalf("SaveChallenge: %v", err)
		}

		_, err := service.FinishRegistrationResponse(ctx, user, []byte("{}"))
		if err == nil || !strings.Contains(err.Error(), "unmarshaling session") {
			t.Fatalf("FinishRegistrationResponse() error = %v, want it to name the session unmarshal step", err)
		}
	})

	t.Run("login", func(t *testing.T) {
		t.Parallel()

		challenges := newFakeChallengeStore()
		service := newTestService(t, &fakeStore{}, challenges)
		if err := challenges.SaveChallenge(ctx, challengeKey("login", "ceremony-1"), []byte(corrupt)); err != nil {
			t.Fatalf("SaveChallenge: %v", err)
		}

		_, err := service.FinishLoginResponse(ctx, user, "ceremony-1", []byte("{}"))
		if err == nil || !strings.Contains(err.Error(), "unmarshaling session") {
			t.Fatalf("FinishLoginResponse() error = %v, want it to name the session unmarshal step", err)
		}
	})

	t.Run("discoverable login", func(t *testing.T) {
		t.Parallel()

		challenges := newFakeChallengeStore()
		service := newTestService(t, &fakeStore{}, challenges)
		if err := challenges.SaveChallenge(ctx, challengeKey("discover", "ceremony-1"), []byte(corrupt)); err != nil {
			t.Fatalf("SaveChallenge: %v", err)
		}

		_, err := service.FinishDiscoverableLoginResponse(ctx, "ceremony-1", []byte("{}"))
		if err == nil || !strings.Contains(err.Error(), "unmarshaling session") {
			t.Fatalf("FinishDiscoverableLoginResponse() error = %v, want it to name the session unmarshal step", err)
		}
	})
}

// TestNewServiceRejectsInvalidRelyingPartyConfig covers the constructor's
// remaining failure mode: go-webauthn requires at least one relying party
// origin, and a Service built without one would accept a credential from any
// origin at all — the check that makes passkeys unphishable.
func TestNewServiceRejectsInvalidRelyingPartyConfig(t *testing.T) {
	t.Parallel()

	svc, err := NewService(&fakeStore{}, newFakeChallengeStore(), WebAuthnConfig{
		RPDisplayName: "Test",
		RPID:          "example.com",
	})
	if err == nil {
		t.Fatal("NewService() error = nil, want a rejection for a relying party config with no origins")
	}
	if svc != nil {
		t.Fatalf("NewService() service = %#v, want nil", svc)
	}
}

// failingBodyReader is an io.Reader that fails partway through, standing in
// for a client connection that drops mid-upload.
type failingBodyReader struct{}

func (failingBodyReader) Read([]byte) (int, error) { return 0, errStoreFailure }

// TestFinishCeremoniesReportBodyReadFailures covers the net/http wrappers'
// remaining branch: a body that fails to read for a reason other than
// exceeding the size cap must be reported as a read failure, and must be
// clearly distinguishable from ErrCeremonyBodyTooLarge so a caller does not
// log a dropped connection as an oversized-body attack.
func TestFinishCeremoniesReportBodyReadFailures(t *testing.T) {
	t.Parallel()

	user := &User{ID: []byte("user-1")}
	ctx := context.Background()

	newFailingRequest := func(t *testing.T) *http.Request {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, "https://example.com", failingBodyReader{})
		if err != nil {
			t.Fatalf("http.NewRequest() error = %v", err)
		}
		req.ContentLength = -1
		return req
	}

	assertReadFailure := func(t *testing.T, err error) {
		t.Helper()
		if !errors.Is(err, errStoreFailure) {
			t.Fatalf("error = %v, want errors.Is(err, errStoreFailure)", err)
		}
		if errors.Is(err, ErrCeremonyBodyTooLarge) {
			t.Error("a failed read was reported as an oversized body")
		}
		if !strings.Contains(err.Error(), "reading ceremony response body") {
			t.Errorf("error = %q, want it to name the body read step", err)
		}
	}

	t.Run("registration", func(t *testing.T) {
		t.Parallel()
		_, err := newTestService(t, &fakeStore{}, newFakeChallengeStore()).FinishRegistration(ctx, user, newFailingRequest(t))
		assertReadFailure(t, err)
	})

	t.Run("login", func(t *testing.T) {
		t.Parallel()
		_, err := newTestService(t, &fakeStore{}, newFakeChallengeStore()).FinishLogin(ctx, user, "ceremony-1", newFailingRequest(t))
		assertReadFailure(t, err)
	})

	t.Run("discoverable login", func(t *testing.T) {
		t.Parallel()
		_, err := newTestService(t, &fakeStore{}, newFakeChallengeStore()).FinishDiscoverableLogin(ctx, "ceremony-1", newFailingRequest(t))
		assertReadFailure(t, err)
	})
}

// TestBeginCeremoniesRejectIncompleteRelyingPartyConfig documents where the
// two WebAuthnConfig fields NewService does NOT validate are actually
// enforced. go-webauthn's own config validation only rejects an empty
// RPOrigins list (see TestNewServiceRejectsInvalidRelyingPartyConfig); an
// empty RPID or RPDisplayName passes construction and is caught later, per
// ceremony, by go-webauthn's Begin* methods.
//
// That ordering is worth pinning down rather than leaving to chance: a
// misconfigured Service that constructs cleanly and only fails on the first
// real user's first ceremony is a deployment-time surprise, so these tests
// record which ceremony reports it and make it obvious if a future version of
// the library moves the check.
func TestBeginCeremoniesRejectIncompleteRelyingPartyConfig(t *testing.T) {
	t.Parallel()

	user := &User{ID: []byte("user-1"), Name: "alice", DisplayName: "Alice"}
	ctx := context.Background()

	newService := func(t *testing.T, cfg WebAuthnConfig) *Service {
		t.Helper()
		store := &fakeStore{credentialsByUser: map[string][]Credential{
			"user-1": {{ID: "cred-1", UserID: "user-1", CredentialID: []byte("credential-1")}},
		}}
		svc, err := NewService(store, newFakeChallengeStore(), cfg)
		if err != nil {
			t.Fatalf("NewService() error = %v, want nil — this config is only rejected at ceremony time", err)
		}
		return svc
	}

	t.Run("registration needs a relying party display name", func(t *testing.T) {
		t.Parallel()

		svc := newService(t, WebAuthnConfig{RPID: "example.com", RPOrigins: []string{"https://example.com"}})

		creation, err := svc.BeginRegistration(ctx, user)
		if err == nil {
			t.Fatal("BeginRegistration() error = nil, want a rejection for an empty RPDisplayName")
		}
		if creation != nil {
			t.Fatalf("BeginRegistration() creation = %#v, want nil", creation)
		}
		if !strings.Contains(err.Error(), "begin registration") {
			t.Errorf("BeginRegistration() error = %q, want it to name the ceremony step", err)
		}
	})

	t.Run("login needs a relying party id", func(t *testing.T) {
		t.Parallel()

		svc := newService(t, WebAuthnConfig{RPDisplayName: "Sulis Test", RPOrigins: []string{"https://example.com"}})

		_, ceremonyID, err := svc.BeginLogin(ctx, user)
		if err == nil {
			t.Fatal("BeginLogin() error = nil, want a rejection for an empty RPID")
		}
		if ceremonyID != "" {
			t.Fatalf("BeginLogin() ceremony ID = %q, want empty", ceremonyID)
		}
		if !strings.Contains(err.Error(), "begin login") {
			t.Errorf("BeginLogin() error = %q, want it to name the ceremony step", err)
		}
	})

	t.Run("discoverable login needs a relying party id", func(t *testing.T) {
		t.Parallel()

		svc := newService(t, WebAuthnConfig{RPDisplayName: "Sulis Test", RPOrigins: []string{"https://example.com"}})

		_, ceremonyID, err := svc.BeginDiscoverableLogin(ctx)
		if err == nil {
			t.Fatal("BeginDiscoverableLogin() error = nil, want a rejection for an empty RPID")
		}
		if ceremonyID != "" {
			t.Fatalf("BeginDiscoverableLogin() ceremony ID = %q, want empty", ceremonyID)
		}
		if !strings.Contains(err.Error(), "begin discoverable login") {
			t.Errorf("BeginDiscoverableLogin() error = %q, want it to name the ceremony step", err)
		}
	})
}
