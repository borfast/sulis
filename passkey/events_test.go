package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type recordingEventSink struct {
	mu     sync.Mutex
	events []Event
}

func (s *recordingEventSink) Emit(_ context.Context, e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *recordingEventSink) snapshot() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.events...)
}

func TestPasskeyEventsCoverRegistrationAndLoginSuccess(t *testing.T) {
	sink := &recordingEventSink{}
	f := newForgingFixture(t, WithEventSink(sink))
	ctx := t.Context()

	creation, err := f.service.BeginRegistration(ctx, f.user)
	if err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}
	rq := f.registrationRequest(creation.Response.Challenge.String())
	rk := true
	rq.credPropsRK = &rk
	if _, err := f.service.FinishRegistrationResponse(ctx, f.user, f.auth.forgeRegistration(rq)); err != nil {
		t.Fatalf("FinishRegistrationResponse() error = %v", err)
	}

	challenge, ceremonyID := f.beginLogin()
	if _, err := f.service.FinishLoginResponse(ctx, f.user, ceremonyID, f.auth.forgeAssertion(f.assertionRequest(challenge))); err != nil {
		t.Fatalf("FinishLoginResponse() error = %v", err)
	}

	events := sink.snapshot()
	var registration, login bool
	for _, event := range events {
		registration = registration || event.Kind == EventRegistrationSucceeded
		login = login || event.Kind == EventLoginSucceeded
	}
	if !registration || !login {
		t.Fatalf("events = %+v, want registration and login success", events)
	}
}

func TestPasskeyEventsCoverRegistrationAndLoginRejection(t *testing.T) {
	sink := &recordingEventSink{}
	store := &fakeStore{credentialsByUser: map[string][]Credential{
		"user-1": {{CredentialID: []byte("credential-1")}},
	}}
	challenges := newFakeChallengeStore()
	service := newTestServiceWithOptions(t, store, challenges, WithEventSink(sink))
	user := &User{ID: []byte("user-1")}

	if _, err := service.BeginRegistration(context.Background(), user); err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}
	if _, err := service.FinishRegistrationResponse(context.Background(), user, []byte("not valid json")); err == nil {
		t.Fatal("FinishRegistrationResponse() error = nil, want rejection")
	}

	_, ceremonyID, err := service.BeginLogin(context.Background(), user)
	if err != nil {
		t.Fatalf("BeginLogin() error = %v", err)
	}
	if _, err := service.FinishLoginResponse(context.Background(), user, ceremonyID, []byte("not valid json")); !errors.Is(err, ErrChallengeFailed) {
		t.Fatalf("FinishLoginResponse() error = %v, want ErrChallengeFailed", err)
	}

	events := sink.snapshot()
	var registration, login bool
	for _, event := range events {
		if event.Kind == EventRegistrationRejected {
			registration = true
			if event.Diagnostic != "invalid_request" {
				t.Errorf("registration rejection diagnostic = %q, want invalid_request", event.Diagnostic)
			}
		}
		if event.Kind == EventLoginRejected {
			login = true
			if event.Diagnostic != "invalid_request" {
				t.Errorf("login rejection diagnostic = %q, want invalid_request", event.Diagnostic)
			}
		}
	}
	if !registration || !login {
		t.Fatalf("events = %+v, want registration and login rejection", events)
	}
}

func TestPasskeyEventsCoverLoginOutcomesAndStoreFailures(t *testing.T) {
	sink := &recordingEventSink{}
	store := &fakeStore{
		credentialByID: map[string]*Credential{
			"credential-1": {ID: "credential-row-1", UserID: "user-1", CredentialID: []byte("credential-1")},
		},
	}
	service := newTestServiceWithOptions(t, store, newFakeChallengeStore(), WithEventSink(sink))

	if _, err := service.finishLoginCredential(context.Background(), "user-1", &webauthn.Credential{ID: []byte("credential-1")}); err != nil {
		t.Fatalf("successful finishLoginCredential() error = %v", err)
	}
	if _, err := service.finishLoginCredential(context.Background(), "user-1", &webauthn.Credential{
		ID:            []byte("credential-1"),
		Authenticator: webauthn.Authenticator{CloneWarning: true},
	}); !errors.Is(err, ErrCloneWarning) {
		t.Fatalf("clone-warning finishLoginCredential() error = %v, want ErrCloneWarning", err)
	}

	store.updateAfterLoginErr = errStoreFailure
	if _, err := service.finishLoginCredential(context.Background(), "user-1", &webauthn.Credential{ID: []byte("credential-1")}); !errors.Is(err, errStoreFailure) {
		t.Fatalf("store-failure finishLoginCredential() error = %v, want errStoreFailure", err)
	}

	events := sink.snapshot()
	if len(events) != 3 {
		t.Fatalf("events = %+v, want login success, clone warning, and store failure", events)
	}
	if events[0].Kind != EventLoginSucceeded {
		t.Errorf("first event kind = %q, want %q", events[0].Kind, EventLoginSucceeded)
	}
	if events[1].Kind != EventCloneWarning || events[1].Diagnostic != "clone_warning" {
		t.Errorf("clone event = %+v", events[1])
	}
	if events[2].Kind != EventStoreFailed || events[2].Operation != "update_credential_after_login" {
		t.Errorf("store event = %+v", events[2])
	}
}

func TestPasskeyEventsCoverDeletionAndChallengeExpiry(t *testing.T) {
	sink := &recordingEventSink{}
	store := &fakeStore{credentialsByUser: map[string][]Credential{
		"user-1": {{ID: "credential-row-1", UserID: "user-1", CredentialID: []byte("credential-1")}},
	}}
	service := newTestServiceWithOptions(t, store, newFakeChallengeStore(), WithEventSink(sink))

	if err := service.DeleteCredential(context.Background(), "user-1", "credential-row-1", DeleteOptions{AllowLast: true}); err != nil {
		t.Fatalf("DeleteCredential() error = %v", err)
	}
	if err := service.DeleteCredential(context.Background(), "user-1", "missing", DeleteOptions{AllowLast: true}); !errors.Is(err, ErrPasskeyNotFound) {
		t.Fatalf("missing DeleteCredential() error = %v, want ErrPasskeyNotFound", err)
	}

	if _, err := service.FinishRegistrationResponse(context.Background(), &User{ID: []byte("user-1")}, []byte("{}")); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("missing registration challenge error = %v, want ErrChallengeExpired", err)
	}

	events := sink.snapshot()
	if len(events) != 3 {
		t.Fatalf("events = %+v, want deletion, deletion rejection, and expiry", events)
	}
	if events[0].Kind != EventCredentialDeleted {
		t.Errorf("delete event = %+v", events[0])
	}
	if events[1].Kind != EventCredentialDeletionRejected {
		t.Errorf("delete rejection event = %+v", events[1])
	}
	if events[2].Kind != EventRegistrationChallengeExpired || events[2].Diagnostic != "challenge_expired" {
		t.Errorf("expiry event = %+v", events[2])
	}
}

func TestPasskeyEventPayloadContainsNoCredentialMaterial(t *testing.T) {
	sink := &recordingEventSink{}
	store := &fakeStore{credentialByID: map[string]*Credential{
		"credential-public-id": {ID: "credential-row", UserID: "opaque-user", CredentialID: []byte("credential-public-id")},
	}}
	service := newTestServiceWithOptions(t, store, newFakeChallengeStore(), WithEventSink(sink))

	if _, err := service.finishLoginCredential(context.Background(), "opaque-user", &webauthn.Credential{ID: []byte("credential-public-id")}); err != nil {
		t.Fatalf("finishLoginCredential() error = %v", err)
	}

	events := sink.snapshot()
	if len(events) != 1 {
		t.Fatalf("events = %+v, want one event", events)
	}
	encoded, err := json.Marshal(events[0])
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	text := string(encoded) + fmt.Sprintf("%#v", events[0])
	for _, secret := range []string{
		"raw-challenge-value",
		"full-client-data-json",
		"credential-private-key",
		"credential-public-key-bytes",
		"credential-secret",
		"protocol diagnostic details",
	} {
		if strings.Contains(text, secret) {
			t.Fatalf("event payload contains credential material %q: %s", secret, text)
		}
	}
}

func TestDiagnosticCategoryRetainsProtocolIdentityWithoutDetails(t *testing.T) {
	underlying := protocol.ErrBadRequest.WithInfo("json: unmarshal clientExtensionResults")
	wrapped := fmt.Errorf("%w: %w", ErrChallengeFailed, underlying)

	var protocolErr *protocol.Error
	if !errors.As(wrapped, &protocolErr) {
		t.Fatal("wrapped challenge error does not retain protocol.Error for errors.As")
	}
	if got := diagnosticCategory(wrapped); got != "invalid_request" {
		t.Fatalf("diagnosticCategory() = %q, want invalid_request", got)
	}
	if strings.Contains(diagnosticCategory(wrapped), underlying.DevInfo) {
		t.Fatal("diagnostic category contains protocol DevInfo")
	}
}
