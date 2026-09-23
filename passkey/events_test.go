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

// TestFinishRegistrationRejectionEmitsOpaqueDiagnosticWithoutDevInfo replaces
// the old TestPasskeyEventPayloadContainsNoCredentialMaterial, which scanned
// a marshaled event for placeholder strings ("raw-challenge-value",
// "credential-private-key", ...) that no code path ever produces — it could
// never fail. This drives a real registration-finish call end to end, with a
// client payload go-webauthn genuinely rejects, and checks the real leak
// path: the rejection's *protocol.Error.DevInfo — obtained the same way a
// caller would, via errors.As, not a placeholder — must not reach either the
// returned error or the emitted event.
//
// A non-bool credProps.rk extension value makes go-webauthn's JSON decode of
// the client's response fail. The library reports that failure two ways: the
// opaque, fixed "Parse error for Registration" message that becomes this
// call's returned error, and a DevInfo field on the wrapped *protocol.Error
// carrying the real reason (a Go encoding/json type-mismatch message,
// specific enough to be an internal detail worth withholding). Diagnostic's
// doc comment promises event sinks never receive DevInfo; this is the
// scenario named there driven end to end, in the shape the review named:
// this package's diagnostic taxonomy exercised through a real go-webauthn
// rejection, not a hand-built error.
func TestFinishRegistrationRejectionEmitsOpaqueDiagnosticWithoutDevInfo(t *testing.T) {
	sink := &recordingEventSink{}
	f := newForgingFixture(t, WithEventSink(sink))
	ctx := t.Context()

	creation, err := f.service.BeginRegistration(ctx, f.user)
	if err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}
	rk := true
	rq := f.registrationRequest(creation.Response.Challenge.String())
	rq.credPropsRK = &rk
	body := f.auth.forgeRegistration(rq)

	// Corrupt the client's reported credProps.rk from a bool to a string:
	// a malformed-client-payload shape a fuzzer or a broken client
	// produces, and the one that reaches go-webauthn's JSON decoder rather
	// than sulis's own validation.
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("unmarshal forged body: %v", err)
	}
	ext, ok := raw["clientExtensionResults"].(map[string]any)
	if !ok {
		t.Fatalf("forged body has no clientExtensionResults: %s", body)
	}
	credProps, ok := ext["credProps"].(map[string]any)
	if !ok {
		t.Fatalf("forged body has no credProps: %s", body)
	}
	credProps["rk"] = "not-a-bool"
	mutated, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal mutated body: %v", err)
	}

	_, err = f.service.FinishRegistrationResponse(ctx, f.user, mutated)
	if err == nil {
		t.Fatal("FinishRegistrationResponse() error = nil, want a rejection")
	}

	var protocolErr *protocol.Error
	if !errors.As(err, &protocolErr) {
		t.Fatalf("errors.As() did not recover *protocol.Error from %v", err)
	}
	if protocolErr.DevInfo == "" {
		t.Fatal("protocolErr.DevInfo is empty; the assertions below would be vacuous")
	}

	// (a) The returned error is opaque: it does not contain the real
	// reason, even though errors.As can reach it.
	if strings.Contains(err.Error(), protocolErr.DevInfo) {
		t.Fatalf("FinishRegistrationResponse() error = %q is not opaque: it contains DevInfo %q", err.Error(), protocolErr.DevInfo)
	}

	// (b) A failure event was emitted.
	events := sink.snapshot()
	var rejection *Event
	for i := range events {
		if events[i].Kind == EventRegistrationRejected {
			rejection = &events[i]
			break
		}
	}
	if rejection == nil {
		t.Fatalf("events = %+v, want an %s event", events, EventRegistrationRejected)
	}

	// (c) The marshaled event does not contain DevInfo — the real leaked
	// string, not a placeholder nothing produces.
	encoded, err := json.Marshal(rejection)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	payload := string(encoded) + fmt.Sprintf("%#v", *rejection)
	if strings.Contains(payload, protocolErr.DevInfo) {
		t.Fatalf("event payload contains the real DevInfo %q: %s", protocolErr.DevInfo, payload)
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

// TestNilSinkPathAllocatesNothing is the empirical half of the guarantee
// WithEventSink's doc comment makes: with no sink configured, a ceremony
// failure that would otherwise derive Event.Diagnostic from an error costs
// one nil check and nothing else.
//
// It exists because the obvious way to report a diagnosed failure — call
// diagnosticCategory(err) at the call site and drop the result straight into
// an Event{} literal's Diagnostic field — quietly breaks that claim: Go
// evaluates a composite literal's field expressions before the call that
// receives it, so the errors.As walk would run whether or not a sink is
// configured. emitDiag takes err and the diagnostic function separately and
// applies diagFn only after its own nil-sink check; this test is what stops
// that from being undone by a well-meaning refactor back to a Diagnostic
// field computed at the call site.
func TestNilSinkPathAllocatesNothing(t *testing.T) {
	service := newTestServiceWithOptions(t, &fakeStore{}, newFakeChallengeStore())
	if service.cfg.EventSink != nil {
		t.Fatal("this test needs a Service with no sink configured")
	}
	ctx := context.Background()

	underlying := protocol.ErrBadRequest.WithInfo("json: unmarshal clientExtensionResults")
	failureErr := fmt.Errorf("passkey: parsing registration response: %w", underlying)

	allocs := testing.AllocsPerRun(100, func() {
		service.emitDiag(ctx, Event{Kind: EventRegistrationRejected, UserID: "user-123"}, failureErr, diagnosticCategory)
	})
	if allocs != 0 {
		t.Fatalf("emitting to a nil sink allocated %v objects per call, want 0 — diagnosticCategory's errors.As walk is running before the nil-sink check", allocs)
	}
}

// TestNilSinkAllocationTestIsNotVacuous is the control for the test above:
// the identical call, with a sink configured, must actually deliver the
// derived Diagnostic. Without this, TestNilSinkPathAllocatesNothing would
// keep passing if emitDiag stopped deriving Diagnostic at all.
func TestNilSinkAllocationTestIsNotVacuous(t *testing.T) {
	sink := &recordingEventSink{}
	service := newTestServiceWithOptions(t, &fakeStore{}, newFakeChallengeStore(), WithEventSink(sink))
	ctx := context.Background()

	underlying := protocol.ErrBadRequest.WithInfo("json: unmarshal clientExtensionResults")
	failureErr := fmt.Errorf("passkey: parsing registration response: %w", underlying)

	service.emitDiag(ctx, Event{Kind: EventRegistrationRejected, UserID: "user-123"}, failureErr, diagnosticCategory)

	events := sink.snapshot()
	if len(events) != 1 {
		t.Fatalf("events = %+v, want exactly one", events)
	}
	if events[0].Diagnostic != "invalid_request" {
		t.Fatalf("Diagnostic = %q, want %q", events[0].Diagnostic, "invalid_request")
	}
}
