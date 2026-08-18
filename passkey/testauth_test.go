package passkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// This file holds a forging test authenticator: a software authenticator that
// mints complete, structurally valid WebAuthn registration and assertion
// responses with every security-relevant input under the test's control —
// the authenticator-data flags (UP/UV/BE/BS), the RP ID that is hashed into
// the signed authenticator data, the origin baked into the client data JSON,
// the signature counter, the user handle, the credential ID, and the signing
// key itself.
//
// It exists because sulis's ceremony rejection paths cannot be reached any
// other way. Static spec vectors (see registrationSpecVectorNoneES256 in
// passkey_test.go) prove one fixed response verifies, but they cannot be
// mutated: flipping a single flag or byte invalidates the vector's signature,
// so every test built on one would fail for the wrong reason. Forging with a
// key the test holds means a rejection can be attributed to the specific
// check under test — a UV-absent assertion is rejected *because* UV is
// missing, not because the signature no longer matched.
//
// Everything here builds on the stdlib plus the already-pinned go-webauthn
// module (including its own webauthncbor wrapper around fxamacker/cbor);
// nothing new enters the dependency graph.

const (
	// testRPID and testOrigin match newTestService's configuration, so a
	// response forged with these defaults verifies against a Service built
	// by either that helper or newForgingFixture.
	testRPID   = "example.com"
	testOrigin = "https://example.com"
)

// testAuthenticator forges WebAuthn responses for a single credential whose
// P-256 private key it holds. The zero value is not usable; call
// newTestAuthenticator.
type testAuthenticator struct {
	t   *testing.T
	key *ecdsa.PrivateKey

	credentialID []byte
	aaguid       []byte
}

// newTestAuthenticator creates an authenticator with a fresh P-256 key pair
// and a random credential ID. ES256 (COSE alg -7) is used because it is the
// algorithm every WebAuthn authenticator must support and the one
// go-webauthn's CredentialParametersDefault lists first.
func newTestAuthenticator(t *testing.T) *testAuthenticator {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating test authenticator key: %v", err)
	}

	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		t.Fatalf("generating test credential ID: %v", err)
	}

	return &testAuthenticator{
		t:            t,
		key:          key,
		credentialID: credentialID,
		// An all-zero AAGUID is what a privacy-preserving authenticator
		// reports ("model not disclosed"); go-webauthn accepts it and it
		// keeps the fixture free of a made-up vendor identity.
		aaguid: make([]byte, 16),
	}
}

// coseKey returns the authenticator's public key in the COSE_Key CBOR
// encoding that go-webauthn's webauthncose.ParsePublicKey expects: an integer
// keyed map of kty (1) = EC2, alg (3) = ES256, crv (-1) = P-256, and the x
// (-2) and y (-3) coordinates as fixed 32-byte strings. The coordinates come
// from PublicKey.Bytes' uncompressed-point encoding (0x04 ‖ X ‖ Y, each
// already padded to the curve's 32-byte length, which validateEC2PublicKey
// requires) rather than the ecdsa.PublicKey.X/Y fields, deprecated since
// Go 1.26.
func (a *testAuthenticator) coseKey() []byte {
	a.t.Helper()

	point, err := a.key.PublicKey.Bytes()
	if err != nil {
		a.t.Fatalf("encoding public key point: %v", err)
	}
	if len(point) != 65 || point[0] != 0x04 {
		a.t.Fatalf("unexpected uncompressed point encoding: %d bytes, prefix %#x", len(point), point[0])
	}

	key := map[int]any{
		1:  2,            // kty: EC2.
		3:  -7,           // alg: ES256.
		-1: 1,            // crv: P-256.
		-2: point[1:33],  // x coordinate.
		-3: point[33:65], // y coordinate.
	}

	encoded, err := webauthncbor.Marshal(key)
	if err != nil {
		a.t.Fatalf("encoding COSE public key: %v", err)
	}
	return encoded
}

// authenticatorData assembles the signed authenticator data structure:
// SHA-256(rpID) ‖ flags ‖ signCount, optionally followed by attested
// credential data (AAGUID ‖ credential ID length ‖ credential ID ‖ COSE public
// key). rpID is hashed in here rather than sent alongside, which is exactly
// why an RP ID mismatch is detectable at all: the value is covered by the
// signature and cannot be swapped after the fact.
func (a *testAuthenticator) authenticatorData(rpID string, flags protocol.AuthenticatorFlags, signCount uint32, attested bool) []byte {
	a.t.Helper()

	rpIDHash := sha256.Sum256([]byte(rpID))

	data := make([]byte, 0, 37)
	data = append(data, rpIDHash[:]...)
	data = append(data, byte(flags))

	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], signCount)
	data = append(data, counter[:]...)

	if attested {
		var idLen [2]byte
		binary.BigEndian.PutUint16(idLen[:], uint16(len(a.credentialID)))

		data = append(data, a.aaguid...)
		data = append(data, idLen[:]...)
		data = append(data, a.credentialID...)
		data = append(data, a.coseKey()...)
	}

	return data
}

// clientDataJSON builds the client data the browser would hand the
// authenticator. The exact bytes returned here are both sent in the response
// and hashed into the signature, so a test that alters the origin alters what
// was signed — the assertion stays cryptographically valid and is rejected on
// the origin check rather than the signature check.
func (a *testAuthenticator) clientDataJSON(ceremony protocol.CeremonyType, challenge, origin string) []byte {
	a.t.Helper()

	data, err := json.Marshal(map[string]any{
		"type":        string(ceremony),
		"challenge":   challenge,
		"origin":      origin,
		"crossOrigin": false,
	})
	if err != nil {
		a.t.Fatalf("marshaling client data JSON: %v", err)
	}
	return data
}

// registrationRequest describes the registration response to forge. The zero
// value is not useful; start from forgingFixture.registrationRequest.
type registrationRequest struct {
	challenge string
	rpID      string
	origin    string
	flags     protocol.AuthenticatorFlags
	signCount uint32

	// credPropsRK, when non-nil, adds a top-level
	// clientExtensionResults.credProps.rk output — a client-reported value
	// that is not part of the signed attestation object.
	credPropsRK *bool

	// transports, when non-nil, adds the client-reported
	// response.transports list.
	transports []string

	// attestationObject, when non-nil, replaces the forged attestation
	// object entirely (before base64url encoding), for malformed-CBOR tests.
	attestationObject []byte
}

// forgeRegistration returns a complete registration response body: a
// "none"-format attestation object (the format a real passkey uses when the
// relying party asks for no attestation) wrapping the forged authenticator
// data, alongside the client data JSON. FlagAttestedCredentialData is always
// set because a registration response without it is not parseable at all —
// it is a structural requirement, not a security knob a test would vary.
func (a *testAuthenticator) forgeRegistration(req registrationRequest) []byte {
	a.t.Helper()

	attestationObject := req.attestationObject
	if attestationObject == nil {
		authData := a.authenticatorData(req.rpID, req.flags|protocol.FlagAttestedCredentialData, req.signCount, true)

		var err error
		attestationObject, err = webauthncbor.Marshal(map[string]any{
			"fmt":      "none",
			"attStmt":  map[string]any{},
			"authData": authData,
		})
		if err != nil {
			a.t.Fatalf("encoding attestation object: %v", err)
		}
	}

	clientData := a.clientDataJSON(protocol.CreateCeremony, req.challenge, req.origin)

	response := map[string]any{
		"attestationObject": base64.RawURLEncoding.EncodeToString(attestationObject),
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
	}
	if req.transports != nil {
		response["transports"] = req.transports
	}

	id := base64.RawURLEncoding.EncodeToString(a.credentialID)
	body := map[string]any{
		"id":       id,
		"rawId":    id,
		"type":     "public-key",
		"response": response,
	}
	if req.credPropsRK != nil {
		body["clientExtensionResults"] = map[string]any{
			"credProps": map[string]any{"rk": *req.credPropsRK},
		}
	}

	return a.marshalBody(body)
}

// assertionRequest describes the login assertion to forge. The zero value is
// not useful; start from forgingFixture.assertionRequest.
type assertionRequest struct {
	challenge string
	rpID      string
	origin    string
	flags     protocol.AuthenticatorFlags
	signCount uint32

	// userHandle, when non-empty, is returned as response.userHandle. A
	// discoverable ("usernameless") assertion must carry one; an identified
	// assertion normally does not.
	userHandle []byte

	// credentialID overrides the credential ID reported in id/rawId,
	// defaulting to the authenticator's own.
	credentialID []byte

	// signingKey overrides the key the assertion is signed with, defaulting
	// to the authenticator's own. A different key produces a structurally
	// perfect assertion with an invalid signature.
	signingKey *ecdsa.PrivateKey

	// authenticatorData replaces the forged authenticator data entirely, for
	// malformed-input tests. The signature is still computed over whatever
	// is supplied, so the response fails on the malformed data rather than
	// on the signature.
	authenticatorData []byte
}

// forgeAssertion returns a complete login assertion response body, signed
// over authenticatorData ‖ SHA-256(clientDataJSON) exactly as §7.2 of the
// WebAuthn specification requires. The ECDSA signature is DER (ASN.1)
// encoded, which is what go-webauthn's EC2PublicKeyData.Verify parses.
func (a *testAuthenticator) forgeAssertion(req assertionRequest) []byte {
	a.t.Helper()

	authData := req.authenticatorData
	if authData == nil {
		authData = a.authenticatorData(req.rpID, req.flags, req.signCount, false)
	}

	clientData := a.clientDataJSON(protocol.AssertCeremony, req.challenge, req.origin)
	clientDataHash := sha256.Sum256(clientData)

	signed := make([]byte, 0, len(authData)+len(clientDataHash))
	signed = append(signed, authData...)
	signed = append(signed, clientDataHash[:]...)
	digest := sha256.Sum256(signed)

	key := req.signingKey
	if key == nil {
		key = a.key
	}
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		a.t.Fatalf("signing assertion: %v", err)
	}

	response := map[string]any{
		"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
		"signature":         base64.RawURLEncoding.EncodeToString(signature),
	}
	if len(req.userHandle) > 0 {
		response["userHandle"] = base64.RawURLEncoding.EncodeToString(req.userHandle)
	}

	credentialID := req.credentialID
	if credentialID == nil {
		credentialID = a.credentialID
	}
	id := base64.RawURLEncoding.EncodeToString(credentialID)

	return a.marshalBody(map[string]any{
		"id":       id,
		"rawId":    id,
		"type":     "public-key",
		"response": response,
	})
}

func (a *testAuthenticator) marshalBody(body map[string]any) []byte {
	a.t.Helper()

	encoded, err := json.Marshal(body)
	if err != nil {
		a.t.Fatalf("marshaling ceremony response body: %v", err)
	}
	return encoded
}

// storedCredential returns the Credential a store would hold for this
// authenticator after a registration that reported the given flags and sign
// count. BackupEligible/BackupState are derived from the flags because
// go-webauthn re-checks them against every later assertion (see
// toWebAuthnCreds).
func (a *testAuthenticator) storedCredential(userID string, flags protocol.AuthenticatorFlags, signCount uint32) Credential {
	return Credential{
		ID:              "cred-" + userID,
		UserID:          userID,
		CredentialID:    a.credentialID,
		PublicKey:       a.coseKey(),
		AttestationType: "none",
		AAGUID:          a.aaguid,
		SignCount:       signCount,
		BackupEligible:  flags.HasBackupEligible(),
		BackupState:     flags.HasBackupState(),
	}
}

// forgingFixture bundles a Service, its two fake stores, and a
// testAuthenticator configured to satisfy that Service's RP ID and origin.
type forgingFixture struct {
	t          *testing.T
	auth       *testAuthenticator
	store      *fakeStore
	challenges *fakeChallengeStore
	service    *Service
	user       *User
}

func newForgingFixture(t *testing.T, opts ...Option) *forgingFixture {
	t.Helper()

	return newForgingFixtureForRP(t, testRPID, testOrigin, opts...)
}

// newForgingFixtureForRP builds a fixture whose Service is configured for a
// specific RP ID and origin. Tests use it to prove a rejection came from the
// check they are exercising: the same forged response is replayed against a
// Service the response *does* match, and must then be accepted. The RP ID and
// the origin are independent inputs to verification (one is hashed into the
// signed authenticator data, the other is read from the client data JSON), so
// they can be varied one at a time.
func newForgingFixtureForRP(t *testing.T, rpID, origin string, opts ...Option) *forgingFixture {
	t.Helper()

	store := &fakeStore{}
	challenges := newFakeChallengeStore()
	service, err := NewService(store, challenges, WebAuthnConfig{
		RPDisplayName: "Sulis Test",
		RPID:          rpID,
		RPOrigins:     []string{origin},
	}, opts...)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	return &forgingFixture{
		t:          t,
		auth:       newTestAuthenticator(t),
		store:      store,
		challenges: challenges,
		service:    service,
		user:       &User{ID: []byte("user-1"), Name: "alice", DisplayName: "Alice"},
	}
}

// seedCredential puts the authenticator's credential in the store as though a
// registration ceremony had already saved it.
func (f *forgingFixture) seedCredential(flags protocol.AuthenticatorFlags, signCount uint32) Credential {
	f.t.Helper()

	cred := f.auth.storedCredential(string(f.user.ID), flags, signCount)
	f.store.seed(cred)
	return cred
}

// registrationRequest returns a registration request that verifies against
// this fixture's Service: correct RP ID and origin, and both the User Present
// and User Verified flags set.
func (f *forgingFixture) registrationRequest(challenge string) registrationRequest {
	return registrationRequest{
		challenge: challenge,
		rpID:      testRPID,
		origin:    testOrigin,
		flags:     protocol.FlagUserPresent | protocol.FlagUserVerified,
	}
}

// assertionRequest returns an assertion request that verifies against this
// fixture's Service, for a credential seeded with no backup flags.
func (f *forgingFixture) assertionRequest(challenge string) assertionRequest {
	return assertionRequest{
		challenge: challenge,
		rpID:      testRPID,
		origin:    testOrigin,
		flags:     protocol.FlagUserPresent | protocol.FlagUserVerified,
		signCount: 1,
	}
}

func (f *forgingFixture) beginLogin() (challenge, ceremonyID string) {
	f.t.Helper()

	assertion, ceremonyID, err := f.service.BeginLogin(f.t.Context(), f.user)
	if err != nil {
		f.t.Fatalf("BeginLogin() error = %v", err)
	}
	return assertion.Response.Challenge.String(), ceremonyID
}

func (f *forgingFixture) beginDiscoverableLogin() (challenge, ceremonyID string) {
	f.t.Helper()

	assertion, ceremonyID, err := f.service.BeginDiscoverableLogin(f.t.Context())
	if err != nil {
		f.t.Fatalf("BeginDiscoverableLogin() error = %v", err)
	}
	return assertion.Response.Challenge.String(), ceremonyID
}

// TestForgedAuthenticatorCompletesRegistrationAndLogin is the test that makes
// every other test in this file meaningful: it proves the forging
// authenticator produces responses go-webauthn genuinely accepts, through
// both ceremonies, with no fixture seeding at all. Registration runs against
// the challenge BeginRegistration actually generated (as a browser would),
// the resulting credential is persisted by the store, and a freshly forged
// assertion then logs in with it.
//
// Without this, a rejection-path test proves nothing: every assertion would
// be rejected whether or not the check under test exists.
func TestForgedAuthenticatorCompletesRegistrationAndLogin(t *testing.T) {
	t.Parallel()

	f := newForgingFixture(t)
	ctx := t.Context()

	creation, err := f.service.BeginRegistration(ctx, f.user)
	if err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}

	rk := true
	req := f.registrationRequest(creation.Response.Challenge.String())
	req.credPropsRK = &rk
	req.transports = []string{"internal"}

	registered, err := f.service.FinishRegistrationResponse(ctx, f.user, f.auth.forgeRegistration(req))
	if err != nil {
		t.Fatalf("FinishRegistrationResponse() error = %v", err)
	}
	if string(registered.CredentialID) != string(f.auth.credentialID) {
		t.Fatalf("CredentialID = %x, want %x", registered.CredentialID, f.auth.credentialID)
	}
	if !registered.Discoverable {
		t.Error("Discoverable = false, want true (credProps.rk was reported as true)")
	}
	if f.store.saveCredentialCalls != 1 {
		t.Fatalf("SaveCredential() calls = %d, want 1", f.store.saveCredentialCalls)
	}

	challenge, ceremonyID := f.beginLogin()
	loggedIn, err := f.service.FinishLoginResponse(ctx, f.user, ceremonyID, f.auth.forgeAssertion(f.assertionRequest(challenge)))
	if err != nil {
		t.Fatalf("FinishLoginResponse() error = %v", err)
	}
	if loggedIn.SignCount != 1 {
		t.Errorf("SignCount = %d, want 1 (the assertion's counter must be persisted)", loggedIn.SignCount)
	}
	if loggedIn.LastUsedAt == nil {
		t.Error("LastUsedAt = nil, want the login timestamp")
	}
}

// errAuthDataVerification is the message go-webauthn's authenticator-data
// verification returns for ALL THREE of its checks — RP ID hash mismatch,
// missing User Present, missing User Verified. The distinguishing text lives
// in the error's DevInfo field, which sulis does not surface: both
// FinishLoginResponse and FinishRegistrationResponse wrap the library error
// with %v, not %w, so the *protocol.Error (and its DevInfo) is not recoverable
// from the chain either.
//
// Tests for those three checks therefore cannot tell them apart by message.
// They pair the rejection with a control instead: the identical forged bytes
// are replayed against a Service that should accept them, so a rejection is
// attributable to the one input that differs. Asserting this message on top
// still narrows the failure to the authenticator-data step, since the client
// data checks (challenge, origin, ceremony type) and the signature check
// each have their own distinct message.
const errAuthDataVerification = "Error validating the authenticator response"

// TestFinishLoginRejectsAssertionWithoutUserVerification discharges the
// end-to-end debt T105 left behind. T105 could only prove that
// VerificationRequired is requested in the client options and recorded in the
// saved session data — go-webauthn's enforcement is driven entirely by
// session.UserVerification, so that was the library behaviour sulis controls,
// but it stops short of proving an assertion that skips user verification is
// actually turned away.
//
// The sub-tests are each other's mutation test. The same authenticator forges
// the same UV-absent assertion twice; the only difference is the Service's
// configured user-verification requirement. Under the default
// (VerificationRequired) it must be rejected; under
// VerificationDiscouraged — the documented second-factor escape hatch — the
// very same bytes must be accepted. So the rejection is attributable to the
// UV policy and nothing else, and the test cannot pass vacuously.
func TestFinishLoginRejectsAssertionWithoutUserVerification(t *testing.T) {
	t.Parallel()

	// User Present but NOT User Verified: someone tapped the key, but no PIN
	// or biometric was collected. This is the bare-possession case that
	// reduces a passwordless passkey to a single factor.
	const presenceOnly = protocol.FlagUserPresent

	t.Run("required rejects it", func(t *testing.T) {
		t.Parallel()

		f := newForgingFixture(t)
		f.seedCredential(0, 0)

		challenge, ceremonyID := f.beginLogin()
		req := f.assertionRequest(challenge)
		req.flags = presenceOnly

		cred, err := f.service.FinishLoginResponse(t.Context(), f.user, ceremonyID, f.auth.forgeAssertion(req))
		if !errors.Is(err, ErrChallengeFailed) {
			t.Fatalf("FinishLoginResponse() error = %v, want errors.Is(err, ErrChallengeFailed)", err)
		}
		if cred != nil {
			t.Fatalf("FinishLoginResponse() credential = %#v, want nil", cred)
		}
		if !strings.Contains(err.Error(), errAuthDataVerification) {
			t.Errorf("FinishLoginResponse() error = %q, want it to name the authenticator-data verification step", err)
		}
		if f.store.updateAfterLoginCalls != 0 {
			t.Errorf("UpdateCredentialAfterLogin() calls = %d, want 0 — a rejected assertion must not advance the credential's bookkeeping", f.store.updateAfterLoginCalls)
		}
	})

	t.Run("discouraged accepts it", func(t *testing.T) {
		t.Parallel()

		f := newForgingFixture(t, WithUserVerification(protocol.VerificationDiscouraged))
		f.seedCredential(0, 0)

		challenge, ceremonyID := f.beginLogin()
		req := f.assertionRequest(challenge)
		req.flags = presenceOnly

		if _, err := f.service.FinishLoginResponse(t.Context(), f.user, ceremonyID, f.auth.forgeAssertion(req)); err != nil {
			t.Fatalf("FinishLoginResponse() error = %v, want nil — the identical assertion must pass when user verification is not required, or the rejection above proves nothing about the UV policy", err)
		}
	})
}

// TestFinishDiscoverableLoginRejectsAssertionWithoutUserVerification is the
// usernameless counterpart: BeginDiscoverableLogin carries the same
// user-verification requirement into its session data, and must enforce it
// just as the identified ceremony does. Paired with its own control for the
// reason given on errAuthDataVerification.
func TestFinishDiscoverableLoginRejectsAssertionWithoutUserVerification(t *testing.T) {
	t.Parallel()

	const presenceOnly = protocol.FlagUserPresent

	t.Run("required rejects it", func(t *testing.T) {
		t.Parallel()

		f := newForgingFixture(t)
		f.seedCredential(0, 0)

		challenge, ceremonyID := f.beginDiscoverableLogin()
		req := f.assertionRequest(challenge)
		req.flags = presenceOnly
		req.userHandle = f.user.ID

		_, err := f.service.FinishDiscoverableLoginResponse(t.Context(), ceremonyID, f.auth.forgeAssertion(req))
		if !errors.Is(err, ErrChallengeFailed) {
			t.Fatalf("FinishDiscoverableLoginResponse() error = %v, want errors.Is(err, ErrChallengeFailed)", err)
		}
		if !strings.Contains(err.Error(), errAuthDataVerification) {
			t.Errorf("FinishDiscoverableLoginResponse() error = %q, want it to name the authenticator-data verification step", err)
		}
	})

	t.Run("discouraged accepts it", func(t *testing.T) {
		t.Parallel()

		f := newForgingFixture(t, WithUserVerification(protocol.VerificationDiscouraged))
		f.seedCredential(0, 0)

		challenge, ceremonyID := f.beginDiscoverableLogin()
		req := f.assertionRequest(challenge)
		req.flags = presenceOnly
		req.userHandle = f.user.ID

		if _, err := f.service.FinishDiscoverableLoginResponse(t.Context(), ceremonyID, f.auth.forgeAssertion(req)); err != nil {
			t.Fatalf("FinishDiscoverableLoginResponse() error = %v, want nil — the identical assertion must pass when user verification is not required", err)
		}
	})
}

// TestFinishLoginRejectsAssertionWithoutUserPresence covers the weaker
// sibling of the UV check: go-webauthn always requires the User Present bit
// on a login assertion, so an assertion claiming verification without even
// presence must be refused too. Unlike user verification there is no
// configuration that relaxes it, so the control is the same assertion with
// the presence bit restored.
func TestFinishLoginRejectsAssertionWithoutUserPresence(t *testing.T) {
	t.Parallel()

	t.Run("presence bit clear is rejected", func(t *testing.T) {
		t.Parallel()

		f := newForgingFixture(t)
		f.seedCredential(0, 0)

		challenge, ceremonyID := f.beginLogin()
		req := f.assertionRequest(challenge)
		req.flags = protocol.FlagUserVerified

		_, err := f.service.FinishLoginResponse(t.Context(), f.user, ceremonyID, f.auth.forgeAssertion(req))
		if !errors.Is(err, ErrChallengeFailed) {
			t.Fatalf("FinishLoginResponse() error = %v, want errors.Is(err, ErrChallengeFailed)", err)
		}
		if !strings.Contains(err.Error(), errAuthDataVerification) {
			t.Errorf("FinishLoginResponse() error = %q, want it to name the authenticator-data verification step", err)
		}
	})

	t.Run("presence bit set is accepted", func(t *testing.T) {
		t.Parallel()

		f := newForgingFixture(t)
		f.seedCredential(0, 0)

		challenge, ceremonyID := f.beginLogin()
		req := f.assertionRequest(challenge)
		req.flags = protocol.FlagUserVerified | protocol.FlagUserPresent

		if _, err := f.service.FinishLoginResponse(t.Context(), f.user, ceremonyID, f.auth.forgeAssertion(req)); err != nil {
			t.Fatalf("FinishLoginResponse() error = %v, want nil — only the presence bit differs from the rejected case", err)
		}
	})
}

// TestFinishLoginRejectsClonedAuthenticatorEndToEnd exercises the clone
// warning through a real signed assertion rather than by handing
// finishLoginCredential a pre-built webauthn.Credential. A signature counter
// that fails to advance is the only evidence a relying party gets that a
// credential's private key may have been extracted and copied, so it has to
// survive the whole verification path, not just the last function in it.
//
// The two sub-tests are each other's mutation test: the same credential and
// the same forging authenticator, differing only in whether the assertion's
// counter moves forward.
func TestFinishLoginRejectsClonedAuthenticatorEndToEnd(t *testing.T) {
	t.Parallel()

	const storedSignCount = 10

	t.Run("stale counter is rejected", func(t *testing.T) {
		t.Parallel()

		f := newForgingFixture(t)
		f.seedCredential(0, storedSignCount)

		challenge, ceremonyID := f.beginLogin()
		req := f.assertionRequest(challenge)
		req.signCount = storedSignCount - 5

		cred, err := f.service.FinishLoginResponse(t.Context(), f.user, ceremonyID, f.auth.forgeAssertion(req))
		if !errors.Is(err, ErrCloneWarning) {
			t.Fatalf("FinishLoginResponse() error = %v, want %v", err, ErrCloneWarning)
		}
		if cred != nil {
			t.Fatalf("FinishLoginResponse() credential = %#v, want nil", cred)
		}
		if f.store.updateAfterLoginCalls != 0 {
			t.Errorf("UpdateCredentialAfterLogin() calls = %d, want 0 — a suspected clone must not have its sign count persisted", f.store.updateAfterLoginCalls)
		}
	})

	t.Run("advancing counter is accepted", func(t *testing.T) {
		t.Parallel()

		f := newForgingFixture(t)
		f.seedCredential(0, storedSignCount)

		challenge, ceremonyID := f.beginLogin()
		req := f.assertionRequest(challenge)
		req.signCount = storedSignCount + 1

		cred, err := f.service.FinishLoginResponse(t.Context(), f.user, ceremonyID, f.auth.forgeAssertion(req))
		if err != nil {
			t.Fatalf("FinishLoginResponse() error = %v, want nil", err)
		}
		if cred.SignCount != storedSignCount+1 {
			t.Errorf("SignCount = %d, want %d", cred.SignCount, storedSignCount+1)
		}
	})
}

// TestFinishLoginRejectsOriginMismatch covers the phishing defence: the
// origin the browser reports in the client data JSON is the value that makes
// a passkey unphishable, since a look-alike site cannot make the browser lie
// about which origin it is serving.
func TestFinishLoginRejectsOriginMismatch(t *testing.T) {
	t.Parallel()

	f := newForgingFixture(t)
	f.seedCredential(0, 0)

	challenge, ceremonyID := f.beginLogin()
	req := f.assertionRequest(challenge)
	req.origin = "https://evil.example.net"

	cred, err := f.service.FinishLoginResponse(t.Context(), f.user, ceremonyID, f.auth.forgeAssertion(req))
	if !errors.Is(err, ErrChallengeFailed) {
		t.Fatalf("FinishLoginResponse() error = %v, want errors.Is(err, ErrChallengeFailed)", err)
	}
	if cred != nil {
		t.Fatalf("FinishLoginResponse() credential = %#v, want nil", cred)
	}
	if !strings.Contains(err.Error(), "Error validating origin") {
		t.Errorf("FinishLoginResponse() error = %q, want it to name the origin check — the assertion is otherwise perfectly signed, so any other rejection reason would be a bug in the test", err)
	}
	if f.store.updateAfterLoginCalls != 0 {
		t.Errorf("UpdateCredentialAfterLogin() calls = %d, want 0", f.store.updateAfterLoginCalls)
	}
}

// TestFinishLoginRejectsRPIDMismatch covers the other half of the binding: the
// RP ID is hashed into the *signed* authenticator data, so an assertion
// harvested for a different relying party cannot be replayed here even with a
// valid signature over it.
//
// The control sub-test configures a Service whose RP ID is the one the
// assertion was forged for, keeping the origin unchanged — the two are
// separate inputs to verification — so the same authenticator data that was
// rejected above is accepted, and the rejection is attributable to the RP ID
// hash and nothing else.
func TestFinishLoginRejectsRPIDMismatch(t *testing.T) {
	t.Parallel()

	const otherRPID = "evil.example.net"

	t.Run("mismatched rp id is rejected", func(t *testing.T) {
		t.Parallel()

		f := newForgingFixture(t)
		f.seedCredential(0, 0)

		challenge, ceremonyID := f.beginLogin()
		req := f.assertionRequest(challenge)
		req.rpID = otherRPID

		cred, err := f.service.FinishLoginResponse(t.Context(), f.user, ceremonyID, f.auth.forgeAssertion(req))
		if !errors.Is(err, ErrChallengeFailed) {
			t.Fatalf("FinishLoginResponse() error = %v, want errors.Is(err, ErrChallengeFailed)", err)
		}
		if cred != nil {
			t.Fatalf("FinishLoginResponse() credential = %#v, want nil", cred)
		}
		if !strings.Contains(err.Error(), errAuthDataVerification) {
			t.Errorf("FinishLoginResponse() error = %q, want it to name the authenticator-data verification step", err)
		}
	})

	t.Run("matching rp id is accepted", func(t *testing.T) {
		t.Parallel()

		f := newForgingFixtureForRP(t, otherRPID, testOrigin)
		f.seedCredential(0, 0)

		challenge, ceremonyID := f.beginLogin()
		req := f.assertionRequest(challenge)
		req.rpID = otherRPID

		if _, err := f.service.FinishLoginResponse(t.Context(), f.user, ceremonyID, f.auth.forgeAssertion(req)); err != nil {
			t.Fatalf("FinishLoginResponse() error = %v, want nil — the same authenticator data must verify for the relying party whose RP ID it was signed over", err)
		}
	})
}

// TestFinishLoginRejectsChallengeMismatch covers replay: an assertion signed
// over a challenge this ceremony never issued must be refused even though it
// is otherwise valid for this credential, RP ID, and origin.
func TestFinishLoginRejectsChallengeMismatch(t *testing.T) {
	t.Parallel()

	f := newForgingFixture(t)
	f.seedCredential(0, 0)

	_, ceremonyID := f.beginLogin()
	req := f.assertionRequest(base64.RawURLEncoding.EncodeToString([]byte("a-challenge-from-elsewhere")))

	_, err := f.service.FinishLoginResponse(t.Context(), f.user, ceremonyID, f.auth.forgeAssertion(req))
	if !errors.Is(err, ErrChallengeFailed) {
		t.Fatalf("FinishLoginResponse() error = %v, want errors.Is(err, ErrChallengeFailed)", err)
	}
	if !strings.Contains(err.Error(), "Error validating challenge") {
		t.Errorf("FinishLoginResponse() error = %q, want it to name the challenge check", err)
	}
}

// TestFinishLoginRejectsAssertionSignedByAnotherKey is the test that proves
// the signature is actually verified — and therefore that every accepting
// test in this file is accepting because of real cryptography, not because
// go-webauthn waves signatures through. The response is structurally
// flawless: right credential ID, right challenge, right origin, right RP ID,
// right flags. Only the private key is wrong.
func TestFinishLoginRejectsAssertionSignedByAnotherKey(t *testing.T) {
	t.Parallel()

	f := newForgingFixture(t)
	f.seedCredential(0, 0)

	attacker := newTestAuthenticator(t)

	challenge, ceremonyID := f.beginLogin()
	req := f.assertionRequest(challenge)
	req.signingKey = attacker.key

	cred, err := f.service.FinishLoginResponse(t.Context(), f.user, ceremonyID, f.auth.forgeAssertion(req))
	if !errors.Is(err, ErrChallengeFailed) {
		t.Fatalf("FinishLoginResponse() error = %v, want errors.Is(err, ErrChallengeFailed)", err)
	}
	if cred != nil {
		t.Fatalf("FinishLoginResponse() credential = %#v, want nil", cred)
	}
	if !strings.Contains(err.Error(), "Error validating the assertion signature") {
		t.Errorf("FinishLoginResponse() error = %q, want it to name the signature check", err)
	}
}

// TestFinishLoginRejectsUnknownCredentialID covers an assertion for a
// credential the asserted user does not own: BeginLogin pins the ceremony to
// the user's own credential IDs, so a different one must not be substituted.
func TestFinishLoginRejectsUnknownCredentialID(t *testing.T) {
	t.Parallel()

	f := newForgingFixture(t)
	f.seedCredential(0, 0)

	challenge, ceremonyID := f.beginLogin()
	req := f.assertionRequest(challenge)
	req.credentialID = []byte("some-other-credential-id")

	_, err := f.service.FinishLoginResponse(t.Context(), f.user, ceremonyID, f.auth.forgeAssertion(req))
	if !errors.Is(err, ErrChallengeFailed) {
		t.Fatalf("FinishLoginResponse() error = %v, want errors.Is(err, ErrChallengeFailed)", err)
	}
	if !strings.Contains(err.Error(), "not owned by the user") {
		t.Errorf("FinishLoginResponse() error = %q, want it to name the credential-ownership check", err)
	}
}

// TestFinishLoginRejectsMalformedAuthenticatorData covers a response whose
// authenticator data is too short to parse at all — the parse failure must
// surface as ErrChallengeFailed rather than a panic or a bare library error.
func TestFinishLoginRejectsMalformedAuthenticatorData(t *testing.T) {
	t.Parallel()

	f := newForgingFixture(t)
	f.seedCredential(0, 0)

	challenge, ceremonyID := f.beginLogin()
	req := f.assertionRequest(challenge)
	req.authenticatorData = []byte("far too short to be authenticator data")

	_, err := f.service.FinishLoginResponse(t.Context(), f.user, ceremonyID, f.auth.forgeAssertion(req))
	if !errors.Is(err, ErrChallengeFailed) {
		t.Fatalf("FinishLoginResponse() error = %v, want errors.Is(err, ErrChallengeFailed)", err)
	}
}

// TestLoginSucceedsForBackupEligibleCredential is the signed-assertion
// regression test T205 left owing. toWebAuthnCreds feeds every ceremony's
// credential list into go-webauthn, and go-webauthn's validateLogin compares
// the stored credential's BackupEligible bit against the bit in the fresh,
// signed authenticator data — rejecting the login outright on a mismatch.
// T205 could only cover that at the unit level (that toWebAuthnCreds copies
// the fields); this covers the path that actually enforces it.
//
// The sub-tests are each other's mutation test. Both forge an assertion whose
// signed BE/BS bits are set; they differ only in whether the *stored*
// credential agrees. If toWebAuthnCreds ever drops the flags again, the
// stored credential looks backup-ineligible to go-webauthn and the first
// sub-test fails exactly the way a real backup-eligible passkey would fail on
// its second login.
func TestLoginSucceedsForBackupEligibleCredential(t *testing.T) {
	t.Parallel()

	const backedUp = protocol.FlagBackupEligible | protocol.FlagBackupState

	t.Run("stored flags match the assertion", func(t *testing.T) {
		t.Parallel()

		f := newForgingFixture(t)
		seeded := f.seedCredential(backedUp, 0)
		if !seeded.BackupEligible || !seeded.BackupState {
			t.Fatalf("seeded credential = %+v, want BackupEligible and BackupState set", seeded)
		}

		challenge, ceremonyID := f.beginLogin()
		req := f.assertionRequest(challenge)
		req.flags |= backedUp

		cred, err := f.service.FinishLoginResponse(t.Context(), f.user, ceremonyID, f.auth.forgeAssertion(req))
		if err != nil {
			t.Fatalf("FinishLoginResponse() error = %v, want nil — a backup-eligible credential must be able to log in, which requires its stored BackupEligible bit to reach go-webauthn through toWebAuthnCreds", err)
		}
		if !cred.BackupState {
			t.Error("BackupState = false, want true (re-derived from the signed assertion)")
		}
	})

	t.Run("stored flags contradict the assertion", func(t *testing.T) {
		t.Parallel()

		f := newForgingFixture(t)
		f.seedCredential(0, 0) // stored as NOT backup eligible

		challenge, ceremonyID := f.beginLogin()
		req := f.assertionRequest(challenge)
		req.flags |= backedUp

		_, err := f.service.FinishLoginResponse(t.Context(), f.user, ceremonyID, f.auth.forgeAssertion(req))
		if !errors.Is(err, ErrChallengeFailed) {
			t.Fatalf("FinishLoginResponse() error = %v, want errors.Is(err, ErrChallengeFailed)", err)
		}
		if !strings.Contains(err.Error(), "Backup Eligible flag inconsistency") {
			t.Errorf("FinishLoginResponse() error = %q, want it to name the backup-eligibility consistency check — this is the failure a dropped flag would produce, so the test above must be failing for this exact reason if it ever regresses", err)
		}
	})
}

// TestFinishLoginTracksBackupStateChanges covers the other backup bit:
// BackupState can legitimately flip over a credential's lifetime (a synced
// passkey moving in or out of a device keychain backup), so a change must be
// persisted rather than rejected the way a BackupEligible change is.
func TestFinishLoginTracksBackupStateChanges(t *testing.T) {
	t.Parallel()

	f := newForgingFixture(t)
	f.seedCredential(protocol.FlagBackupEligible|protocol.FlagBackupState, 0)

	challenge, ceremonyID := f.beginLogin()
	req := f.assertionRequest(challenge)
	req.flags |= protocol.FlagBackupEligible // eligible, but no longer backed up

	cred, err := f.service.FinishLoginResponse(t.Context(), f.user, ceremonyID, f.auth.forgeAssertion(req))
	if err != nil {
		t.Fatalf("FinishLoginResponse() error = %v, want nil", err)
	}
	if cred.BackupState {
		t.Error("BackupState = true, want false — the assertion reported the credential is no longer backed up")
	}
	if !cred.BackupEligible {
		t.Error("BackupEligible = false, want it left true — eligibility is a fixed property, unlike backup state")
	}
}

// TestFinishDiscoverableLoginSucceeds covers the usernameless happy path: the
// caller supplies no identity, and the user is resolved from the credential's
// stored owner via the handler.
func TestFinishDiscoverableLoginSucceeds(t *testing.T) {
	t.Parallel()

	f := newForgingFixture(t)
	f.seedCredential(0, 0)

	challenge, ceremonyID := f.beginDiscoverableLogin()
	req := f.assertionRequest(challenge)
	req.userHandle = f.user.ID

	cred, err := f.service.FinishDiscoverableLoginResponse(t.Context(), ceremonyID, f.auth.forgeAssertion(req))
	if err != nil {
		t.Fatalf("FinishDiscoverableLoginResponse() error = %v, want nil", err)
	}
	if cred.UserID != string(f.user.ID) {
		t.Errorf("UserID = %q, want %q", cred.UserID, f.user.ID)
	}
	if cred.LastUsedAt == nil {
		t.Error("LastUsedAt = nil, want the login timestamp")
	}
}

// TestFinishDiscoverableLoginRejectsCredentialOwnedByAnotherUser covers the
// ownership check inside the discoverable handler. The user handle in a
// discoverable assertion is supplied by the authenticator, not by the relying
// party, so it must be reconciled against the credential's stored owner: an
// authenticator (or an attacker replaying a captured assertion) that presents
// one user's credential alongside another user's handle must not be able to
// log in as either.
func TestFinishDiscoverableLoginRejectsCredentialOwnedByAnotherUser(t *testing.T) {
	t.Parallel()

	f := newForgingFixture(t)
	f.seedCredential(0, 0)

	challenge, ceremonyID := f.beginDiscoverableLogin()
	req := f.assertionRequest(challenge)
	req.userHandle = []byte("user-2") // the credential belongs to user-1

	cred, err := f.service.FinishDiscoverableLoginResponse(t.Context(), ceremonyID, f.auth.forgeAssertion(req))
	if !errors.Is(err, ErrChallengeFailed) {
		t.Fatalf("FinishDiscoverableLoginResponse() error = %v, want errors.Is(err, ErrChallengeFailed)", err)
	}
	if cred != nil {
		t.Fatalf("FinishDiscoverableLoginResponse() credential = %#v, want nil", cred)
	}
	if !strings.Contains(err.Error(), ErrChallengeFailed.Error()) {
		t.Errorf("FinishDiscoverableLoginResponse() error = %q, want the handler's own rejection to survive into the message", err)
	}
	if f.store.updateAfterLoginCalls != 0 {
		t.Errorf("UpdateCredentialAfterLogin() calls = %d, want 0", f.store.updateAfterLoginCalls)
	}
}

// TestFinishDiscoverableLoginRejectsUnknownCredential covers the handler's
// other failure mode: an assertion for a credential the store has never seen.
func TestFinishDiscoverableLoginRejectsUnknownCredential(t *testing.T) {
	t.Parallel()

	f := newForgingFixture(t)
	// Deliberately no seeded credential.

	challenge, ceremonyID := f.beginDiscoverableLogin()
	req := f.assertionRequest(challenge)
	req.userHandle = f.user.ID

	_, err := f.service.FinishDiscoverableLoginResponse(t.Context(), ceremonyID, f.auth.forgeAssertion(req))
	if !errors.Is(err, ErrChallengeFailed) {
		t.Fatalf("FinishDiscoverableLoginResponse() error = %v, want errors.Is(err, ErrChallengeFailed)", err)
	}
	if !strings.Contains(err.Error(), ErrPasskeyNotFound.Error()) {
		t.Errorf("FinishDiscoverableLoginResponse() error = %q, want the handler's not-found reason to survive into the message", err)
	}
}

// TestFinishLoginRejectsReplayOfAConsumedChallenge is the end-to-end
// single-use proof for the login ceremony. T201's concurrency test shows two
// racing finishes cannot both retrieve the challenge; this shows the
// sequential case with a genuinely valid assertion: the first call succeeds,
// and replaying the exact same bytes against the same ceremony ID is refused
// because the challenge is gone, not because the response is bad.
func TestFinishLoginRejectsReplayOfAConsumedChallenge(t *testing.T) {
	t.Parallel()

	f := newForgingFixture(t)
	f.seedCredential(0, 0)
	ctx := t.Context()

	challenge, ceremonyID := f.beginLogin()
	body := f.auth.forgeAssertion(f.assertionRequest(challenge))

	if _, err := f.service.FinishLoginResponse(ctx, f.user, ceremonyID, body); err != nil {
		t.Fatalf("first FinishLoginResponse() error = %v, want nil", err)
	}

	cred, err := f.service.FinishLoginResponse(ctx, f.user, ceremonyID, body)
	if !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("replayed FinishLoginResponse() error = %v, want %v", err, ErrChallengeExpired)
	}
	if cred != nil {
		t.Fatalf("replayed FinishLoginResponse() credential = %#v, want nil", cred)
	}
}

// TestFinishDiscoverableLoginRejectsReplayOfAConsumedChallenge is the
// usernameless counterpart of the replay test above.
func TestFinishDiscoverableLoginRejectsReplayOfAConsumedChallenge(t *testing.T) {
	t.Parallel()

	f := newForgingFixture(t)
	f.seedCredential(0, 0)
	ctx := t.Context()

	challenge, ceremonyID := f.beginDiscoverableLogin()
	req := f.assertionRequest(challenge)
	req.userHandle = f.user.ID
	body := f.auth.forgeAssertion(req)

	if _, err := f.service.FinishDiscoverableLoginResponse(ctx, ceremonyID, body); err != nil {
		t.Fatalf("first FinishDiscoverableLoginResponse() error = %v, want nil", err)
	}

	if _, err := f.service.FinishDiscoverableLoginResponse(ctx, ceremonyID, body); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("replayed FinishDiscoverableLoginResponse() error = %v, want %v", err, ErrChallengeExpired)
	}
}

// TestFinishRegistrationRejectsReplayOfAConsumedChallenge is the registration
// ceremony's replay test. Registration challenges are keyed per user rather
// than per ceremony, so a burned challenge is the only thing stopping the
// same attestation being submitted twice.
func TestFinishRegistrationRejectsReplayOfAConsumedChallenge(t *testing.T) {
	t.Parallel()

	f := newForgingFixture(t)
	ctx := t.Context()

	creation, err := f.service.BeginRegistration(ctx, f.user)
	if err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}
	body := f.auth.forgeRegistration(f.registrationRequest(creation.Response.Challenge.String()))

	if _, err := f.service.FinishRegistrationResponse(ctx, f.user, body); err != nil {
		t.Fatalf("first FinishRegistrationResponse() error = %v, want nil", err)
	}

	if _, err := f.service.FinishRegistrationResponse(ctx, f.user, body); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("replayed FinishRegistrationResponse() error = %v, want %v", err, ErrChallengeExpired)
	}
}

// TestFinishRegistrationRejectsOriginMismatch covers the registration
// ceremony's origin binding: a credential must not be enrollable from a site
// the relying party does not recognise.
func TestFinishRegistrationRejectsOriginMismatch(t *testing.T) {
	t.Parallel()

	f := newForgingFixture(t)
	ctx := t.Context()

	creation, err := f.service.BeginRegistration(ctx, f.user)
	if err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}

	req := f.registrationRequest(creation.Response.Challenge.String())
	req.origin = "https://evil.example.net"

	cred, err := f.service.FinishRegistrationResponse(ctx, f.user, f.auth.forgeRegistration(req))
	if err == nil {
		t.Fatal("FinishRegistrationResponse() error = nil, want a rejection")
	}
	if cred != nil {
		t.Fatalf("FinishRegistrationResponse() credential = %#v, want nil", cred)
	}
	if !strings.Contains(err.Error(), "Error validating origin") {
		t.Errorf("FinishRegistrationResponse() error = %q, want it to name the origin check", err)
	}
	if f.store.saveCredentialCalls != 0 {
		t.Errorf("SaveCredential() calls = %d, want 0 — a rejected registration must not persist a credential", f.store.saveCredentialCalls)
	}
}

// TestFinishRegistrationRejectsRPIDMismatch covers the registration
// ceremony's RP ID binding, which — unlike the origin — is inside the signed
// authenticator data. Paired with a control for the reason given on
// errAuthDataVerification.
func TestFinishRegistrationRejectsRPIDMismatch(t *testing.T) {
	t.Parallel()

	const otherRPID = "evil.example.net"

	t.Run("mismatched rp id is rejected", func(t *testing.T) {
		t.Parallel()

		f := newForgingFixture(t)
		ctx := t.Context()

		creation, err := f.service.BeginRegistration(ctx, f.user)
		if err != nil {
			t.Fatalf("BeginRegistration() error = %v", err)
		}

		req := f.registrationRequest(creation.Response.Challenge.String())
		req.rpID = otherRPID

		_, err = f.service.FinishRegistrationResponse(ctx, f.user, f.auth.forgeRegistration(req))
		if err == nil {
			t.Fatal("FinishRegistrationResponse() error = nil, want a rejection")
		}
		if !strings.Contains(err.Error(), errAuthDataVerification) {
			t.Errorf("FinishRegistrationResponse() error = %q, want it to name the authenticator-data verification step", err)
		}
		if f.store.saveCredentialCalls != 0 {
			t.Errorf("SaveCredential() calls = %d, want 0", f.store.saveCredentialCalls)
		}
	})

	t.Run("matching rp id is accepted", func(t *testing.T) {
		t.Parallel()

		f := newForgingFixtureForRP(t, otherRPID, testOrigin)
		ctx := t.Context()

		creation, err := f.service.BeginRegistration(ctx, f.user)
		if err != nil {
			t.Fatalf("BeginRegistration() error = %v", err)
		}

		req := f.registrationRequest(creation.Response.Challenge.String())
		req.rpID = otherRPID

		if _, err := f.service.FinishRegistrationResponse(ctx, f.user, f.auth.forgeRegistration(req)); err != nil {
			t.Fatalf("FinishRegistrationResponse() error = %v, want nil", err)
		}
	})
}

// TestFinishRegistrationRejectsResponseWithoutUserVerification is the
// registration counterpart of the UV debt: user verification is requested at
// enrollment too, and a credential created without it would be a
// single-factor credential from birth. Paired with a control for the reason
// given on errAuthDataVerification.
func TestFinishRegistrationRejectsResponseWithoutUserVerification(t *testing.T) {
	t.Parallel()

	const presenceOnly = protocol.FlagUserPresent

	t.Run("required rejects it", func(t *testing.T) {
		t.Parallel()

		f := newForgingFixture(t)
		ctx := t.Context()

		creation, err := f.service.BeginRegistration(ctx, f.user)
		if err != nil {
			t.Fatalf("BeginRegistration() error = %v", err)
		}

		req := f.registrationRequest(creation.Response.Challenge.String())
		req.flags = presenceOnly

		_, err = f.service.FinishRegistrationResponse(ctx, f.user, f.auth.forgeRegistration(req))
		if err == nil {
			t.Fatal("FinishRegistrationResponse() error = nil, want a rejection")
		}
		if !strings.Contains(err.Error(), errAuthDataVerification) {
			t.Errorf("FinishRegistrationResponse() error = %q, want it to name the authenticator-data verification step", err)
		}
		if f.store.saveCredentialCalls != 0 {
			t.Errorf("SaveCredential() calls = %d, want 0", f.store.saveCredentialCalls)
		}
	})

	t.Run("discouraged accepts it", func(t *testing.T) {
		t.Parallel()

		f := newForgingFixture(t, WithUserVerification(protocol.VerificationDiscouraged))
		ctx := t.Context()

		creation, err := f.service.BeginRegistration(ctx, f.user)
		if err != nil {
			t.Fatalf("BeginRegistration() error = %v", err)
		}

		req := f.registrationRequest(creation.Response.Challenge.String())
		req.flags = presenceOnly

		if _, err := f.service.FinishRegistrationResponse(ctx, f.user, f.auth.forgeRegistration(req)); err != nil {
			t.Fatalf("FinishRegistrationResponse() error = %v, want nil — the identical registration must pass when user verification is not required", err)
		}
	})
}

// TestFinishRegistrationRejectsMalformedCBORAttestationObject covers a body
// that is valid JSON and valid base64url but whose attestation object is not
// decodable CBOR at all. This is the shape a fuzzer or a broken client
// produces, and it must be turned away as a parse error rather than
// panicking or being partially processed.
func TestFinishRegistrationRejectsMalformedCBORAttestationObject(t *testing.T) {
	t.Parallel()

	f := newForgingFixture(t)
	ctx := t.Context()

	creation, err := f.service.BeginRegistration(ctx, f.user)
	if err != nil {
		t.Fatalf("BeginRegistration() error = %v", err)
	}

	req := f.registrationRequest(creation.Response.Challenge.String())
	// 0xff is the CBOR "break" stop code, which is never a valid top-level
	// data item; the rest is arbitrary trailing garbage.
	req.attestationObject = []byte{0xff, 0xff, 0xff, 0xff}

	cred, err := f.service.FinishRegistrationResponse(ctx, f.user, f.auth.forgeRegistration(req))
	if err == nil {
		t.Fatal("FinishRegistrationResponse() error = nil, want a parse rejection")
	}
	if cred != nil {
		t.Fatalf("FinishRegistrationResponse() credential = %#v, want nil", cred)
	}
	if !strings.Contains(err.Error(), "parsing registration response") {
		t.Errorf("FinishRegistrationResponse() error = %q, want it to name the response parse step", err)
	}
	if f.store.saveCredentialCalls != 0 {
		t.Errorf("SaveCredential() calls = %d, want 0", f.store.saveCredentialCalls)
	}
}

// TestFinishLoginRejectsMalformedCBORPublicKey covers the mirror-image case
// for login: the response is fine, but the *stored* credential's COSE public
// key is unparseable. sulis must surface that as a rejected ceremony rather
// than propagating a panic out of the key parser.
func TestFinishLoginRejectsMalformedCBORPublicKey(t *testing.T) {
	t.Parallel()

	f := newForgingFixture(t)
	cred := f.auth.storedCredential(string(f.user.ID), 0, 0)
	cred.PublicKey = []byte{0xff, 0xff, 0xff, 0xff}
	f.store.seed(cred)

	challenge, ceremonyID := f.beginLogin()

	_, err := f.service.FinishLoginResponse(t.Context(), f.user, ceremonyID, f.auth.forgeAssertion(f.assertionRequest(challenge)))
	if !errors.Is(err, ErrChallengeFailed) {
		t.Fatalf("FinishLoginResponse() error = %v, want errors.Is(err, ErrChallengeFailed)", err)
	}
	if !strings.Contains(err.Error(), "assertion public key") {
		t.Errorf("FinishLoginResponse() error = %q, want it to name the public key parse step", err)
	}
}

// TestFinishLoginConsumesChallengeExactlyOnce is the login-ceremony
// counterpart of T201's TestFinishDiscoverableLoginConsumesChallengeExactlyOnce,
// which covered only the discoverable ceremony. It is a stronger test than
// that one: because the forging authenticator can produce a genuinely valid
// assertion, the expected outcome is one *success* and one ErrChallengeExpired
// rather than one failure of any kind and one ErrChallengeExpired — so a
// challenge that leaked to both racers would show up as two successes, i.e. a
// login replayed against a single ceremony.
//
// Both goroutines are released from a shared start gate on every iteration to
// make the race as tight as possible, and the property is checked across many
// iterations, since a single run can get lucky.
func TestFinishLoginConsumesChallengeExactlyOnce(t *testing.T) {
	const iterations = 200

	for i := 0; i < iterations; i++ {
		f := newForgingFixture(t)
		f.seedCredential(0, 0)
		ctx := t.Context()

		challenge, ceremonyID := f.beginLogin()
		body := f.auth.forgeAssertion(f.assertionRequest(challenge))

		// More racers than the two T201's test uses: FinishLoginResponse
		// loads the user's credentials before it consumes the challenge, and
		// that store call staggers the goroutines' arrival at the consume
		// step. Widening the field restores the odds that two of them land
		// inside the window a non-atomic consume would leave open.
		const racers = 8
		start := make(chan struct{})
		errs := make([]error, racers)
		var wg sync.WaitGroup
		wg.Add(racers)
		for g := 0; g < racers; g++ {
			go func() {
				defer wg.Done()
				<-start
				_, errs[g] = f.service.FinishLoginResponse(ctx, f.user, ceremonyID, body)
			}()
		}
		close(start)
		wg.Wait()

		var succeeded, expired int
		for _, err := range errs {
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, ErrChallengeExpired):
				expired++
			default:
				t.Fatalf("iteration %d: FinishLoginResponse() unexpected error = %v", i, err)
			}
		}
		if succeeded != 1 || expired != racers-1 {
			t.Fatalf("iteration %d: got %d successes and %d ErrChallengeExpired among %d racers, want exactly 1 and %d (single-use challenge violated: a valid assertion was accepted more than once against one ceremony)",
				i, succeeded, expired, racers, racers-1)
		}
	}
}

// TestFinishRegistrationConsumesChallengeExactlyOnce is the registration
// ceremony's version of the same property: two concurrent submissions of the
// same attestation must not both enroll a credential.
func TestFinishRegistrationConsumesChallengeExactlyOnce(t *testing.T) {
	const iterations = 200

	for i := 0; i < iterations; i++ {
		f := newForgingFixture(t)
		ctx := t.Context()

		creation, err := f.service.BeginRegistration(ctx, f.user)
		if err != nil {
			t.Fatalf("iteration %d: BeginRegistration() error = %v", i, err)
		}
		body := f.auth.forgeRegistration(f.registrationRequest(creation.Response.Challenge.String()))

		const racers = 2
		start := make(chan struct{})
		errs := make([]error, racers)
		var wg sync.WaitGroup
		wg.Add(racers)
		for g := 0; g < racers; g++ {
			go func() {
				defer wg.Done()
				<-start
				_, errs[g] = f.service.FinishRegistrationResponse(ctx, f.user, body)
			}()
		}
		close(start)
		wg.Wait()

		var succeeded, expired int
		for _, err := range errs {
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, ErrChallengeExpired):
				expired++
			default:
				t.Fatalf("iteration %d: FinishRegistrationResponse() unexpected error = %v", i, err)
			}
		}
		if succeeded != 1 || expired != 1 {
			t.Fatalf("iteration %d: got %d successes and %d ErrChallengeExpired among %d racers, want exactly 1 and 1 (single-use challenge violated)",
				i, succeeded, expired, racers)
		}
		if f.store.saveCredentialCalls != 1 {
			t.Fatalf("iteration %d: SaveCredential() calls = %d, want 1 (one ceremony must enroll exactly one credential)", i, f.store.saveCredentialCalls)
		}
	}
}
