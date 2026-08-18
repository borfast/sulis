package passkey

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// FinishRegistration completes the WebAuthn registration ceremony from an
// *http.Request. It is a thin wrapper around FinishRegistrationResponse: the
// request body is read through readCeremonyBody, which caps it at the
// Service's configured WithMaxCeremonyBody limit (default 64 KiB) via
// http.MaxBytesReader — so an oversized body is rejected as it's being read,
// never buffered into memory in full.
//
// The http.Request must contain the authenticator's response body.
func (s *Service) FinishRegistration(ctx context.Context, user *User, r *http.Request) (*Credential, error) {
	body, err := s.readCeremonyBody(r)
	if err != nil {
		return nil, err
	}
	return s.FinishRegistrationResponse(ctx, user, body)
}

// FinishLogin completes the WebAuthn authentication ceremony started by
// BeginLogin, reading its request body the same way FinishRegistration
// does. ceremonyID must be the value returned by the matching BeginLogin
// call.
//
// The http.Request must contain the authenticator's response body.
func (s *Service) FinishLogin(ctx context.Context, user *User, ceremonyID string, r *http.Request) (*Credential, error) {
	body, err := s.readCeremonyBody(r)
	if err != nil {
		return nil, err
	}
	return s.FinishLoginResponse(ctx, user, ceremonyID, body)
}

// FinishDiscoverableLogin completes a usernameless WebAuthn authentication
// ceremony started by BeginDiscoverableLogin, reading its request body the
// same way FinishRegistration does. ceremonyID must be the value returned
// by the matching BeginDiscoverableLogin call.
//
// The http.Request must contain the authenticator's response body.
func (s *Service) FinishDiscoverableLogin(ctx context.Context, ceremonyID string, r *http.Request) (*Credential, error) {
	body, err := s.readCeremonyBody(r)
	if err != nil {
		return nil, err
	}
	return s.FinishDiscoverableLoginResponse(ctx, ceremonyID, body)
}

// readCeremonyBody reads r.Body capped at the Service's configured
// WithMaxCeremonyBody limit via http.MaxBytesReader, so a body larger than
// the limit is rejected as soon as that many bytes have been read — never
// buffered into memory in full. go-webauthn's own body decoding
// (protocol.decodeBody, unexported in its decoder.go) has no such limit;
// this cap is only possible because sulis owns the *http.Request here,
// which is exactly what the []byte-taking core methods in passkey.go do not
// — they get the same bound only because they check len(body) themselves.
//
// A nil request or nil body is treated as an empty body rather than an
// error here: the caller's challenge is still consumed as normal (and, for
// a real ceremony, the empty body then simply fails to parse), so callers
// don't observe a different code path depending on whether a body was
// supplied.
func (s *Service) readCeremonyBody(r *http.Request) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, s.cfg.maxCeremonyBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, fmt.Errorf("%w: over the %d byte limit", ErrCeremonyBodyTooLarge, tooLarge.Limit)
		}
		return nil, fmt.Errorf("passkey: reading ceremony response body: %w", err)
	}
	return body, nil
}
