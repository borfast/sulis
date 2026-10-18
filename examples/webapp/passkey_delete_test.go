package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/borfast/sulis/passkey"
)

func signedInPasskeyDeleteUser(t *testing.T, a *app, email string) (*testClient, uuid.UUID) {
	t.Helper()
	c := newTestClient(t, a)
	if rec := registerUser(t, c, email, testPassword); rec.Code != http.StatusOK {
		t.Fatalf("register: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec := verifyEmail(t, a, c, email); rec.Code != http.StatusOK {
		t.Fatalf("verify: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec := login(t, c, email, testPassword); rec.Code != http.StatusSeeOther {
		t.Fatalf("login: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	user, err := a.users.GetUserByEmail(t.Context(), email)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	return c, user.ID
}

func savePasskeyForDelete(t *testing.T, a *app, userID, credentialID uuid.UUID) {
	t.Helper()
	err := a.db.PasskeyStore().SaveCredential(t.Context(), &passkey.Credential{
		ID: credentialID, UserID: userID, CredentialID: []byte(credentialID.String()),
		PublicKey: []byte("public-key"), CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("save passkey: %v", err)
	}
}

func deletePasskeyRequest(t *testing.T, c *testClient, credentialID string) *httptest.ResponseRecorder {
	t.Helper()
	rec := c.get("/security")
	if rec.Code != http.StatusOK {
		t.Fatalf("security page: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	return c.post("/security/passkeys/delete", url.Values{
		"csrf_token":    {extractCSRFToken(t, rec.Body.String())},
		"credential_id": {credentialID},
	})
}

func TestPasskeyDeleteLastCredentialRequiresActiveTOTP(t *testing.T) {
	for _, tc := range []struct {
		name       string
		withTOTP   bool
		wantStatus int
		wantCount  int
	}{
		{"without TOTP", false, http.StatusUnprocessableEntity, 1},
		{"with active TOTP", true, http.StatusSeeOther, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newTestApp(t)
			c, userID := signedInPasskeyDeleteUser(t, a, "passkey-delete@example.com")
			lastID := uuid.NewV7()
			savePasskeyForDelete(t, a, userID, lastID)
			if tc.withTOTP {
				enrollTOTP(t, a, c)
			}

			rec := deletePasskeyRequest(t, c, lastID.String())
			if rec.Code != tc.wantStatus {
				t.Fatalf("delete: status = %d, want %d, body = %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if !tc.withTOTP && !strings.Contains(rec.Body.String(), "Enable another second factor first") {
				t.Errorf("missing last-passkey explanation: %s", rec.Body.String())
			}
			creds, err := a.db.PasskeyStore().GetCredentialsByUserID(t.Context(), userID)
			if err != nil {
				t.Fatalf("list passkeys: %v", err)
			}
			if len(creds) != tc.wantCount {
				t.Errorf("remaining passkeys = %d, want %d", len(creds), tc.wantCount)
			}
		})
	}
}

func TestPasskeyDeleteCannotRemoveAnotherUsersCredential(t *testing.T) {
	a := newTestApp(t)
	_, ownerID := signedInPasskeyDeleteUser(t, a, "passkey-owner@example.com")
	attacker, _ := signedInPasskeyDeleteUser(t, a, "passkey-attacker@example.com")
	ownerPasskey := uuid.NewV7()
	savePasskeyForDelete(t, a, ownerID, ownerPasskey)
	enrollTOTP(t, a, attacker)

	rec := deletePasskeyRequest(t, attacker, ownerPasskey.String())
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("delete another user's passkey: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	creds, err := a.db.PasskeyStore().GetCredentialsByUserID(t.Context(), ownerID)
	if err != nil {
		t.Fatalf("list owner's passkeys: %v", err)
	}
	if len(creds) != 1 || creds[0].ID != ownerPasskey {
		t.Errorf("owner's passkeys changed: %+v", creds)
	}
}

func TestDeletePasskeyWithMalformedIDReturns400(t *testing.T) {
	a := newTestApp(t)
	c, userID := signedInPasskeyDeleteUser(t, a, "passkey-malformed@example.com")
	id := uuid.NewV7()
	savePasskeyForDelete(t, a, userID, id)
	enrollTOTP(t, a, c)

	rec := deletePasskeyRequest(t, c, "not-a-uuid")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("delete with malformed ID: status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
	creds, err := a.db.PasskeyStore().GetCredentialsByUserID(t.Context(), userID)
	if err != nil {
		t.Fatalf("list passkeys: %v", err)
	}
	if len(creds) != 1 || creds[0].ID != id {
		t.Errorf("passkeys changed: %+v", creds)
	}
}
