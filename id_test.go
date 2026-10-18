package sulis_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"uuid"

	"github.com/borfast/sulis"
	"github.com/borfast/sulis/memstore"
)

// recordingTokenStore remembers every token handed to CreateToken.
type recordingTokenStore struct {
	sulis.TokenStore
	created []sulis.Token
}

func (r *recordingTokenStore) CreateToken(ctx context.Context, t *sulis.Token) error {
	r.created = append(r.created, *t)
	return r.TokenStore.CreateToken(ctx, t)
}

// memSulisArgon2Params keep password hashing cheap under -race.
var memSulisArgon2Params = sulis.Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}

func newMemSulis(t *testing.T, tokens sulis.TokenStore) *sulis.Sulis {
	t.Helper()
	s, err := sulis.New(memstore.NewUserStore(), memstore.NewSessionStore(), tokens, sulis.NoSecondFactors{},
		sulis.WithArgon2Params(memSulisArgon2Params))
	if err != nil {
		t.Fatalf("sulis.New: %v", err)
	}
	return s
}

func TestGeneratedIDsAreVersion7(t *testing.T) {
	ctx := context.Background()
	tokens := &recordingTokenStore{TokenStore: memstore.NewTokenStore()}
	s := newMemSulis(t, tokens)

	user, session, _, err := s.Register(ctx, "v7@example.com", "correct horse battery staple", sulis.RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := s.CreatePasswordResetToken(ctx, "v7@example.com", sulis.RequestInfo{}); err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}
	if len(tokens.created) != 1 {
		t.Fatalf("recorded %d tokens, want 1", len(tokens.created))
	}

	for name, id := range map[string]uuid.UUID{
		"user":    user.ID,
		"session": session.ID,
		"token":   tokens.created[0].ID,
	} {
		if id[6]>>4 != 7 {
			t.Errorf("%s ID %v is version %d, want 7", name, id, id[6]>>4)
		}
	}
}

func TestSlogSinkOmitsNilIDs(t *testing.T) {
	var buf bytes.Buffer
	sink := sulis.NewSlogSink(slog.New(slog.NewJSONHandler(&buf, nil)))
	ctx := context.Background()

	decode := func() map[string]any {
		t.Helper()
		var rec map[string]any
		if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
			t.Fatalf("decoding log record %q: %v", buf.String(), err)
		}
		buf.Reset()
		return rec
	}

	sink.Emit(ctx, sulis.Event{Kind: sulis.EventLoginFailed})
	rec := decode()
	for _, key := range []string{"user_id", "session_id"} {
		if _, ok := rec[key]; ok {
			t.Errorf("record has %q for a nil ID: %v", key, rec)
		}
	}

	id := uuid.NewV7()
	sink.Emit(ctx, sulis.Event{Kind: sulis.EventLoginFailed, UserID: id})
	rec = decode()
	if rec["user_id"] != id.String() {
		t.Errorf("user_id = %v, want %v", rec["user_id"], id.String())
	}
}

func TestIssueSessionUncheckedNilUserReturnsErrUserNotFound(t *testing.T) {
	s := newMemSulis(t, memstore.NewTokenStore())

	session, _, err := s.IssueSessionUnchecked(context.Background(), uuid.Nil(), sulis.AuthMethodPassword)
	if !errors.Is(err, sulis.ErrUserNotFound) {
		t.Errorf("error = %v, want ErrUserNotFound", err)
	}
	if session != nil {
		t.Errorf("session = %v, want nil", session)
	}
}
