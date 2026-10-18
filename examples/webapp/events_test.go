package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"uuid"

	"github.com/borfast/sulis/passkey"
)

func TestPasskeySlogSinkOmitsNilUserID(t *testing.T) {
	var buf bytes.Buffer
	sink := newPasskeySlogSink(slog.New(slog.NewJSONHandler(&buf, nil)))
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

	sink.Emit(ctx, passkey.Event{Kind: passkey.EventLoginRejected})
	if rec := decode(); rec["user_id"] != nil {
		t.Errorf("record has user_id for uuid.Nil(): %v", rec)
	}

	id := uuid.NewV7()
	sink.Emit(ctx, passkey.Event{Kind: passkey.EventLoginRejected, UserID: id})
	if rec := decode(); rec["user_id"] != id.String() {
		t.Errorf("user_id = %v, want %v", rec["user_id"], id.String())
	}
}
