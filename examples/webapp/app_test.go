package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/borfast/sulis/store/sql/sqlite"
)

// newTestApp builds an app against an in-memory SQLite database with a
// discard logger, for tests that only need a working app, not a running
// server.
func newTestApp(t *testing.T) *app {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := newApp(t.Context(), sqlite.MemoryDSN(), "https://localhost:8443", logger)
	if err != nil {
		t.Fatalf("newApp: %v", err)
	}
	t.Cleanup(func() { _ = a.db.Close() })
	return a
}

func TestHomePageRenders(t *testing.T) {
	a := newTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	a.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "Sulis") {
		t.Errorf("body does not contain %q:\n%s", "Sulis", rec.Body.String())
	}
}

func TestHealthz(t *testing.T) {
	a := newTestApp(t)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	a.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Body.String(); got != "ok" {
		t.Errorf("body = %q, want %q", got, "ok")
	}
}
