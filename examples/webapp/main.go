// Command webapp is a runnable example application that wires the sulis
// authentication library end to end against a local SQLite database. See
// README.md for how to run it and what to click.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/borfast/sulis/store/sql/sqlite"
)

// cleanupInterval is how often the background loop removes expired sessions
// and tokens.
const cleanupInterval = 10 * time.Minute

func main() {
	addr := flag.String("addr", ":8443", "address to listen on")
	dbPath := flag.String("db", "webapp.db", "path to the SQLite database file")
	useTLS := flag.Bool("tls", true, "serve over TLS with a self-signed certificate (Safari requires this for secure cookies)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	scheme := "http"
	if *useTLS {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://localhost%s", scheme, *addr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	a, err := newApp(ctx, sqlite.FileDSN(*dbPath), baseURL, logger)
	if err != nil {
		logger.Error("failed to start", "error", err)
		os.Exit(1)
	}
	defer func() { _ = a.db.Close() }()

	go cleanupLoop(ctx, a)

	server := &http.Server{
		Addr:    *addr,
		Handler: a.routes(),
		// ReadHeaderTimeout bounds how long a client can take sending
		// request headers, closing off a Slowloris-style resource hold.
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if *useTLS {
			cert, err := selfSignedCert()
			if err != nil {
				errCh <- fmt.Errorf("generating self-signed certificate: %w", err)
				return
			}
			server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
			logger.Info("listening", "addr", *addr, "base_url", baseURL, "tls", true)
			errCh <- server.ListenAndServeTLS("", "")
		} else {
			logger.Info("listening", "addr", *addr, "base_url", baseURL, "tls", false)
			errCh <- server.ListenAndServe()
		}
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped", "error", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("shutdown error", "error", err)
		}
	}
}

// cleanupLoop periodically removes expired sessions and tokens. It stops as
// soon as ctx is cancelled, so tests that build an app with newApp directly
// never start it.
func cleanupLoop(ctx context.Context, a *app) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.db.SessionStore().CleanExpired(ctx); err != nil {
				a.log.Error("cleanup: removing expired sessions failed", "error", err)
			}
			if err := a.db.TokenStore().DeleteExpiredTokens(ctx); err != nil {
				a.log.Error("cleanup: removing expired tokens failed", "error", err)
			}
		}
	}
}
