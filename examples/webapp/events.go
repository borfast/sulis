package main

import (
	"context"
	"log/slog"

	"github.com/borfast/sulis/passkey"
)

// Each sulis module declares its own event type, on purpose: passkey does
// not import the root package, and the root package does not know what a
// WebAuthn ceremony is. Joining them into one log stream is therefore the
// application's job, and it is one small adapter per module at the wiring
// boundary. newApp uses two: sulis.NewSlogSink for the root package's
// events, and the adapter below for the passkey package's, so both end up
// in the same *slog.Logger with the same shape of attributes.

// passkeySlogSink adapts a *slog.Logger to passkey.EventSink, mirroring
// what sulis.NewSlogSink does for sulis.Event: one attribute per populated
// field, empty fields omitted rather than logged as "".
type passkeySlogSink struct{ logger *slog.Logger }

// newPasskeySlogSink returns a sink that logs every passkey event to
// logger. A nil logger falls back to slog.Default, the same way
// sulis.NewSlogSink does: a forgotten logger should be a misconfiguration,
// not a panic on the first ceremony.
func newPasskeySlogSink(logger *slog.Logger) passkey.EventSink {
	if logger == nil {
		logger = slog.Default()
	}
	return passkeySlogSink{logger: logger}
}

// Emit logs one passkey event at info level. Everything passkey.Event
// carries is already an opaque identifier or a closed-category label, so
// there is nothing here to redact before it reaches the log.
func (s passkeySlogSink) Emit(ctx context.Context, e passkey.Event) {
	attrs := make([]slog.Attr, 0, 5)
	attrs = append(attrs, slog.String("kind", string(e.Kind)))
	if e.UserID != "" {
		attrs = append(attrs, slog.String("user_id", e.UserID))
	}
	if e.Operation != "" {
		attrs = append(attrs, slog.String("operation", e.Operation))
	}
	if e.Diagnostic != "" {
		attrs = append(attrs, slog.String("diagnostic", e.Diagnostic))
	}
	if !e.At.IsZero() {
		attrs = append(attrs, slog.Time("at", e.At))
	}
	s.logger.LogAttrs(ctx, slog.LevelInfo, "passkey security event", attrs...)
}
