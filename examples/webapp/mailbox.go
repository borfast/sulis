package main

import (
	"log/slog"
	"sync"
	"time"
)

// mailMessage is one message captured by outbox, standing in for whatever a
// real deployment would send through an actual mail transport.
type mailMessage struct {
	To, Subject, Body string
	SentAt            time.Time
}

// outbox captures every email this demo would otherwise send, so it can run
// without a real mail transport. Registration and the verification-resend
// flow both call Send; the /dev/mailbox page lists what it holds so a
// developer running the demo can find the link a real inbox would show.
type outbox struct {
	mu   sync.Mutex
	msgs []mailMessage
}

// Send records a message and logs its body, standing in for delivering it.
func (o *outbox) Send(to, subject, body string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.msgs = append(o.msgs, mailMessage{To: to, Subject: subject, Body: body, SentAt: time.Now()})
	slog.Info("mail sent", "to", to, "subject", subject, "body", body)
}

// Messages returns a copy of every message sent so far, oldest first. A copy
// is returned so a caller ranging over it in a template cannot race with a
// concurrent Send.
func (o *outbox) Messages() []mailMessage {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]mailMessage, len(o.msgs))
	copy(out, o.msgs)
	return out
}
