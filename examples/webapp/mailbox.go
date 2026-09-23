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

// emailChangeNoticeTTL matches the lifetime of the confirmation token these
// entries are keyed by (sulis's EmailVerificationTokenDuration default, 24
// hours), so an entry never outlives the link that would consume it.
const emailChangeNoticeTTL = 24 * time.Hour

// pendingEmailChange is one staged email change: the address that was live
// when the change was requested, and until when the entry is worth keeping.
type pendingEmailChange struct {
	oldAddr string
	expires time.Time
}

// pendingEmailChanges remembers which address to notify once a staged email
// change is confirmed, keyed by tokenKey of the raw confirmation token.
// sulis.ConfirmEmailChange returns the user with the NEW address already in
// place, so by then the old one is gone from the database: if the app wants
// to tell the previous owner that the change went through (and it should,
// since that address is the one an attacker does not control), it has to
// remember the address itself, at the moment the change is staged.
type pendingEmailChanges struct {
	mu sync.Mutex
	m  map[string]pendingEmailChange
}

func newPendingEmailChanges() *pendingEmailChanges {
	return &pendingEmailChanges{m: make(map[string]pendingEmailChange)}
}

// add records oldAddr against rawToken, sweeping expired entries first so
// abandoned change requests cannot pile up.
func (p *pendingEmailChanges) add(rawToken, oldAddr string) {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, entry := range p.m {
		if now.After(entry.expires) {
			delete(p.m, key)
		}
	}
	p.m[tokenKey(rawToken)] = pendingEmailChange{oldAddr: oldAddr, expires: now.Add(emailChangeNoticeTTL)}
}

// take returns the address recorded for rawToken and removes the entry,
// whether or not it had expired: the token it belongs to is single-use, so
// the entry has no second reader.
func (p *pendingEmailChanges) take(rawToken string) (string, bool) {
	key := tokenKey(rawToken)
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, ok := p.m[key]
	delete(p.m, key)
	if !ok || time.Now().After(entry.expires) {
		return "", false
	}
	return entry.oldAddr, true
}
