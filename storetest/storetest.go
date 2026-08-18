// Package storetest is the conformance suite for the persistence interfaces
// sulis defines.
//
// Every store interface in this module documents behavior that no compiler
// can check: ConsumeToken must find-and-mark in one atomic step, UpdateUser
// must reject a write built from a stale read, DeleteSession must scope its
// delete to the owning user, ConfirmEnrollment must compare-and-swap, the
// TOTP replay counter must never move backwards. Those requirements are the
// difference between a store that merely compiles and one that is safe to
// authenticate against. This package turns each of them into an executable
// test so an adopter can prove their own implementation compliant instead of
// hoping it is.
//
// # Using it
//
// Point each Run function at a factory that returns a fresh, empty store:
//
//	func TestMyStores(t *testing.T) {
//		storetest.RunUserStore(t, func() sulis.UserStore { return myUserStore(t) })
//		storetest.RunSessionStore(t, func() sulis.SessionStore { return mySessionStore(t) })
//		storetest.RunTokenStore(t, func() sulis.TokenStore { return myTokenStore(t) })
//		storetest.RunTOTPStore(t, func() totp.Store { return myTOTPStore(t) })
//		storetest.RunRecoveryStore(t, func() recovery.Store { return myRecoveryStore(t) })
//	}
//
// The passkey interfaces have their own entry points, RunPasskeyStore and
// RunPasskeyChallengeStore, in the same shape.
//
// # What a factory must return
//
// Each factory call must return a store observing no state from any earlier
// call — an empty database, a truncated schema, a new map. Every subtest
// calls the factory at least once, and the concurrency subtests call it once
// per iteration, so a factory backed by a real database should make that
// reset cheap.
//
// Identifiers, e-mail addresses, and token hashes the suite generates are
// unique per process run, so a factory that cannot truly reset (a shared
// development database, say) will still not see collisions between runs.
// Assertions about counts are always scoped to the specific users the
// subtest created, never to the whole store.
//
// # Concurrency coverage
//
// The atomicity requirements are checked by racing goroutines through a
// shared start gate and asserting on the aggregate outcome — "exactly one
// caller succeeded", "the user still has one credential", "the counter did
// not move backwards". A store whose check-and-mutate is really a separate
// read then write fails these; a store that holds a lock, a transaction, or
// a single conditional statement across both passes.
//
// Those subtests repeat many times, since a race that loses is not a race
// that cannot happen. Run with -race, and pass -short to cut the iteration
// count when the store is slow (a real database) and the suite is only being
// smoke-tested.
//
// # Scope
//
// The suite asserts on the documented contracts and nothing else. It never
// inspects storage, never assumes an ordering the interfaces do not promise,
// and never asserts on timestamps beyond their presence, so it is equally
// valid against SQL, key-value, and in-memory stores. Package memstore is a
// reference implementation that passes all of it.
package storetest

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// raceIterations reports how many times a concurrency subtest repeats its
// race. Losing a race once proves nothing, so the default is high enough
// that a non-atomic implementation loses reliably; -short cuts it for slow
// stores being smoke-tested rather than certified.
func raceIterations() int {
	if testing.Short() {
		return 5
	}
	return 100
}

// runTag distinguishes one process run of the suite from another, so a
// factory backed by a store that cannot truly reset between runs (a shared
// development database) still never sees an identifier collide with one left
// behind by an earlier run.
var runTag = newRunTag()

func newRunTag() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// A failure here costs uniqueness across process runs, not
		// correctness within one: seq below still makes every identifier
		// unique inside this run.
		return "storetest"
	}
	return hex.EncodeToString(b)
}

var seq atomic.Uint64

// uniqueID returns an identifier no other call returns, so subtests never
// collide even when a factory hands back a store that was not really reset.
func uniqueID(prefix string) string {
	return fmt.Sprintf("%s-%s-%d", prefix, runTag, seq.Add(1))
}

// uniqueEmail returns an address at a reserved TLD (RFC 2606), so a store
// that validates or normalizes addresses still accepts it and no test can
// ever reach a real mailbox.
func uniqueEmail(prefix string) string {
	return uniqueID(prefix) + "@storetest.example"
}

// uniqueHash returns a distinct 64-character lowercase hex string, the shape
// sulis stores every token and session hash in.
func uniqueHash(prefix string) string {
	sum := sha256.Sum256([]byte(uniqueID(prefix)))
	return hex.EncodeToString(sum[:])
}

// mutateMetadata rewrites a caller-held Metadata map the way an application
// naturally would — overwriting an existing key and adding a new one. If a
// store kept the caller's map rather than copying it, this reaches straight
// into the persisted row. A nil map is left alone: a store is not obliged to
// persist Metadata at all.
func mutateMetadata(m map[string]any) {
	if m == nil {
		return
	}
	for k := range m {
		m[k] = "mutated-by-the-caller"
	}
	m["injected-by-the-caller"] = true
}

// assertMetadataUnchanged checks that a Metadata map a store handed back still
// holds the value it was stored with and gained nothing a caller added
// afterwards.
//
// A store that does not persist Metadata at all returns nil (or an empty map)
// and is not failed for it: the interfaces promise nothing about the field.
// What they cannot allow is persisting it and then sharing the map, which
// would let a caller rewrite a stored row without going through the write
// path — the same lost-update problem Version exists to prevent, reached by a
// different route.
func assertMetadataUnchanged(t *testing.T, op string, got map[string]any, key string, want any) {
	t.Helper()

	if len(got) == 0 {
		return
	}
	if v, ok := got[key]; ok && v != want {
		t.Fatalf("%s: Metadata[%q] = %v, want %v — the store shares its map with the caller, so mutating the caller's copy rewrote a persisted row",
			op, key, v, want)
	}
	if _, ok := got["injected-by-the-caller"]; ok {
		t.Fatalf("%s: a key the caller added to its own map after handing it over appeared in the stored Metadata — the store must copy the map, not keep it",
			op)
	}
}

// race runs fn in racers goroutines that all block on one start gate and are
// released together, so the calls overlap as tightly as the runtime allows.
// It returns each goroutine's error, indexed by goroutine number.
func race(racers int, fn func(i int) error) []error {
	errs := make([]error, racers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(racers)
	for i := range racers {
		go func() {
			defer wg.Done()
			<-start
			errs[i] = fn(i)
		}()
	}
	close(start)
	wg.Wait()
	return errs
}

// exactlyOneWinner asserts that exactly one of errs is nil and that every
// other error is wantLoser, and returns the winner's index. This is the
// shape every atomicity requirement in this module reduces to: a
// check-and-mutate that two callers can both pass is a check-and-mutate that
// is not atomic.
func exactlyOneWinner(t *testing.T, errs []error, wantLoser error, op string) int {
	t.Helper()

	winner := -1
	for i, err := range errs {
		switch {
		case err == nil:
			if winner >= 0 {
				t.Fatalf("%s: goroutines %d and %d both succeeded — want exactly one; the check and the mutation are not atomic",
					op, winner, i)
			}
			winner = i
		case errors.Is(err, wantLoser):
		default:
			t.Fatalf("%s: goroutine %d failed with %v, want nil or %v", op, i, err, wantLoser)
		}
	}
	if winner < 0 {
		t.Fatalf("%s: every one of the %d goroutines failed — want exactly one to succeed", op, len(errs))
	}
	return winner
}
