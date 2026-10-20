package sulis

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/borfast/sulis/recovery"
	"github.com/borfast/sulis/totp"
)

// The three Limiter interfaces — sulis.Limiter (config.go), totp.Limiter
// (totp/totp.go) and recovery.Limiter (recovery/recovery.go) — are declared
// separately so neither subpackage takes a dependency on the root module,
// and are deliberately identical so that one implementation (canonically
// *MemoryLimiter) guards all three via structural typing. Nothing enforced
// that: adding, renaming or re-typing a method on any one of them compiles
// cleanly here and breaks only in the application that wired a single
// limiter into two packages, at a call site none of these packages own.
//
// These declarations are the enforcement. Mutual assignability between two
// interface types is Go's way of saying "identical method sets", so
// widening any one of the three fails the build in this file, next to the
// limiter whose doc comment makes the promise.
var (
	_ totp.Limiter     = Limiter(nil)
	_ recovery.Limiter = Limiter(nil)
	_ Limiter          = totp.Limiter(nil)
	_ recovery.Limiter = totp.Limiter(nil)
	_ Limiter          = recovery.Limiter(nil)
	_ totp.Limiter     = recovery.Limiter(nil)

	// And the concrete promise MemoryLimiter's doc comment makes: one
	// instance serves all three packages.
	_ Limiter          = (*MemoryLimiter)(nil)
	_ totp.Limiter     = (*MemoryLimiter)(nil)
	_ recovery.Limiter = (*MemoryLimiter)(nil)
)

// fakeClock lets limiter tests advance time without sleeping.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)}
}

// TestDefaultLimiterThrottlesPasswordGuessing covers audit finding B1: the
// limiter used to default to nil, which silently made every choke point a
// no-op. A Sulis built with no options must resist guessing.
func TestDefaultLimiterThrottlesPasswordGuessing(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	var limited bool
	for i := 0; i < 200; i++ {
		_, err := s.Login(ctx, "alice@example.com", "wrong-password", RequestInfo{})
		if errors.Is(err, ErrRateLimited) {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("a Sulis built with no options must throttle repeated password failures")
	}
}

// TestDefaultLimiterThrottlesPerIP covers the second dimension: guesses spread
// across many accounts from one host must also be throttled, or an attacker
// simply rotates the email.
func TestDefaultLimiterThrottlesPerIP(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params))
	ctx := context.Background()
	ri := RequestInfo{IP: "203.0.113.7"}

	var limited bool
	for i := 0; i < 200; i++ {
		// A different account every time, so the per-account budget never
		// runs out and only the IP dimension can stop this.
		email := fmt.Sprintf("victim-%d@example.com", i)
		_, err := s.Login(ctx, email, "wrong-password", ri)
		if errors.Is(err, ErrRateLimited) {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("guesses spread across accounts from one IP must be throttled")
	}
}

// TestPerAccountBudgetDoesNotLockOutFromOtherIPs guards the denial-of-service
// side of rate limiting: an attacker must not be able to lock a victim out of
// their own account by exhausting a shared budget from elsewhere.
func TestPerAccountBudgetDoesNotLockOutFromOtherIPs(t *testing.T) {
	l := NewMemoryLimiter()
	ctx := context.Background()

	// Exhaust one IP's budget entirely.
	for i := 0; i < 1000; i++ {
		if errors.Is(l.Allow(ctx, "password:ip:198.51.100.1"), ErrRateLimited) {
			break
		}
	}
	if err := l.Allow(ctx, "password:ip:198.51.100.1"); !errors.Is(err, ErrRateLimited) {
		t.Fatal("expected the attacker's IP budget to be exhausted")
	}

	// A different IP is unaffected.
	if err := l.Allow(ctx, "password:ip:198.51.100.2"); err != nil {
		t.Errorf("a different IP must not inherit the exhausted budget, got %v", err)
	}
}

func TestWithoutRateLimitingDisablesThrottling(t *testing.T) {
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithoutRateLimiting())
	ctx := context.Background()

	user, _, _, err := s.Register(ctx, "alice@example.com", "correct-battery-staple", RequestInfo{})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	verifyUserEmail(t, users, user.ID)

	for i := 0; i < 50; i++ {
		if _, err := s.Login(ctx, "alice@example.com", "wrong", RequestInfo{}); errors.Is(err, ErrRateLimited) {
			t.Fatal("WithoutRateLimiting must disable throttling entirely")
		}
	}
}

// TestRegisterIsRateLimitedPerIP covers Register's IP bucket. Each call costs
// an Argon2 hash, so a refused call must be refused before any of that work.
func TestRegisterIsRateLimitedPerIP(t *testing.T) {
	checker, sink := &recordingChecker{}, &recordingSink{}
	limiter := NewMemoryLimiter(WithBudget("register:ip:", Budget{Burst: 2, Interval: time.Hour}))
	s, users, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithLimiter(limiter),
		WithPasswordChecker(checker), WithEventSink(sink))
	ctx := context.Background()
	ri := RequestInfo{IP: "203.0.113.9"}

	for i := range 2 {
		if _, _, _, err := s.Register(ctx, fmt.Sprintf("user-%d@example.com", i), "correct-battery-staple", ri); err != nil {
			t.Fatalf("Register %d within the budget: %v", i, err)
		}
	}
	checks := len(checker.calls())

	if _, _, _, err := s.Register(ctx, "user-2@example.com", "correct-battery-staple", ri); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Register after the budget is spent = %v, want ErrRateLimited", err)
	}
	// The IP is checked before the email is even validated.
	if _, _, _, err := s.Register(ctx, "not-an-email", "correct-battery-staple", ri); !errors.Is(err, ErrRateLimited) {
		t.Errorf("Register with a bad email after the budget is spent = %v, want ErrRateLimited", err)
	}
	// The password policy runs just before the hash, so no check means no hash.
	if got := len(checker.calls()); got != checks {
		t.Errorf("refused calls reached the password policy (%d checks, want %d), so they may have hashed", got, checks)
	}
	users.mu.Lock()
	stored := len(users.users)
	users.mu.Unlock()
	if stored != 2 {
		t.Errorf("stored users = %d, want 2: a refused Register wrote a user", stored)
	}
	e, ok := sink.first(EventRateLimitTripped)
	if !ok || e.Metadata[MetaScope] != "register" || e.Metadata[MetaDimension] != DimensionIP {
		t.Errorf("rate-limit event metadata = %v (found: %v), want scope register and dimension ip", e.Metadata, ok)
	}

	if _, _, _, err := s.Register(ctx, "user-3@example.com", "correct-battery-staple", RequestInfo{IP: "203.0.113.10"}); err != nil {
		t.Errorf("Register from a different IP = %v, want success", err)
	}
}

// TestRegisterWithoutAnIPIsNotRateLimited matches the other IP buckets: with
// no address there is nothing to key the bucket on.
func TestRegisterWithoutAnIPIsNotRateLimited(t *testing.T) {
	limiter := &fakeLimiter{denied: true}
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithLimiter(limiter))

	if _, _, _, err := s.Register(context.Background(), "alice@example.com", "correct-battery-staple", RequestInfo{}); err != nil {
		t.Fatalf("Register with no IP = %v, want success", err)
	}
	if len(limiter.keys) != 0 {
		t.Errorf("Register with no IP consulted the limiter with %v", limiter.keys)
	}
}

func TestWithoutRateLimitingDoesNotLimitRegister(t *testing.T) {
	s, _, _, _ := newTestEnv(WithArgon2Params(testArgon2Params), WithoutRateLimiting())
	ri := RequestInfo{IP: "203.0.113.9"}

	// More than the default register:ip: burst.
	for i := range budgetTokenIP.Burst + 5 {
		if _, _, _, err := s.Register(context.Background(), fmt.Sprintf("user-%d@example.com", i), "correct-battery-staple", ri); err != nil {
			t.Fatalf("Register %d with WithoutRateLimiting: %v", i, err)
		}
	}
}

// TestDefaultRegisterBudgetIsTheTokenIPBudget pins the default budget for
// Register's IP bucket. NewMemoryLimiter's doc comment says why it is this one.
func TestDefaultRegisterBudgetIsTheTokenIPBudget(t *testing.T) {
	if got := NewMemoryLimiter().budgetFor("register:ip:203.0.113.9"); got != budgetTokenIP {
		t.Errorf("default register:ip: budget = %+v, want %+v", got, budgetTokenIP)
	}
}

func TestMemoryLimiterRefillsOverTime(t *testing.T) {
	clock := newFakeClock()
	l := NewMemoryLimiter(withClock(clock.now), WithBudget("test:", Budget{Burst: 2, Interval: time.Minute}))
	ctx := context.Background()

	for i := range 2 {
		if err := l.Allow(ctx, "test:k"); err != nil {
			t.Fatalf("attempt %d should be allowed within the burst: %v", i, err)
		}
	}
	if err := l.Allow(ctx, "test:k"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("expected the burst to be exhausted, got %v", err)
	}

	clock.advance(time.Minute)
	if err := l.Allow(ctx, "test:k"); err != nil {
		t.Errorf("one token should have refilled after the interval, got %v", err)
	}
	if err := l.Allow(ctx, "test:k"); !errors.Is(err, ErrRateLimited) {
		t.Errorf("only one token should have refilled, got %v", err)
	}

	// Refill saturates at the burst rather than accumulating unboundedly.
	clock.advance(time.Hour)
	for i := range 2 {
		if err := l.Allow(ctx, "test:k"); err != nil {
			t.Fatalf("attempt %d after a long idle should be allowed: %v", i, err)
		}
	}
	if err := l.Allow(ctx, "test:k"); !errors.Is(err, ErrRateLimited) {
		t.Error("a long idle period must not bank more than the burst")
	}
}

// TestMemoryLimiterBoundsTrackedKeys guards against the limiter itself
// becoming the denial of service: unbounded distinct keys would grow forever.
func TestMemoryLimiterBoundsTrackedKeys(t *testing.T) {
	clock := newFakeClock()
	l := NewMemoryLimiter(withClock(clock.now), WithMaxTrackedKeys(64),
		WithBudget("test:", Budget{Burst: 1, Interval: time.Hour}))
	ctx := context.Background()

	for i := range 5000 {
		if err := l.Allow(ctx, fmt.Sprintf("test:%d", i)); err != nil {
			t.Fatalf("first attempt for a fresh key should be allowed: %v", err)
		}
	}

	l.mu.Lock()
	tracked := len(l.buckets)
	l.mu.Unlock()
	if tracked > 64 {
		t.Errorf("tracked keys must stay bounded, got %d for a cap of 64", tracked)
	}
}

func TestMemoryLimiterLongestPrefixWins(t *testing.T) {
	clock := newFakeClock()
	l := NewMemoryLimiter(withClock(clock.now),
		WithBudget("password:", Budget{Burst: 1, Interval: time.Hour}),
		WithBudget("password:ip:", Budget{Burst: 3, Interval: time.Hour}))
	ctx := context.Background()

	// "password:ip:..." must take the more specific budget of 3, not 1.
	for i := range 3 {
		if err := l.Allow(ctx, "password:ip:203.0.113.1"); err != nil {
			t.Fatalf("attempt %d should use the longer-prefix budget: %v", i, err)
		}
	}
	if err := l.Allow(ctx, "password:ip:203.0.113.1"); !errors.Is(err, ErrRateLimited) {
		t.Error("expected the longer-prefix budget to be exhausted after 3")
	}
}
