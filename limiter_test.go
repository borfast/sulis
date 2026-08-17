package sulis

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
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

	user, _, _, err := s.Register(ctx, "alice@example.com", "password123", RequestInfo{})
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
