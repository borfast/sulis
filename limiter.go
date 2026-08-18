package sulis

import (
	"context"
	"sync"
	"time"
)

// Budget describes how many attempts a key may make and how fast the
// allowance refills. Burst is both the bucket size and the number of attempts
// available after a long idle period; one token is restored every Interval.
type Budget struct {
	Burst    int
	Interval time.Duration
}

// Default budgets. Per-account budgets are deliberately generous and per-IP
// budgets deliberately tight: an attacker must not be able to lock a victim
// out by burning their account's allowance, but one host should not get many
// guesses across many accounts either.
var (
	budgetPasswordAccount = Budget{Burst: 10, Interval: 30 * time.Second}
	budgetPasswordIP      = Budget{Burst: 20, Interval: 5 * time.Second}
	budgetTokenAccount    = Budget{Burst: 5, Interval: 2 * time.Minute}
	budgetTokenIP         = Budget{Burst: 15, Interval: 20 * time.Second}
	budgetDefault         = Budget{Burst: 10, Interval: 30 * time.Second}
)

// MemoryLimiter is a per-process token-bucket Limiter. It is the default, so
// that a Sulis built with no options still resists guessing — a library whose
// documentation has to ask for rate limiting is a library that mostly runs
// without it.
//
// It is per-process: with several instances behind a load balancer, each
// enforces its own budget. Replace it with a shared implementation (Redis or
// similar) via WithLimiter for a multi-instance deployment.
//
// A single MemoryLimiter satisfies sulis.Limiter, totp.Limiter and
// recovery.Limiter, which are structurally identical, so one instance can
// guard all three packages. That identity is compiler-enforced rather than
// hoped for: see the assignability declarations at the top of
// limiter_test.go.
type MemoryLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket

	budgets  map[string]Budget // by key prefix, longest match wins
	fallback Budget
	maxKeys  int
	now      func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// MemoryLimiterOption configures a MemoryLimiter.
type MemoryLimiterOption func(*MemoryLimiter)

// WithBudget sets the budget for keys carrying the given prefix. The longest
// matching prefix wins.
func WithBudget(prefix string, b Budget) MemoryLimiterOption {
	return func(l *MemoryLimiter) { l.budgets[prefix] = b }
}

// WithMaxTrackedKeys bounds how many distinct keys are held in memory. A
// limiter that can be driven out of memory is a denial of service rather than
// a defence, so tracking is capped and the least recently used keys are
// dropped once the cap is reached.
func WithMaxTrackedKeys(n int) MemoryLimiterOption {
	return func(l *MemoryLimiter) { l.maxKeys = n }
}

// withClock injects a clock for tests, so they need not sleep.
func withClock(now func() time.Time) MemoryLimiterOption {
	return func(l *MemoryLimiter) { l.now = now }
}

// NewMemoryLimiter creates a token-bucket limiter with the default budgets.
func NewMemoryLimiter(opts ...MemoryLimiterOption) *MemoryLimiter {
	l := &MemoryLimiter{
		buckets: make(map[string]*bucket),
		budgets: map[string]Budget{
			"password:":    budgetPasswordAccount,
			"password:ip:": budgetPasswordIP,
			"reset:":       budgetTokenAccount,
			"reset:ip:":    budgetTokenIP,
			"magic:":       budgetTokenAccount,
			"magic:ip:":    budgetTokenIP,
			"totp:":        budgetPasswordAccount,
		},
		fallback: budgetDefault,
		maxKeys:  100_000,
		now:      time.Now,
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

// Allow consumes one token for key, returning ErrRateLimited when the key's
// bucket is empty.
func (l *MemoryLimiter) Allow(_ context.Context, key string) error {
	b := l.budgetFor(key)
	if b.Burst <= 0 || b.Interval <= 0 {
		return nil
	}

	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	bkt, ok := l.buckets[key]
	if !ok {
		l.evictIfNeededLocked()
		bkt = &bucket{tokens: float64(b.Burst), last: now}
		l.buckets[key] = bkt
	} else {
		refill := now.Sub(bkt.last).Seconds() / b.Interval.Seconds()
		if refill > 0 {
			bkt.tokens = min(float64(b.Burst), bkt.tokens+refill)
			bkt.last = now
		}
	}

	if bkt.tokens < 1 {
		return ErrRateLimited
	}
	bkt.tokens--
	return nil
}

// budgetFor returns the budget for the longest configured prefix matching key.
func (l *MemoryLimiter) budgetFor(key string) Budget {
	best := l.fallback
	bestLen := -1
	for prefix, b := range l.budgets {
		if len(prefix) > bestLen && len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			best, bestLen = b, len(prefix)
		}
	}
	return best
}

// evictIfNeededLocked drops tracked keys once the cap is reached. Buckets that
// have fully refilled carry no information, so they go first; if that is not
// enough, the least recently touched entries go too.
func (l *MemoryLimiter) evictIfNeededLocked() {
	if len(l.buckets) < l.maxKeys {
		return
	}

	now := l.now()
	for key, bkt := range l.buckets {
		b := l.budgetFor(key)
		if bkt.tokens+now.Sub(bkt.last).Seconds()/b.Interval.Seconds() >= float64(b.Burst) {
			delete(l.buckets, key)
		}
	}
	if len(l.buckets) < l.maxKeys {
		return
	}

	var oldestKey string
	var oldest time.Time
	for key, bkt := range l.buckets {
		if oldestKey == "" || bkt.last.Before(oldest) {
			oldestKey, oldest = key, bkt.last
		}
	}
	delete(l.buckets, oldestKey)
}

// allowIP consults the limiter on the IP dimension, if the caller supplied an
// address. Keyed separately from the account dimension so one host cannot
// spread guesses across many accounts unthrottled, and so an attacker cannot
// lock a victim out by exhausting the victim's own budget.
func (s *Sulis) allowIP(ctx context.Context, prefix string, ri RequestInfo) error {
	if ri.IP == "" {
		return nil
	}
	return s.allow(ctx, prefix+"ip:"+ri.IP, ri)
}
