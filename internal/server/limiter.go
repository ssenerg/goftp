package server

import (
	"sync"
	"time"
)

// maxTrackedClients bounds the limiter's memory. When full, an arbitrary
// entry is evicted.
const maxTrackedClients = 100_000

// rateLimiter caps counted events, such as failed password checks, per key
// within a fixed window. Checking and counting happen under one lock, so
// concurrent guesses cannot slip past the budget.
type rateLimiter struct {
	max    int
	window time.Duration

	mu    sync.Mutex
	hits  map[string]*failures
	sweep time.Time
}

type failures struct {
	count int
	reset time.Time
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	return &rateLimiter{max: max, window: window, hits: make(map[string]*failures)}
}

// attempt returns how long key is still blocked, or 0 if the attempt may
// proceed, in which case it is counted if count is set.
func (l *rateLimiter) attempt(key string, count bool, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	f := l.hits[key]
	if f != nil && !now.Before(f.reset) {
		f = nil
	}
	if f != nil && f.count >= l.max {
		return f.reset.Sub(now)
	}
	if !count {
		return 0
	}
	if f == nil {
		l.evict(now)
		f = &failures{reset: now.Add(l.window)}
		l.hits[key] = f
	}
	f.count++
	return 0
}

// evict drops expired entries once per window and makes room when full.
func (l *rateLimiter) evict(now time.Time) {
	if !now.Before(l.sweep) || len(l.hits) >= maxTrackedClients {
		for k, f := range l.hits {
			if !now.Before(f.reset) {
				delete(l.hits, k)
			}
		}
		l.sweep = now.Add(l.window)
	}
	for k := range l.hits {
		if len(l.hits) < maxTrackedClients {
			break
		}
		delete(l.hits, k)
	}
}

// refund takes back one counted failure, for an attempt that was counted
// before it ran and then succeeded.
func (l *rateLimiter) refund(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if f := l.hits[key]; f != nil && f.count > 0 {
		f.count--
	}
}
