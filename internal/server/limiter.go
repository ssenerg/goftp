package server

import (
	"errors"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
)

// maxTrackedClients bounds the limiter's memory; beyond it new clients are
// not tracked until old entries expire.
const maxTrackedClients = 100_000

// failureLimiter blocks a client after too many 4xx responses within a
// fixed window. Only completed failures count, so concurrent successful
// requests can never lock a client out.
type failureLimiter struct {
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

func newFailureLimiter(max int, window time.Duration) *failureLimiter {
	return &failureLimiter{max: max, window: window, hits: make(map[string]*failures)}
}

// blockedFor returns how long key remains blocked, or 0.
func (l *failureLimiter) blockedFor(key string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.hits[key]
	if f == nil || f.count < l.max || !now.Before(f.reset) {
		return 0
	}
	return f.reset.Sub(now)
}

func (l *failureLimiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !now.Before(l.sweep) {
		for k, f := range l.hits {
			if !now.Before(f.reset) {
				delete(l.hits, k)
			}
		}
		l.sweep = now.Add(l.window)
	}
	f := l.hits[key]
	if f == nil || !now.Before(f.reset) {
		if f == nil && len(l.hits) >= maxTrackedClients {
			return
		}
		f = &failures{reset: now.Add(l.window)}
		l.hits[key] = f
	}
	f.count++
}

// limitFailures runs as route middleware, so Fiber's request-level error
// pass (malformed requests, idle timeouts) never reaches it.
func (s *Server) limitFailures(c fiber.Ctx) error {
	key := clientKey(c.IP())
	if wait := s.limiter.blockedFor(key, time.Now()); wait > 0 {
		c.Set(fiber.HeaderRetryAfter, strconv.Itoa(int(math.Ceil(wait.Seconds()))))
		return fiber.ErrTooManyRequests
	}
	err := c.Next()
	if code := statusOf(c, err); code >= 400 && code < 500 {
		s.limiter.fail(key, time.Now())
	}
	return err
}

func statusOf(c fiber.Ctx, err error) int {
	var fe *fiber.Error
	switch {
	case err == nil:
		return c.Response().StatusCode()
	case errors.As(err, &fe):
		return fe.Code
	default:
		return fiber.StatusInternalServerError
	}
}
