// Package ratelimit provides a per-key token-bucket limiter shared by the
// SMTP gateway and the forward-auth endpoint. Both face untrusted callers
// (LAN apps, external reverse proxies) and need to bound request rate per
// source IP without pulling in a dependency.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a per-key token bucket; perMinute tokens refill linearly and the
// bucket is capped at perMinute. Safe for concurrent use.
type Limiter struct {
	mu        sync.Mutex
	perMinute int
	buckets   map[string]*bucket
}

type bucket struct {
	tokens   float64
	lastFill time.Time
}

func New(perMinute int) *Limiter {
	if perMinute <= 0 {
		perMinute = 5
	}
	return &Limiter{
		perMinute: perMinute,
		buckets:   make(map[string]*bucket),
	}
}

// Allow consumes a token for key, returning false when the bucket is empty.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(l.perMinute), lastFill: now}
		l.buckets[key] = b
	} else {
		elapsed := now.Sub(b.lastFill).Seconds()
		b.tokens += elapsed * (float64(l.perMinute) / 60.0)
		if b.tokens > float64(l.perMinute) {
			b.tokens = float64(l.perMinute)
		}
		b.lastFill = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Reap drops buckets idle longer than maxIdle. A bucket idle that long has
// fully refilled, so removing it can't change a future decision — it only
// stops a churn of source keys from growing the map without bound.
func (l *Limiter) Reap(now time.Time, maxIdle time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, b := range l.buckets {
		if now.Sub(b.lastFill) > maxIdle {
			delete(l.buckets, key)
		}
	}
}
