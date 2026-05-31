package smtp

import (
	"sync"
	"time"
)

// Per-source-IP token bucket; `perMinute` refills linearly.
type ipLimiter struct {
	mu        sync.Mutex
	perMinute int
	buckets   map[string]*bucket
}

type bucket struct {
	tokens   float64
	lastFill time.Time
}

func newIPLimiter(perMinute int) *ipLimiter {
	if perMinute <= 0 {
		perMinute = 5
	}
	return &ipLimiter{
		perMinute: perMinute,
		buckets:   make(map[string]*bucket),
	}
}

func (l *ipLimiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[ip]
	if !ok {
		b = &bucket{tokens: float64(l.perMinute), lastFill: now}
		l.buckets[ip] = b
	} else {
		// Refill perMinute/60 tokens/sec, capped at perMinute.
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

// Idle ≥ maxIdle → fully refilled, so reaping doesn't change decisions.
func (l *ipLimiter) reap(now time.Time, maxIdle time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, b := range l.buckets {
		if now.Sub(b.lastFill) > maxIdle {
			delete(l.buckets, ip)
		}
	}
}
