package smtp

import (
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/ratelimit"
)

// ipLimiter is the per-source-IP token bucket; it wraps the shared
// ratelimit.Limiter, keeping the gateway's existing lower-case helpers.
type ipLimiter struct {
	*ratelimit.Limiter
}

func newIPLimiter(perMinute int) *ipLimiter {
	return &ipLimiter{ratelimit.New(perMinute)}
}

func (l *ipLimiter) reap(now time.Time, maxIdle time.Duration) {
	l.Reap(now, maxIdle)
}
