package ratelimit

import (
	"testing"
	"time"
)

func TestLimiter_Burst(t *testing.T) {
	l := New(3) // 3 per minute
	for i := 0; i < 3; i++ {
		if !l.Allow("1.1.1.1") {
			t.Errorf("attempt %d should be allowed", i+1)
		}
	}
	if l.Allow("1.1.1.1") {
		t.Error("4th attempt within the same instant should be denied")
	}
	// Different key gets its own bucket.
	if !l.Allow("2.2.2.2") {
		t.Error("different key should get its own budget")
	}
}

func TestLimiter_NonPositiveDefaults(t *testing.T) {
	l := New(0)
	if !l.Allow("k") {
		t.Error("New(0) should fall back to a usable default, not deny everything")
	}
}

func TestLimiter_Reap(t *testing.T) {
	l := New(5)
	l.Allow("1.1.1.1")
	l.Allow("2.2.2.2")
	// Backdate one bucket so it looks idle.
	l.mu.Lock()
	l.buckets["1.1.1.1"].lastFill = time.Now().Add(-10 * time.Minute)
	l.mu.Unlock()

	l.Reap(time.Now(), 5*time.Minute)

	l.mu.Lock()
	_, stale := l.buckets["1.1.1.1"]
	_, fresh := l.buckets["2.2.2.2"]
	l.mu.Unlock()
	if stale {
		t.Error("idle bucket should have been reaped")
	}
	if !fresh {
		t.Error("recently-used bucket should survive reaping")
	}
}
