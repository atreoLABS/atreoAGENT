package relay

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// When the agent needs the relay but holds no grant, the loop must ask the
// coordination service for one — this request is the relay-usage signal.
func TestManagerRequestsGrantWhenRelayWanted(t *testing.T) {
	m := NewManager(nil, 51820, true, func() bool { return true })
	requested := make(chan struct{}, 1)
	m.SetRequester(func(context.Context, string) error {
		select {
		case requested <- struct{}{}:
		default:
		}
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)

	select {
	case <-requested:
	case <-time.After(2 * time.Second):
		t.Fatal("expected a grant request when the relay is wanted")
	}
}

// A non-CGNAT agent (relay not wanted) must never ask for a grant, so it never
// registers as a relay user.
func TestManagerSilentWhenRelayNotWanted(t *testing.T) {
	m := NewManager(nil, 51820, true, func() bool { return false })
	var calls int32
	m.SetRequester(func(context.Context, string) error {
		atomic.AddInt32(&calls, 1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	cancel()

	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Fatalf("expected no grant request when relay not wanted, got %d", got)
	}
}

// requestGrant is rate-limited so loop churn can't spam the coordination service.
func TestRequestGrantRateLimited(t *testing.T) {
	m := NewManager(nil, 51820, true, func() bool { return true })
	var calls int32
	m.SetRequester(func(context.Context, string) error {
		atomic.AddInt32(&calls, 1)
		return nil
	})

	m.requestGrant(context.Background(), "")
	m.requestGrant(context.Background(), "") // within the floor — skipped

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("want 1 request through the rate limiter, got %d", got)
	}
}

func TestGrantExpiryHelpers(t *testing.T) {
	var m Manager
	now := time.Now().Unix()

	if !m.grantExpired(Grant{ExpiresAt: now - 1}) {
		t.Fatal("past exp should be expired")
	}
	if m.grantExpired(Grant{ExpiresAt: now + 3600}) {
		t.Fatal("future exp should not be expired")
	}
	if !m.grantExpiring(Grant{ExpiresAt: now + 60}) {
		t.Fatal("exp within the refresh lead should be expiring")
	}
	if m.grantExpiring(Grant{ExpiresAt: now + 3600}) {
		t.Fatal("exp well beyond the lead should not be expiring")
	}
	if m.grantExpired(Grant{ExpiresAt: 0}) || m.grantExpiring(Grant{ExpiresAt: 0}) {
		t.Fatal("zero exp means never expires")
	}
}

// A send that fails (tunnel not attached yet) must not consume the rate-limit
// slot, so the very next attempt can retry immediately.
func TestRequestGrantFailedSendDoesNotRateLimit(t *testing.T) {
	m := NewManager(nil, 51820, true, func() bool { return true })
	var calls int32
	var failNext int32 = 1
	m.SetRequester(func(context.Context, string) error {
		atomic.AddInt32(&calls, 1)
		if atomic.LoadInt32(&failNext) == 1 {
			return errors.New("not attached")
		}
		return nil
	})

	m.requestGrant(context.Background(), "") // fails — must not set lastRequest
	atomic.StoreInt32(&failNext, 0)
	m.requestGrant(context.Background(), "") // immediate retry must go through

	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("want 2 calls (failed send not rate-limited), got %d", got)
	}
}

// After the first request fails (tunnel not yet attached), Wake must make the
// loop retry promptly rather than waiting out the retry interval.
func TestWakeTriggersGrantRequestAfterAttach(t *testing.T) {
	m := NewManager(nil, 51820, true, func() bool { return true })
	var attached int32
	got := make(chan struct{}, 1)
	m.SetRequester(func(context.Context, string) error {
		if atomic.LoadInt32(&attached) == 0 {
			return errors.New("not attached")
		}
		select {
		case got <- struct{}{}:
		default:
		}
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)

	time.Sleep(50 * time.Millisecond) // let the first (failing) attempt park on the timer
	atomic.StoreInt32(&attached, 1)
	m.Wake()

	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("Wake did not trigger a grant request after attach (would have waited the full retry interval)")
	}
}

// requestGrant passes the failed-relay-host hint through to the requester.
func TestRequestGrantPassesHint(t *testing.T) {
	m := NewManager(nil, 51820, true, func() bool { return true })
	got := make(chan string, 1)
	m.SetRequester(func(_ context.Context, failedHost string) error {
		got <- failedHost
		return nil
	})

	m.requestGrant(context.Background(), "relay1-data.example.com")
	select {
	case h := <-got:
		if h != "relay1-data.example.com" {
			t.Fatalf("hint = %q, want relay1-data.example.com", h)
		}
	case <-time.After(time.Second):
		t.Fatal("requester not called")
	}
}

// A failover request (hint set) bypasses the rate-limit floor, so it isn't
// dropped just because an unhinted request happened moments earlier.
func TestFailoverRequestBypassesRateLimit(t *testing.T) {
	m := NewManager(nil, 51820, true, func() bool { return true })
	var hinted int32
	m.SetRequester(func(_ context.Context, failedHost string) error {
		if failedHost != "" {
			atomic.AddInt32(&hinted, 1)
		}
		return nil
	})

	m.requestGrant(context.Background(), "")                        // consumes the floor
	m.requestGrant(context.Background(), "relay1-data.example.com") // must still go through

	if got := atomic.LoadInt32(&hinted); got != 1 {
		t.Fatalf("want the failover request to bypass the rate limit, hinted=%d", got)
	}
}

// Clearing keep-alive while the agent has a public path (relay no longer wanted)
// must tear down the live session at once, not leave it lingering.
func TestSetKeepAliveTearsDownSessionWhenNotWanted(t *testing.T) {
	m := NewManager(nil, 51820, true, func() bool { return false }) // has a public path
	m.SetKeepAlive(true)                                            // relay wanted via keep-alive

	cancelled := make(chan struct{})
	m.setSessionCancel(func() { close(cancelled) })

	m.SetKeepAlive(false) // not wanted anymore → cancel the live session
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("expected the live session to be torn down when the relay is no longer wanted")
	}
}

// Clearing keep-alive while there's NO public path must keep the session — the
// agent still needs the relay.
func TestSetKeepAliveKeepsSessionWhenStillCGNAT(t *testing.T) {
	m := NewManager(nil, 51820, true, func() bool { return true }) // no public path
	m.SetKeepAlive(true)

	var cancelled int32
	m.setSessionCancel(func() { atomic.AddInt32(&cancelled, 1) })

	m.SetKeepAlive(false) // still wanted via shouldRelay → must not cancel
	if atomic.LoadInt32(&cancelled) != 0 {
		t.Fatal("must not tear down the session while the agent has no public path")
	}
}

// SetKeepAlive makes the agent both want the relay and stick to its node.
func TestKeepAliveStickyAndWanted(t *testing.T) {
	// shouldRelay returns false (has a public path); keepalive must still win.
	m := NewManager(nil, 51820, true, func() bool { return false })

	if m.relayWanted() {
		t.Fatal("relay should not be wanted before keepalive")
	}
	if m.isSticky() {
		t.Fatal("should not be sticky before keepalive")
	}

	m.SetKeepAlive(true)
	if !m.relayWanted() {
		t.Fatal("keepalive must make the relay wanted even with a public path")
	}
	if !m.isSticky() {
		t.Fatal("keepalive must make the agent sticky")
	}

	m.SetKeepAlive(false)
	if m.relayWanted() || m.isSticky() {
		t.Fatal("clearing keepalive must drop wanted + sticky")
	}
}
