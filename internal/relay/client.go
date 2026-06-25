package relay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/atreoLABS/atreoAGENT/internal/canonjson"
	"github.com/atreoLABS/atreoAGENT/internal/crypto"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
)

// Control message types — must match the relay's control protocol.
const (
	typeHello         = "relay:hello"
	typeChallenge     = "relay:challenge"
	typeChallengeResp = "relay:challenge-resp"
	typeReady         = "relay:ready"
	typeRelease       = "relay:release"
	typeError         = "relay:error"

	challengeIntent = "relay:challenge"
)

type ctrlMsg struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type readyPayload struct {
	PublicHost   string `json:"publicHost"`
	DataPort     int    `json:"dataPort"`
	IngestPort   int    `json:"ingestPort"`
	SessionToken string `json:"sessionToken"`
}

// Manager owns the relay-client lifecycle: it (re)connects to the relay named in
// the latest grant, authenticates, runs the data shim, and exposes the endpoint
// the provision handler signs into a client's Endpoint.
type Manager struct {
	keyManager   *crypto.KeyManager
	wgListenPort int
	enabled      bool
	// shouldRelay reports whether the agent lacks a usable public inbound path.
	// The relay is fallback-only: it's advertised only while this is true.
	// Nil ⇒ always relay.
	shouldRelay func() bool

	mu          sync.Mutex
	grant       *SignedGrant
	info        Grant
	endpoint    string // relayHost:dataPort when a session is live
	started     bool
	request     func(context.Context, string) error // asks for a grant; arg = failed-host hint
	lastRequest time.Time                           // rate-limits grant requests
	keepAlive   bool                                // hold a relay session even with a public path
	// cancelSession drops the live session when the relay stops being wanted.
	cancelSession context.CancelFunc

	wake chan struct{}
}

func NewManager(km *crypto.KeyManager, wgListenPort int, enabled bool, shouldRelay func() bool) *Manager {
	return &Manager{
		keyManager:   km,
		wgListenPort: wgListenPort,
		enabled:      enabled,
		shouldRelay:  shouldRelay,
		wake:         make(chan struct{}, 1),
	}
}

func (m *Manager) relayWanted() bool {
	m.mu.Lock()
	keep := m.keepAlive
	m.mu.Unlock()
	if keep {
		return true
	}
	return m.shouldRelay == nil || m.shouldRelay()
}

// SetKeepAlive holds a relay session up even with a public path (manual relay
// configs depend on it). When it clears and the relay is no longer wanted, the
// live session is torn down at once rather than left to linger.
func (m *Manager) SetKeepAlive(keep bool) {
	m.mu.Lock()
	m.keepAlive = keep
	cancel := m.cancelSession
	m.mu.Unlock()
	if !m.relayWanted() && cancel != nil {
		cancel()
	}
	m.Wake()
}

func (m *Manager) setSessionCancel(c context.CancelFunc) {
	m.mu.Lock()
	m.cancelSession = c
	m.mu.Unlock()
}

// isSticky reports whether the agent must stay on its current relay node: manual
// relay configs are pinned to it, so it must not fail itself over to another.
func (m *Manager) isSticky() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keepAlive
}

const (
	grantRefreshLead    = 10 * time.Minute // re-request this long before expiry
	grantRetryInterval  = 60 * time.Second // re-ask cadence while waiting for a grant
	grantReqMinInterval = 30 * time.Second // floor between two unhinted requests

	// Failed sessions before asking to move to another node. Above 1 so a quick
	// relay restart reconnects to the same node rather than bouncing away.
	relayFailoverThreshold = 3
)

// SetRequester wires the callback that asks for a grant (it sends
// relay:grant:request over the tunnel; the string arg is a failed-host hint,
// empty for a normal request). Must be set before Start.
func (m *Manager) SetRequester(fn func(context.Context, string) error) {
	m.mu.Lock()
	m.request = fn
	m.mu.Unlock()
}

// requestGrant asks for a grant. Unhinted requests are rate-limited so loop churn
// can't spam the service; a failover hint bypasses the floor. A send that fails
// (e.g. the tunnel isn't attached yet) doesn't consume the slot, so a Wake can
// retry immediately.
func (m *Manager) requestGrant(ctx context.Context, failedHost string) {
	m.mu.Lock()
	req := m.request
	throttled := failedHost == "" && time.Since(m.lastRequest) < grantReqMinInterval
	m.mu.Unlock()
	if req == nil || throttled {
		return
	}
	if err := req(ctx, failedHost); err != nil {
		if !errors.Is(err, context.Canceled) {
			logging.Debug("relay: grant request not sent: %v", err)
		}
		return
	}
	m.mu.Lock()
	m.lastRequest = time.Now()
	m.mu.Unlock()
}

// Wake nudges the session loop to re-evaluate now instead of waiting out its
// timer. Non-blocking.
func (m *Manager) Wake() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *Manager) grantExpired(info Grant) bool {
	return info.ExpiresAt != 0 && time.Now().Unix() >= info.ExpiresAt
}

func (m *Manager) grantExpiring(info Grant) bool {
	return info.ExpiresAt != 0 && time.Now().Add(grantRefreshLead).Unix() >= info.ExpiresAt
}

// SetGrant stores the latest coordination-signed grant and wakes the loop.
func (m *Manager) SetGrant(sg SignedGrant) error {
	info, err := sg.Parse()
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.grant = &sg
	m.info = info
	m.mu.Unlock()
	m.Wake()
	return nil
}

// Endpoint returns relayHost:dataPort and true once a relay session is live; the
// provision handler signs it as the client Endpoint in relay mode.
func (m *Manager) Endpoint() (string, bool) {
	m.mu.Lock()
	ep := m.endpoint
	m.mu.Unlock()
	return ep, ep != "" && m.enabled && m.relayWanted()
}

func (m *Manager) setEndpoint(ep string) {
	m.mu.Lock()
	m.endpoint = ep
	m.mu.Unlock()
}

func (m *Manager) current() (SignedGrant, Grant, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.grant == nil {
		return SignedGrant{}, Grant{}, false
	}
	return *m.grant, m.info, true
}

// Start launches the session loop once; it idles until a grant arrives.
func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	if m.started || !m.enabled {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.mu.Unlock()
	go m.loop(ctx)
}

func (m *Manager) loop(ctx context.Context) {
	attempt := 0
	failures := 0 // consecutive sessions that never reached ready, for failover
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if !m.relayWanted() {
			select {
			case <-ctx.Done():
				return
			case <-m.wake:
			case <-time.After(30 * time.Second):
			}
			continue
		}

		sg, info, ok := m.current()
		if !ok || m.grantExpired(info) {
			m.requestGrant(ctx, "")
			select {
			case <-ctx.Done():
				return
			case <-m.wake:
			case <-time.After(grantRetryInterval):
			}
			continue
		}
		if m.grantExpiring(info) {
			m.requestGrant(ctx, "") // refresh ahead of expiry; keep using the valid one
		}

		established, err := m.runSession(ctx, sg, info)
		m.setEndpoint("")
		// A deliberate teardown (relay no longer wanted) can surface as a
		// non-Canceled socket error; don't log that as a failure.
		if err != nil && !errors.Is(err, context.Canceled) && m.relayWanted() {
			logging.Error("relay: session ended: %v", err)
		}
		// An established session resets the backoff (fast reconnect after a relay
		// restart); only genuinely failing dials escalate the delay.
		if established {
			attempt = 0
			failures = 0
		} else {
			failures++
			// Can't reach the assigned node — ask to move, unless we're sticky
			// (manual relay configs pin us here; we follow the node's DNS switch).
			if failures >= relayFailoverThreshold {
				if m.isSticky() {
					failures = 0
				} else {
					logging.Info("relay: %s unreachable after %d attempts — requesting failover", info.RelayHost, failures)
					m.requestGrant(ctx, info.RelayHost)
					failures = 0
				}
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff(attempt)):
		case <-m.wake:
		}
		attempt++
	}
}

// runSession dials control, authenticates, opens the data association, and runs
// the shim until control or data fails. The bool reports whether the session
// reached the ready state — an established session resets the loop's backoff.
func (m *Manager) runSession(ctx context.Context, sg SignedGrant, info Grant) (bool, error) {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Expose the canceller so SetKeepAlive can drop this session promptly.
	m.setSessionCancel(cancel)
	defer m.setSessionCancel(nil)

	conn, _, err := websocket.Dial(sctx, info.ControlURL, nil)
	if err != nil {
		return false, fmt.Errorf("dial relay control: %w", err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "closing")

	ready, err := m.authenticate(sctx, conn, sg, info)
	if err != nil {
		return false, err
	}

	host := ready.PublicHost
	if host == "" {
		host = info.RelayHost
	}
	token, err := hex.DecodeString(ready.SessionToken)
	if err != nil || len(token) != sessionTokenLen {
		return false, fmt.Errorf("relay: bad session token")
	}

	ingest, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(ready.IngestPort)))
	if err != nil {
		return false, fmt.Errorf("resolve relay ingest: %w", err)
	}
	dataConn, err := net.DialUDP("udp", nil, ingest)
	if err != nil {
		return false, fmt.Errorf("dial relay ingest: %w", err)
	}
	defer dataConn.Close()

	m.setEndpoint(net.JoinHostPort(host, strconv.Itoa(ready.DataPort)))
	logging.Info("relay: session ready endpoint=%s ingest=%s", net.JoinHostPort(host, strconv.Itoa(ready.DataPort)), ingest)

	sh := newShim(dataConn, token, m.wgListenPort)

	// Run the data shim and control watcher together; either ending tears the
	// session down so the loop reconnects.
	errCh := make(chan error, 2)
	go func() { errCh <- sh.run(sctx) }()
	go func() { errCh <- m.watchControl(sctx, conn) }()

	select {
	case <-ctx.Done():
		return true, ctx.Err()
	case err := <-errCh:
		cancel()
		_ = dataConn.Close()
		return true, err
	}
}

// watchControl pings the control WS and reads it so a relay-side teardown (or a
// dead socket) ends the session promptly.
func (m *Manager) watchControl(ctx context.Context, conn *websocket.Conn) error {
	pingCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		t := time.NewTicker(25 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-pingCtx.Done():
				return
			case <-t.C:
				pctx, pc := context.WithTimeout(pingCtx, 10*time.Second)
				err := conn.Ping(pctx)
				pc()
				if err != nil {
					cancel()
					return
				}
			}
		}
	}()
	for {
		var msg ctrlMsg
		if err := wsjson.Read(ctx, conn, &msg); err != nil {
			return err
		}
		if msg.Type == typeRelease {
			return errors.New("relay released session")
		}
	}
}

func (m *Manager) authenticate(ctx context.Context, conn *websocket.Conn, sg SignedGrant, info Grant) (readyPayload, error) {
	hctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if err := writeCtrl(hctx, conn, typeHello, map[string]any{"grant": sg}); err != nil {
		return readyPayload{}, err
	}

	var chMsg ctrlMsg
	if err := wsjson.Read(hctx, conn, &chMsg); err != nil {
		return readyPayload{}, err
	}
	if chMsg.Type == typeError {
		return readyPayload{}, fmt.Errorf("relay rejected hello: %s", string(chMsg.Payload))
	}
	if chMsg.Type != typeChallenge {
		return readyPayload{}, fmt.Errorf("expected relay:challenge, got %q", chMsg.Type)
	}
	var ch struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(chMsg.Payload, &ch); err != nil {
		return readyPayload{}, err
	}

	transcript, err := canonjson.Marshal(map[string]any{
		"intent":    challengeIntent,
		"deviceId":  info.DeviceID,
		"nonce":     ch.Nonce,
		"relayHost": info.RelayHost,
	})
	if err != nil {
		return readyPayload{}, err
	}
	if err := writeCtrl(hctx, conn, typeChallengeResp, map[string]any{"signature": m.keyManager.Sign(transcript)}); err != nil {
		return readyPayload{}, err
	}

	var rdMsg ctrlMsg
	if err := wsjson.Read(hctx, conn, &rdMsg); err != nil {
		return readyPayload{}, err
	}
	if rdMsg.Type == typeError {
		return readyPayload{}, fmt.Errorf("relay rejected challenge: %s", string(rdMsg.Payload))
	}
	if rdMsg.Type != typeReady {
		return readyPayload{}, fmt.Errorf("expected relay:ready, got %q", rdMsg.Type)
	}
	var ready readyPayload
	if err := json.Unmarshal(rdMsg.Payload, &ready); err != nil {
		return readyPayload{}, err
	}
	return ready, nil
}

func writeCtrl(ctx context.Context, conn *websocket.Conn, typ string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return wsjson.Write(ctx, conn, ctrlMsg{Type: typ, Payload: raw})
}

var backoffSteps = []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}

func backoff(attempt int) time.Duration {
	base := backoffSteps[len(backoffSteps)-1]
	if attempt < len(backoffSteps) {
		base = backoffSteps[attempt]
	}
	return time.Duration(float64(base) * (0.75 + 0.5*rand.Float64()))
}
