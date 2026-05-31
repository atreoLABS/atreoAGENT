package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/crypto"
)

type MessageHandler func(msg atreolink.TunnelMessage) (*atreolink.TunnelMessage, error)

// Callers wanting at-least-once delivery should retry via SetOnConnect.
var ErrNotAttached = errors.New("tunnel: no active WebSocket connection")

type Client struct {
	atreolink        *atreolink.Client
	handlers         map[string]MessageHandler
	atreolinkURL     string
	keyManager       *crypto.KeyManager
	deviceID         string
	reconnectAttempt int
	onConnect        func() []atreolink.TunnelMessage
	stopCh           chan struct{}
	mu               sync.RWMutex

	writeMu    sync.Mutex
	activeConn *websocket.Conn
}

// The WS upgrade is authenticated by an Ed25519 signature in the URL
// query string.
func NewClient(atreolinkClient *atreolink.Client, atreolinkURL string, km *crypto.KeyManager, deviceID string) *Client {
	return &Client{
		atreolink:    atreolinkClient,
		handlers:     make(map[string]MessageHandler),
		atreolinkURL: atreolinkURL,
		keyManager:   km,
		deviceID:     deviceID,
		stopCh:       make(chan struct{}),
	}
}

// onConnect runs after every successful WS attach; returned messages
// are pushed before the read loop starts.
func (c *Client) SetOnConnect(fn func() []atreolink.TunnelMessage) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onConnect = fn
}

func (c *Client) RegisterHandler(msgType string, handler MessageHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handlers[msgType] = handler
}

// Start reconnects with exponential backoff on disconnect.
func (c *Client) Start(ctx context.Context) error {
	logging.Info("Tunnel client starting")

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-c.stopCh:
			return nil
		default:
		}

		err := c.runWebSocket(ctx)
		if err != nil {
			logging.Error("Tunnel WebSocket error: %v", err)
		}

		if err := c.waitForReconnect(ctx); err != nil {
			return err
		}
	}
}

func (c *Client) Stop() {
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
}

// deviceId lives inside the signed intent; a separate query param would
// invite a confused-deputy bug.
func (c *Client) wsURL() (string, error) {
	if c.deviceID == "" || c.keyManager == nil {
		return "", errors.New("tunnel: wsURL requires deviceID + keyManager (agent paired?)")
	}
	intent, ts, sig, err := c.keyManager.SignWSConnectAuth(c.deviceID)
	if err != nil {
		return "", err
	}
	u := c.atreolinkURL
	if strings.HasPrefix(u, "https://") {
		u = "wss://" + strings.TrimPrefix(u, "https://")
	} else if strings.HasPrefix(u, "http://") {
		u = "ws://" + strings.TrimPrefix(u, "http://")
	} else {
		u = "wss://" + u
	}
	u = strings.TrimRight(u, "/")
	q := url.Values{
		"intent": []string{intent},
		"ts":     []string{strconv.FormatInt(ts, 10)},
		"sig":    []string{sig},
	}
	return u + "/v1/tunnel?" + q.Encode(), nil
}

// 25s app-level ping defeats silent NAT/CGNAT/router idle timeouts:
// without it the TCP socket can drop while writes pile up in a dead
// send buffer.
func (c *Client) runWebSocket(ctx context.Context) error {
	wsCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	u, err := c.wsURL()
	if err != nil {
		return err
	}
	conn, _, err := websocket.Dial(wsCtx, u, nil)
	if err != nil {
		return err
	}
	// Default read limit (~32 KiB) is too small for a full DeviceState.
	conn.SetReadLimit(1 << 20)
	defer func() { _ = conn.Close(websocket.StatusNormalClosure, "closing") }()

	c.writeMu.Lock()
	c.activeConn = conn
	c.writeMu.Unlock()
	defer func() {
		c.writeMu.Lock()
		c.activeConn = nil
		c.writeMu.Unlock()
	}()

	logging.Info("Tunnel WebSocket connected")
	c.reconnectAttempt = 0

	c.mu.RLock()
	onConnect := c.onConnect
	c.mu.RUnlock()
	if onConnect != nil {
		for _, m := range onConnect() {
			if werr := c.writeLocked(wsCtx, conn, m); werr != nil {
				logging.Error("Tunnel on-connect publish failed for %q: %v", m.Type, werr)
				break
			}
		}
	}

	// Ping in a goroutine so it doesn't block the read; cancel wsCtx
	// on failure to trigger reconnect.
	pingDone := make(chan struct{})
	go func() {
		defer close(pingDone)
		t := time.NewTicker(25 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-wsCtx.Done():
				return
			case <-t.C:
				pctx, pcancel := context.WithTimeout(wsCtx, 10*time.Second)
				err := conn.Ping(pctx)
				pcancel()
				if err != nil {
					logging.Error("Tunnel WebSocket ping failed: %v — forcing reconnect", err)
					cancel()
					return
				}
			}
		}
	}()

	readErr := c.readLoop(wsCtx, conn)
	cancel()
	<-pingDone
	return readErr
}

func (c *Client) readLoop(wsCtx context.Context, conn *websocket.Conn) error {
	for {
		select {
		case <-wsCtx.Done():
			return wsCtx.Err()
		case <-c.stopCh:
			return nil
		default:
		}

		var msg atreolink.TunnelMessage
		if err := wsjson.Read(wsCtx, conn, &msg); err != nil {
			return err
		}

		resp := c.dispatch(msg)
		if resp != nil {
			if err := c.writeLocked(wsCtx, conn, *resp); err != nil {
				return err
			}
		}
	}
}

func (c *Client) writeLocked(ctx context.Context, conn *websocket.Conn, msg atreolink.TunnelMessage) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return wsjson.Write(ctx, conn, msg)
}

func (c *Client) Send(ctx context.Context, msg atreolink.TunnelMessage) error {
	c.writeMu.Lock()
	conn := c.activeConn
	c.writeMu.Unlock()
	if conn == nil {
		return ErrNotAttached
	}
	// Short timeout: the ping loop will catch the dead socket within 35s
	// anyway; don't block the caller in the meantime.
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return c.writeLocked(wctx, conn, msg)
}

func (c *Client) dispatch(msg atreolink.TunnelMessage) *atreolink.TunnelMessage {
	c.mu.RLock()
	handler, ok := c.handlers[msg.Type]
	c.mu.RUnlock()

	if !ok {
		logging.Debug("Tunnel: no handler for message type %q", msg.Type)
		return nil
	}

	resp, err := handler(msg)
	if err != nil {
		logging.Error("Tunnel: handler error for %q: %v", msg.Type, err)
		return nil
	}
	return resp
}

// Capped at 8s so the worst-case dial gap (10s after ±25% jitter) sits
// inside atreoLINK's 15s reply ceiling on /connect/init and /connect/complete.
var backoffDurations = []time.Duration{
	1 * time.Second,
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
}

func (c *Client) waitForReconnect(ctx context.Context) error {
	delay := c.backoffDuration(c.reconnectAttempt)
	c.reconnectAttempt++
	logging.Debug("Tunnel: WebSocket disconnected, reconnecting in %v", delay)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.stopCh:
		return nil
	case <-timer.C:
		return nil
	}
}

func (c *Client) backoffDuration(attempt int) time.Duration {
	base := backoffDurations[len(backoffDurations)-1]
	if attempt < len(backoffDurations) {
		base = backoffDurations[attempt]
	}
	// ±25% jitter — anti-thundering-herd, not security; math/rand is fine.
	return time.Duration(float64(base) * (0.75 + 0.5*rand.Float64()))
}

func MarshalMessage(msgType, correlationID string, payload interface{}) (atreolink.TunnelMessage, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return atreolink.TunnelMessage{}, err
	}
	return atreolink.TunnelMessage{
		Type:          msgType,
		CorrelationID: correlationID,
		Payload:       data,
	}, nil
}
