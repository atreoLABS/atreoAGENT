package atreolink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/banner"
	"github.com/atreoLABS/atreoAGENT/internal/crypto"
)

type App struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	InternalURL string `json:"internalUrl"`
	Icon        string `json:"icon"`
	// Type is "port" for a raw host port or "" / "proxy" for an HTTP service.
	Type string `json:"type,omitempty"`
	Port int    `json:"port,omitempty"`
	// "tcp" | "udp" | "http" | "https", port apps only. http/https are L7
	// hints so clients open the port as a link; the firewall treats them as tcp.
	Protocol string `json:"protocol,omitempty"`
}

func (a *App) IsPort() bool {
	return a.Type == "port"
}

// EffectiveSlug returns the slug, deriving from Name if empty.
func (a *App) EffectiveSlug() string {
	if a.Slug != "" {
		return a.Slug
	}
	return Slugify(a.Name)
}

// Slugify converts a name to a URL-safe slug.
func Slugify(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	result := make([]byte, 0, len(s))
	lastHyphen := false
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			result = append(result, byte(c))
			lastHyphen = false
		} else if !lastHyphen && len(result) > 0 {
			result = append(result, '-')
			lastHyphen = true
		}
	}
	if len(result) > 0 && result[len(result)-1] == '-' {
		result = result[:len(result)-1]
	}
	return string(result)
}

// JoinAttestation: ownerSig over the canonical InvitePayload, plus an
// acceptanceSig over the inviting member's IdentityPublic under the
// `invitePub` embedded in InvitePayload. All three fields are base64.
type JoinAttestation struct {
	InvitePayload string `json:"invitePayload"`
	OwnerSig      string `json:"ownerSig"`
	AcceptanceSig string `json:"acceptanceSig"`
}

// AdmittanceCertificate is the agent-signed durable record of admission.
// Signature is base64 Ed25519 over canonjson of the remaining fields.
type AdmittanceCertificate struct {
	MemberID             string   `json:"memberId"`
	IdentityKey          string   `json:"identityKey"`
	NASPubkey            string   `json:"nasPubkey"`
	AdmittedAt           int64    `json:"admittedAt"`
	AttestationHash      string   `json:"attestationHash"`
	InitialAllowedAppIDs []string `json:"initialAllowedAppIds"`
	Signature            string   `json:"signature"`
}

// Exactly one of JoinAttestation or Admittance is set on non-owner entries.
type MemberACLEntry struct {
	MemberID         string                 `json:"memberId"`
	UserID           string                 `json:"userId"`
	MemberName       string                 `json:"memberName"`
	Email            string                 `json:"email,omitempty"` // lowercased; SMTP RCPT routes against this
	Role             string                 `json:"role"`
	IdentityKey      string                 `json:"identityKey"`
	IdentityKeyProof *string                `json:"identityKeyProof,omitempty"`
	JoinAttestation  *JoinAttestation       `json:"joinAttestation,omitempty"`
	Admittance       *AdmittanceCertificate `json:"admittance,omitempty"`
	Clients          []ClientRecord         `json:"clients"`
	AllowedApps      []App                  `json:"allowedApps"`
	Status           string                 `json:"status"`
}

// atreoLINK may emit an empty TunnelIP — the agent owns allocation.
type ClientRecord struct {
	WGPublicKey string `json:"wgPublicKey"`
	TunnelIP    string `json:"tunnelIp,omitempty"`
	Label       string `json:"label,omitempty"`
	Platform    string `json:"platform,omitempty"`
}

// DSEnvelope is one user-signed envelope inside a DeviceState. Signature is
// base64; Payload is the verbatim signed bytes, re-canonicalised + verified.
type DSEnvelope struct {
	Payload   json.RawMessage `json:"payload"`
	SignerID  string          `json:"signerId,omitempty"`
	Signature string          `json:"signature,omitempty"`
}

// AsMessage adapts an envelope so the envelope-verify path can check it.
func (e *DSEnvelope) AsMessage(msgType string) TunnelMessage {
	return TunnelMessage{Type: msgType, Payload: e.Payload, SignerID: e.SignerID, Signature: e.Signature}
}

type DSClient struct {
	WGPublicKey          string      `json:"wgPublicKey"`
	Label                string      `json:"label,omitempty"`
	Platform             string      `json:"platform,omitempty"`
	RegistrationEnvelope *DSEnvelope `json:"registrationEnvelope"`
	// IPLease is the agent's signed proof of the IP it issued for this
	// pubkey; re-verified against its own key. See TunnelIPLease.
	IPLease *TunnelIPLease `json:"ipLease,omitempty"`
}

// TunnelIPLease is the agent's self-signed binding of (deviceId, wgPublicKey)
// to a tunnel IP it allocated, replayed back later so it can restore the same
// IP after losing local state. NASSignature is Ed25519 over the canonical JSON
// of {deviceId, wgPublicKey, tunnelIp}.
type TunnelIPLease struct {
	DeviceID     string `json:"deviceId"`
	WGPublicKey  string `json:"wgPublicKey"`
	TunnelIP     string `json:"tunnelIp"`
	NASSignature string `json:"nasSignature"`
}

type DSMember struct {
	MemberID            string                 `json:"memberId"`
	UserID              string                 `json:"userId"`
	MemberName          string                 `json:"memberName"`
	Email               string                 `json:"email,omitempty"`
	Role                string                 `json:"role"`
	IdentityKey         string                 `json:"identityKey"`
	JoinAttestation     *JoinAttestation       `json:"joinAttestation,omitempty"`
	Admittance          *AdmittanceCertificate `json:"admittance,omitempty"`
	StatusEnvelope      *DSEnvelope            `json:"statusEnvelope"`
	PermissionsEnvelope *DSEnvelope            `json:"permissionsEnvelope"`
	Clients             []DSClient             `json:"clients"`
}

type DSApp struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Slug        string      `json:"slug"`
	InternalURL string      `json:"internalUrl"`
	Icon        string      `json:"icon"`
	Envelope    *DSEnvelope `json:"envelope"`
}

type DSCustomDomain struct {
	Envelope DSEnvelope `json:"envelope"`
}

// DeviceState is the complete current signed ACL, served on attach and on
// every change. Generation is unsigned transport metadata.
type DeviceState struct {
	DeviceID     string          `json:"deviceId"`
	Generation   int64           `json:"generation"`
	Members      []DSMember      `json:"members"`
	Apps         []DSApp         `json:"apps"`
	CustomDomain *DSCustomDomain `json:"customDomain"`
}

// Signature is over the canonical-JSON encoding of Payload — see
// internal/canonjson and internal/tunnel/verify.go.
type TunnelMessage struct {
	Type          string          `json:"type"`
	CorrelationID string          `json:"correlationId"`
	Payload       json.RawMessage `json:"payload"`
	SignerID      string          `json:"signerId,omitempty"`
	Signature     string          `json:"signature,omitempty"`
}

type PairingInitResponse struct {
	SessionID string `json:"sessionId"`
	UserCode  string `json:"userCode"`
	AuthURL   string `json:"authUrl"`
}

// AES-256-GCM ciphertext, AAD-free; the key is HKDF(pairToken,
// "atreos-pair-v1"). Both fields are base64; Nonce is 12 bytes.
type PairApprovalBlob struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// ApprovalBlob is populated when Status == "approved"; the agent must
// decrypt and verify it before pinning the owner pubkey.
type PairingPollResponse struct {
	Status        string            `json:"status"`
	DeviceID      string            `json:"deviceId"`
	AppsHostname  string            `json:"appsHostname"`
	TunnelHost    string            `json:"tunnelHost,omitempty"`
	ApprovalBlob  *PairApprovalBlob `json:"approvalBlob,omitempty"`
	OwnerMemberID string            `json:"ownerMemberId,omitempty"`
	// Owner* fields bootstrap the local owner ACL entry; atreoLINK's ACL
	// replay omits owner rows, so without these the agent can't resolve
	// the owner by userId or email.
	OwnerUserID string `json:"ownerUserId,omitempty"`
	OwnerEmail  string `json:"ownerEmail,omitempty"`
	OwnerName   string `json:"ownerName,omitempty"`
}

// The agent's Ed25519 identity key doubles as the credential for atreoLINK
// HTTP calls; no bearer token is stored anywhere. The family-bound
// clients are used by UpdateEndpoint so atreoLINK observes the agent's
// source IP family per request and updates the matching A/AAAA record;
// without explicit pinning Happy Eyeballs almost always picks IPv6.
type Client struct {
	baseURL      string
	deviceID     string
	keyManager   *crypto.KeyManager
	httpClient   *http.Client
	httpClientV4 *http.Client
	httpClientV6 *http.Client
}

// deviceID may be empty pre-pairing — only the unauthenticated init/poll
// calls run before pairing completes.
func NewClient(baseURL string, km *crypto.KeyManager, deviceID string) *Client {
	return &Client{
		baseURL:    baseURL,
		deviceID:   deviceID,
		keyManager: km,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		httpClientV4: familyBoundClient("tcp4", nil),
		httpClientV6: familyBoundClient("tcp6", nil),
	}
}

// familyBoundClient returns an http.Client whose dialer is pinned to the
// given network ("tcp4" or "tcp6"). Resolver.PreferGo ensures the family
// hint is honoured on platforms where the cgo resolver would otherwise
// ignore it; Happy Eyeballs cannot intervene because the resolver only
// returns addresses of the chosen family. A dial failure (e.g.
// ENETUNREACH on a v4-only host) surfaces fast.
//
// localAddr, when non-nil, pins the source address of the connection. The
// dual-family DDNS update uses this to force the v6 source onto a stable
// address so atreoLINK records that as the AAAA rather than the temporary
// address the kernel would otherwise select.
func familyBoundClient(family string, localAddr net.Addr) *http.Client {
	dialer := familyDialer(localAddr)
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, family, addr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   8 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
}

// familyDialer builds the dialer used by familyBoundClient. localAddr, when
// non-nil, pins the connection's source address.
func familyDialer(localAddr net.Addr) *net.Dialer {
	return &net.Dialer{
		Timeout:   8 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  &net.Resolver{PreferGo: true},
		LocalAddr: localAddr,
	}
}

func (c *Client) SetDeviceID(deviceID string) {
	c.deviceID = deviceID
}

// pairTokenHash is the hex SHA-256 of the agent's pairToken; atreoLINK
// stores it on the pairing session so the browser can prove possession
// of the matching token at approval time.
func (c *Client) InitPairing(ctx context.Context, fingerprint, hostname, nasPublicKey, pairTokenHash string) (*PairingInitResponse, error) {
	body := map[string]string{
		"fingerprint":   fingerprint,
		"hostname":      hostname,
		"nasPublicKey":  nasPublicKey,
		"pairTokenHash": pairTokenHash,
	}
	var resp PairingInitResponse
	if err := c.post(ctx, "/v1/auth/device/init", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) PollPairing(ctx context.Context, sessionID string) (*PairingPollResponse, error) {
	var resp PairingPollResponse
	if err := c.get(ctx, fmt.Sprintf("/v1/auth/device/poll?session=%s", sessionID), &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// EndpointResult echoes the DDNS hostname and the IP it now points at.
type EndpointResult struct {
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
}

// UpdateEndpoint refreshes the per-device DDNS record. When ipOverride is
// set, a single request carries the override and the server writes the
// matching record. Otherwise the agent fires two concurrent requests on
// family-bound sockets — atreoLINK reads the source family of each and
// updates the A or AAAA record accordingly. Each family runs under an
// independent 10 s deadline so a hung family can't delay the other; an
// at-least-one-success path returns successfully and logs the partial
// failure as a warning. Both families failing is the only error.
//
// v6Source, when non-nil, pins the source address of the v6 request to a
// stable global address. Without it the kernel prefers an RFC 4941 privacy
// temporary, so atreoLINK would record an AAAA that rotates away within hours.
// It is rebuilt per call because the stable prefix can change across ISP lease
// / SLAAC events.
func (c *Client) UpdateEndpoint(ctx context.Context, ipOverride string, v6Source net.IP) ([]EndpointResult, error) {
	if ipOverride != "" {
		var r EndpointResult
		if err := c.authPost(ctx, "device:endpoint", "/v1/device/endpoint",
			map[string]string{"ip": ipOverride}, &r); err != nil {
			return nil, err
		}
		return []EndpointResult{r}, nil
	}

	type famAttempt struct {
		label  string
		client *http.Client
	}
	v6Client := c.httpClientV6
	if v6Source != nil {
		v6Client = familyBoundClient("tcp6", &net.TCPAddr{IP: v6Source})
	}
	attempts := []famAttempt{
		{"v4", c.httpClientV4},
		{"v6", v6Client},
	}

	type famResult struct {
		label string
		res   EndpointResult
		err   error
	}
	results := make([]famResult, len(attempts))

	var wg sync.WaitGroup
	for i, a := range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			famCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			var r EndpointResult
			err := c.authPostVia(famCtx, a.client, "device:endpoint", "/v1/device/endpoint", nil, &r)
			results[i] = famResult{label: a.label, res: r, err: err}
		}()
	}
	wg.Wait()

	var ok []EndpointResult
	var fails []string
	for _, r := range results {
		if r.err != nil {
			fails = append(fails, fmt.Sprintf("%s: %v", r.label, r.err))
			continue
		}
		ok = append(ok, r.res)
	}
	if len(ok) == 0 {
		return nil, fmt.Errorf("device:endpoint failed on both families: %s", strings.Join(fails, "; "))
	}
	if len(fails) > 0 {
		logging.Warn("Warning: device:endpoint partial failure: %s", strings.Join(fails, "; "))
	}
	return ok, nil
}

func (c *Client) DNSPresent(ctx context.Context, fqdn, value string) error {
	return c.authPost(ctx, "dns:present", "/v1/dns/present", map[string]string{"fqdn": fqdn, "value": value}, nil)
}

func (c *Client) DNSCleanup(ctx context.Context, fqdn, value string) error {
	return c.authPost(ctx, "dns:cleanup", "/v1/dns/cleanup", map[string]string{"fqdn": fqdn, "value": value}, nil)
}

func (c *Client) get(ctx context.Context, path string, result interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	return c.doJSON(req, result)
}

func (c *Client) post(ctx context.Context, path string, body, result interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.doJSON(req, result)
}

// authPost wraps body in an identity-signed envelope. intentPrefix is the
// command name atreoLINK matches against the URL it routes; the
// canonical-JSON payload includes intent + ts + deviceId.
func (c *Client) authPost(ctx context.Context, intentPrefix, path string, body, result interface{}) error {
	return c.authPostVia(ctx, c.httpClient, intentPrefix, path, body, result)
}

// authPostVia mirrors authPost but lets the caller pick the http.Client.
// UpdateEndpoint uses this with the family-bound clients so atreoLINK
// sees the source family of each request and updates the matching DDNS
// record. Every request gets its own fresh-ts signature.
func (c *Client) authPostVia(ctx context.Context, httpClient *http.Client, intentPrefix, path string, body, result interface{}) error {
	if c.deviceID == "" {
		return fmt.Errorf("authPost: deviceID not set (agent not paired?)")
	}
	if c.keyManager == nil {
		return fmt.Errorf("authPost: keyManager not set")
	}
	envelope, err := c.keyManager.SignAgentAuth(c.deviceID, intentPrefix, body)
	if err != nil {
		return fmt.Errorf("sign auth envelope: %w", err)
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.doJSONWith(httpClient, req, result)
}

func (c *Client) doJSON(req *http.Request, result interface{}) error {
	return c.doJSONWith(c.httpClient, req, result)
}

func (c *Client) doJSONWith(httpClient *http.Client, req *http.Request, result interface{}) error {
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	if result != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// libsodium sealed-box ciphertext (ephemeral pubkey embedded in Ct).
// atreoLINK relays it opaquely and cannot decrypt.
type SealedField struct {
	Ct string `json:"ct"`
}

// Summary is what the push transport delivers and the lockscreen shows;
// html and plaintext are only fetched when the user opens the notification.
type NotificationEnvelope struct {
	UserID    string       `json:"userId"`
	AgentID   string       `json:"agentId"`
	Summary   SealedField  `json:"summary"`
	HTML      *SealedField `json:"html,omitempty"`
	Plaintext *SealedField `json:"plaintext,omitempty"`
	Severity  string       `json:"severity"`
}

func (c *Client) SendNotification(ctx context.Context, env NotificationEnvelope) error {
	return c.authPost(ctx, "notifications:send", "/v1/notifications", env, nil)
}

// OwnerIdentityPubkey must be persisted before any owner-signed message
// is processed — without that anchor, invite verification is trustable
// only against a key atreoLINK chose.
type PairResult struct {
	DeviceID             string
	AppsHostname         string
	TunnelHost           string
	OwnerIdentityPubkey  []byte
	OwnerMemberID        string
	OwnerUserID          string
	OwnerEmail           string
	OwnerName            string
	ApprovalPayloadCanon []byte
	ApprovedAt           string
}

type PairOption func(*pairOpts)

type pairOpts struct {
	// Injected so AES-GCM + Ed25519 logic stays in the tunnel package
	// (avoids an import cycle). The decoder asserts the inner payload's
	// pairSessionId matches sessionID (cross-session replay defence).
	Decoder func(blob PairApprovalBlob, sessionID string) (ownerPub []byte, payloadCanon []byte, approvedAt string, err error)
	// hex SHA-256 of the agent's pairToken; atreoLINK sees only the hash,
	// the raw token rides the URL fragment to the operator-side approver.
	PairTokenHash  string
	AuthURLBuilder func(atreolinkAuthURL, userCode string) string
}

// Required — without it Pair refuses to complete, because the resulting
// agent state would be trustable only via TOFU.
func WithApprovalDecoder(fn func(blob PairApprovalBlob, sessionID string) (ownerPub []byte, payloadCanon []byte, approvedAt string, err error)) PairOption {
	return func(o *pairOpts) { o.Decoder = fn }
}

func WithPairTokenHash(hexHash string) PairOption {
	return func(o *pairOpts) { o.PairTokenHash = hexHash }
}

func WithAuthURLBuilder(fn func(atreolinkAuthURL, userCode string) string) PairOption {
	return func(o *pairOpts) { o.AuthURLBuilder = fn }
}

// Pair runs the device pairing flow and returns the pinned owner identity
// in PairResult. WithApprovalDecoder is required.
func Pair(ctx context.Context, client *Client, km *crypto.KeyManager, opts ...PairOption) (*PairResult, error) {
	o := &pairOpts{}
	for _, opt := range opts {
		opt(o)
	}
	if o.Decoder == nil {
		return nil, fmt.Errorf("Pair: WithApprovalDecoder is required for owner-identity pinning")
	}

	hostname, _ := os.Hostname()
	fingerprint := km.PublicKeyBase64()[:16]

	initResp, err := client.InitPairing(ctx, fingerprint, hostname, km.PublicKeyBase64(), o.PairTokenHash)
	if err != nil {
		return nil, fmt.Errorf("init pairing: %w", err)
	}

	approveURL := initResp.AuthURL
	if o.AuthURLBuilder != nil {
		approveURL = o.AuthURLBuilder(initResp.AuthURL, initResp.UserCode)
	}

	// Refuse a relative URL up-front so the failure is one clear error
	// at the agent rather than a confusing one in the browser.
	if u, err := url.Parse(approveURL); err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf(
			"refusing to print non-absolute approval URL %q — atreoLINK must return an absolute authUrl (scheme + host) for the operator to follow",
			approveURL,
		)
	}

	fmt.Println("\n" + banner.Box("atreoAGENT pairing — operator approval required"))
	fmt.Printf("\n  Pairing code: %s\n", initResp.UserCode)
	fmt.Printf("  Approve at:   %s\n", approveURL)
	fmt.Println("\n  The fragment portion of the URL (after '#') stays in your")
	fmt.Println("  browser and never reaches atreoLINK. It anchors the owner")
	fmt.Println("  identity key on this agent.")
	fmt.Println("\n  Waiting for approval...")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// Log transient poll errors at most every ~30s — silent retry hides
	// wire-shape mismatch under the "Waiting for approval" message.
	var lastErrLog time.Time
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			pollResp, err := client.PollPairing(ctx, initResp.SessionID)
			if err != nil {
				if time.Since(lastErrLog) > 30*time.Second {
					fmt.Printf("  ⚠ poll error (will retry): %v\n", err)
					lastErrLog = time.Now()
				}
				continue
			}
			if pollResp.Status != "approved" {
				continue
			}
			if pollResp.ApprovalBlob == nil {
				return nil, fmt.Errorf("atreolink reported approval without an approval blob — refusing to pair without an anchored owner identity")
			}
			ownerPub, payloadCanon, approvedAt, derr := o.Decoder(*pollResp.ApprovalBlob, initResp.SessionID)
			if derr != nil {
				return nil, fmt.Errorf("decode approval blob: %w", derr)
			}
			return &PairResult{
				DeviceID:             pollResp.DeviceID,
				AppsHostname:         pollResp.AppsHostname,
				TunnelHost:           pollResp.TunnelHost,
				OwnerIdentityPubkey:  ownerPub,
				OwnerMemberID:        pollResp.OwnerMemberID,
				OwnerUserID:          pollResp.OwnerUserID,
				OwnerEmail:           pollResp.OwnerEmail,
				OwnerName:            pollResp.OwnerName,
				ApprovalPayloadCanon: payloadCanon,
				ApprovedAt:           approvedAt,
			}, nil
		}
	}
}
