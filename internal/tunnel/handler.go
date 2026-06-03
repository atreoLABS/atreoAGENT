package tunnel

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/acl"
	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/certs"
	"github.com/atreoLABS/atreoAGENT/internal/crypto"
	"github.com/atreoLABS/atreoAGENT/internal/notify"
	"github.com/atreoLABS/atreoAGENT/internal/store"
	"github.com/atreoLABS/atreoAGENT/internal/wireguard"
)

// Handlers processes tunnel control messages.
type Handlers struct {
	wgServer        *wireguard.Server
	aclStore        *acl.Store
	keyManager      *crypto.KeyManager
	allocator       *wireguard.IPAllocator
	pairingPath     string
	deviceID        string
	tunnelHost      string   // bound into the v2 provision transcript
	nonceStore      sync.Map // correlationID → nonceEntry
	atreolinkClient *atreolink.Client
	notifyServer    *notify.Server

	// May be nil; custom-domain reconcile is skipped when so.
	certManager       *certs.Manager
	customDomainStore *store.CustomDomainStore

	// Nil until SetUpstreamSender wires it; callers must nil-check.
	sendUpstream func(ctx context.Context, msg atreolink.TunnelMessage) error

	// Fail-closed liveness (lazily initialised at first use).
	livenessOnce sync.Once
	live         *livenessState
}

func (h *Handlers) SetUpstreamSender(fn func(ctx context.Context, msg atreolink.TunnelMessage) error) {
	h.sendUpstream = fn
}

// ClientRegisterPayload is the member-signed client registration envelope.
// Intent: wg:client-register-<deviceId>-<memberId>-<wgPublicKey>-<ts>.
type ClientRegisterPayload struct {
	CommandEnvelopeFields
	DeviceID   string `json:"deviceId"`
	MemberID   string `json:"memberId"`
	PublicKey  string `json:"publicKey"`
	ClientName string `json:"clientName"`
	Platform   string `json:"platform"`
}

type nonceEntry struct {
	Nonce     string
	MemberID  string
	ClientKey string
	CreatedAt time.Time
}

// Intent: "wg:challenge-<memberId>-<unixSeconds>".
type ChallengePayload struct {
	CommandEnvelopeFields
	MembershipID string `json:"membershipId"`
	MemberID     string `json:"memberId"`
	ClientID     string `json:"clientId"`
	ClientKey    string `json:"publicKey"`
	IdentityKey  string `json:"identityKey"`
}

type ChallengeNoncePayload struct {
	Nonce string `json:"nonce"`
}

// Intent: "wg:provision-<memberId>-<clientId>-<nonceHex>-<unixSeconds>".
type ProvisionPayload struct {
	CommandEnvelopeFields
	MemberID          string `json:"memberId"`
	MembershipID      string `json:"membershipId"`
	ClientID          string `json:"clientId"`
	ClientKey         string `json:"publicKey"`
	Nonce             string `json:"nonce"`
	IdentityKey       string `json:"identityKey"`
	ChallengeCorrelID string `json:"challengeCorrelId"`
}

// Field casing is wire-exact: `tunnelIP` and `nasSignature` are load-bearing.
type ProvisionResponsePayload struct {
	ServerPublicKey     string `json:"serverPublicKey"`
	TunnelIP            string `json:"tunnelIP"`
	ListenPort          int    `json:"listenPort"`
	Endpoint            string `json:"endpoint"`
	AllowedIPs          string `json:"allowedIPs"`
	PersistentKeepalive int    `json:"persistentKeepalive"`
	NASSignature        string `json:"nasSignature"`
}

// Both sides feed these into the v2 server transcript, so divergence
// surfaces as a verify failure rather than silent re-routing.
const (
	wgQuickAllowedIPs          = "100.64.0.0/24"
	wgQuickPersistentKeepalive = 25
)

type MemberPermissionsPayload struct {
	CommandEnvelopeFields
	DeviceID      string   `json:"deviceId"`
	MemberID      string   `json:"memberId"`
	AllowedAppIDs []string `json:"allowedAppIds"`
}

// Suspend retains the ACL entry (clientKeys, tunnelIPs, identity key,
// joinAttestation) and only flips the WG peer install; reactivating
// restores the original tunnel IPs without re-provisioning.
type MemberStatusPayload struct {
	CommandEnvelopeFields
	DeviceID  string `json:"deviceId"`
	MemberID  string `json:"memberId"`
	Status    string `json:"status"` // "active" | "suspended"
	ChangedAt string `json:"changedAt"`
}

// AppUpsertedPayload is the admin-signed app definition envelope, replayed
// inside DeviceState and verified freshness-free (intent has no ts).
type AppUpsertedPayload struct {
	CommandEnvelopeFields
	DeviceID string        `json:"deviceId"`
	App      atreolink.App `json:"app"`
}

type DeviceUnpairedPayload struct {
	CommandEnvelopeFields
	DeviceID string `json:"deviceId"`
}

// Long-lived authorisation; intent binds device + parentZone.
type CustomDomainSetPayload struct {
	CommandEnvelopeFields
	DeviceID   string `json:"deviceId"`
	ParentZone string `json:"parentZone"`
	ActedAt    string `json:"actedAt"`
}

type NotifyAPIKeyPayload struct {
	CommandEnvelopeFields
	DeviceID string `json:"deviceId"`
}

type NotifyAPIKeyRotatePayload struct {
	CommandEnvelopeFields
	DeviceID string `json:"deviceId"`
}

type PushDevicesListPayload struct {
	CommandEnvelopeFields
	DeviceID string `json:"deviceId"`
}

// deviceID is folded into signed transcripts so one device's transcript
// can't be applied to another.
//
// `certManager` and `customDomainStore` may be nil — in that case the
// device:custom-domain-set / device:custom-domain-cleared handlers
// reject incoming envelopes (deployment hasn't enabled the feature).
func NewHandlers(
	wgServer *wireguard.Server,
	aclStore *acl.Store,
	keyManager *crypto.KeyManager,
	allocator *wireguard.IPAllocator,
	pairingPath, deviceID, tunnelHost string,
	atreolinkClient *atreolink.Client,
	notifyServer *notify.Server,
	certManager *certs.Manager,
	customDomainStore *store.CustomDomainStore,
) *Handlers {
	return &Handlers{
		wgServer:          wgServer,
		aclStore:          aclStore,
		keyManager:        keyManager,
		allocator:         allocator,
		pairingPath:       pairingPath,
		deviceID:          deviceID,
		tunnelHost:        tunnelHost,
		atreolinkClient:   atreolinkClient,
		notifyServer:      notifyServer,
		certManager:       certManager,
		customDomainStore: customDomainStore,
	}
}

// mustMarshal panics on failure; only call with hand-built literals where
// json.Marshal is total.
func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Errorf("mustMarshal: %w", err))
	}
	return b
}

// Matches the freshness window the consume paths already enforce.
const shortLivedTTL = 5 * time.Minute

// StartReapers prunes abandoned challenge nonces and push-pair entries
// so unfinished flows can't grow either map without bound.
func (h *Handlers) StartReapers(ctx context.Context) {
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				cutoff := time.Now().Add(-shortLivedTTL)
				h.nonceStore.Range(func(k, v any) bool {
					if e, ok := v.(nonceEntry); ok && e.CreatedAt.Before(cutoff) {
						h.nonceStore.Delete(k)
					}
					return true
				})
			}
		}
	}()
}

// RegisterAll registers all tunnel message handlers. ACL state arrives as a
// single signed DeviceState (device:state[:gz]) verified and reconciled
// wholesale; wg:challenge/wg:provision/notify remain live RPCs.
func (h *Handlers) RegisterAll(client *Client) {
	client.RegisterHandler("wg:challenge", h.HandleChallenge)
	client.RegisterHandler("wg:provision", h.HandleProvision)
	client.RegisterHandler("device:state", h.HandleDeviceState)
	client.RegisterHandler("device:state:gz", h.HandleDeviceState)
	client.RegisterHandler("acl:heartbeat:ack", h.HandleHeartbeatAck)
	client.RegisterHandler("device:unpaired", h.HandleUnpaired)
	client.RegisterHandler("notify:apikey", h.HandleNotifyAPIKey)
	client.RegisterHandler("notify:apikey:rotate", h.HandleNotifyAPIKeyRotate)
}

// The admin entry's identityKey is invariantly equal to the pinned admin
// pubkey, so this is equivalent to verifying directly against the pin.
func (h *Handlers) requireAdmin(msg atreolink.TunnelMessage) error {
	if msg.SignerID == "" {
		return ErrUnsigned
	}
	entry := h.aclStore.LookupByMemberID(msg.SignerID)
	if entry == nil {
		return fmt.Errorf("verify admin envelope: %w: %q", ErrUnknownSigner, msg.SignerID)
	}
	if entry.Role != "admin" && entry.Role != "owner" {
		return fmt.Errorf("verify admin envelope: %w (signer %q has role %q)", ErrNotAdmin, msg.SignerID, entry.Role)
	}
	return VerifyEnvelope(msg, h.aclLookup())
}

func (h *Handlers) requireMember(msg atreolink.TunnelMessage, expectedMemberID string) error {
	if msg.SignerID != expectedMemberID {
		return fmt.Errorf("verify member envelope: signerId=%q, expected %q", msg.SignerID, expectedMemberID)
	}
	return VerifyEnvelope(msg, h.aclLookup())
}

func (h *Handlers) aclLookup() ACLLookup {
	return func(memberID string) (string, bool) {
		m := h.aclStore.LookupByMemberID(memberID)
		if m == nil {
			return "", false
		}
		return m.IdentityKey, true
	}
}

func (h *Handlers) ownerPub() ed25519.PublicKey {
	return h.aclStore.PinnedAdminPublicKey()
}

// HandleChallenge issues a nonce for a WireGuard challenge. The envelope
// check stops nonces being issued against members that aren't actually
// requesting a connection; the load-bearing check is in HandleProvision.
func (h *Handlers) HandleChallenge(msg atreolink.TunnelMessage) (*atreolink.TunnelMessage, error) {
	var payload ChallengePayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal challenge: %w", err)
	}

	memberID := payload.MembershipID
	if memberID == "" {
		memberID = payload.MemberID
	}

	// clientId is atreoLINK-minted, so it can't be in the intent; the envelope
	// signature still covers it via canonical-JSON.
	expectedIntent := fmt.Sprintf("wg:challenge-%s-%d", memberID, payload.Timestamp)
	if err := h.verifyCommand(msg, MemberAuth(memberID), payload.CommandEnvelopeFields, expectedIntent); err != nil {
		logging.Error("wg:challenge rejected: %v", err)
		return nil, err
	}

	nonce, err := crypto.GenerateNonce()
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	h.nonceStore.Store(msg.CorrelationID, nonceEntry{
		Nonce:     nonce,
		MemberID:  memberID,
		ClientKey: payload.ClientKey,
		CreatedAt: time.Now(),
	})

	respPayload := mustMarshal(ChallengeNoncePayload{Nonce: nonce})
	return &atreolink.TunnelMessage{
		Type:          "wg:challenge:nonce",
		CorrelationID: msg.CorrelationID,
		Payload:       respPayload,
	}, nil
}

// HandleProvision returns a signed WireGuard config to the client. The
// envelope signature over the canonical payload binds WG pubkey + nonce
// + memberId. The (memberId → identityPublic) mapping comes from the
// ACL, never from the request — identity-pinning invariant.
func (h *Handlers) HandleProvision(msg atreolink.TunnelMessage) (*atreolink.TunnelMessage, error) {
	// Fail before any side effect so a broken deploy doesn't leave
	// half-applied peer state.
	if h.tunnelHost == "" {
		return nil, fmt.Errorf("tunnelHost not configured; cannot build signed endpoint")
	}

	var payload ProvisionPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal provision: %w", err)
	}

	nonceKey := payload.ChallengeCorrelID
	if nonceKey == "" {
		nonceKey = msg.CorrelationID
	}
	raw, ok := h.nonceStore.LoadAndDelete(nonceKey)
	if !ok {
		return nil, fmt.Errorf("no nonce found for correlation %s", nonceKey)
	}
	entry := raw.(nonceEntry)

	if time.Since(entry.CreatedAt) > 5*time.Minute {
		return nil, fmt.Errorf("nonce expired")
	}

	// The signed value must match the nonce we issued.
	if payload.Nonce != entry.Nonce {
		return nil, fmt.Errorf("provision nonce does not match challenge")
	}

	clientKey := payload.ClientKey
	if clientKey == "" {
		clientKey = entry.ClientKey
	}

	expectedIntent := fmt.Sprintf("wg:provision-%s-%s-%s-%d", entry.MemberID, payload.ClientID, payload.Nonce, payload.Timestamp)
	if err := h.verifyCommand(msg, MemberAuth(entry.MemberID), payload.CommandEnvelopeFields, expectedIntent); err != nil {
		logging.Error("wg:provision rejected: %v", err)
		return nil, err
	}

	tunnelIP, err := h.allocator.Allocate(clientKey)
	if err != nil {
		return nil, fmt.Errorf("allocate IP: %w", err)
	}

	// AddClient first so a bogus memberID is caught before the kernel
	// peer install. Order matters for crash safety; rollbacks below
	// undo each step on failure.
	if !h.aclStore.AddClient(entry.MemberID, atreolink.ClientRecord{
		WGPublicKey: clientKey,
		TunnelIP:    tunnelIP,
	}) {
		h.allocator.Release(clientKey)
		return nil, fmt.Errorf("AddClient failed: unknown member %q", entry.MemberID)
	}

	if err := h.wgServer.AddPeer(clientKey, tunnelIP); err != nil {
		h.aclStore.RemoveClient(entry.MemberID, clientKey)
		h.allocator.Release(clientKey)
		return nil, fmt.Errorf("add peer: %w", err)
	}
	if err := h.aclStore.Save(); err != nil {
		logging.Warn("Warning: failed to persist ACL after provision: %v", err)
	}

	// v2 transcript binds every wg-quick field so any in-transit change
	// fails the client's verify.
	serverPubKey := h.wgServer.PublicKey()
	listenPort := h.wgServer.ListenPort()
	endpoint := fmt.Sprintf("%s:%d", h.tunnelHost, listenPort)
	sig, err := h.keyManager.SignProvisionResponse(crypto.ProvisionTranscriptInput{
		NonceHex:            entry.Nonce,
		ClientPubKeyB64:     clientKey,
		DeviceID:            h.deviceID,
		ServerPubKeyB64:     serverPubKey,
		TunnelIP:            tunnelIP,
		Endpoint:            endpoint,
		AllowedIPs:          wgQuickAllowedIPs,
		PersistentKeepalive: wgQuickPersistentKeepalive,
	})
	if err != nil {
		return nil, fmt.Errorf("sign provision response: %w", err)
	}

	respPayload := mustMarshal(ProvisionResponsePayload{
		ServerPublicKey:     serverPubKey,
		TunnelIP:            tunnelIP,
		ListenPort:          listenPort,
		Endpoint:            endpoint,
		AllowedIPs:          wgQuickAllowedIPs,
		PersistentKeepalive: wgQuickPersistentKeepalive,
		NASSignature:        sig,
	})

	logging.Info("Provisioned peer for member %s: IP %s", entry.MemberID, tunnelIP)

	return &atreolink.TunnelMessage{
		Type:          "wg:provision:response",
		CorrelationID: msg.CorrelationID,
		Payload:       respPayload,
	}, nil
}

// Host is unconstrained (operators use LAN hostnames and Docker names);
// scheme is locked to http/https so the proxy never dials file://, etc.
func validateInternalURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("app:upserted: internalUrl %q is not a valid URL: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("app:upserted: internalUrl scheme %q not allowed (only http/https)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("app:upserted: internalUrl %q has no host", raw)
	}
	return nil
}

// HandleUnpaired wipes state and exits; the container restart re-enters
// pairing mode. Re-pairing must establish a fresh admin pin anchor.
// Intent: "unpair-device-<deviceId>-<ts>".
func (h *Handlers) HandleUnpaired(msg atreolink.TunnelMessage) (*atreolink.TunnelMessage, error) {
	var payload DeviceUnpairedPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal device unpaired: %w", err)
	}
	if payload.DeviceID != "" && payload.DeviceID != h.deviceID {
		logging.Error("device:unpaired rejected: deviceId=%q, expected %q", payload.DeviceID, h.deviceID)
		return nil, fmt.Errorf("deviceId mismatch")
	}
	expectedIntent := fmt.Sprintf("unpair-device-%s-%d", h.deviceID, payload.Timestamp)
	if err := h.verifyCommand(msg, AdminAuth(), payload.CommandEnvelopeFields, expectedIntent); err != nil {
		logging.Error("device:unpaired rejected: %v", err)
		return nil, err
	}

	logging.Info("Device unpaired. Returning to setup mode.")

	if err := h.wgServer.Stop(); err != nil {
		logging.Warn("Warning: failed to stop WireGuard on unpair: %v", err)
	}
	if err := h.aclStore.ClearPinnedAdminPublicKey(); err != nil {
		logging.Warn("Warning: failed to clear pinned admin pubkey: %v", err)
	}
	// Remove the agent-owned pairing identity (not the user's
	// config.yaml) so the next start re-enters pairing.
	if h.pairingPath != "" {
		if err := os.Remove(h.pairingPath); err != nil && !os.IsNotExist(err) {
			logging.Warn("Warning: failed to delete pairing state: %v", err)
		}
	}
	os.Exit(0)
	return nil, nil
}

// Owner-signed: the API key is a credential and never leaves an
// authenticated channel.
func (h *Handlers) HandleNotifyAPIKey(msg atreolink.TunnelMessage) (*atreolink.TunnelMessage, error) {
	if h.notifyServer == nil {
		return nil, fmt.Errorf("notification API not configured")
	}

	var payload NotifyAPIKeyPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal notify:apikey: %w", err)
	}
	if payload.DeviceID != "" && payload.DeviceID != h.deviceID {
		logging.Error("notify:apikey rejected: deviceId=%q, expected %q", payload.DeviceID, h.deviceID)
		return nil, fmt.Errorf("deviceId mismatch")
	}
	// Bind to h.deviceID, not payload.DeviceID — stops same-owner
	// cross-device replay.
	expectedIntent := fmt.Sprintf("notify:apikey-%s-%d", h.deviceID, payload.Timestamp)
	if err := h.verifyCommand(msg, AdminAuth(), payload.CommandEnvelopeFields, expectedIntent); err != nil {
		logging.Error("notify:apikey rejected: %v", err)
		return nil, err
	}

	respPayload := mustMarshal(map[string]any{
		"apiKey": h.notifyServer.APIKey(),
		"port":   h.notifyServer.Port(),
	})

	return &atreolink.TunnelMessage{
		Type:          "notify:apikey:response",
		CorrelationID: msg.CorrelationID,
		Payload:       respPayload,
	}, nil
}

func (h *Handlers) HandleNotifyAPIKeyRotate(msg atreolink.TunnelMessage) (*atreolink.TunnelMessage, error) {
	if h.notifyServer == nil {
		return nil, fmt.Errorf("notification API not configured")
	}

	var payload NotifyAPIKeyRotatePayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal notify:apikey:rotate: %w", err)
	}
	if payload.DeviceID != "" && payload.DeviceID != h.deviceID {
		logging.Error("notify:apikey:rotate rejected: deviceId=%q, expected %q", payload.DeviceID, h.deviceID)
		return nil, fmt.Errorf("deviceId mismatch")
	}
	expectedIntent := fmt.Sprintf("notify:apikey:rotate-%s-%d", h.deviceID, payload.Timestamp)
	if err := h.verifyCommand(msg, AdminAuth(), payload.CommandEnvelopeFields, expectedIntent); err != nil {
		logging.Error("notify:apikey:rotate rejected: %v", err)
		return nil, err
	}

	newKey, err := h.notifyServer.RotateAPIKey()
	if err != nil {
		return nil, fmt.Errorf("rotate api key: %w", err)
	}

	respPayload := mustMarshal(map[string]string{
		"apiKey": newKey,
	})

	logging.Info("Notification API key rotated")

	return &atreolink.TunnelMessage{
		Type:          "notify:apikey:rotate:response",
		CorrelationID: msg.CorrelationID,
		Payload:       respPayload,
	}, nil
}
