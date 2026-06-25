package tunnel

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
	"io"
	"sync"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/store"
)

// staleBound is measured against server liveness (a verified apply OR a
// generation-confirming heartbeat), not state change — a quiet device may
// see no ACL change for a long time and must not age out. coldStartTimeout
// applies only before anything has ever been applied this boot.
const (
	staleBound       = 30 * time.Minute
	coldStartTimeout = 90 * time.Second
)

type livenessState struct {
	mu                   sync.Mutex
	bootAt               time.Time
	appliedOnce          bool
	lastPositiveLiveness time.Time
	failClosed           bool
}

func (h *Handlers) liveness() *livenessState {
	h.livenessOnce.Do(func() {
		h.live = &livenessState{bootAt: time.Now()}
	})
	return h.live
}

// markLiveness records server liveness and lifts fail-closed.
func (h *Handlers) markLiveness(applied bool) {
	l := h.liveness()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lastPositiveLiveness = time.Now()
	if applied {
		l.appliedOnce = true
	}
	l.failClosed = false
}

// StartLivenessWatch drops all WG peers once there is no usable verified
// state (cold-start with nothing applied, or last liveness older than
// staleBound). A reconnect/blip alone never drops peers.
func (h *Handlers) StartLivenessWatch(ctx context.Context) {
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				h.checkLiveness()
			}
		}
	}()
}

func (h *Handlers) checkLiveness() {
	l := h.liveness()
	l.mu.Lock()
	now := time.Now()
	var trip bool
	switch {
	case l.failClosed:
		l.mu.Unlock()
		return
	case !l.appliedOnce:
		// Cold boot: a verified, recent on-disk ACL counts as applied.
		if !h.aclStore.LastAppliedAt().IsZero() &&
			now.Sub(h.aclStore.LastAppliedAt()) <= staleBound {
			l.appliedOnce = true
			if l.lastPositiveLiveness.IsZero() {
				l.lastPositiveLiveness = h.aclStore.LastAppliedAt()
			}
			l.mu.Unlock()
			return
		}
		trip = now.Sub(l.bootAt) > coldStartTimeout
	default:
		ref := l.lastPositiveLiveness
		if ref.IsZero() {
			ref = h.aclStore.LastAppliedAt()
		}
		trip = !ref.IsZero() && now.Sub(ref) > staleBound
	}
	if trip {
		l.failClosed = true
	}
	l.mu.Unlock()

	if trip {
		logging.Warn("SECURITY: fail-closed — no usable verified DeviceState (cold-start=%v staleBound=%s). Dropping all WG peers until a fresh verified state arrives.",
			!l.appliedOnce, staleBound)
		h.dropAllPeers()
	}
}

// dropAllPeers removes every WG peer without releasing allocator IPs, so a
// later valid reconcile re-installs the same peers.
func (h *Handlers) dropAllPeers() {
	for _, m := range h.aclStore.AllMembers() {
		for _, c := range m.Clients {
			if c.WGPublicKey == "" {
				continue
			}
			if err := h.wgServer.RemovePeer(c.WGPublicKey); err != nil {
				logging.Error("fail-closed: remove peer %s: %v", c.WGPublicKey, err)
			}
		}
	}
}

func (h *Handlers) decodeDeviceState(msg atreolink.TunnelMessage) (*atreolink.DeviceState, error) {
	raw := []byte(msg.Payload)
	if msg.Type == "device:state:gz" {
		var gzBytes []byte
		if err := json.Unmarshal(msg.Payload, &gzBytes); err != nil {
			return nil, fmt.Errorf("device:state:gz: decode base64 wrapper: %w", err)
		}
		zr, err := gzip.NewReader(bytes.NewReader(gzBytes))
		if err != nil {
			return nil, fmt.Errorf("device:state:gz: gzip reader: %w", err)
		}
		defer func() { _ = zr.Close() }()
		raw, err = io.ReadAll(io.LimitReader(zr, 8<<20))
		if err != nil {
			return nil, fmt.Errorf("device:state:gz: gunzip: %w", err)
		}
	}
	var st atreolink.DeviceState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("device:state: unmarshal: %w", err)
	}
	return &st, nil
}

// HandleDeviceState verifies every item against the pinned owner key, then
// wholesale-replaces. Any present-but-invalid envelope rejects the whole
// push (last verified state keeps serving; no peers dropped). A missing
// member/app is a removal; a missing per-dimension envelope is the safe
// default (active / no apps). Generation must not regress.
func (h *Handlers) HandleDeviceState(msg atreolink.TunnelMessage) (*atreolink.TunnelMessage, error) {
	st, err := h.decodeDeviceState(msg)
	if err != nil {
		logging.Error("device:state rejected: %v", err)
		return nil, err
	}
	if st.DeviceID != "" && st.DeviceID != h.deviceID {
		return nil, fmt.Errorf("device:state rejected: deviceId=%q, expected %q", st.DeviceID, h.deviceID)
	}

	applied := h.aclStore.AppliedGeneration()
	if st.Generation < applied {
		// Refuse to regress; a heartbeat corrects a server DB restore.
		logging.Debug("device:state ignored: generation %d < applied %d; keeping last verified state", st.Generation, applied)
		return nil, nil
	}

	ownerPub := h.ownerPub()
	if ownerPub == nil {
		return nil, errors.New("device:state rejected: no pinned owner pubkey (agent not paired?)")
	}
	nasPub := h.keyManager.PublicKeyBase64()
	now := time.Now()

	// Verify everything before applying anything; one bad item rejects all.
	vApps := make([]atreolink.App, 0, len(st.Apps))
	for _, da := range st.Apps {
		if da.Envelope == nil {
			continue // unverifiable; skip
		}
		var ap AppUpsertedPayload
		if err := json.Unmarshal(da.Envelope.Payload, &ap); err != nil {
			return nil, fmt.Errorf("device:state rejected: app envelope payload: %w", err)
		}
		expectedIntent := fmt.Sprintf("app:upserted-%s-%s", h.deviceID, ap.App.ID)
		if err := h.verifyAuthorization(da.Envelope.AsMessage("app:upserted"), AttestedAuth(ownerPub), ap.CommandEnvelopeFields, expectedIntent); err != nil {
			return nil, fmt.Errorf("device:state rejected: app %s: %w", ap.App.ID, err)
		}
		if err := validateApp(ap.App); err != nil {
			return nil, fmt.Errorf("device:state rejected: app %s: %w", ap.App.ID, err)
		}
		vApps = append(vApps, ap.App)
	}
	appByID := make(map[string]atreolink.App, len(vApps))
	for _, a := range vApps {
		appByID[a.ID] = a
	}

	// Certs to emit upstream after the apply commits. A failed apply must
	// not announce admission we didn't actually carry out.
	var pendingAdmittance []*atreolink.AdmittanceCertificate

	// IPs restorable from a lease this agent itself signed, keyed by pubkey.
	leaseIP := make(map[string]string)

	vMembers := make([]atreolink.MemberACLEntry, 0, len(st.Members))
	for _, dm := range st.Members {
		entry := atreolink.MemberACLEntry{
			MemberID:    dm.MemberID,
			UserID:      dm.UserID,
			MemberName:  dm.MemberName,
			Email:       dm.Email,
			Role:        dm.Role,
			IdentityKey: dm.IdentityKey,
			Status:      "active",
			Clients:     []atreolink.ClientRecord{},
			AllowedApps: []atreolink.App{},
		}

		isAdmin := dm.Role == "admin" || dm.Role == "owner"
		var initialAppIDs []string
		if !isAdmin {
			switch {
			case dm.Admittance != nil:
				if err := VerifyAdmittanceCertificate(dm.Admittance, dm.MemberID, dm.IdentityKey, nasPub, h.keyManager.PublicKey()); err != nil {
					return nil, fmt.Errorf("device:state rejected: member %s admittance: %w", dm.MemberID, err)
				}
				entry.Admittance = dm.Admittance
				initialAppIDs = dm.Admittance.InitialAllowedAppIDs
			default:
				// No inbound cert: reuse a locally-persisted one if we have it
				// (re-emit upstream), else verify the chain and mint.
				if existing := h.aclStore.LookupByMemberID(dm.MemberID); existing != nil && existing.Admittance != nil {
					cert := existing.Admittance
					if err := VerifyAdmittanceCertificate(cert, dm.MemberID, dm.IdentityKey, nasPub, h.keyManager.PublicKey()); err != nil {
						return nil, fmt.Errorf("device:state rejected: member %s existing admittance: %w", dm.MemberID, err)
					}
					entry.Admittance = cert
					initialAppIDs = cert.InitialAllowedAppIDs
					pendingAdmittance = append(pendingAdmittance, cert)
				} else {
					if dm.JoinAttestation == nil {
						return nil, fmt.Errorf("device:state rejected: member %s: no admittance cert and no joinAttestation", dm.MemberID)
					}
					entry.JoinAttestation = dm.JoinAttestation
					inv, err := VerifyJoinAttestation(entry, ownerPub, nasPub, now)
					if err != nil {
						return nil, fmt.Errorf("device:state rejected: member %s admission: %w", dm.MemberID, err)
					}
					inviteBytes, decErr := base64.StdEncoding.DecodeString(dm.JoinAttestation.InvitePayload)
					if decErr != nil {
						return nil, fmt.Errorf("device:state rejected: member %s decode invitePayload: %w", dm.MemberID, decErr)
					}
					cert, mintErr := MintAdmittanceCertificate(
						dm.MemberID, dm.IdentityKey, nasPub,
						inviteBytes, inv.AllowedAppIDs,
						h.keyManager.PrivateKey(), now,
					)
					if mintErr != nil {
						return nil, fmt.Errorf("device:state rejected: member %s mint admittance: %w", dm.MemberID, mintErr)
					}
					entry.Admittance = cert
					entry.JoinAttestation = nil
					initialAppIDs = cert.InitialAllowedAppIDs
					pendingAdmittance = append(pendingAdmittance, cert)
				}
			}
		}

		memberPub, mpErr := decodeEd25519(dm.IdentityKey)
		if mpErr != nil {
			return nil, fmt.Errorf("device:state rejected: member %s identityKey: %w", dm.MemberID, mpErr)
		}

		if dm.StatusEnvelope != nil {
			var sp MemberStatusPayload
			if err := json.Unmarshal(dm.StatusEnvelope.Payload, &sp); err != nil {
				return nil, fmt.Errorf("device:state rejected: member %s status payload: %w", dm.MemberID, err)
			}
			if sp.Status != "active" && sp.Status != "suspended" {
				return nil, fmt.Errorf("device:state rejected: member %s invalid status %q", dm.MemberID, sp.Status)
			}
			// Freshness-free: rebuild the ts-inclusive intent from payload.ts
			// (a tampered ts breaks the signature).
			expectedIntent := fmt.Sprintf("member:status-%s-%s-%s-%d", h.deviceID, sp.MemberID, sp.Status, sp.Timestamp)
			if err := h.verifyAuthorization(dm.StatusEnvelope.AsMessage("member:status"), AttestedAuth(ownerPub), sp.CommandEnvelopeFields, expectedIntent); err != nil {
				return nil, fmt.Errorf("device:state rejected: member %s status: %w", dm.MemberID, err)
			}
			entry.Status = sp.Status
		}

		if dm.PermissionsEnvelope != nil {
			var pp MemberPermissionsPayload
			if err := json.Unmarshal(dm.PermissionsEnvelope.Payload, &pp); err != nil {
				return nil, fmt.Errorf("device:state rejected: member %s permissions payload: %w", dm.MemberID, err)
			}
			expectedIntent := fmt.Sprintf("member:permissions-%s-%s-%d", h.deviceID, pp.MemberID, pp.Timestamp)
			if err := h.verifyAuthorization(dm.PermissionsEnvelope.AsMessage("member:permissions"), AttestedAuth(ownerPub), pp.CommandEnvelopeFields, expectedIntent); err != nil {
				return nil, fmt.Errorf("device:state rejected: member %s permissions: %w", dm.MemberID, err)
			}
			for _, id := range pp.AllowedAppIDs {
				if a, ok := appByID[id]; ok {
					entry.AllowedApps = append(entry.AllowedApps, a)
				}
			}
		} else if isAdmin {
			// Admins/owners see the whole catalogue.
			entry.AllowedApps = append(entry.AllowedApps, vApps...)
		} else {
			// Seed from the admission signature until a fresh permissions
			// envelope supersedes it.
			for _, id := range initialAppIDs {
				if a, ok := appByID[id]; ok {
					entry.AllowedApps = append(entry.AllowedApps, a)
				}
			}
		}

		for _, dc := range dm.Clients {
			if dc.RegistrationEnvelope == nil {
				continue // unverifiable; skip
			}
			var cp ClientRegisterPayload
			if err := json.Unmarshal(dc.RegistrationEnvelope.Payload, &cp); err != nil {
				return nil, fmt.Errorf("device:state rejected: member %s client payload: %w", dm.MemberID, err)
			}
			expectedIntent := fmt.Sprintf("wg:client-register-%s-%s-%s-%d", h.deviceID, cp.MemberID, dc.WGPublicKey, cp.Timestamp)
			if err := h.verifyAuthorization(dc.RegistrationEnvelope.AsMessage("wg:client-register"), AttestedAuth(memberPub), cp.CommandEnvelopeFields, expectedIntent); err != nil {
				return nil, fmt.Errorf("device:state rejected: member %s client %s: %w", dm.MemberID, dc.WGPublicKey, err)
			}
			if cp.MemberID != dm.MemberID || cp.PublicKey != dc.WGPublicKey {
				return nil, fmt.Errorf("device:state rejected: member %s client registration payload mismatch", dm.MemberID)
			}
			// A lease verifying under our own key restores the IP we issued;
			// a bad one is ignored (it grants nothing), never fatal.
			if dc.IPLease != nil {
				if err := VerifyTunnelIPLease(dc.IPLease, h.deviceID, dc.WGPublicKey, h.keyManager.PublicKey()); err != nil {
					logging.Warn("device:state: ignoring invalid IP lease for %s: %v", shortKey(dc.WGPublicKey), err)
				} else {
					leaseIP[dc.WGPublicKey] = dc.IPLease.TunnelIP
				}
			}
			entry.Clients = append(entry.Clients, atreolink.ClientRecord{
				WGPublicKey:  dc.WGPublicKey,
				Label:        dc.Label,
				Platform:     dc.Platform,
				EndpointType: dc.EndpointType,
			})
		}

		vMembers = append(vMembers, entry)
	}

	// The agent owns the pubkey→tunnelIP binding. An existing allocation
	// wins; an unknown pubkey is restored only from a verified lease into a
	// free address; otherwise allocate our own.
	for mi := range vMembers {
		for ci := range vMembers[mi].Clients {
			c := &vMembers[mi].Clients[ci]
			if c.WGPublicKey == "" {
				continue
			}
			if ip := h.allocator.Lookup(c.WGPublicKey); ip != "" {
				c.TunnelIP = ip
				continue
			}
			if lip := leaseIP[c.WGPublicKey]; lip != "" && h.allocator.TryAdopt(c.WGPublicKey, lip) {
				c.TunnelIP = lip
				continue
			}
			ip, aerr := h.allocator.Allocate(c.WGPublicKey)
			if aerr != nil {
				return nil, fmt.Errorf("device:state rejected: allocate IP for %s: %w", c.WGPublicKey, aerr)
			}
			c.TunnelIP = ip
		}
	}

	// Wholesale replace. removedClientKeys covers every client that
	// disappeared — whole-member removals, clients dropped from a
	// surviving member, and clients excluded because their registration
	// envelope failed verification — so a de-authorised client's kernel
	// peer + IP are always torn down, not just on full-member removal.
	_, removedClientKeys, _, rerr := h.aclStore.Reconcile(vMembers, vApps)
	if rerr != nil {
		return nil, fmt.Errorf("device:state rejected: %w", rerr)
	}
	for _, k := range removedClientKeys {
		if err := h.wgServer.RemovePeer(k); err != nil {
			logging.Error("device:state: remove pruned peer %s: %v", k, err)
		}
		h.allocator.Release(k)
	}

	for _, m := range vMembers {
		if m.Status == "suspended" {
			for _, c := range m.Clients {
				if c.WGPublicKey != "" {
					if err := h.wgServer.RemovePeer(c.WGPublicKey); err != nil {
						logging.Error("device:state: drop suspended peer %s: %v", c.WGPublicKey, err)
					}
				}
			}
			continue
		}
		for _, c := range m.Clients {
			if c.WGPublicKey == "" || c.TunnelIP == "" {
				continue
			}
			if err := h.wgServer.AddPeer(c.WGPublicKey, c.TunnelIP); err != nil {
				logging.Error("device:state: add peer %s: %v", c.WGPublicKey, err)
			}
		}
	}

	// Reconcile firewall grants after peers so their tunnel IPs are present.
	if h.firewallReconcile != nil {
		h.firewallReconcile(context.Background())
	}

	h.reconcileCustomDomain(st.CustomDomain, ownerPub)

	h.aclStore.SetAppliedGeneration(st.Generation, now)
	if err := h.aclStore.Save(); err != nil {
		logging.Warn("Warning: failed to persist ACL after device:state: %v", err)
	}
	h.markLiveness(true)
	logging.Info("device:state applied: gen=%d members=%d apps=%d", st.Generation, len(vMembers), len(vApps))

	// Fire-and-forget: the next inbound state lacking the cert re-queues
	// the same send via the recovery path, so a failed Send self-heals.
	if h.sendUpstream != nil {
		for _, cert := range pendingAdmittance {
			msg, err := BuildAdmittanceMessage(h.deviceID, cert, h.keyManager.PrivateKey(), now)
			if err != nil {
				logging.Warn("member:admittance: build envelope failed for member %s: %v", cert.MemberID, err)
				continue
			}
			go func(m atreolink.TunnelMessage, memberID string) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := h.sendUpstream(ctx, m); err != nil {
					logging.Warn("member:admittance: send failed for member %s: %v", memberID, err)
				}
			}(msg, cert.MemberID)
		}
	}
	return nil, nil
}

func decodeEd25519(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("wrong length %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// reconcileCustomDomain: present ⇒ verify + EnsureCert + persist; absent ⇒
// clear any active row. Best-effort — cert failures don't fail the reconcile.
func (h *Handlers) reconcileCustomDomain(cd *atreolink.DSCustomDomain, ownerPub ed25519.PublicKey) {
	if h.certManager == nil || h.customDomainStore == nil {
		return
	}
	if cd == nil {
		row, err := h.customDomainStore.Get()
		if err != nil || row == nil {
			return
		}
		if rerr := h.certManager.Registry.RemoveSuffix(row.ParentZone); rerr != nil {
			logging.Error("device:state: custom-domain registry remove %s: %v", row.ParentZone, rerr)
		}
		if cerr := h.customDomainStore.Clear(); cerr != nil {
			logging.Error("device:state: custom-domain store clear: %v", cerr)
		}
		logging.Info("Custom domain cleared: stopped serving *.%s", row.ParentZone)
		return
	}
	var payload CustomDomainSetPayload
	if err := json.Unmarshal(cd.Envelope.Payload, &payload); err != nil {
		logging.Error("device:state: custom-domain payload: %v", err)
		return
	}
	zone := normaliseZone(payload.ParentZone)
	if zone == "" {
		return
	}
	expectedIntent := fmt.Sprintf("custom-domain-set-%s-%s", h.deviceID, zone)
	if err := h.verifyAuthorization(cd.Envelope.AsMessage("device:custom-domain-set"), AttestedAuth(ownerPub), payload.CommandEnvelopeFields, expectedIntent); err != nil {
		logging.Error("device:state: custom-domain envelope rejected: %v", err)
		return
	}
	if existing, err := h.customDomainStore.Get(); err == nil && existing != nil && existing.ParentZone == zone {
		return // idempotent: already serving this zone
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := h.certManager.EnsureCert(ctx, zone); err != nil {
		logging.Error("device:state: custom-domain cert issuance failed for %s: %v", zone, err)
		return
	}
	if err := h.customDomainStore.Set(&store.CustomDomain{
		ParentZone:       zone,
		EnvelopePayload:  cd.Envelope.Payload,
		EnvelopeOwnerSig: cd.Envelope.Signature,
		VerifiedAt:       time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		logging.Error("device:state: custom-domain persist failed for %s: %v", zone, err)
	}
	logging.Info("Custom domain active: serving *.%s", zone)
}

// HandleHeartbeatAck: equal generation = liveness (resets staleBound); a
// greater server generation just keeps serving (a fresh state is re-pushed).
func (h *Handlers) HandleHeartbeatAck(msg atreolink.TunnelMessage) (*atreolink.TunnelMessage, error) {
	var payload struct {
		Generation int64 `json:"generation"`
	}
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal acl:heartbeat:ack: %w", err)
	}
	applied := h.aclStore.AppliedGeneration()
	if payload.Generation == applied {
		h.markLiveness(false)
	} else if payload.Generation > applied {
		logging.Debug("acl:heartbeat:ack: server gen %d > applied %d — awaiting fresh device:state", payload.Generation, applied)
	}
	return nil, nil
}
