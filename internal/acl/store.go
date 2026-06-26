package acl

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
)

// Rotation only happens via an explicit re-pair (which clears the pin first).
var ErrAdminPinAlreadySet = errors.New("acl: pinned admin public key is already set; clear via re-pair")

const adminPinFilename = "admin_pin.json"

type adminPinFile struct {
	Algorithm string `json:"algorithm"` // informational; future-proofs if we rotate off Ed25519
	PublicKey string `json:"publicKey"` // base64 32-byte Ed25519 pubkey
}

type Store struct {
	mu      sync.RWMutex
	members []atreolink.MemberACLEntry
	// Device-level app catalogue, populated via app:upserted envelopes.
	// Owner/admin proxy lookups bypass the per-member gate and resolve here.
	apps        []atreolink.App
	filePath    string
	byTunnelIP  map[string]*atreolink.MemberACLEntry
	byMemberID  map[string]*atreolink.MemberACLEntry
	byEmailFull map[string]*atreolink.MemberACLEntry // SMTP routes by full RCPT match

	// Once set, ACL syncs that try to mutate the admin entry's
	// IdentityKey to a different value are rejected.
	pinnedAdminPubKey ed25519.PublicKey
	pinPath           string

	// Last applied cloud generation + the wall clock of that apply.
	generation    int64
	lastAppliedAt time.Time
}

type persistedState struct {
	Version       int                        `json:"version"`
	Members       []atreolink.MemberACLEntry `json:"members"`
	Apps          []atreolink.App            `json:"apps"`
	Generation    int64                      `json:"generation,omitempty"`
	LastAppliedAt string                     `json:"lastAppliedAt,omitempty"`
}

const persistedVersion = 1

// The pinned admin pubkey lives at `<aclDir>/admin_pin.json` (sibling).
func NewStore(filePath string) *Store {
	dir := filepath.Dir(filePath)
	return &Store{
		filePath:    filePath,
		pinPath:     filepath.Join(dir, adminPinFilename),
		byTunnelIP:  make(map[string]*atreolink.MemberACLEntry),
		byMemberID:  make(map[string]*atreolink.MemberACLEntry),
		byEmailFull: make(map[string]*atreolink.MemberACLEntry),
	}
}

// Load is a no-op when neither file exists (fresh agent).
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Pin first so subsequent paths see it set when present.
	if err := s.loadPinLocked(); err != nil {
		return fmt.Errorf("load admin pin: %w", err)
	}

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			s.members = nil
			s.apps = nil
			s.byTunnelIP = make(map[string]*atreolink.MemberACLEntry)
			s.byMemberID = make(map[string]*atreolink.MemberACLEntry)
			s.byEmailFull = make(map[string]*atreolink.MemberACLEntry)
			return nil
		}
		return err
	}

	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	s.members = state.Members
	s.apps = state.Apps
	s.generation = state.Generation
	if state.LastAppliedAt != "" {
		if t, perr := time.Parse(time.RFC3339, state.LastAppliedAt); perr == nil {
			s.lastAppliedAt = t
		}
	}
	s.rebuildIndexes()
	return nil
}

// loadPinLocked reads the admin pin file. Caller must hold s.mu (write).
func (s *Store) loadPinLocked() error {
	data, err := os.ReadFile(s.pinPath)
	if err != nil {
		if os.IsNotExist(err) {
			s.pinnedAdminPubKey = nil
			return nil
		}
		return err
	}
	var file adminPinFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parse admin pin file: %w", err)
	}
	if file.PublicKey == "" {
		s.pinnedAdminPubKey = nil
		return nil
	}
	pub, err := base64.StdEncoding.DecodeString(file.PublicKey)
	if err != nil {
		return fmt.Errorf("decode pinned pubkey: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("pinned pubkey wrong length: %d", len(pub))
	}
	s.pinnedAdminPubKey = ed25519.PublicKey(pub)
	return nil
}

// Returns a copy, or nil if no pin is set.
func (s *Store) PinnedAdminPublicKey() ed25519.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.pinnedAdminPubKey == nil {
		return nil
	}
	out := make(ed25519.PublicKey, len(s.pinnedAdminPubKey))
	copy(out, s.pinnedAdminPubKey)
	return out
}

// One-shot: re-pairing must call ClearPinnedAdminPublicKey first.
func (s *Store) SetPinnedAdminPublicKey(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("pubkey must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pinnedAdminPubKey != nil {
		return ErrAdminPinAlreadySet
	}
	s.pinnedAdminPubKey = make(ed25519.PublicKey, len(pub))
	copy(s.pinnedAdminPubKey, pub)
	return s.persistPinLocked()
}

// Reserved for the explicit re-pair path.
func (s *Store) ClearPinnedAdminPublicKey() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pinnedAdminPubKey = nil
	if err := os.Remove(s.pinPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *Store) persistPinLocked() error {
	dir := filepath.Dir(s.pinPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	file := adminPinFile{
		Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(s.pinnedAdminPubKey),
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.pinPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.pinPath)
}

func (s *Store) Save() error {
	s.mu.RLock()
	state := persistedState{
		Version:    persistedVersion,
		Members:    s.members,
		Apps:       s.apps,
		Generation: s.generation,
	}
	if !s.lastAppliedAt.IsZero() {
		state.LastAppliedAt = s.lastAppliedAt.UTC().Format(time.RFC3339)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return err
	}

	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// 0600: the file is the membership graph (emails, internalUrls, pubkeys).
	tmp := s.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.filePath)
}

// Returns ErrAdminPinViolation if any admin entry's IdentityKey doesn't
// match the pin, leaving the in-memory ACL untouched.
func (s *Store) ReplaceAll(members []atreolink.MemberACLEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateAdminPinLocked(members); err != nil {
		return err
	}
	s.members = members
	s.rebuildIndexes()
	return nil
}

// 0 = none applied yet.
func (s *Store) AppliedGeneration() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.generation
}

// Caller must Save() to persist.
func (s *Store) SetAppliedGeneration(gen int64, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.generation = gen
	s.lastAppliedAt = at
}

// Zero = never applied.
func (s *Store) LastAppliedAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastAppliedAt
}

// Reconcile wholesale-replaces the member + app sets and reports what was
// present before but absent after: whole members, individual client WG
// public keys (covers clients dropped from a *surviving* member, not just
// fully-removed members), and app IDs — so the caller can drop the
// corresponding WireGuard peers / proxy routes. A key still present
// anywhere in the new set is not reported. Admin pin is enforced; on
// violation the ACL is left untouched and nothing is reported.
func (s *Store) Reconcile(members []atreolink.MemberACLEntry, apps []atreolink.App) (removedMembers []atreolink.MemberACLEntry, removedClientKeys []string, removedAppIDs []string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if verr := s.validateAdminPinLocked(members); verr != nil {
		return nil, nil, nil, verr
	}

	next := make(map[string]struct{}, len(members))
	nextKeys := make(map[string]struct{})
	for _, m := range members {
		next[m.MemberID] = struct{}{}
		for _, c := range m.Clients {
			if c.WGPublicKey != "" {
				nextKeys[c.WGPublicKey] = struct{}{}
			}
		}
	}
	seenRemoved := make(map[string]struct{})
	for _, prev := range s.members {
		if _, stillPresent := next[prev.MemberID]; !stillPresent {
			removedMembers = append(removedMembers, prev)
		}
		for _, c := range prev.Clients {
			if c.WGPublicKey == "" {
				continue
			}
			if _, kept := nextKeys[c.WGPublicKey]; kept {
				continue
			}
			if _, dup := seenRemoved[c.WGPublicKey]; dup {
				continue
			}
			seenRemoved[c.WGPublicKey] = struct{}{}
			removedClientKeys = append(removedClientKeys, c.WGPublicKey)
		}
	}

	nextApps := make(map[string]struct{}, len(apps))
	for _, a := range apps {
		nextApps[a.ID] = struct{}{}
	}
	for _, prev := range s.apps {
		if _, ok := nextApps[prev.ID]; !ok {
			removedAppIDs = append(removedAppIDs, prev.ID)
		}
	}

	s.members = members
	s.apps = apps
	s.rebuildIndexes()
	return removedMembers, removedClientKeys, removedAppIDs, nil
}

var ErrAdminPinViolation = errors.New("acl: admin entry IdentityKey does not match pinned admin pubkey")

// Rejects blank IdentityKey too — without that check, admin metadata
// (Email, UserID, MemberName) consumed by SMTP routing and notify
// lookups could land in the store before signature verification.
func (s *Store) validateAdminPinLocked(members []atreolink.MemberACLEntry) error {
	if s.pinnedAdminPubKey == nil {
		return nil
	}
	pinB64 := base64.StdEncoding.EncodeToString(s.pinnedAdminPubKey)
	for _, m := range members {
		if m.Role != "admin" && m.Role != "owner" {
			continue
		}
		if m.IdentityKey == "" {
			return fmt.Errorf("%w: member %s has admin/owner role but empty IdentityKey (rejected to defeat pin-bypass-via-empty-key)", ErrAdminPinViolation, m.MemberID)
		}
		if m.IdentityKey != pinB64 {
			return fmt.Errorf("%w: member %s claims identityKey %s but pin is %s", ErrAdminPinViolation, m.MemberID, m.IdentityKey, pinB64)
		}
	}
	return nil
}

// UpsertMember preserves existing Clients (with their allocator-assigned
// tunnel IPs) when the incoming member entry's Clients are empty or
// missing IPs — the agent owns IP allocation, atreoLINK may not know.
func (s *Store) UpsertMember(member atreolink.MemberACLEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateAdminPinLocked([]atreolink.MemberACLEntry{member}); err != nil {
		return err
	}
	for i, existing := range s.members {
		if existing.MemberID == member.MemberID {
			if len(member.Clients) == 0 {
				member.Clients = existing.Clients
			} else {
				byKey := make(map[string]atreolink.ClientRecord, len(existing.Clients))
				for _, c := range existing.Clients {
					byKey[c.WGPublicKey] = c
				}
				for j, in := range member.Clients {
					prev, ok := byKey[in.WGPublicKey]
					if !ok {
						continue
					}
					if in.TunnelIP == "" {
						in.TunnelIP = prev.TunnelIP
					}
					if in.Label == "" {
						in.Label = prev.Label
					}
					if in.Platform == "" {
						in.Platform = prev.Platform
					}
					if in.EndpointType == "" {
						in.EndpointType = prev.EndpointType
					}
					member.Clients[j] = in
				}
			}
			s.members[i] = member
			s.rebuildIndexes()
			return nil
		}
	}
	s.members = append(s.members, member)
	s.rebuildIndexes()
	return nil
}

// SetAllowedApps replaces a member's allowed apps list. Returns false if the
// member isn't in the ACL (no-op).
func (s *Store) SetAllowedApps(memberID string, apps []atreolink.App) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, m := range s.members {
		if m.MemberID == memberID {
			s.members[i].AllowedApps = apps
			s.rebuildIndexes()
			return true
		}
	}
	return false
}

// Returns a Clients snapshot so the caller can reconcile WG peers
// against the kernel.
func (s *Store) SetMemberStatus(memberID, status string) (clients []atreolink.ClientRecord, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, m := range s.members {
		if m.MemberID == memberID {
			s.members[i].Status = status
			snap := append([]atreolink.ClientRecord(nil), s.members[i].Clients...)
			s.rebuildIndexes()
			return snap, true
		}
	}
	return nil, false
}

// Upserts a client record, enforcing global uniqueness on WGPublicKey
// and TunnelIP. Idempotent on (memberID, WGPublicKey): re-adding
// refreshes any non-empty fields, otherwise preserves existing.
func (s *Store) AddClient(memberID string, rec atreolink.ClientRecord) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec.WGPublicKey == "" {
		return false
	}

	// Strip key OR IP from every other member.
	for i := range s.members {
		if s.members[i].MemberID == memberID {
			continue
		}
		kept := s.members[i].Clients[:0]
		for _, c := range s.members[i].Clients {
			if c.WGPublicKey == rec.WGPublicKey {
				continue
			}
			if rec.TunnelIP != "" && c.TunnelIP == rec.TunnelIP {
				continue
			}
			kept = append(kept, c)
		}
		s.members[i].Clients = kept
	}

	for i := range s.members {
		if s.members[i].MemberID != memberID {
			continue
		}
		for j, c := range s.members[i].Clients {
			if c.WGPublicKey == rec.WGPublicKey {
				if rec.TunnelIP == "" {
					rec.TunnelIP = c.TunnelIP
				}
				if rec.TunnelIPv6 == "" {
					rec.TunnelIPv6 = c.TunnelIPv6
				}
				if rec.Label == "" {
					rec.Label = c.Label
				}
				if rec.Platform == "" {
					rec.Platform = c.Platform
				}
				if rec.EndpointType == "" {
					rec.EndpointType = c.EndpointType
				}
				s.members[i].Clients[j] = rec
				s.rebuildIndexes()
				return true
			}
		}
		s.members[i].Clients = append(s.members[i].Clients, rec)
		s.rebuildIndexes()
		return true
	}
	return false
}

// RemoveClient drops the client record matching wgPublicKey from a member.
// Returns false if no such client was found (or member doesn't exist).
func (s *Store) RemoveClient(memberID, wgPublicKey string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.members {
		if s.members[i].MemberID != memberID {
			continue
		}
		removed := false
		kept := s.members[i].Clients[:0]
		for _, c := range s.members[i].Clients {
			if c.WGPublicKey == wgPublicKey {
				removed = true
				continue
			}
			kept = append(kept, c)
		}
		s.members[i].Clients = kept
		if removed {
			s.rebuildIndexes()
		}
		return removed
	}
	return false
}

// LookupClientByIP returns the (memberID, ClientRecord) holding ip.
func (s *Store) LookupClientByIP(ip string) (memberID string, rec atreolink.ClientRecord, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if entry, found := s.byTunnelIP[ip]; found {
		for _, c := range entry.Clients {
			if c.TunnelIP == ip || c.TunnelIPv6 == ip {
				return entry.MemberID, c, true
			}
		}
	}
	return "", atreolink.ClientRecord{}, false
}

// Upserts into the device app catalogue and mirrors changes onto any
// member AllowedApps entry already referencing the same ID, so a
// changed internalUrl propagates.
func (s *Store) SetAppDefinitions(apps []atreolink.App) {
	s.mu.Lock()
	defer s.mu.Unlock()
	byID := make(map[string]atreolink.App, len(apps))
	for _, a := range apps {
		byID[a.ID] = a
	}
	for _, incoming := range apps {
		updated := false
		for i, existing := range s.apps {
			if existing.ID == incoming.ID {
				s.apps[i] = incoming
				updated = true
				break
			}
		}
		if !updated {
			s.apps = append(s.apps, incoming)
		}
	}
	for i := range s.members {
		for j, existing := range s.members[i].AllowedApps {
			if updated, ok := byID[existing.ID]; ok {
				s.members[i].AllowedApps[j] = updated
			}
		}
	}
}

// Returns the number of member-level AllowedApps removals.
func (s *Store) RemoveAppByID(appID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	keptApps := s.apps[:0]
	for _, a := range s.apps {
		if a.ID != appID {
			keptApps = append(keptApps, a)
		}
	}
	s.apps = keptApps
	removed := 0
	for i := range s.members {
		filtered := s.members[i].AllowedApps[:0]
		for _, a := range s.members[i].AllowedApps {
			if a.ID == appID {
				removed++
				continue
			}
			filtered = append(filtered, a)
		}
		s.members[i].AllowedApps = filtered
	}
	return removed
}

// LookupByTunnelIP finds a member by one of their tunnel IPs.
func (s *Store) LookupByTunnelIP(ip string) *atreolink.MemberACLEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byTunnelIP[ip]
}

// LookupByMemberID finds a member by their member ID.
func (s *Store) LookupByMemberID(id string) *atreolink.MemberACLEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byMemberID[id]
}

// AdminEntry returns a copy, or nil if no admin row is installed yet.
func (s *Store) AdminEntry() *atreolink.MemberACLEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.members {
		if s.members[i].Role == "admin" || s.members[i].Role == "owner" {
			cp := s.members[i]
			return &cp
		}
	}
	return nil
}

func (s *Store) RemoveMember(memberID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, m := range s.members {
		if m.MemberID == memberID {
			s.members = append(s.members[:i], s.members[i+1:]...)
			break
		}
	}
	s.rebuildIndexes()
}

// Used at startup to re-check joinAttestations against the pinned
// owner pubkey. Does not persist — caller decides whether to Save.
func (s *Store) DropMembersFailing(verify func(atreolink.MemberACLEntry) error) []atreolink.MemberACLEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	var kept []atreolink.MemberACLEntry
	var dropped []atreolink.MemberACLEntry
	for _, m := range s.members {
		if err := verify(m); err != nil {
			dropped = append(dropped, m)
			continue
		}
		kept = append(kept, m)
	}
	if len(dropped) == 0 {
		return nil
	}
	s.members = kept
	s.rebuildIndexes()
	return dropped
}

// AllMembers returns a copy of all members.
func (s *Store) AllMembers() []atreolink.MemberACLEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]atreolink.MemberACLEntry, len(s.members))
	copy(result, s.members)
	return result
}

// Source of truth for owner/admin proxy lookups.
func (s *Store) AllApps() []atreolink.App {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]atreolink.App, len(s.apps))
	copy(out, s.apps)
	return out
}

// IsAppAllowed checks whether sourceIP may reach the app with appSlug.
func (s *Store) IsAppAllowed(sourceIP, appSlug string) (bool, *atreolink.App) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	member := s.byTunnelIP[sourceIP]
	if member == nil {
		return false, nil
	}

	// Suspended members get nothing, regardless of role/AllowedApps.
	if member.Status != "" && member.Status != "active" {
		return false, nil
	}

	// Owners/admins bypass the per-member AllowedApps gate.
	if member.Role == "admin" || member.Role == "owner" {
		app := s.findAppBySlug(appSlug)
		if app != nil {
			return true, app
		}
		return false, nil
	}

	for i, app := range member.AllowedApps {
		if app.IsPort() {
			continue // firewall-reached, never the proxy
		}
		if app.EffectiveSlug() == appSlug {
			return true, &member.AllowedApps[i]
		}
	}
	return false, nil
}

// FindAppBySlug returns an app by its slug across all members.
func (s *Store) FindAppBySlug(slug string) *atreolink.App {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findAppBySlug(slug)
}

func (s *Store) findAppBySlug(slug string) *atreolink.App {
	for i, app := range s.apps {
		if app.IsPort() {
			continue // firewall-reached, never the proxy
		}
		if app.EffectiveSlug() == slug {
			return &s.apps[i]
		}
	}
	// Fallback for member-permissioned apps that pre-date the catalogue.
	for _, m := range s.members {
		for i, app := range m.AllowedApps {
			if app.IsPort() {
				continue
			}
			if app.EffectiveSlug() == slug {
				return &m.AllowedApps[i]
			}
		}
	}
	return nil
}

// PortGrant authorises a peer (by tunnel source IP) to reach raw host ports.
// TunnelIPv6 is the peer's v6 overlay address (empty on a v4-only overlay) so
// the firewall can confine the same peer reaching the proxy over either family.
type PortGrant struct {
	TunnelIP   string
	TunnelIPv6 string
	TCP        []int
	UDP        []int
}

// PortGrants derives the per-peer raw-port grants: one per active member's
// client tunnel IP, from that member's port-type AllowedApps.
func (s *Store) PortGrants() []PortGrant {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var grants []PortGrant
	for i := range s.members {
		m := &s.members[i]
		if m.Status != "" && m.Status != "active" {
			continue
		}
		var tcp, udp []int
		for _, app := range m.AllowedApps {
			if !app.IsPort() || app.Port < 1 || app.Port > 65535 {
				continue
			}
			switch app.Protocol {
			case "tcp", "http", "https": // http/https are L7 hints; firewall-wise TCP
				tcp = append(tcp, app.Port)
			case "udp":
				udp = append(udp, app.Port)
			}
		}
		if len(tcp) == 0 && len(udp) == 0 {
			continue
		}
		for _, c := range m.Clients {
			if c.TunnelIP == "" {
				continue
			}
			grants = append(grants, PortGrant{TunnelIP: c.TunnelIP, TunnelIPv6: c.TunnelIPv6, TCP: tcp, UDP: udp})
		}
	}
	return grants
}

func (s *Store) rebuildIndexes() {
	s.byTunnelIP = make(map[string]*atreolink.MemberACLEntry, len(s.members))
	s.byMemberID = make(map[string]*atreolink.MemberACLEntry, len(s.members))
	s.byEmailFull = make(map[string]*atreolink.MemberACLEntry, len(s.members))
	for i := range s.members {
		m := &s.members[i]
		s.byMemberID[m.MemberID] = m
		for _, c := range m.Clients {
			if c.TunnelIP != "" {
				s.byTunnelIP[c.TunnelIP] = m
			}
			if c.TunnelIPv6 != "" {
				s.byTunnelIP[c.TunnelIPv6] = m
			}
		}
		if email := strings.ToLower(strings.TrimSpace(m.Email)); email != "" {
			s.byEmailFull[email] = m
		}
	}
}

// Case-insensitive, whitespace-trimmed. Unique by contract.
func (s *Store) LookupByEmail(email string) *atreolink.MemberACLEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byEmailFull[strings.ToLower(strings.TrimSpace(email))]
}

// String returns a summary for debugging.
func (s *Store) String() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return fmt.Sprintf("ACLStore{members=%d, tunnelIPs=%d}", len(s.members), len(s.byTunnelIP))
}
