package wireguard

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// IPAllocator manages tunnel IP allocation within a subnet.
type IPAllocator struct {
	mu        sync.Mutex
	serverIP  string
	prefix    string            // e.g., "100.64.0"
	allocated map[string]string // pubkey → IP
	usedIPs   map[string]bool
	filePath  string
}

type ipAllocState struct {
	Allocated map[string]string `json:"allocated"`
}

// NewIPAllocator creates an allocator for the given subnet.
func NewIPAllocator(subnet, serverIP, filePath string) (*IPAllocator, error) {
	prefix, err := subnetPrefix(subnet)
	if err != nil {
		return nil, err
	}

	a := &IPAllocator{
		serverIP:  serverIP,
		prefix:    prefix,
		allocated: make(map[string]string),
		usedIPs:   make(map[string]bool),
		filePath:  filePath,
	}

	// Reserve server IP
	a.usedIPs[serverIP] = true
	// Reserve network and broadcast
	a.usedIPs[prefix+".0"] = true
	a.usedIPs[prefix+".255"] = true

	if err := a.Load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	return a, nil
}

// subnetPrefix extracts the /24 prefix from a subnet string like "100.64.0.0/24".
func subnetPrefix(subnet string) (string, error) {
	parts := strings.Split(subnet, "/")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid subnet: %s", subnet)
	}
	ip := parts[0]
	octets := strings.Split(ip, ".")
	if len(octets) != 4 {
		return "", fmt.Errorf("invalid subnet IP: %s", ip)
	}
	return strings.Join(octets[:3], "."), nil
}

// Allocate assigns a tunnel IP for the given client public key.
// Returns an existing allocation if one exists.
func (a *IPAllocator) Allocate(clientPubKey string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Return existing allocation
	if ip, ok := a.allocated[clientPubKey]; ok {
		return ip, nil
	}

	// Find next available IP (skip .0, .1, .255)
	for i := 2; i < 255; i++ {
		ip := fmt.Sprintf("%s.%d", a.prefix, i)
		if !a.usedIPs[ip] {
			a.allocated[clientPubKey] = ip
			a.usedIPs[ip] = true
			return ip, nil
		}
	}

	return "", fmt.Errorf("no available IPs in subnet %s.0/24", a.prefix)
}

// MarkUsed records that clientPubKey already holds ip, so a subsequent
// Allocate won't hand the same address to a different client. Idempotent.
// Used on startup by reconcilePeers to repopulate the allocator from the
// authoritative (atomically-persisted) ACL after a crash that lost the
// allocator's own state file — without it, Save() runs only on clean
// shutdown, so a SIGKILL/OOM leaves stale state and new allocations collide.
func (a *IPAllocator) MarkUsed(clientPubKey, ip string) {
	if ip == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.usedIPs[ip] = true
	if clientPubKey != "" {
		a.allocated[clientPubKey] = ip
	}
}

// TryAdopt records a tunnel IP for a not-yet-known pubkey, but only when it is
// safe: a canonical IPv4 in this allocator's /24, not reserved, and not held
// by another pubkey. Returns false otherwise so the caller falls back to
// Allocate. Used to restore an IP from the agent's own signed lease; the
// collision check refuses a stale lease whose IP was since reissued.
func (a *IPAllocator) TryAdopt(clientPubKey, ip string) bool {
	if clientPubKey == "" || ip == "" {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil || parsed.String() != ip {
		return false // unparseable, IPv6, or non-canonical (e.g. leading zeros)
	}
	if !strings.HasPrefix(ip, a.prefix+".") {
		return false // outside this allocator's subnet
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if cur, ok := a.allocated[clientPubKey]; ok {
		return cur == ip // idempotent if already ours; never silently move
	}
	for pk, held := range a.allocated {
		if held == ip && pk != clientPubKey {
			return false // already held by a different peer
		}
	}
	if a.usedIPs[ip] {
		return false // reserved (server IP, network, or broadcast)
	}
	a.usedIPs[ip] = true
	a.allocated[clientPubKey] = ip
	return true
}

// Release frees the IP allocated to the given client public key.
func (a *IPAllocator) Release(clientPubKey string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if ip, ok := a.allocated[clientPubKey]; ok {
		delete(a.usedIPs, ip)
		delete(a.allocated, clientPubKey)
	}
}

// Lookup returns the IP allocated to the given client public key, or empty string.
func (a *IPAllocator) Lookup(clientPubKey string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.allocated[clientPubKey]
}

// Save persists the allocator state to disk.
func (a *IPAllocator) Save() error {
	a.mu.Lock()
	state := ipAllocState{Allocated: a.allocated}
	a.mu.Unlock()

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(a.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// 0640: the file's bytes are WG pubkeys (not secrets) + tunnel-IP
	// allocations. World-readable would leak the membership graph
	// (which keys are paired to which IPs); group-readable is fine
	// because the agent container is a single-user image.
	tmp := a.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0640); err != nil {
		return err
	}
	return os.Rename(tmp, a.filePath)
}

// Load restores the allocator state from disk.
func (a *IPAllocator) Load() error {
	data, err := os.ReadFile(a.filePath)
	if err != nil {
		return err
	}

	var state ipAllocState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	for k, v := range state.Allocated {
		a.allocated[k] = v
		a.usedIPs[v] = true
	}
	return nil
}
