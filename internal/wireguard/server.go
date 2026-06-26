package wireguard

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/curve25519"

	"github.com/atreoLABS/atreoAGENT/internal/atomic"
)

// Leading `-` is rejected to defeat flag injection into `wg`.
func validateWGPublicKey(s string) error {
	if s == "" {
		return fmt.Errorf("empty")
	}
	if strings.HasPrefix(s, "-") {
		return fmt.Errorf("starts with '-' (rejected to defeat flag injection)")
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("not standard base64: %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("must decode to 32 bytes (got %d)", len(b))
	}
	return nil
}

// Defence against an unexpected value reaching `ip route add`.
func validateTunnelIPv4(s string) error {
	ip := net.ParseIP(s)
	if ip == nil {
		return fmt.Errorf("not a parseable IP literal: %q", s)
	}
	if ip.To4() == nil {
		return fmt.Errorf("not an IPv4 address: %q", s)
	}
	return nil
}

func validateTunnelIPv6(s string) error {
	ip := net.ParseIP(s)
	if ip == nil {
		return fmt.Errorf("not a parseable IP literal: %q", s)
	}
	if ip.To4() != nil {
		return fmt.Errorf("not an IPv6 address: %q", s)
	}
	return nil
}

// deriveTunnelIPv6 maps an allocated IPv4 overlay host to its IPv6 overlay
// counterpart by reusing the v4 host octet: 100.64.0.7 -> <serverIPv6>::7. The
// dual-stack overlay keeps a 1:1 host mapping so the single IPv4 allocator
// stays the source of truth and no separate v6 allocation state is persisted.
func deriveTunnelIPv6(serverIPv6, tunnelIPv4 string) (string, error) {
	v4 := net.ParseIP(tunnelIPv4)
	if v4 == nil || v4.To4() == nil {
		return "", fmt.Errorf("derive v6: %q is not an IPv4 literal", tunnelIPv4)
	}
	base := net.ParseIP(serverIPv6)
	if base == nil || base.To4() != nil {
		return "", fmt.Errorf("derive v6: server v6 %q is not an IPv6 literal", serverIPv6)
	}
	out := make(net.IP, net.IPv6len)
	copy(out, base.To16())
	out[15] = v4.To4()[3] // reuse the v4 host octet as the v6 interface id
	return out.String(), nil
}

// v6PrefixLen reads the prefix length from a ULA subnet like "fd00:64::/64".
func v6PrefixLen(subnetV6 string) int {
	if _, ipnet, err := net.ParseCIDR(subnetV6); err == nil {
		if ones, _ := ipnet.Mask.Size(); ones > 0 {
			return ones
		}
	}
	return 64
}

type Peer struct {
	PublicKey  string
	TunnelIP   string
	TunnelIPv6 string
}

// Drives a real WireGuard interface via the `wg` and `ip` CLIs.
type Server struct {
	listenPort int
	serverIP   string
	subnet     string
	serverIPv6 string
	subnetV6   string
	iface      string
	privateKey []byte
	publicKey  []byte
	keysDir    string
	allocator  *IPAllocator
	peers      map[string]Peer
	mu         sync.RWMutex
	running    bool
}

func NewServer(listenPort int, serverIP, subnet, serverIPv6, subnetV6, keysDir string, allocator *IPAllocator) (*Server, error) {
	s := &Server{
		listenPort: listenPort,
		serverIP:   serverIP,
		subnet:     subnet,
		serverIPv6: serverIPv6,
		subnetV6:   subnetV6,
		iface:      "wg-atreo",
		keysDir:    keysDir,
		allocator:  allocator,
		peers:      make(map[string]Peer),
	}

	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, fmt.Errorf("create keys dir: %w", err)
	}

	if err := s.loadOrGenerateKeys(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Server) loadOrGenerateKeys() error {
	privPath := filepath.Join(s.keysDir, "wg_private.key")
	pubPath := filepath.Join(s.keysDir, "wg_public.key")

	privData, err := os.ReadFile(privPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("read WG private key: %w", err)
		}
		priv := make([]byte, 32)
		if _, err := rand.Read(priv); err != nil {
			return fmt.Errorf("generate WG key: %w", err)
		}
		priv[0] &= 248
		priv[31] &= 127
		priv[31] |= 64

		pub, err := curve25519.X25519(priv, curve25519.Basepoint)
		if err != nil {
			return fmt.Errorf("derive WG public key: %w", err)
		}

		s.privateKey = priv
		s.publicKey = pub

		if err := atomic.WriteFile(privPath, []byte(base64.StdEncoding.EncodeToString(priv)), 0600); err != nil {
			return fmt.Errorf("write WG private key: %w", err)
		}
		if err := os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(pub)), 0600); err != nil {
			return fmt.Errorf("write WG public key: %w", err)
		}
		logging.Info("WireGuard: generated new keypair")
	} else {
		priv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(privData)))
		if err != nil {
			return fmt.Errorf("decode WG private key: %w", err)
		}
		pub, err := curve25519.X25519(priv, curve25519.Basepoint)
		if err != nil {
			return fmt.Errorf("derive WG public key: %w", err)
		}
		s.privateKey = priv
		s.publicKey = pub
	}
	return nil
}

func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("WireGuard server already running")
	}

	logging.Info("WireGuard: starting interface %s on :%d (IP: %s)", s.iface, s.listenPort, s.serverIP)
	logging.Info("WireGuard: public key: %s", s.PublicKey())

	// `wg set private-key` requires a file path. Written 0600 and removed
	// once the kernel has the key so it doesn't sit resident on disk for
	// the process lifetime (the canonical copy already lives 0600 under
	// keysDir; this raw base64 file is purely transient).
	privKeyFile := filepath.Join(s.keysDir, "wg_private_raw.key")
	if err := atomic.WriteFile(privKeyFile, []byte(base64.StdEncoding.EncodeToString(s.privateKey)+"\n"), 0600); err != nil {
		return fmt.Errorf("write temp private key: %w", err)
	}
	defer func() { _ = os.Remove(privKeyFile) }()

	_ = exec.CommandContext(ctx, "ip", "link", "del", s.iface).Run()

	if err := run(ctx, "ip", "link", "add", s.iface, "type", "wireguard"); err != nil {
		return fmt.Errorf("create interface: %w", err)
	}

	if err := run(ctx, "wg", "set", s.iface, "private-key", privKeyFile, "listen-port", fmt.Sprintf("%d", s.listenPort)); err != nil {
		_ = exec.CommandContext(ctx, "ip", "link", "del", s.iface).Run()
		return fmt.Errorf("configure interface: %w", err)
	}

	if err := run(ctx, "ip", "addr", "add", s.serverIP+"/24", "dev", s.iface); err != nil {
		_ = exec.CommandContext(ctx, "ip", "link", "del", s.iface).Run()
		return fmt.Errorf("assign IP: %w", err)
	}

	// Dual-stack overlay: app hostnames also carry an AAAA to this ULA so
	// IPv6-only / DNS64 clients aren't NAT64-synthesised off the IPv4 route.
	// Non-fatal — a host with IPv6 disabled keeps running the v4 overlay.
	if s.serverIPv6 != "" {
		v6addr := fmt.Sprintf("%s/%d", s.serverIPv6, v6PrefixLen(s.subnetV6))
		if err := run(ctx, "ip", "addr", "add", v6addr, "dev", s.iface); err != nil {
			logging.Warn("WireGuard: assign IPv6 %s failed — v6 overlay disabled on this host: %v", v6addr, err)
		}
	}

	if err := run(ctx, "ip", "link", "set", s.iface, "up"); err != nil {
		_ = exec.CommandContext(ctx, "ip", "link", "del", s.iface).Run()
		return fmt.Errorf("bring up interface: %w", err)
	}

	logging.Info("WireGuard: interface %s is up", s.iface)
	s.running = true
	return nil
}

func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	logging.Info("WireGuard: stopping interface %s (%d peers)", s.iface, len(s.peers))
	_ = exec.Command("ip", "link", "del", s.iface).Run()
	s.running = false
	return nil
}

// TunnelIPv6 derives a peer's IPv6 overlay address from its allocated v4, or
// "" when the v6 overlay is unconfigured or derivation fails — callers then
// degrade to a v4-only peer. Deterministic, so every call site (peer install,
// ACL index, firewall grant) agrees without sharing state.
func (s *Server) TunnelIPv6(tunnelIPv4 string) string {
	if s.serverIPv6 == "" {
		return ""
	}
	v6, err := deriveTunnelIPv6(s.serverIPv6, tunnelIPv4)
	if err != nil {
		logging.Error("WireGuard: derive v6 for %s failed: %v", tunnelIPv4, err)
		return ""
	}
	if err := validateTunnelIPv6(v6); err != nil {
		logging.Error("WireGuard: derived v6 %s invalid: %v", v6, err)
		return ""
	}
	return v6
}

// AllowedIPs is the client-side route set for the dual-stack overlay — the v4
// /24 plus the v6 /64 when configured. Signed into the provision transcript.
func (s *Server) AllowedIPs() string {
	if s.subnetV6 != "" {
		return s.subnet + "," + s.subnetV6
	}
	return s.subnet
}

// pubKey and tunnelIP arrive untrusted; both are validated to defeat
// flag-injection into the subprocess. The peer's v6 overlay address is derived
// from its v4 (1:1 host mapping) and added alongside when the overlay is dual-stack.
func (s *Server) AddPeer(pubKey, tunnelIP string) error {
	if err := validateWGPublicKey(pubKey); err != nil {
		return fmt.Errorf("wg pubkey: %w", err)
	}
	if err := validateTunnelIPv4(tunnelIP); err != nil {
		return fmt.Errorf("tunnel ip: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tunnelIPv6 := s.TunnelIPv6(tunnelIP)
	allowedIPs := tunnelIP + "/32"
	if tunnelIPv6 != "" {
		allowedIPs += "," + tunnelIPv6 + "/128"
	}
	if err := run(context.Background(), "wg", "set", s.iface,
		"peer", pubKey,
		"allowed-ips", allowedIPs,
	); err != nil {
		return fmt.Errorf("add peer: %w", err)
	}

	// `route replace` is idempotent — no-op if an identical route already exists.
	if err := run(context.Background(), "ip", "route", "replace", tunnelIP+"/32", "dev", s.iface); err != nil {
		logging.Error("WireGuard: route replace for %s failed: %v", tunnelIP, err)
	}
	if tunnelIPv6 != "" {
		if err := run(context.Background(), "ip", "-6", "route", "replace", tunnelIPv6+"/128", "dev", s.iface); err != nil {
			logging.Error("WireGuard: v6 route replace for %s failed: %v", tunnelIPv6, err)
		}
	}

	s.peers[pubKey] = Peer{PublicKey: pubKey, TunnelIP: tunnelIP, TunnelIPv6: tunnelIPv6}
	logging.Info("WireGuard: added peer %s with IP %s (%d total)", truncateKey(pubKey), tunnelIP, len(s.peers))
	return nil
}

func (s *Server) RemovePeer(pubKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	peer, exists := s.peers[pubKey]
	if !exists {
		return nil
	}

	if err := run(context.Background(), "wg", "set", s.iface, "peer", pubKey, "remove"); err != nil {
		logging.Warn("WireGuard: peer remove %s failed: %v", truncateKey(pubKey), err)
	}
	if err := run(context.Background(), "ip", "route", "del", peer.TunnelIP+"/32", "dev", s.iface); err != nil {
		logging.Error("WireGuard: route del %s failed (may already be gone): %v", peer.TunnelIP, err)
	}
	if peer.TunnelIPv6 != "" {
		if err := run(context.Background(), "ip", "-6", "route", "del", peer.TunnelIPv6+"/128", "dev", s.iface); err != nil {
			logging.Error("WireGuard: v6 route del %s failed (may already be gone): %v", peer.TunnelIPv6, err)
		}
	}

	delete(s.peers, pubKey)
	logging.Info("WireGuard: removed peer %s (%d remaining)", truncateKey(pubKey), len(s.peers))
	return nil
}

func (s *Server) ListPeers() []Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()

	peers := make([]Peer, 0, len(s.peers))
	for _, p := range s.peers {
		peers = append(peers, p)
	}
	return peers
}

func (s *Server) PublicKey() string {
	return base64.StdEncoding.EncodeToString(s.publicKey)
}

func (s *Server) ListenPort() int { return s.listenPort }

func run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func truncateKey(key string) string {
	if len(key) > 16 {
		return key[:16] + "..."
	}
	return key
}

// Returns (privateKey, publicKey) as base64.
func GenerateKeyPair() (string, string, error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("derive public key: %w", err)
	}

	return base64.StdEncoding.EncodeToString(priv), base64.StdEncoding.EncodeToString(pub), nil
}
