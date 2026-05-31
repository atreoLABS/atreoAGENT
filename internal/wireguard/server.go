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

type Peer struct {
	PublicKey string
	TunnelIP  string
}

// Drives a real WireGuard interface via the `wg` and `ip` CLIs.
type Server struct {
	listenPort int
	serverIP   string
	subnet     string
	iface      string
	privateKey []byte
	publicKey  []byte
	keysDir    string
	allocator  *IPAllocator
	peers      map[string]Peer
	mu         sync.RWMutex
	running    bool
}

func NewServer(listenPort int, serverIP, subnet, keysDir string, allocator *IPAllocator) (*Server, error) {
	s := &Server{
		listenPort: listenPort,
		serverIP:   serverIP,
		subnet:     subnet,
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

	// `wg set private-key` requires a file path.
	privKeyFile := filepath.Join(s.keysDir, "wg_private_raw.key")
	if err := atomic.WriteFile(privKeyFile, []byte(base64.StdEncoding.EncodeToString(s.privateKey)+"\n"), 0600); err != nil {
		return fmt.Errorf("write temp private key: %w", err)
	}

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

// pubKey and tunnelIP arrive untrusted; both are validated to defeat
// flag-injection into the subprocess.
func (s *Server) AddPeer(pubKey, tunnelIP string) error {
	if err := validateWGPublicKey(pubKey); err != nil {
		return fmt.Errorf("wg pubkey: %w", err)
	}
	if err := validateTunnelIPv4(tunnelIP); err != nil {
		return fmt.Errorf("tunnel ip: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	allowedIPs := tunnelIP + "/32"
	if err := run(context.Background(), "wg", "set", s.iface,
		"peer", pubKey,
		"allowed-ips", allowedIPs,
	); err != nil {
		return fmt.Errorf("add peer: %w", err)
	}

	// `route replace` is idempotent — no-op if an identical route already exists.
	if err := run(context.Background(), "ip", "route", "replace", allowedIPs, "dev", s.iface); err != nil {
		logging.Error("WireGuard: route replace for %s failed: %v", allowedIPs, err)
	}

	s.peers[pubKey] = Peer{PublicKey: pubKey, TunnelIP: tunnelIP}
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
