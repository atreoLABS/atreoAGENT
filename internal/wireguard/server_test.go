package wireguard

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	allocator, err := NewIPAllocator("100.64.0.0/24", "100.64.0.1", filepath.Join(dir, "alloc.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(51820, "100.64.0.1", "100.64.0.0/24", "fd00:64::1", "fd00:64::/64", keysDir, allocator)
	if err != nil {
		t.Fatal(err)
	}
	return srv, keysDir
}

func TestDeriveTunnelIPv6(t *testing.T) {
	cases := []struct {
		v4, want string
	}{
		{"100.64.0.1", "fd00:64::1"},   // server
		{"100.64.0.2", "fd00:64::2"},   // first client
		{"100.64.0.42", "fd00:64::2a"}, // host octet 42 == 0x2a
		{"100.64.0.254", "fd00:64::fe"},
	}
	for _, c := range cases {
		got, err := deriveTunnelIPv6("fd00:64::1", c.v4)
		if err != nil {
			t.Fatalf("deriveTunnelIPv6(%q): %v", c.v4, err)
		}
		if got != c.want {
			t.Errorf("deriveTunnelIPv6(%q) = %q, want %q", c.v4, got, c.want)
		}
	}
	if _, err := deriveTunnelIPv6("fd00:64::1", "not-an-ip"); err == nil {
		t.Error("expected error for non-IPv4 input")
	}
	if _, err := deriveTunnelIPv6("100.64.0.1", "100.64.0.2"); err == nil {
		t.Error("expected error when serverIPv6 is not IPv6")
	}
}

func TestServerTunnelIPv6_EmptyWhenUnconfigured(t *testing.T) {
	dir := t.TempDir()
	allocator, _ := NewIPAllocator("100.64.0.0/24", "100.64.0.1", filepath.Join(dir, "alloc.json"))
	// serverIPv6 == "" → v4-only overlay, derivation returns "".
	srv, err := NewServer(51820, "100.64.0.1", "100.64.0.0/24", "", "", filepath.Join(dir, "keys"), allocator)
	if err != nil {
		t.Fatal(err)
	}
	if got := srv.TunnelIPv6("100.64.0.7"); got != "" {
		t.Errorf("TunnelIPv6 on v4-only overlay = %q, want empty", got)
	}
	if got := srv.AllowedIPs(); got != "100.64.0.0/24" {
		t.Errorf("AllowedIPs v4-only = %q, want 100.64.0.0/24", got)
	}
}

func TestNewServer_GeneratesKeysIfMissing(t *testing.T) {
	srv, keysDir := newTestServer(t)
	if srv.PublicKey() == "" {
		t.Error("PublicKey is empty after NewServer")
	}
	for _, name := range []string{"wg_private.key", "wg_public.key"} {
		if _, err := os.Stat(filepath.Join(keysDir, name)); err != nil {
			t.Errorf("expected %s to be generated: %v", name, err)
		}
	}
	if got := srv.ListenPort(); got != 51820 {
		t.Errorf("ListenPort=%d", got)
	}
}

func TestNewServer_LoadsExistingKeys(t *testing.T) {
	srv1, keysDir := newTestServer(t)
	pub1 := srv1.PublicKey()

	allocator, _ := NewIPAllocator("100.64.0.0/24", "100.64.0.1", filepath.Join(t.TempDir(), "alloc.json"))
	srv2, err := NewServer(51820, "100.64.0.1", "100.64.0.0/24", "fd00:64::1", "fd00:64::/64", keysDir, allocator)
	if err != nil {
		t.Fatal(err)
	}
	if srv2.PublicKey() != pub1 {
		t.Error("loaded key differs from generated key")
	}
}

func TestNewServer_BadKeyFile(t *testing.T) {
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "wg_private.key"), []byte("not-base64!!!"), 0600); err != nil {
		t.Fatal(err)
	}
	allocator, _ := NewIPAllocator("100.64.0.0/24", "100.64.0.1", filepath.Join(dir, "alloc.json"))
	if _, err := NewServer(51820, "100.64.0.1", "100.64.0.0/24", "fd00:64::1", "fd00:64::/64", keysDir, allocator); err == nil {
		t.Error("expected error on corrupt private key file")
	}
}

func TestPublicKeyDecodesToCurve25519(t *testing.T) {
	srv, _ := newTestServer(t)
	raw, err := base64.StdEncoding.DecodeString(srv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 32 {
		t.Errorf("public key len=%d, want 32", len(raw))
	}
}

func TestListPeers_StartsEmpty(t *testing.T) {
	srv, _ := newTestServer(t)
	if peers := srv.ListPeers(); len(peers) != 0 {
		t.Errorf("expected 0 peers, got %d", len(peers))
	}
}

func TestRemovePeer_NoOpWhenAbsent(t *testing.T) {
	srv, _ := newTestServer(t)
	// Removing a peer that was never added returns nil (no error) without
	// invoking the wg subprocess.
	if err := srv.RemovePeer("never-added"); err != nil {
		t.Errorf("RemovePeer absent: %v", err)
	}
}

func TestGenerateKeyPair(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	privB, err := base64.StdEncoding.DecodeString(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubB, err := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(privB) != 32 || len(pubB) != 32 {
		t.Errorf("len(priv)=%d len(pub)=%d, want 32", len(privB), len(pubB))
	}

	// Two calls produce distinct keypairs.
	priv2, _, _ := GenerateKeyPair()
	if priv == priv2 {
		t.Error("two GenerateKeyPair calls collided")
	}
}

// validKey32 returns a strict-base64 32-byte string usable as a
// well-formed WG public key fixture.
func validKey32() string {
	var b [32]byte
	for i := range b {
		b[i] = byte(i)
	}
	return base64.StdEncoding.EncodeToString(b[:])
}

func TestValidateWGPublicKey(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"valid", validKey32(), false},
		{"empty", "", true},
		{"leading-dash", "-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", true},
		{"not-base64", "not!base64@@", true},
		{"wrong-length", base64.StdEncoding.EncodeToString([]byte("only-15-bytes!!")), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateWGPublicKey(tc.key)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateWGPublicKey(%q) err=%v, wantErr=%v", tc.key, err, tc.wantErr)
			}
		})
	}
}

func TestValidateTunnelIPv4(t *testing.T) {
	cases := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"valid-v4", "100.64.0.7", false},
		{"empty", "", true},
		{"garbage", "not-an-ip", true},
		{"v6", "::1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTunnelIPv4(tc.ip)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateTunnelIPv4(%q) err=%v, wantErr=%v", tc.ip, err, tc.wantErr)
			}
		})
	}
}

// TestAddPeer_RejectsMalformedKey exercises the validator gate before
// any wg CLI call. The test runs without the wg subprocess because
// validation happens up front.
func TestAddPeer_RejectsMalformedKey(t *testing.T) {
	srv, _ := newTestServer(t)
	if err := srv.AddPeer("", "100.64.0.7"); err == nil {
		t.Error("expected empty pubkey to be rejected")
	}
	if err := srv.AddPeer("-injected", "100.64.0.7"); err == nil {
		t.Error("expected leading-dash pubkey to be rejected")
	}
	if err := srv.AddPeer("not!base64", "100.64.0.7"); err == nil {
		t.Error("expected non-base64 pubkey to be rejected")
	}
}

func TestAddPeer_RejectsMalformedTunnelIP(t *testing.T) {
	srv, _ := newTestServer(t)
	if err := srv.AddPeer(validKey32(), "not-an-ip"); err == nil {
		t.Error("expected non-IP tunnelIP to be rejected")
	}
	if err := srv.AddPeer(validKey32(), "::1"); err == nil {
		t.Error("expected IPv6 tunnelIP to be rejected")
	}
}

func TestTruncateKey(t *testing.T) {
	if got := truncateKey("short"); got != "short" {
		t.Errorf("truncateKey(short)=%q", got)
	}
	long := "0123456789abcdef0123456789"
	if got := truncateKey(long); got != "0123456789abcdef..." {
		t.Errorf("truncateKey long: %q", got)
	}
}
