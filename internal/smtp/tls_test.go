package smtp

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sasl "github.com/emersion/go-sasl"
	gosmtp "github.com/emersion/go-smtp"

	"github.com/atreoLABS/atreoAGENT/internal/acl"
	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
)

func TestLoadOrGenerateTLSCert_GeneratesAndPersists(t *testing.T) {
	dir := t.TempDir()
	cert, err := loadOrGenerateTLSCert(dir)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("no certificate bytes")
	}
	for _, name := range []string{tlsCertFile, tlsKeyFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected %s to be written: %v", name, err)
		}
	}

	leaf1, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if time.Now().After(leaf1.NotAfter) {
		t.Error("freshly generated cert is already expired")
	}

	// Second call must reuse the on-disk material (same leaf serial).
	cert2, err := loadOrGenerateTLSCert(dir)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	leaf2, err := x509.ParseCertificate(cert2.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf 2: %v", err)
	}
	if leaf1.SerialNumber.Cmp(leaf2.SerialNumber) != 0 {
		t.Error("expected the persisted cert to be reused, got a freshly generated one")
	}
}

func TestNewServer_TLSDisabledByDefault(t *testing.T) {
	s := mustNewServer(t, Config{}, nil)
	if s.tlsOn {
		t.Error("tlsOn should be false by default")
	}
	if s.gosmtp.TLSConfig != nil {
		t.Error("gosmtp.TLSConfig should be nil when TLS is disabled")
	}
}

func TestNewServer_TLSEnabledRequiresDataDir(t *testing.T) {
	store := acl.NewStore("")
	if _, err := NewServer(Config{TLSEnabled: true}, store, &fakeNotify{}); err == nil {
		t.Fatal("expected error when TLS enabled without a data dir")
	}
}

func TestNewServer_TLSEnabledLoadsCert(t *testing.T) {
	s := mustNewServer(t, Config{TLSEnabled: true, DataDir: t.TempDir()}, nil)
	if !s.tlsOn {
		t.Error("tlsOn should be true")
	}
	if s.gosmtp.TLSConfig == nil || len(s.gosmtp.TLSConfig.Certificates) != 1 {
		t.Error("gosmtp.TLSConfig should carry exactly one certificate")
	}
}

// TestSTARTTLS_EndToEnd brings up the gateway with TLS enabled, connects
// a real go-smtp client over STARTTLS, authenticates with the notify API
// key, and sends a message — asserting the whole opportunistic-TLS path
// works and the dispatch reaches notify.
func TestSTARTTLS_EndToEnd(t *testing.T) {
	const apiKey = "test-notify-api-key-32-bytes!!!"
	store := acl.NewStore("")
	if err := store.ReplaceAll([]atreolink.MemberACLEntry{
		{MemberID: "m1", Role: "admin", Email: "alice@example.com", IdentityKey: "x"},
	}); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}
	fn := &fakeNotify{key: apiKey}
	srv := mustNewServer(t, Config{TLSEnabled: true, DataDir: t.TempDir()}, store)
	srv.notify = fn

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() { _ = srv.gosmtp.Serve(ln) }()
	addr := ln.Addr().String()

	// Plain probe: STARTTLS must be advertised.
	probe, err := gosmtp.Dial(addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if ok, _ := probe.Extension("STARTTLS"); !ok {
		t.Error("server did not advertise STARTTLS in EHLO")
	}
	_ = probe.Close()

	// DialStartTLS performs EHLO + STARTTLS; it errors if STARTTLS isn't
	// advertised, so reaching the post-handshake state proves the path.
	c, err := gosmtp.DialStartTLS(addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("DialStartTLS: %v", err)
	}
	defer func() { _ = c.Close() }()
	if _, ok := c.TLSConnectionState(); !ok {
		t.Fatal("connection is not TLS after STARTTLS")
	}
	if err := c.Auth(sasl.NewPlainClient("", "anything", apiKey)); err != nil {
		t.Fatalf("AUTH after STARTTLS: %v", err)
	}
	if err := c.SendMail("sender@example.com", []string{"alice@example.com"},
		strings.NewReader("Subject: hi\r\n\r\nbody\r\n")); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	sent, member, req := fn.snapshot()
	if sent != 1 || member == nil || member.MemberID != "m1" {
		t.Fatalf("expected one dispatch to m1, got sent=%d member=%v", sent, member)
	}
	if req == nil || req.Title != "hi" {
		t.Errorf("unexpected notify request: %+v", req)
	}
}

// TestPlaintext_StillWorksWithTLSEnabled confirms TLS is *opportunistic*:
// a client that never issues STARTTLS can still auth and send (the LAN
// residual is accepted; we don't force the upgrade).
func TestPlaintext_StillWorksWithTLSEnabled(t *testing.T) {
	const apiKey = "another-test-key-value-here-32b"
	store := acl.NewStore("")
	if err := store.ReplaceAll([]atreolink.MemberACLEntry{
		{MemberID: "m1", Role: "admin", Email: "alice@example.com", IdentityKey: "x"},
	}); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}
	fn := &fakeNotify{key: apiKey}
	srv := mustNewServer(t, Config{TLSEnabled: true, DataDir: t.TempDir()}, store)
	srv.notify = fn

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() { _ = srv.gosmtp.Serve(ln) }()

	c, err := gosmtp.Dial(ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Auth(sasl.NewPlainClient("", "x", apiKey)); err != nil {
		t.Fatalf("plaintext AUTH: %v", err)
	}
	if err := c.SendMail("s@example.com", []string{"alice@example.com"},
		strings.NewReader("Subject: plain\r\n\r\nb\r\n")); err != nil {
		t.Fatalf("SendMail: %v", err)
	}
	if sent, _, _ := fn.snapshot(); sent != 1 {
		t.Fatalf("expected one dispatch, got %d", sent)
	}
}

func mustNewServer(t *testing.T, cfg Config, store *acl.Store) *Server {
	t.Helper()
	if store == nil {
		store = acl.NewStore("")
	}
	s, err := NewServer(cfg, store, &fakeNotify{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s
}
