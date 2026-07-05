package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"
)

// writeSelfSignedCert generates a self-signed wildcard cert for `*.<host>`
// and writes the PEM-encoded cert + key to the given paths. Used to seed
// the registry in tests without the lego/ACME machinery.
func writeSelfSignedCert(t *testing.T, host, certPath, keyPath string, expiresIn time.Duration) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "*." + host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(expiresIn),
		DNSNames:     []string{"*." + host},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func seededRegistry(t *testing.T, hosts ...string) *Registry {
	t.Helper()
	root := t.TempDir()
	for _, h := range hosts {
		certPath := filepath.Join(root, h, "cert.pem")
		keyPath := filepath.Join(root, h, "key.pem")
		writeSelfSignedCert(t, h, certPath, keyPath, 24*time.Hour)
	}
	r := NewRegistry(root)
	if err := r.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	return r
}

// --- AddSuffix / RemoveSuffix / Suffixes -------------------------------

func TestRegistry_AddRemoveSuffix(t *testing.T) {
	r := NewRegistry(t.TempDir())
	r.AddSuffix("alice.atreo.link")
	r.AddSuffix("example.com")
	got := r.Suffixes()
	// Longest-first ordering — "alice.atreo.link" (16) before "example.com" (10).
	want := []string{"alice.atreo.link", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Suffixes: got %v, want %v", got, want)
	}

	if err := r.RemoveSuffix("example.com"); err != nil {
		t.Fatalf("RemoveSuffix: %v", err)
	}
	if got := r.Suffixes(); !reflect.DeepEqual(got, []string{"alice.atreo.link"}) {
		t.Errorf("after remove: got %v", got)
	}
}

func TestRegistry_AddSuffix_Idempotent(t *testing.T) {
	r := NewRegistry(t.TempDir())
	r.AddSuffix("alice.atreo.link")
	r.AddSuffix("alice.atreo.link")
	if got := r.Suffixes(); len(got) != 1 {
		t.Errorf("expected 1 suffix, got %v", got)
	}
}

func TestRegistry_RemoveSuffix_Unknown(t *testing.T) {
	r := NewRegistry(t.TempDir())
	if err := r.RemoveSuffix("never-added.com"); err != nil {
		t.Errorf("removing unknown suffix should be a no-op: %v", err)
	}
}

func TestRegistry_NormaliseInputs(t *testing.T) {
	r := NewRegistry(t.TempDir())
	// All four forms should normalise to the same key.
	r.AddSuffix("  *.EXAMPLE.com.  ")
	r.AddSuffix("example.com")
	r.AddSuffix("EXAMPLE.COM")
	r.AddSuffix("*.example.com")
	if got := r.Suffixes(); !reflect.DeepEqual(got, []string{"example.com"}) {
		t.Errorf("expected single normalised entry, got %v", got)
	}
}

// --- Load + LoadSuffix --------------------------------------------------

func TestRegistry_LoadPicksUpExistingFiles(t *testing.T) {
	r := seededRegistry(t, "alice.atreo.link", "example.com")
	if !r.Has("alice.atreo.link") {
		t.Errorf("expected alice cert loaded")
	}
	if !r.Has("example.com") {
		t.Errorf("expected harvey cert loaded")
	}
}

func TestRegistry_Load_IgnoresLooseFiles(t *testing.T) {
	root := t.TempDir()
	// Drop a stray file at the root — should be ignored, not crash.
	if err := os.WriteFile(filepath.Join(root, "stray.txt"), []byte("not a cert"), 0644); err != nil {
		t.Fatalf("write stray: %v", err)
	}
	r := NewRegistry(root)
	if err := r.Load(); err != nil {
		t.Fatalf("Load with stray file: %v", err)
	}
	if got := r.Suffixes(); len(got) != 0 {
		t.Errorf("expected 0 suffixes, got %v", got)
	}
}

// --- HasAny / GetCertificate -------------------------------------------

func TestRegistry_HasAny(t *testing.T) {
	r := NewRegistry(t.TempDir())
	if r.HasAny() {
		t.Errorf("empty registry should not HasAny")
	}
	// AddSuffix without cert leaves entry.cert nil — still no cert
	// available.
	r.AddSuffix("alice.atreo.link")
	if r.HasAny() {
		t.Errorf("placeholder entry shouldn't count")
	}
	r2 := seededRegistry(t, "alice.atreo.link")
	if !r2.HasAny() {
		t.Errorf("seeded registry should HasAny")
	}
}

func TestRegistry_GetCertificate_SNIMatch(t *testing.T) {
	r := seededRegistry(t, "alice.atreo.link")
	hello := &tls.ClientHelloInfo{ServerName: "jellyfin.alice.atreo.link"}
	cert, err := r.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected cert")
	}
}

func TestRegistry_GetCertificate_SNIIsBareSuffix(t *testing.T) {
	// Some clients send SNI = the suffix itself (no leading slug).
	// Should still find the cert.
	r := seededRegistry(t, "alice.atreo.link")
	hello := &tls.ClientHelloInfo{ServerName: "alice.atreo.link"}
	cert, err := r.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected cert")
	}
}

func TestRegistry_GetCertificate_FallbackOnNoSNI(t *testing.T) {
	r := seededRegistry(t, "alice.atreo.link", "example.com")
	cert, err := r.GetCertificate(&tls.ClientHelloInfo{}) // no SNI
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("expected fallback cert")
	}
}

func TestRegistry_GetCertificate_EmptyRegistry_Errors(t *testing.T) {
	r := NewRegistry(t.TempDir())
	_, err := r.GetCertificate(&tls.ClientHelloInfo{ServerName: "anything.example.com"})
	if err == nil {
		t.Errorf("expected error from empty registry")
	}
}

func TestRegistry_GetCertificate_UnknownSNI_FallsBack(t *testing.T) {
	// SNI for a hostname we don't serve — return whatever cert we
	// have (the connection will likely fail TLS validation but at
	// least the handshake completes).
	r := seededRegistry(t, "alice.atreo.link")
	cert, err := r.GetCertificate(&tls.ClientHelloInfo{ServerName: "bob.example.com"})
	if err != nil {
		t.Fatalf("expected fallback, got error: %v", err)
	}
	if cert == nil {
		t.Fatal("expected fallback cert")
	}
}

// --- Concurrent access --------------------------------------------------

func TestRegistry_ConcurrentAddRemoveLookup(t *testing.T) {
	r := seededRegistry(t, "alice.atreo.link")
	const goroutines = 16
	const iters = 200
	var wg sync.WaitGroup

	// Mixed read/write workload — race detector catches any unprotected
	// map access.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				switch j % 4 {
				case 0:
					r.AddSuffix("ephemeral.example.com")
				case 1:
					_ = r.RemoveSuffix("ephemeral.example.com")
				case 2:
					_ = r.Suffixes()
				case 3:
					_, _ = r.GetCertificate(&tls.ClientHelloInfo{
						ServerName: "alice.atreo.link",
					})
				}
			}
		}(i)
	}
	wg.Wait()

	// Original alice cert must still be loaded after the storm.
	if !r.Has("alice.atreo.link") {
		t.Errorf("alice cert lost during concurrent workload")
	}
}

// --- PathsFor / RemoveSuffix file cleanup ------------------------------

func TestRegistry_RemoveSuffix_DeletesFiles(t *testing.T) {
	r := seededRegistry(t, "alice.atreo.link")
	dir := filepath.Join(r.rootDir, "alice.atreo.link")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("seed should have created dir: %v", err)
	}
	if err := r.RemoveSuffix("alice.atreo.link"); err != nil {
		t.Fatalf("RemoveSuffix: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("expected dir to be gone, got %v", err)
	}
}

func TestRegistry_PathsFor_CreatesDir(t *testing.T) {
	r := NewRegistry(t.TempDir())
	certPath, keyPath, err := r.PathsFor("example.com")
	if err != nil {
		t.Fatalf("PathsFor: %v", err)
	}
	if certPath == "" || keyPath == "" {
		t.Errorf("paths empty: %q %q", certPath, keyPath)
	}
	if _, err := os.Stat(filepath.Dir(certPath)); err != nil {
		t.Errorf("PathsFor should create the directory: %v", err)
	}
}

// --- Manager.isCertValid ------------------------------------------------

func TestIsCertValid(t *testing.T) {
	dir := t.TempDir()
	freshPath := filepath.Join(dir, "fresh.pem")
	expiringPath := filepath.Join(dir, "expiring.pem")
	missingPath := filepath.Join(dir, "missing.pem")
	// renewBefore is 30d; cert that expires in 60d is valid.
	writeSelfSignedCert(t, "alice.atreo.link",
		freshPath, filepath.Join(dir, "fresh.key"), 60*24*time.Hour)
	// Cert that expires in 5d (well within renewBefore) is invalid.
	writeSelfSignedCert(t, "alice.atreo.link",
		expiringPath, filepath.Join(dir, "expiring.key"), 5*24*time.Hour)

	if !isCertValid(freshPath) {
		t.Errorf("fresh cert should be valid")
	}
	if isCertValid(expiringPath) {
		t.Errorf("expiring cert should not be valid")
	}
	if isCertValid(missingPath) {
		t.Errorf("missing cert should not be valid")
	}
}

// --- Cert/suffix SAN validation -----------------------------------------

// writeCertWithSAN builds a self-signed cert with arbitrary DNS names
// and an optional Subject.CN, writing PEM to certPath/keyPath. Used to
// drive assertCertMatchesSuffix through its branches.
func writeCertWithSAN(t *testing.T, certPath, keyPath string, dnsNames []string, cn string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}), 0600); err != nil {
		t.Fatal(err)
	}
}

// TestAssertCertMatchesSuffix_AcceptedShapes exercises the three
// accepted shapes: wildcard SAN, bare-suffix SAN, and legacy CN-only.
func TestAssertCertMatchesSuffix_AcceptedShapes(t *testing.T) {
	dir := t.TempDir()
	suffix := "alice.atreo.link"

	cases := map[string]struct {
		dns []string
		cn  string
	}{
		"wildcard SAN":     {dns: []string{"*." + suffix}, cn: ""},
		"bare SAN":         {dns: []string{suffix}, cn: ""},
		"legacy CN only":   {dns: nil, cn: suffix},
		"case-insensitive": {dns: []string{"*.ALICE.ATREO.LINK"}, cn: ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			certPath := filepath.Join(dir, name, "cert.pem")
			keyPath := filepath.Join(dir, name, "key.pem")
			writeCertWithSAN(t, certPath, keyPath, tc.dns, tc.cn)
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				t.Fatalf("LoadX509KeyPair: %v", err)
			}
			if err := assertCertMatchesSuffix(cert, suffix); err != nil {
				t.Errorf("unexpected reject: %v", err)
			}
		})
	}
}

// TestAssertCertMatchesSuffix_RejectsMismatch covers the security
// failure case: a cert whose SANs don't include the expected suffix
// must be refused. This is the substitution-defence path.
func TestAssertCertMatchesSuffix_RejectsMismatch(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeCertWithSAN(t, certPath, keyPath, []string{"*.attacker.example"}, "attacker.example")
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	if err := assertCertMatchesSuffix(cert, "alice.atreo.link"); err == nil {
		t.Fatal("expected mismatch to be rejected")
	}
}

// TestLoadSuffix_RejectsMismatchedCert is the integration version of
// the above — LoadSuffix wraps the validator and must surface the
// rejection rather than silently registering an unmatched cert.
func TestLoadSuffix_RejectsMismatchedCert(t *testing.T) {
	root := t.TempDir()
	suffix := "alice.atreo.link"
	certPath := filepath.Join(root, suffix, "cert.pem")
	keyPath := filepath.Join(root, suffix, "key.pem")
	writeCertWithSAN(t, certPath, keyPath, []string{"*.attacker.example"}, "")

	r := NewRegistry(root)
	err := r.LoadSuffix(suffix)
	if err == nil {
		t.Fatal("expected LoadSuffix to reject SAN-mismatched cert")
	}
}

// --- Sort assertion -----------------------------------------------------

func TestRegistry_Suffixes_LongestFirst(t *testing.T) {
	r := NewRegistry(t.TempDir())
	r.AddSuffix("a.b")
	r.AddSuffix("foo.bar.baz")
	r.AddSuffix("xx.yy")
	got := r.Suffixes()
	if !sort.SliceIsSorted(got, func(i, j int) bool {
		if len(got[i]) != len(got[j]) {
			return len(got[i]) > len(got[j])
		}
		return got[i] < got[j]
	}) {
		t.Errorf("Suffixes not sorted longest-first: %v", got)
	}
}
