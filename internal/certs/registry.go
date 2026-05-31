package certs

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Keyed by bare hostname; thread-safe; supports runtime Add/Remove for
// custom-domain activation.
type Registry struct {
	mu      sync.RWMutex
	rootDir string
	entries map[string]*entry
}

// cert is nil while the issuer is still working on the first cert.
type entry struct {
	cert     *tls.Certificate
	certPath string
	keyPath  string
}

// Per-suffix files at `<rootDir>/<suffix>/{cert.pem,key.pem}`.
func NewRegistry(rootDir string) *Registry {
	return &Registry{
		rootDir: rootDir,
		entries: make(map[string]*entry),
	}
}

// Per-suffix errors logged, not returned.
func (r *Registry) Load() error {
	if err := os.MkdirAll(r.rootDir, 0700); err != nil {
		return fmt.Errorf("create cert root: %w", err)
	}
	entries, err := os.ReadDir(r.rootDir)
	if err != nil {
		return fmt.Errorf("read cert root: %w", err)
	}
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		host := ent.Name()
		if err := r.LoadSuffix(host); err != nil {
			logging.Error("Registry: failed to load cert for %s: %v", host, err)
		}
	}
	return nil
}

// Leaf is checked against the suffix to catch a substituted file
// before the proxy serves it.
func (r *Registry) LoadSuffix(host string) error {
	host = normaliseHost(host)
	if host == "" {
		return errors.New("empty host")
	}
	dir := filepath.Join(r.rootDir, host)
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return fmt.Errorf("load cert pair: %w", err)
	}
	if err := assertCertMatchesSuffix(cert, host); err != nil {
		return fmt.Errorf("cert/suffix mismatch for %s: %w", host, err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[host] = &entry{
		cert:     &cert,
		certPath: certPath,
		keyPath:  keyPath,
	}
	return nil
}

// Accepts `*.<suffix>` or `<suffix>` in SANs, or legacy CN match.
func assertCertMatchesSuffix(cert tls.Certificate, suffix string) error {
	if len(cert.Certificate) == 0 {
		return errors.New("no leaf in chain")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse leaf: %w", err)
	}
	want := strings.ToLower(suffix)
	wildcard := "*." + want
	for _, dns := range leaf.DNSNames {
		d := strings.ToLower(dns)
		if d == wildcard || d == want {
			return nil
		}
	}
	if strings.EqualFold(leaf.Subject.CommonName, suffix) {
		return nil
	}
	logging.Error("Cert SAN mismatch: expected %q (or %q), got DNSNames=%v CN=%q",
		wildcard, want, leaf.DNSNames, leaf.Subject.CommonName)
	return fmt.Errorf("expected DNSName %q (or CN %q), got DNSNames=%v CN=%q",
		wildcard, want, leaf.DNSNames, leaf.Subject.CommonName)
}

func (r *Registry) PathsFor(host string) (certPath, keyPath string, err error) {
	host = normaliseHost(host)
	if host == "" {
		return "", "", errors.New("empty host")
	}
	dir := filepath.Join(r.rootDir, host)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", "", fmt.Errorf("create suffix dir: %w", err)
	}
	return filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), nil
}

func (r *Registry) AddSuffix(host string) {
	host = normaliseHost(host)
	if host == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.entries[host]; !ok {
		r.entries[host] = &entry{}
	}
}

// Idempotent.
func (r *Registry) RemoveSuffix(host string) error {
	host = normaliseHost(host)
	if host == "" {
		return nil
	}
	r.mu.Lock()
	delete(r.entries, host)
	r.mu.Unlock()
	dir := filepath.Join(r.rootDir, host)
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove suffix dir: %w", err)
	}
	return nil
}

// Sorted longest-first for deterministic longest-suffix matching.
func (r *Registry) Suffixes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.entries))
	for h := range r.entries {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

func (r *Registry) Has(host string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[normaliseHost(host)]
	return ok && e.cert != nil
}

func (r *Registry) HasAny() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.entries {
		if e.cert != nil {
			return true
		}
	}
	return false
}

// SNI ServerName's parent (wildcard depth = 1, matching LE issuance).
// Falls back to the first usable cert when SNI is missing.
func (r *Registry) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil {
		return r.fallbackCert()
	}
	if hello.ServerName != "" {
		bare := stripFirstLabel(hello.ServerName)
		if cert := r.lookup(bare); cert != nil {
			return cert, nil
		}
		// Some clients send SNI without the app-slug.
		if cert := r.lookup(hello.ServerName); cert != nil {
			return cert, nil
		}
	}
	return r.fallbackCert()
}

func (r *Registry) lookup(host string) *tls.Certificate {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if e, ok := r.entries[normaliseHost(host)]; ok && e.cert != nil {
		return e.cert
	}
	return nil
}

func (r *Registry) fallbackCert() (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.entries) == 0 {
		return nil, errors.New("registry empty: no certificate available")
	}
	keys := make([]string, 0, len(r.entries))
	for k, e := range r.entries {
		if e.cert != nil {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("registry has no usable certificates")
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	return r.entries[keys[0]].cert, nil
}

// Reduces SNI hostname to its wildcard parent.
func stripFirstLabel(host string) string {
	if i := strings.IndexByte(host, '.'); i >= 0 {
		return host[i+1:]
	}
	return ""
}

func normaliseHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimPrefix(h, "*.")
	h = strings.TrimSuffix(h, ".")
	return h
}
