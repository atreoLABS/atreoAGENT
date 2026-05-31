package certs

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
)

// Lead time before expiry; absorbs a few failed ACME attempts.
const renewBefore = 30 * 24 * time.Hour

// EnsureCert is the per-suffix entry point.
type Manager struct {
	Registry *Registry
	Issuer   *Issuer

	renewalStatePath string
	renewalState     map[string]*RenewalState
	renewalStateMu   sync.Mutex
	notifyOwner      func(suffix string, consecutiveFailures int) // nil = skip alerts
}

// Exported so `atreoagent status` can read it without Manager.
type RenewalState struct {
	ConsecutiveFailures int       `json:"consecutiveFailures"`
	LastAttempt         time.Time `json:"lastAttempt"`
	LastSuccess         time.Time `json:"lastSuccess"`
	LastNotification    time.Time `json:"lastNotification,omitempty"`
}

// ≈3 days at the daily cadence; ~27 days remain to fix.
const renewalAlertThreshold = 3
const renewalAlertCooldown = 24 * time.Hour

// deviceID is passed to the issuer for the DNS-01 scope check.
func NewManager(keysDir, certDir, dataDir, email, deviceID string, link *atreolink.Client) *Manager {
	m := &Manager{
		Registry: NewRegistry(certDir),
		Issuer:   NewIssuer(keysDir, email, deviceID, link),
	}
	if dataDir != "" {
		m.renewalStatePath = filepath.Join(dataDir, "cert_renewal_state.json")
		m.renewalState = loadRenewalState(m.renewalStatePath)
	} else {
		m.renewalState = make(map[string]*RenewalState)
	}
	return m
}

func (m *Manager) SetOwnerNotifier(fn func(suffix string, consecutiveFailures int)) {
	m.notifyOwner = fn
}

func (m *Manager) RenewalSnapshot() map[string]RenewalState {
	m.renewalStateMu.Lock()
	defer m.renewalStateMu.Unlock()
	out := make(map[string]RenewalState, len(m.renewalState))
	for k, v := range m.renewalState {
		out[k] = *v
	}
	return out
}

// suffix is bare (e.g. "alice.example.com"); the issuer adds the
// wildcard. On ACME failure falls back to the existing on-disk cert.
func (m *Manager) EnsureCert(ctx context.Context, suffix string) error {
	suffix = normaliseHost(suffix)
	if suffix == "" {
		return errors.New("EnsureCert: empty suffix")
	}

	certPath, keyPath, err := m.Registry.PathsFor(suffix)
	if err != nil {
		return err
	}

	if certFileIsValidForSuffix(certPath, suffix) {
		if err := m.Registry.LoadSuffix(suffix); err != nil {
			logging.Warn("Manager: cert valid but load failed for %s: %v", suffix, err)
		} else {
			logging.Info("TLS certificate is valid for %s", suffix)
			return nil
		}
	}

	logging.Info("Obtaining certificate for *.%s via ACME DNS-01...", suffix)
	if err := m.Issuer.IssueCert(ctx, suffix, certPath, keyPath); err != nil {
		// Stale TLS beats 502s until the next renewal tick.
		if loadErr := m.Registry.LoadSuffix(suffix); loadErr == nil {
			logging.Warn("ACME failed for %s (%v) — using existing cert files", suffix, err)
			return nil
		}
		return err
	}

	if err := m.Registry.LoadSuffix(suffix); err != nil {
		return err
	}
	logging.Info("Certificate ready for *.%s", suffix)
	return nil
}

// Daily ticker; EnsureCert per suffix near expiry.
func (m *Manager) StartAutoRenewal(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.renewAll(ctx)
			}
		}
	}()
}

// One bad cert doesn't stop the others.
func (m *Manager) renewAll(ctx context.Context) {
	for _, suffix := range m.Registry.Suffixes() {
		certPath, _, err := m.Registry.PathsFor(suffix)
		if err != nil {
			logging.Error("Manager: PathsFor(%s) failed: %v", suffix, err)
			continue
		}
		if certFileIsValidForSuffix(certPath, suffix) {
			continue
		}
		logging.Info("Certificate expiring for %s, attempting renewal...", suffix)
		if err := m.EnsureCert(ctx, suffix); err != nil {
			logging.Error("Renewal failed for %s: %v", suffix, err)
			m.recordRenewalFailure(suffix)
		} else {
			m.recordRenewalSuccess(suffix)
		}
	}
}

// recordRenewalFailure bumps consecutive failures and fires the
// notifier if the threshold is hit (subject to cooldown).
func (m *Manager) recordRenewalFailure(suffix string) {
	m.renewalStateMu.Lock()
	defer m.renewalStateMu.Unlock()
	st, ok := m.renewalState[suffix]
	if !ok {
		st = &RenewalState{}
		m.renewalState[suffix] = st
	}
	st.ConsecutiveFailures++
	st.LastAttempt = time.Now()
	if st.ConsecutiveFailures >= renewalAlertThreshold &&
		time.Since(st.LastNotification) > renewalAlertCooldown &&
		m.notifyOwner != nil {
		// Snapshot before unlocking.
		count := st.ConsecutiveFailures
		st.LastNotification = time.Now()
		go m.notifyOwner(suffix, count)
	}
	m.persistRenewalStateLocked()
}

func (m *Manager) recordRenewalSuccess(suffix string) {
	m.renewalStateMu.Lock()
	defer m.renewalStateMu.Unlock()
	st, ok := m.renewalState[suffix]
	if !ok {
		st = &RenewalState{}
		m.renewalState[suffix] = st
	}
	st.ConsecutiveFailures = 0
	now := time.Now()
	st.LastAttempt = now
	st.LastSuccess = now
	m.persistRenewalStateLocked()
}

// Caller must hold renewalStateMu. Best-effort.
func (m *Manager) persistRenewalStateLocked() {
	if m.renewalStatePath == "" {
		return
	}
	data, err := json.MarshalIndent(m.renewalState, "", "  ")
	if err != nil {
		logging.Error("Manager: marshal renewal state: %v", err)
		return
	}
	tmp := m.renewalStatePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		logging.Error("Manager: write renewal state: %v", err)
		return
	}
	if err := os.Rename(tmp, m.renewalStatePath); err != nil {
		logging.Error("Manager: rename renewal state: %v", err)
	}
}

func loadRenewalState(path string) map[string]*RenewalState {
	out := make(map[string]*RenewalState)
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	if err := json.Unmarshal(data, &out); err != nil {
		logging.Error("Manager: parse renewal state (resetting): %v", err)
		return make(map[string]*RenewalState)
	}
	return out
}

// Free function so the renewal loop can call without locking.
// suffix="" skips the DNSNames/CN check.
func isCertValid(certPath string) bool {
	return certFileIsValidForSuffix(certPath, "")
}

func certFileIsValidForSuffix(certPath, suffix string) bool {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	if time.Until(cert.NotAfter) <= renewBefore {
		return false
	}
	if suffix == "" {
		return true
	}
	want := suffix
	wildcard := "*." + want
	for _, dns := range cert.DNSNames {
		if dns == wildcard || dns == want {
			return true
		}
	}
	return cert.Subject.CommonName == want
}
