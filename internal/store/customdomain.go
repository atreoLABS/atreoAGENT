// Package store holds JSON-backed persistence helpers; all writes are
// atomic (temp + rename) so a crash mid-write can't leave a half file.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// EnvelopePayload + EnvelopeOwnerSig kept verbatim so the agent can
// re-verify owner intent on restart without phoning atreoLINK.
type CustomDomain struct {
	ParentZone       string `json:"parentZone"`
	EnvelopePayload  []byte `json:"envelopePayload,omitempty"`
	EnvelopeOwnerSig string `json:"envelopeOwnerSig,omitempty"`
	VerifiedAt       string `json:"verifiedAt,omitempty"` // RFC3339
}

type CustomDomainStore struct {
	path string
	mu   sync.RWMutex
}

func NewCustomDomainStore(path string) *CustomDomainStore {
	return &CustomDomainStore{path: path}
}

// Missing/corrupt file → (nil, nil).
func (s *CustomDomainStore) Get() (*CustomDomain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read custom domain: %w", err)
	}
	var cd CustomDomain
	if err := json.Unmarshal(data, &cd); err != nil {
		return nil, fmt.Errorf("parse custom domain: %w", err)
	}
	if cd.ParentZone == "" {
		return nil, nil
	}
	return &cd, nil
}

// One row per device — Set overwrites any previous row.
func (s *CustomDomainStore) Set(cd *CustomDomain) error {
	if cd == nil || cd.ParentZone == "" {
		return errors.New("set: nil or empty parentZone")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return fmt.Errorf("create custom-domain dir: %w", err)
	}
	data, err := json.MarshalIndent(cd, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal custom domain: %w", err)
	}
	// Same-dir temp keeps the rename on one filesystem.
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".custom_domain.*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("rename temp: %w", err)
	}
	return nil
}

// Idempotent.
func (s *CustomDomainStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove custom domain: %w", err)
	}
	return nil
}
