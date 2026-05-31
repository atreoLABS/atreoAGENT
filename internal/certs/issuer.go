package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"

	"github.com/atreoLABS/atreoAGENT/internal/atomic"
	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
)

// account.key lives in keysDir, not in certDir with cert leaves.
type Issuer struct {
	keysDir   string
	email     string
	deviceID  string // DNS-01 scope check
	atreolink *atreolink.Client
}

func NewIssuer(keysDir, email, deviceID string, link *atreolink.Client) *Issuer {
	return &Issuer{keysDir: keysDir, email: email, deviceID: deviceID, atreolink: link}
}

// Wildcard added internally. ctx is plumbed into Present/CleanUp;
// lego doesn't watch ctx on its HTTP paths.
func (i *Issuer) IssueCert(ctx context.Context, suffix, certPath, keyPath string) error {
	suffix = normaliseHost(suffix)
	if suffix == "" {
		return errors.New("issuer: empty suffix")
	}

	if err := os.MkdirAll(i.keysDir, 0700); err != nil {
		return fmt.Errorf("create issuer keys dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0700); err != nil {
		return fmt.Errorf("create cert dir: %w", err)
	}

	accountKey, err := i.loadOrCreateAccountKey()
	if err != nil {
		return fmt.Errorf("account key: %w", err)
	}
	user := &acmeUser{email: i.email, key: accountKey}

	regPath := filepath.Join(i.keysDir, "registration.json")
	if data, err := os.ReadFile(regPath); err == nil {
		var reg registration.Resource
		if err := json.Unmarshal(data, &reg); err == nil && reg.URI != "" {
			user.registration = &reg
		}
	}
	// 0600 — the URI + account key can renew every paired suffix.
	if _, err := os.Stat(regPath); err == nil {
		if err := os.Chmod(regPath, 0600); err != nil {
			logging.Warn("ACME: chmod registration.json: %v", err)
		}
	}

	config := lego.NewConfig(user)
	config.Certificate.KeyType = certcrypto.EC256
	config.CADirURL = lego.LEDirectoryProduction

	client, err := lego.NewClient(config)
	if err != nil {
		return fmt.Errorf("create ACME client: %w", err)
	}

	if user.registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return fmt.Errorf("ACME registration: %w", err)
		}
		user.registration = reg
		regData, err := json.Marshal(reg)
		if err != nil {
			return fmt.Errorf("marshal registration: %w", err)
		}
		if err := atomic.WriteFile(regPath, regData, 0600); err != nil {
			return fmt.Errorf("write registration: %w", err)
		}
		logging.Info("ACME: registered new account")
	}

	// Scoped writes — see isAllowedFQDN.
	provider := &atreoLinkDNSProvider{
		atreolink:     i.atreolink,
		ctx:           ctx,
		currentSuffix: suffix,
		deviceID:      i.deviceID,
	}
	// CNAME-delegated TXT lives in atreoLINK's zone; the default
	// authoritative-NS check would time out. Public recursors follow
	// the CNAME to the actual write target.
	if err := client.Challenge.SetDNS01Provider(
		provider,
		dns01.AddRecursiveNameservers([]string{"1.1.1.1:53", "8.8.8.8:53"}),
	); err != nil {
		return fmt.Errorf("set DNS provider: %w", err)
	}

	domain := "*." + suffix
	logging.Info("ACME: requesting wildcard certificate for %s", domain)

	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}
	certs, err := client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("obtain cert: %w", err)
	}

	if err := atomic.WriteFile(certPath, certs.Certificate, 0600); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := atomic.WriteFile(keyPath, certs.PrivateKey, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	logging.Info("ACME: certificate issued for %s", domain)
	return nil
}

func (i *Issuer) loadOrCreateAccountKey() (crypto.PrivateKey, error) {
	keyPath := filepath.Join(i.keysDir, "acme_account.key")

	if data, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return key, nil
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}
	if err := atomic.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		return nil, err
	}
	return key, nil
}

type acmeUser struct {
	email        string
	key          crypto.PrivateKey
	registration *registration.Resource
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

type atreoLinkDNSProvider struct {
	atreolink     *atreolink.Client
	ctx           context.Context
	currentSuffix string
	deviceID      string
}

var _ challenge.Provider = (*atreoLinkDNSProvider)(nil)

// Two legitimate FQDN shapes:
//  1. Direct: `_acme-challenge.<currentSuffix>` (cert inside the
//     atreoLINK zone).
//  2. CNAME-delegated: any FQDN containing deviceID as a dot-bounded
//     label (custom-domain path). The deviceID requirement is the
//     cross-tenant defence.
func (p *atreoLinkDNSProvider) isAllowedFQDN(fqdn string) bool {
	if fqdn == "_acme-challenge."+p.currentSuffix {
		return true
	}
	if p.deviceID == "" {
		return false
	}
	// Dot-bounded so a deviceID prefix/suffix can't false-positive.
	return strings.Contains("."+fqdn+".", "."+p.deviceID+".")
}

func (p *atreoLinkDNSProvider) Present(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	fqdn := strings.TrimSuffix(info.EffectiveFQDN, ".")
	if !p.isAllowedFQDN(fqdn) {
		return fmt.Errorf("agent refusing FQDN scope mismatch: got %q (suffix %q, deviceID %q)", fqdn, p.currentSuffix, p.deviceID)
	}
	logging.Debug("ACME DNS-01: presenting TXT for %s", fqdn)
	ctx := p.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return p.atreolink.DNSPresent(ctx, fqdn, info.Value)
}

func (p *atreoLinkDNSProvider) CleanUp(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	fqdn := strings.TrimSuffix(info.EffectiveFQDN, ".")
	if !p.isAllowedFQDN(fqdn) {
		return fmt.Errorf("agent refusing FQDN scope mismatch: got %q (suffix %q, deviceID %q)", fqdn, p.currentSuffix, p.deviceID)
	}
	logging.Debug("ACME DNS-01: cleaning up TXT for %s", fqdn)
	ctx := p.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return p.atreolink.DNSCleanup(ctx, fqdn, info.Value)
}
