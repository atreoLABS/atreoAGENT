package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"os"

	"github.com/atreoLABS/atreoAGENT/internal/acl"
	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/config"
	"github.com/atreoLABS/atreoAGENT/internal/crypto"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
	"github.com/atreoLABS/atreoAGENT/internal/tunnel"
)

func runPair(args []string) {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	dataDir := fs.String("data-dir", "/var/lib/atreoagent", "Data directory")
	_ = fs.Parse(args)

	cfg := config.DefaultConfig()
	if v := os.Getenv("ATREOLINK_API_URL"); v != "" {
		cfg.AtreoLinkAPIURL = v
	}
	if v := os.Getenv("ATREOLINK_APP_URL"); v != "" {
		cfg.AtreoLinkAppURL = v
	}
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		if err := logging.Init(v); err != nil {
			logging.Fatalf("%v", err)
		}
	}
	cfg.DataDir = *dataDir

	km, err := crypto.NewKeyManager(cfg.KeysDir())
	if err != nil {
		logging.Fatalf("Failed to initialize keys: %v", err)
	}

	client := atreolink.NewClient(cfg.AtreoLinkAPIURL, km, "")
	aclStore := acl.NewStore(cfg.ACLPath())
	if err := aclStore.Load(); err != nil {
		logging.Warn("Warning: load ACL: %v", err)
	}

	pairToken := make([]byte, 32)
	if _, err := rand.Read(pairToken); err != nil {
		logging.Fatalf("Failed to generate pair token: %v", err)
	}
	pairTokenHash := sha256.Sum256(pairToken)
	pairTokenURL := base64.RawURLEncoding.EncodeToString(pairToken)

	buildURL := func(atreolinkAuthURL, _userCode string) string {
		if atreolinkAuthURL == "" {
			return ""
		}
		return atreolinkAuthURL + "#" + pairTokenURL
	}

	expectedNASPubkey := km.PublicKeyBase64()
	decoder := func(blob atreolink.PairApprovalBlob, deviceID string) ([]byte, []byte, string, error) {
		return tunnel.DecodePairApprovalBlob(blob, pairToken, deviceID, expectedNASPubkey)
	}

	ctx := context.Background()
	result, err := atreolink.Pair(ctx, client, km,
		atreolink.WithApprovalDecoder(decoder),
		atreolink.WithPairTokenHash(hex.EncodeToString(pairTokenHash[:])),
		atreolink.WithAuthURLBuilder(buildURL),
	)
	if err != nil {
		logging.Fatalf("Pairing failed: %v", err)
	}

	if err := aclStore.SetPinnedAdminPublicKey(result.OwnerIdentityPubkey); err != nil {
		logging.Fatalf("Failed to pin owner identity: %v (delete %s/admin_pin.json if intentional)", err, cfg.DataDir)
	}

	// Bootstrap the owner ACL entry — see agent.go for the rationale.
	if result.OwnerMemberID != "" {
		ownerEntry := atreolink.MemberACLEntry{
			MemberID:    result.OwnerMemberID,
			Role:        "owner",
			Status:      "active",
			IdentityKey: base64.StdEncoding.EncodeToString(result.OwnerIdentityPubkey),
			Clients:     []atreolink.ClientRecord{},
			AllowedApps: []atreolink.App{},
		}
		if err := aclStore.UpsertMember(ownerEntry); err != nil {
			logging.Fatalf("Failed to install owner ACL entry: %v", err)
		}
		if err := aclStore.Save(); err != nil {
			logging.Warn("Warning: failed to persist ACL after owner upsert: %v", err)
		}
	}

	cfg.DeviceID = result.DeviceID
	cfg.AppsHostname = result.AppsHostname
	cfg.TunnelHost = result.TunnelHost

	if err := cfg.SavePairing(); err != nil {
		logging.Fatalf("Failed to save pairing state: %v", err)
	}

	if cfg.AppsHostname == "" {
		logging.Info("Paired successfully! Device ID: %s (waiting for atreoLINK to report its appsHostname)", result.DeviceID)
	} else {
		logging.Info("Paired successfully! Apps hostname: %s", cfg.AppsHostname)
	}
}
