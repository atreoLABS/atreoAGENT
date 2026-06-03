package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
	"net"
	"os"
	"sync"
	"time"

	"github.com/atreoLABS/atreoAGENT/internal/acl"
	"github.com/atreoLABS/atreoAGENT/internal/atreolink"
	"github.com/atreoLABS/atreoAGENT/internal/banner"
	"github.com/atreoLABS/atreoAGENT/internal/certs"
	"github.com/atreoLABS/atreoAGENT/internal/config"
	"github.com/atreoLABS/atreoAGENT/internal/crypto"
	"github.com/atreoLABS/atreoAGENT/internal/endpoints"
	"github.com/atreoLABS/atreoAGENT/internal/firewall"
	"github.com/atreoLABS/atreoAGENT/internal/notify"
	"github.com/atreoLABS/atreoAGENT/internal/probe"
	"github.com/atreoLABS/atreoAGENT/internal/proxy"
	"github.com/atreoLABS/atreoAGENT/internal/smtp"
	"github.com/atreoLABS/atreoAGENT/internal/store"
	"github.com/atreoLABS/atreoAGENT/internal/tunnel"
	"github.com/atreoLABS/atreoAGENT/internal/upnp"
	"github.com/atreoLABS/atreoAGENT/internal/wireguard"
)

// Agent orchestrates all atreoAGENT components.
type Agent struct {
	cfg               *config.Config
	atreolink         *atreolink.Client
	keyManager        *crypto.KeyManager
	wgServer          *wireguard.Server
	allocator         *wireguard.IPAllocator
	aclStore          *acl.Store
	tunnel            *tunnel.Client
	proxy             *proxy.Server
	certs             *certs.Manager
	upnp              *upnp.Client
	notifyServer      *notify.Server
	customDomainStore *store.CustomDomainStore
	firewall          *firewall.Manager

	// Dedupe v6-pinhole failure logging: a gateway that supports neither PCP
	// nor IGDv2 v6 firewall control fails every tick, so log at INFO only when
	// the outcome changes.
	v6PinholeMu      sync.Mutex
	lastV6PinholeErr string
}

// New creates a new Agent with all components initialized.
func New(cfg *config.Config) (*Agent, error) {
	km, err := crypto.NewKeyManager(cfg.KeysDir())
	if err != nil {
		return nil, fmt.Errorf("init keys: %w", err)
	}

	allocator, err := wireguard.NewIPAllocator(
		cfg.WireGuard.TunnelSubnet,
		cfg.WireGuard.ServerIP,
		cfg.IPAllocPath(),
	)
	if err != nil {
		return nil, fmt.Errorf("init IP allocator: %w", err)
	}

	wgServer, err := wireguard.NewServer(
		cfg.WireGuard.ListenPort,
		cfg.WireGuard.ServerIP,
		cfg.WireGuard.TunnelSubnet,
		cfg.KeysDir(),
		allocator,
	)
	if err != nil {
		return nil, fmt.Errorf("init WireGuard: %w", err)
	}

	atreolinkClient := atreolink.NewClient(cfg.AtreoLinkAPIURL, km, cfg.DeviceID)
	aclStore := acl.NewStore(cfg.ACLPath())
	upnpClient := upnp.NewClient(cfg.WireGuard.ListenPort)
	upnpClient.SetPCPEnabled(cfg.WireGuard.PCPEnabled)
	upnpClient.SetStatePath(cfg.PinholePath())

	// Registry keyed by bare hostname so the proxy can serve multiple
	// wildcard certs at once — operator-issued plus optional custom-domain.
	// The operator-issued hostname is added below via EnsureCert; custom
	// domains add extra suffixes through the device:custom-domain-set
	// envelope.
	certsMgr := certs.NewManager(
		cfg.KeysDir(),
		cfg.CertsDir(),
		cfg.DataDir,
		cfg.Certs.Email,
		cfg.DeviceID,
		atreolinkClient,
	)

	customDomainStore := store.NewCustomDomainStore(cfg.CustomDomainPath())

	return &Agent{
		cfg:               cfg,
		atreolink:         atreolinkClient,
		keyManager:        km,
		wgServer:          wgServer,
		allocator:         allocator,
		aclStore:          aclStore,
		upnp:              upnpClient,
		certs:             certsMgr,
		customDomainStore: customDomainStore,
	}, nil
}

// Run starts the agent and blocks until the context is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	logging.Info("atreoAGENT starting...")

	if a.cfg.DeviceID == "" {
		logging.Info("No deviceID found, starting pairing flow...")
		// Agent keeps the raw 32 bytes; only the SHA-256 hash reaches the
		// atreoLINK. The raw token travels to the browser via the URL fragment.
		pairToken := make([]byte, 32)
		if _, err := rand.Read(pairToken); err != nil {
			return fmt.Errorf("generate pair token: %w", err)
		}
		pairTokenHash := sha256.Sum256(pairToken)
		pairTokenURL := base64.RawURLEncoding.EncodeToString(pairToken)

		buildURL := func(atreolinkAuthURL, _userCode string) string {
			if atreolinkAuthURL == "" {
				return ""
			}
			return atreolinkAuthURL + "#" + pairTokenURL
		}

		expectedNASPubkey := a.keyManager.PublicKeyBase64()
		decoder := func(blob atreolink.PairApprovalBlob, sessionID string) ([]byte, []byte, string, error) {
			return tunnel.DecodePairApprovalBlob(blob, pairToken, sessionID, expectedNASPubkey)
		}

		result, err := atreolink.Pair(ctx, a.atreolink, a.keyManager,
			atreolink.WithApprovalDecoder(decoder),
			atreolink.WithPairTokenHash(hex.EncodeToString(pairTokenHash[:])),
			atreolink.WithAuthURLBuilder(buildURL),
		)
		if err != nil {
			return fmt.Errorf("auto-pair: %w", err)
		}
		a.cfg.DeviceID = result.DeviceID
		a.cfg.AppsHostname = result.AppsHostname
		a.cfg.TunnelHost = result.TunnelHost
		a.atreolink.SetDeviceID(result.DeviceID)

		if err := a.aclStore.SetPinnedAdminPublicKey(result.OwnerIdentityPubkey); err != nil {
			return fmt.Errorf("pin owner identity: %w (clear admin_pin.json if this is an intentional re-pair)", err)
		}

		// Bootstrap the owner ACL entry — atreoLINK's ACL replay skips
		// owner rows, so wg:provision and notify lookups would otherwise
		// fail to resolve the owner.
		if result.OwnerMemberID != "" {
			ownerEntry := atreolink.MemberACLEntry{
				MemberID:    result.OwnerMemberID,
				UserID:      result.OwnerUserID,
				Email:       result.OwnerEmail,
				MemberName:  result.OwnerName,
				Role:        "owner",
				Status:      "active",
				IdentityKey: base64.StdEncoding.EncodeToString(result.OwnerIdentityPubkey),
				Clients:     []atreolink.ClientRecord{},
				AllowedApps: []atreolink.App{},
			}
			if err := a.aclStore.UpsertMember(ownerEntry); err != nil {
				return fmt.Errorf("install owner ACL entry: %w", err)
			}
			if err := a.aclStore.Save(); err != nil {
				logging.Warn("Warning: failed to persist ACL after owner upsert: %v", err)
			}
		} else {
			logging.Warn("Warning: atreoLINK did not return ownerMemberId — owner-initiated wg:provision will fail until atreoLINK is updated")
		}

		logging.Info("Paired: deviceID=%s appsHostname=%q ownerPin=%s... ownerMemberID=%s", result.DeviceID, result.AppsHostname, pairTokenHexShort(result.OwnerIdentityPubkey), result.OwnerMemberID)
		pairingPath := a.cfg.PairingPath()
		if err := a.cfg.SavePairing(); err != nil {
			logging.Warn("Warning: failed to save pairing state to %s: %v", pairingPath, err)
		} else {
			logging.Info("Pairing state saved to %s", pairingPath)
		}

		a.certs = certs.NewManager(
			a.cfg.KeysDir(),
			a.cfg.CertsDir(),
			a.cfg.DataDir,
			a.cfg.Certs.Email,
			a.cfg.DeviceID,
			a.atreolink,
		)
	}

	logging.Info("Config: appsHostname=%q deviceID=%s dataDir=%s", a.cfg.AppsHostname, a.cfg.DeviceID, a.cfg.DataDir)

	if a.cfg.AppsHostname == "" {
		return fmt.Errorf("AppsHostname is empty — re-pair or set apps_hostname in config.yaml as a one-time bridge")
	}
	if a.cfg.TunnelHost == "" {
		return fmt.Errorf("TunnelHost is empty — re-pair or set tunnel_host in config.yaml as a one-time bridge")
	}

	if err := a.wgServer.Start(ctx); err != nil {
		return fmt.Errorf("start WireGuard: %w", err)
	}

	// Without the firewall, anything bound to 0.0.0.0 is reachable to
	// every paired peer, bypassing the proxy ACL. Fail closed: abort
	// startup (WireGuard is already up but no peers are configured yet)
	// rather than admit peers unconfined. Operators who genuinely can't
	// run iptables must opt out via wireguard.firewall_enabled=false.
	if a.cfg.WireGuard.FirewallEnabled != nil && *a.cfg.WireGuard.FirewallEnabled {
		allowed := []int{a.cfg.Proxy.HTTPSPort, a.cfg.Proxy.HTTPPort}
		a.firewall = firewall.NewManager(firewall.Config{
			Iface:           "wg-atreo",
			AllowedTCPPorts: allowed,
		})
		if err := a.firewall.Apply(ctx); err != nil {
			_ = a.wgServer.Stop()
			return fmt.Errorf("tunnel firewall not installed (%w) — refusing to admit peers unconfined; install iptables or set wireguard.firewall_enabled=false to override", err)
		}
		a.firewall.StartWatchdog(ctx)
	} else {
		logging.Warn("WARNING: wireguard.firewall_enabled=false — peers can reach every host port bound to 0.0.0.0.")
	}

	wgPort := a.cfg.WireGuard.ListenPort
	upnpEnabled := a.cfg.WireGuard.UPnPEnabled
	// IPv6 has no NAT; the master UPnP gate still governs whether the agent
	// opens any inbound path automatically.
	v6PinholeEnabled := upnpEnabled &&
		(a.cfg.WireGuard.IPv6PinholeEnabled == nil || *a.cfg.WireGuard.IPv6PinholeEnabled)

	// Report immediately and independently of UPnP so the DDNS record
	// exists before the first client connects. Dual-family: one report
	// per IPv4/IPv6 socket so both A and AAAA land.
	if results, err := a.atreolink.UpdateEndpoint(ctx, a.cfg.EndpointIP, a.preferredV6Source()); err != nil {
		logging.Error("ERROR: failed to report endpoint to atreoLINK: %v", err)
	} else {
		for _, res := range results {
			if res.Hostname != "" {
				logging.Info("Endpoint reported: %s -> %s", res.Hostname, res.IP)
			}
		}
	}

	if !upnpEnabled {
		logging.Info("UPnP/NAT-PMP disabled. Forward UDP %d on your router to this host.", wgPort)
	}

	// Run on the last-known-good ACL until atreoLINK's signed envelopes
	// replay on WS reconnect.
	if err := a.aclStore.Load(); err != nil {
		logging.Warn("Warning: failed to load ACL from disk: %v", err)
	}

	// Re-verify on load: acl.json has no integrity tag, so a tampered copy
	// could otherwise pin forged identities.
	if a.aclStore.PinnedAdminPublicKey() != nil {
		nasPubB64 := a.keyManager.PublicKeyBase64()
		nasPub := a.keyManager.PublicKey()
		dropped := a.aclStore.DropMembersFailing(func(m atreolink.MemberACLEntry) error {
			if m.Role == "owner" || m.Role == "admin" {
				return nil
			}
			if m.Admittance == nil {
				return fmt.Errorf("missing admittance certificate")
			}
			return tunnel.VerifyAdmittanceCertificate(m.Admittance, m.MemberID, m.IdentityKey, nasPubB64, nasPub)
		})
		for _, m := range dropped {
			logging.Warn("SECURITY: dropped ACL member %s (%q) — admittance cert failed re-verification on load", m.MemberID, m.MemberName)
		}
		if len(dropped) > 0 {
			if err := a.aclStore.Save(); err != nil {
				logging.Warn("Warning: failed to persist ACL after dropping %d unverified member(s): %v", len(dropped), err)
			}
		}
	}

	a.reconcilePeers()

	if err := a.certs.Registry.Load(); err != nil {
		logging.Warn("Warning: failed to load existing certs: %v", err)
	}
	if err := a.certs.EnsureCert(ctx, a.cfg.AppsHostname); err != nil {
		logging.Warn("Warning: certificate not available for %s: %v", a.cfg.AppsHostname, err)
	}
	// Replay the persisted custom-domain row so a restart serves the
	// parent zone without waiting for atreoLINK's replay.
	if a.customDomainStore != nil {
		if cd, err := a.customDomainStore.Get(); err != nil {
			logging.Warn("Warning: read custom-domain store failed: %v", err)
		} else if cd != nil && cd.ParentZone != "" {
			logging.Info("Replaying persisted custom domain: *.%s", cd.ParentZone)
			if err := a.certs.EnsureCert(ctx, cd.ParentZone); err != nil {
				logging.Warn("Warning: custom-domain cert not available for %s: %v", cd.ParentZone, err)
			}
		}
	}

	// Start proxy (HTTPS if certs available, HTTP otherwise). Bind to all
	// interfaces so LAN clients can reach the proxy via the
	// trusted_networks bypass; every request is gated on TCP peer IP (ACL
	// for tunnel peers, IsTrusted for LAN) and fails closed for unknown IPs.
	if a.cfg.Proxy.Enabled != nil && *a.cfg.Proxy.Enabled {
		httpsListen := fmt.Sprintf(":%d", a.cfg.Proxy.HTTPSPort)
		httpListen := fmt.Sprintf(":%d", a.cfg.Proxy.HTTPPort)
		a.proxy = proxy.NewServer(
			a.aclStore, httpsListen, httpListen,
			a.certs.Registry,
			a.cfg.Proxy.TrustedNetworks,
			a.cfg.AtreoLinkAppURL,
		)
		go func() {
			if err := a.proxy.Start(ctx); err != nil {
				logging.Error("Proxy server error: %v", err)
			}
		}()
	} else {
		logging.Info("Built-in proxy disabled. Use your own reverse proxy to serve apps on the WireGuard interface.")
		logging.Info("Forward-auth endpoint available at %s:%d/auth", a.cfg.WireGuard.ServerIP, a.cfg.Proxy.AuthPort)
	}

	// Forward-auth always runs — external reverse proxies depend on it.
	authListen := fmt.Sprintf("%s:%d", a.cfg.WireGuard.ServerIP, a.cfg.Proxy.AuthPort)
	authServer := proxy.NewAuthServer(a.aclStore, authListen, a.certs.Registry, a.cfg.Proxy.TrustedNetworks, a.cfg.Proxy.TrustedProxies)
	go func() {
		if err := authServer.Start(ctx); err != nil {
			logging.Error("Auth server error: %v", err)
		}
	}()

	notifySrv, err := notify.NewServer(a.cfg.Notify.Port, a.cfg.DataDir, a.cfg.DeviceID, a.atreolink, a.aclStore)
	if err != nil {
		logging.Warn("Warning: notification API failed to start: %v", err)
	} else {
		a.notifyServer = notifySrv
		go func() {
			if err := notifySrv.Start(ctx); err != nil {
				logging.Error("Notification API error: %v", err)
			}
		}()
	}

	// Deferred until notifyServer is up so the failure-path push
	// has somewhere to land.
	if upnpEnabled {
		go func() {
			mapCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			_, mappedPort, err := a.upnp.TryMapping(mapCtx)
			cancel()
			switch {
			case err != nil:
				fmt.Print("\n" + banner.Box(
					fmt.Sprintf("Automatic port mapping failed. Please manually forward UDP port %d to this host.", wgPort),
				) + "\n\n")
				logging.Error("UPnP/NAT-PMP mapping failed (%v). Forward UDP %d on your router to this host if you haven't already. You can disable UPnP/NAT-PMP in the config to suppress this message.", err, wgPort)
				a.portMappingAlert(ctx, &notify.NotifyRequest{
					Title:    "Port forwarding required",
					Body:     fmt.Sprintf("UPnP/NAT-PMP couldn't map a port. Forward UDP %d on your router to this host if you haven't already. You can disable UPnP/NAT-PMP in the config to suppress this alert.", wgPort),
					Severity: "error",
				})
			case mappedPort != wgPort:
				logging.Error("ERROR: UPnP mapped external port %d but clients connect on %d. Forward UDP %d manually instead.", mappedPort, wgPort, wgPort)
				a.clearPortMappingAlertCooldown()
			default:
				logging.Info("UPnP/NAT-PMP mapped UDP %d", mappedPort)
				a.clearPortMappingAlertCooldown()
			}
		}()
	}

	// IPv6 firewall pinholes for the advertised public6 candidates. Best
	// effort — many gateways run neither PCP nor IGDv2 v6 firewall control.
	if v6PinholeEnabled {
		go a.refreshV6Pinholes(ctx, 20*time.Second)
	}

	// Optional SMTP-to-push gateway. Routes RCPT TO by full-email match
	// against the ACL. Failure here is logged but non-fatal.
	if a.cfg.SMTP.Enabled && a.notifyServer != nil {
		smtpSrv, err := smtp.NewServer(smtp.Config{
			Listen:          a.cfg.SMTP.Listen,
			MaxMessageBytes: a.cfg.SMTP.MaxMessageBytes,
			RatePerMinute:   a.cfg.SMTP.RatePerMinute,
			TLSEnabled:      a.cfg.SMTP.TLSEnabled,
			DataDir:         a.cfg.DataDir,
			TrustedNetworks: a.cfg.SMTP.TrustedNetworks,
		}, a.aclStore, a.notifyServer)
		if err != nil {
			logging.Warn("Warning: SMTP gateway failed to start: %v", err)
		} else {
			go func() {
				if err := smtpSrv.Start(ctx); err != nil {
					logging.Error("SMTP gateway error: %v", err)
				}
			}()
		}
	}

	a.tunnel = tunnel.NewClient(a.atreolink, a.cfg.AtreoLinkAPIURL, a.keyManager, a.cfg.DeviceID)
	handlers := tunnel.NewHandlers(
		a.wgServer, a.aclStore, a.keyManager, a.allocator,
		a.cfg.PairingPath(), a.cfg.DeviceID, a.cfg.TunnelHost,
		a.atreolink, a.notifyServer,
		a.certs, a.customDomainStore,
	)
	handlers.SetUpstreamSender(a.tunnel.Send)
	handlers.RegisterAll(a.tunnel)
	handlers.StartReapers(ctx)
	handlers.StartLivenessWatch(ctx)

	// Report the applied ACL generation so the server can confirm the
	// agent is current and re-push when it is behind. Best-effort.
	go func() {
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				hb, _ := json.Marshal(map[string]int64{"generation": a.aclStore.AppliedGeneration()})
				_ = a.tunnel.Send(ctx, atreolink.TunnelMessage{Type: "acl:heartbeat", Payload: hb})
			}
		}
	}()

	probeSrv := probe.NewServer(probe.Config{
		DeviceID:   a.cfg.DeviceID,
		PrivateKey: a.keyManager.PrivateKey(),
	})
	probeSrv.Start(ctx)
	go func() {
		<-ctx.Done()
		probeSrv.Stop()
	}()

	endpointsSvc := endpoints.NewService(endpoints.Config{
		DeviceID:       a.cfg.DeviceID,
		WGPort:         a.cfg.WireGuard.ListenPort,
		IfaceSource:    endpoints.NewRealSource(),
		PublicEndpoint: a.upnp,
		Sender:         a.tunnel,
		PrivateKey:     a.keyManager.PrivateKey(),
		OnChange: func(lan []endpoints.Candidate) {
			// Probe binds to exactly the LAN IPs just advertised.
			ips := make([]net.IP, 0, len(lan))
			for _, c := range lan {
				if ip := net.ParseIP(c.Host); ip != nil {
					ips = append(ips, ip)
				}
			}
			probeSrv.SetBindAddresses(probe.BindAddressesFor(ips, a.cfg.WireGuard.ListenPort))
		},
	})

	a.tunnel.SetOnConnect(func() []atreolink.TunnelMessage {
		payload, _ := json.Marshal(map[string]int{
			"proxyHttpsPort": a.cfg.Proxy.HTTPSPort,
		})
		msgs := []atreolink.TunnelMessage{
			{Type: "device:metadata", Payload: payload},
		}
		if env, ok := endpointsSvc.CurrentMessage(); ok {
			msgs = append(msgs, env)
		}
		return msgs
	})

	go func() {
		if err := a.tunnel.Start(ctx); err != nil {
			logging.Error("Tunnel client error: %v", err)
		}
	}()

	go endpointsSvc.Run(ctx)

	if a.notifyServer != nil {
		a.certs.SetOwnerNotifier(func(suffix string, failures int) {
			body := fmt.Sprintf(
				"ACME renewal for %s is failing (%d consecutive attempts). Check DNS / registrar configuration. Cert will lapse in %s if not resolved.",
				suffix, failures, "less than 30 days",
			)
			ownerEntry := a.aclStore.AdminEntry()
			if ownerEntry == nil || ownerEntry.UserID == "" {
				logging.Warn("cert-renewal alert: no admin ACL entry — dropping alert for %s", suffix)
				return
			}
			req := &notify.NotifyRequest{
				UserID:   ownerEntry.UserID,
				Title:    "atreoLINK: certificate renewal failing",
				Body:     body,
				Severity: "warning",
			}
			if err := a.notifyServer.SendToMember(ctx, ownerEntry, req); err != nil {
				logging.Error("cert-renewal alert send failed for %s: %v", suffix, err)
			}
		})
	}

	a.certs.StartAutoRenewal(ctx)

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	expectedPort := a.cfg.WireGuard.ListenPort
	// Per-family tracking so the "Endpoint IP changed" log fires only on
	// the family that actually moved; a v6-only outage doesn't print a
	// spurious change for the v4 record.
	lastReportedV4 := ""
	lastReportedV6 := ""
	portMismatchSince := time.Time{}
	portMismatchNotified := false
	renewalFailures := 0
	renewalFailNotified := false

	logging.Info("atreoAGENT running")

	for {
		select {
		case <-ctx.Done():
			logging.Info("atreoAGENT shutting down...")
			a.tunnel.Stop()
			a.upnp.Stop()
			if a.firewall != nil {
				// Fresh ctx: parent is cancelled, iptables honours ctx at exec.Start.
				a.firewall.Stop(context.Background())
			}
			if err := a.wgServer.Stop(); err != nil {
				logging.Warn("Warning: failed to stop WireGuard server: %v", err)
			}
			if err := a.allocator.Save(); err != nil {
				logging.Warn("Warning: failed to save IP allocations: %v", err)
			}
			return nil
		case <-ticker.C:
			// Refresh DDNS every tick, independent of UPnP. Dual-family.
			if results, err := a.atreolink.UpdateEndpoint(ctx, a.cfg.EndpointIP, a.preferredV6Source()); err != nil {
				logging.Error("ERROR: failed to refresh endpoint on atreoLINK: %v", err)
			} else {
				for _, res := range results {
					if res.IP == "" {
						continue
					}
					parsed := net.ParseIP(res.IP)
					isV6 := parsed != nil && parsed.To4() == nil
					var prev *string
					if isV6 {
						prev = &lastReportedV6
					} else {
						prev = &lastReportedV4
					}
					if res.IP != *prev {
						if *prev != "" {
							family := "v4"
							if isV6 {
								family = "v6"
							}
							logging.Info("Endpoint IP changed (%s): %s -> %s (%s)", family, *prev, res.IP, res.Hostname)
						}
						*prev = res.IP
					}
				}
			}

			endpointsSvc.Trigger()

			// Renew IPv6 pinholes (lease ≫ tick) and pick up new addresses.
			if v6PinholeEnabled {
				a.refreshV6Pinholes(ctx, 30*time.Second)
			}

			if !upnpEnabled {
				continue
			}

			renewCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			_, newPort, err := a.upnp.RenewMapping(renewCtx)
			cancel()
			if err != nil {
				// Logged every cycle on purpose — a standing reminder
				// until the port is forwarded. DDNS above is unaffected.
				logging.Error("UPnP/NAT-PMP renewal failed (%v). Forward UDP %d on your router to this host if you haven't already. You can disable UPnP/NAT-PMP in the config to suppress this message.", err, expectedPort)
				// Only alert if UPnP was previously working — otherwise the
				// user is presumably hand-forwarded and this is just noise.
				if _, lastPort := a.upnp.PublicEndpoint(); lastPort == 0 {
					continue
				}
				renewalFailures++
				// Two consecutive failures ≈ 5–10 min of sustained
				// outage, immune to sub-second timer drift.
				if !renewalFailNotified && renewalFailures >= 2 {
					if a.portMappingAlert(ctx, &notify.NotifyRequest{
						Title:    "Port mapping lost",
						Body:     fmt.Sprintf("UPnP/NAT-PMP renewal failed. Forward UDP %d on your router to this host if you haven't already. You can disable UPnP/NAT-PMP in the config to suppress this alert.", expectedPort),
						Severity: "error",
					}) {
						renewalFailNotified = true
					}
				}
				continue
			}

			// UPnP is healthy this tick — re-arm the cooldown for the
			// next failure episode regardless of whether the prior
			// alert came from startup or renewal.
			a.clearPortMappingAlertCooldown()

			if renewalFailures > 0 {
				logging.Info("UPnP renewal recovered after %d failed attempt(s)", renewalFailures)
				if renewalFailNotified {
					a.notifyOwner(ctx, &notify.NotifyRequest{
						Title:    "Port mapping restored",
						Body:     fmt.Sprintf("UPnP port mapping is working again. Remote access on UDP port %d should resume automatically.", expectedPort),
						Severity: "info",
					})
				}
				renewalFailures = 0
				renewalFailNotified = false
			}

			// A port change breaks every existing client; never
			// auto-update DDNS — keep requesting the original port.
			if newPort != expectedPort {
				if portMismatchSince.IsZero() {
					portMismatchSince = time.Now()
				}
				logging.Error("ERROR: Port changed from %d to %d — all clients will fail to connect. Retrying original port on next renewal.", expectedPort, newPort)

				if !portMismatchNotified && time.Since(portMismatchSince) >= 35*time.Minute {
					if a.notifyServer != nil {
						sent, _ := a.notifyServer.SendToAll(ctx,
							"Port mapping lost",
							fmt.Sprintf("Your router assigned port %d instead of %d. All tunnel connections are broken. Check your router's UPnP/NAT-PMP settings or configure a static port forward for UDP %d.", newPort, expectedPort, expectedPort),
							"error",
							"atreoagent",
						)
						if sent > 0 {
							portMismatchNotified = true
							logging.Info("Sent port change alert to %d mobile device(s)", sent)
						}
					}
				}
				continue
			}

			if !portMismatchSince.IsZero() {
				duration := time.Since(portMismatchSince).Round(time.Second)
				logging.Info("Port recovered to %d after %s", expectedPort, duration)
				if a.notifyServer != nil {
					a.notifyServer.SendToAll(ctx,
						"Port mapping recovered",
						fmt.Sprintf("Your router has restored port %d. Tunnel connections should resume automatically.", expectedPort),
						"info",
						"atreoagent",
					)
				}
				portMismatchSince = time.Time{}
				portMismatchNotified = false
			}
		}
	}
}

// Short hex prefix so the operator can eyeball-confirm the pin matches.
func pairTokenHexShort(pub []byte) string {
	if len(pub) == 0 {
		return ""
	}
	h := hex.EncodeToString(pub)
	if len(h) > 16 {
		return h[:16]
	}
	return h
}

// preferredV6Source picks the stable global IPv6 address to bind as the source
// of the DDNS update, so atreoLINK records a routable AAAA instead of a privacy
// temporary. Returns nil when a manual endpoint_ip override is set (binding is
// irrelevant then) or when no stable address is found, leaving the kernel to
// choose. Errors degrade to nil — a failed lookup shouldn't block the report.
func (a *Agent) preferredV6Source() net.IP {
	if a.cfg.EndpointIP != "" {
		return nil
	}
	ip, err := endpoints.PreferredV6Source()
	if err != nil {
		logging.Debug("ddns: preferred v6 source lookup failed: %v", err)
		return nil
	}
	return ip
}

// refreshV6Pinholes opens/renews IPv6 firewall pinholes for exactly the
// addresses currently advertised as public6 candidates. Failures are logged at
// info (no alert) since gateway support for PCP/IGDv2-v6 is uncommon, and the
// candidates stay advertised either way.
func (a *Agent) refreshV6Pinholes(ctx context.Context, timeout time.Duration) {
	addrs, err := endpoints.PublicV6()
	if err != nil {
		logging.Debug("v6 pinhole: enumerate failed: %v", err)
		return
	}
	if len(addrs) == 0 {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	err = a.upnp.RefreshV6Pinholes(rctx, addrs)

	// Log at INFO only when the outcome changes; an unsupported gateway would
	// otherwise repeat the same line every tick.
	a.v6PinholeMu.Lock()
	defer a.v6PinholeMu.Unlock()
	if err != nil {
		if msg := err.Error(); msg != a.lastV6PinholeErr {
			logging.Info("IPv6 firewall pinhole not established (gateway may not support PCP or UPnP IGDv2): %v", err)
			a.lastV6PinholeErr = msg
		} else {
			logging.Debug("IPv6 firewall pinhole still not established: %v", err)
		}
		return
	}
	if a.lastV6PinholeErr != "" {
		logging.Info("IPv6 firewall pinhole(s) established for %d address(es)", len(addrs))
	}
	a.lastV6PinholeErr = ""
}

// notifyOwner pushes a router-config alert to the agent's owner. Returns
// true on successful relay. Safe to call before notifyServer is up.
func (a *Agent) notifyOwner(ctx context.Context, req *notify.NotifyRequest) bool {
	if a.notifyServer == nil {
		logging.Warn("owner alert %q dropped: notify server not ready", req.Title)
		return false
	}
	owner := a.aclStore.AdminEntry()
	if owner == nil || owner.UserID == "" {
		logging.Warn("owner alert %q dropped: no admin ACL entry", req.Title)
		return false
	}
	if err := a.notifyServer.SendToMember(ctx, owner, req); err != nil {
		logging.Error("owner alert %q send failed: %v", req.Title, err)
		return false
	}
	logging.Info("owner alert %q sent", req.Title)
	return true
}

// 24h cooldown for the port-mapping alert family — prevents a restart
// loop from spamming the owner while UPnP is broken.
const portMappingAlertCooldown = 24 * time.Hour

func (a *Agent) portMappingAlertOnCooldown() bool {
	info, err := os.Stat(a.cfg.PortMappingAlertPath())
	if err != nil {
		return false
	}
	return time.Since(info.ModTime()) < portMappingAlertCooldown
}

func (a *Agent) markPortMappingAlertSent() {
	path := a.cfg.PortMappingAlertPath()
	f, err := os.Create(path)
	if err != nil {
		logging.Warn("port-mapping alert cooldown: write failed: %v", err)
		return
	}
	_ = f.Close()
}

func (a *Agent) clearPortMappingAlertCooldown() {
	_ = os.Remove(a.cfg.PortMappingAlertPath())
}

// portMappingAlert sends the alert if not on cooldown. Returns true when
// the cooldown was already in effect or the send succeeded — i.e. the
// caller should consider the alert "handled" and not retry.
func (a *Agent) portMappingAlert(ctx context.Context, req *notify.NotifyRequest) bool {
	if a.portMappingAlertOnCooldown() {
		logging.Debug("owner alert %q suppressed by 24h cooldown", req.Title)
		return true
	}
	if a.notifyOwner(ctx, req) {
		a.markPortMappingAlertSent()
		return true
	}
	return false
}

// reconcilePeers re-aligns WireGuard peers with the ACL on startup.
// Suspended members are excluded from the add phase; their ACL state
// (and allocator slot) is preserved for the next member:status active.
func (a *Agent) reconcilePeers() {
	members := a.aclStore.AllMembers()

	// allocator.Save runs only on clean shutdown, so on SIGKILL the
	// alloc file may be stale; the ACL is authoritative.
	for _, member := range members {
		for _, c := range member.Clients {
			a.allocator.MarkUsed(c.WGPublicKey, c.TunnelIP)
		}
	}

	validKeys := make(map[string]bool)
	skippedSuspended := 0
	added := 0
	for _, member := range members {
		if member.Status != "" && member.Status != "active" {
			skippedSuspended += len(member.Clients)
			continue
		}
		for _, c := range member.Clients {
			if c.WGPublicKey == "" {
				continue
			}
			validKeys[c.WGPublicKey] = true
			tunnelIP := c.TunnelIP
			if tunnelIP == "" {
				ip, err := a.allocator.Allocate(c.WGPublicKey)
				if err != nil {
					logging.Warn("Warning: failed to allocate IP for peer %s: %v", c.WGPublicKey[:16], err)
					continue
				}
				tunnelIP = ip
			}
			if err := a.wgServer.AddPeer(c.WGPublicKey, tunnelIP); err != nil {
				logging.Warn("Warning: failed to add peer %s: %v", c.WGPublicKey[:16], err)
				continue
			}
			a.aclStore.AddClient(member.MemberID, atreolink.ClientRecord{
				WGPublicKey: c.WGPublicKey,
				TunnelIP:    tunnelIP,
				Label:       c.Label,
				Platform:    c.Platform,
			})
			added++
		}
	}

	removed := 0
	for _, peer := range a.wgServer.ListPeers() {
		if !validKeys[peer.PublicKey] {
			if err := a.wgServer.RemovePeer(peer.PublicKey); err != nil {
				logging.Warn("Warning: failed to remove stale WG peer %s: %v", peer.PublicKey, err)
			}
			a.allocator.Release(peer.PublicKey)
			removed++
		}
	}

	if added > 0 || removed > 0 || skippedSuspended > 0 {
		logging.Info("Reconciled WireGuard peers: %d added, %d stale removed, %d skipped (suspended members)", added, removed, skippedSuspended)
		if err := a.aclStore.Save(); err != nil {
			logging.Warn("Warning: failed to save ACL: %v", err)
		}
	}
}
