package upnp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
	"github.com/atreoLABS/atreoAGENT/internal/pcp"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/huin/goupnp"
	"github.com/huin/goupnp/dcps/internetgateway2"
	natpmp "github.com/jackpal/go-nat-pmp"
)

// Lease requested for every mapping/pinhole — short enough to expire soon
// after a crash, well above the 5-minute renewal cadence.
const (
	mappingLeaseSeconds = 1800
	pinholeLeaseSeconds = 3600 // IGDv2 AddPinhole lease (seconds)
)

type Client struct {
	internalPort int
	externalPort int
	description  string
	pcpEnabled   bool

	mu             sync.Mutex
	v4cleanup      func()              // tears down the active IPv4 mapping
	lastExternalIP string              // last IPv4 external IP (feeds public4 candidate)
	v6pinholes     map[string]*pinhole // keyed by IPv6 address string
	statePath      string              // JSON file persisting PCP nonces ("" = no persistence)

	// IPv4 mapping nonce, reused across renewals/restarts so each renewal
	// refreshes the same mapping instead of colliding with the live one.
	v4nonce    pcp.Nonce
	v4nonceSet bool
	v4localIP  string // internal IP the v4 nonce is keyed to
}

// pinhole holds the teardown for one IPv6 firewall pinhole plus, for the PCP
// path, the nonce needed to renew/delete it.
type pinhole struct {
	nonce  pcp.Nonce
	remove func()
}

func NewClient(internalPort int) *Client {
	return &Client{
		internalPort: internalPort,
		externalPort: internalPort,
		description:  "atreoAGENT WireGuard",
		pcpEnabled:   true,
		v6pinholes:   make(map[string]*pinhole),
	}
}

// SetPCPEnabled toggles PCP attempts (both families). Call once at
// construction, before any mapping goroutine starts.
func (c *Client) SetPCPEnabled(enabled bool) { c.pcpEnabled = enabled }

// SetStatePath persists the PCP nonces (v4 mapping + v6 pinholes) to path and
// loads any saved ones. Call once at construction. A renewal must reuse the
// original nonce or the gateway rejects it NOT_AUTHORIZED (RFC 6887 anti-hijack).
func (c *Client) SetStatePath(path string) {
	c.statePath = path
	c.loadNonces()
}

func (c *Client) TryMapping(ctx context.Context) (externalIP string, externalPort int, err error) {
	ip, port, err := c.addMapping(ctx)
	if err != nil {
		return "", 0, err
	}
	c.mu.Lock()
	c.externalPort = port
	c.lastExternalIP = ip
	c.mu.Unlock()
	return ip, port, nil
}

// Returned port may differ if the gateway reassigned. The requested
// externalPort is NOT updated — subsequent renewals keep asking for the
// original so the gateway can recover it.
func (c *Client) RenewMapping(ctx context.Context) (externalIP string, externalPort int, err error) {
	ip, port, err := c.addMapping(ctx)
	if err != nil {
		return "", 0, err
	}
	c.mu.Lock()
	c.lastExternalIP = ip
	c.mu.Unlock()
	return ip, port, nil
}

func (c *Client) Stop() {
	c.mu.Lock()
	v4 := c.v4cleanup
	c.v4cleanup = nil
	removers := make([]func(), 0, len(c.v6pinholes))
	for k, p := range c.v6pinholes {
		removers = append(removers, p.remove)
		delete(c.v6pinholes, k)
	}
	c.mu.Unlock()

	if v4 != nil {
		v4()
	}
	for _, rm := range removers {
		rm()
	}
}

func (c *Client) addMapping(ctx context.Context) (externalIP string, externalPort int, err error) {
	localIP, err := getLocalIP()
	if err != nil {
		return "", 0, fmt.Errorf("get local IP: %w", err)
	}
	logging.Info("NAT: searching for gateways (local IP: %s)...", localIP)

	// PCP first — NAT-PMP's successor on the same port 5351. On
	// UNSUPP_VERSION/timeout fall through to NAT-PMP.
	if c.pcpEnabled {
		extIP, extPort, err := c.tryPCPv4(ctx, localIP)
		if err == nil {
			return extIP, extPort, nil
		}
		logging.Debug("PCP (v4) unavailable: %v", err)
	}

	// NAT-PMP next — direct UDP, no multicast.
	extIP, extPort, err := c.tryNATPMP(localIP)
	if err == nil {
		return extIP, extPort, nil
	}
	logging.Warn("NAT-PMP failed: %v", err)

	extIP, extPort, err = c.tryHighLevel(ctx, localIP)
	if err == nil {
		return extIP, extPort, nil
	}
	logging.Warn("UPnP standard discovery failed: %v", err)

	logging.Info("UPnP: trying per-interface raw SSDP...")
	extIP, extPort, err = c.tryRawSSDPAllInterfaces(ctx, localIP)
	if err == nil {
		return extIP, extPort, nil
	}

	return "", 0, fmt.Errorf("NAT: no gateway found via NAT-PMP or UPnP: %w", err)
}

func (c *Client) tryNATPMP(localIP string) (string, int, error) {
	gateway, err := getDefaultGateway()
	if err != nil {
		return "", 0, fmt.Errorf("NAT-PMP: get gateway: %w", err)
	}
	logging.Debug("NAT-PMP: trying gateway %s", gateway.String())

	client := natpmp.NewClientWithTimeout(gateway, 3*time.Second)

	extResp, err := client.GetExternalAddress()
	if err != nil {
		return "", 0, fmt.Errorf("NAT-PMP: get external address: %w", err)
	}
	extIP := fmt.Sprintf("%d.%d.%d.%d",
		extResp.ExternalIPAddress[0], extResp.ExternalIPAddress[1],
		extResp.ExternalIPAddress[2], extResp.ExternalIPAddress[3])

	// 1800s lease — quickly expires after a crash, well above 5min renewal.
	mapResp, err := client.AddPortMapping("udp", c.internalPort, c.externalPort, 1800)
	if err != nil {
		return "", 0, fmt.Errorf("NAT-PMP: add port mapping: %w", err)
	}

	mappedPort := int(mapResp.MappedExternalPort)
	logging.Info("NAT-PMP: mapped %s:%d -> %s:%d (lifetime %ds)",
		extIP, mappedPort, localIP, c.internalPort, mapResp.PortMappingLifetimeInSeconds)

	c.mu.Lock()
	c.v4cleanup = func() {
		cl := natpmp.NewClientWithTimeout(gateway, 3*time.Second)
		if _, err := cl.AddPortMapping("udp", c.internalPort, 0, 0); err != nil {
			logging.Warn("NAT-PMP: failed to remove port mapping: %v", err)
		} else {
			logging.Info("NAT-PMP: port mapping removed")
		}
	}
	c.mu.Unlock()

	return extIP, mappedPort, nil
}

// tryPCPv4 requests an IPv4 MAP from the default gateway. Behind a NAT the
// gateway picks the external address (suggested = unspecified); the result
// feeds the public4 endpoint candidate just like NAT-PMP.
func (c *Client) tryPCPv4(ctx context.Context, localIP string) (string, int, error) {
	gw, err := getDefaultGateway()
	if err != nil {
		return "", 0, fmt.Errorf("PCP: get gateway: %w", err)
	}
	gwAddr, ok := ipToAddr(gw)
	if !ok {
		return "", 0, fmt.Errorf("PCP: bad gateway %v", gw)
	}
	server := netip.AddrPortFrom(gwAddr, pcp.ServerPort)
	clientAddr := net.ParseIP(localIP)

	// Reuse the same nonce across renewals (and restarts) so the gateway
	// refreshes the existing mapping instead of rejecting a fresh-nonce add for
	// an internal IP+port that's still mapped. A changed internal IP starts a
	// new mapping, so re-key the nonce when localIP moves.
	nonce, err := c.v4MappingNonce(localIP)
	if err != nil {
		return "", 0, err
	}
	m, err := pcp.RequestMapping(ctx, server, clientAddr, net.IPv4zero, pcp.ProtoUDP,
		uint16(c.internalPort), uint16(c.externalPort), mappingLeaseSeconds, nonce)
	if err != nil {
		return "", 0, err
	}
	c.persistNonces()

	extIP := m.ExternalIP.String()
	mappedPort := int(m.ExternalPort)
	logging.Info("PCP: mapped %s:%d -> %s:%d (lifetime %ds)", extIP, mappedPort, localIP, c.internalPort, m.Lifetime)

	c.mu.Lock()
	c.v4cleanup = func() {
		dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := pcp.RequestMapping(dctx, server, clientAddr, net.IPv4zero, pcp.ProtoUDP,
			uint16(c.internalPort), uint16(c.externalPort), 0, nonce); err != nil {
			logging.Warn("PCP: failed to remove mapping: %v", err)
		} else {
			logging.Info("PCP: mapping removed")
		}
	}
	c.mu.Unlock()

	return extIP, mappedPort, nil
}

// v4MappingNonce returns the persistent IPv4 PCP nonce, minting (and keying to
// localIP) one on first use or whenever the internal IP changes.
func (c *Client) v4MappingNonce(localIP string) (pcp.Nonce, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.v4nonceSet && c.v4localIP == localIP {
		return c.v4nonce, nil
	}
	n, err := pcp.NewNonce()
	if err != nil {
		return pcp.Nonce{}, err
	}
	c.v4nonce, c.v4nonceSet, c.v4localIP = n, true, localIP
	return n, nil
}

// /proc/net/route — x.x.x.1 is just a convention, not a rule.
func getDefaultGateway() (net.IP, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("open /proc/net/route: %w", err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	header := true
	for sc.Scan() {
		if header {
			header = false
			continue
		}
		// Iface Destination Gateway Flags ...
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		if fields[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&0x2 == 0 { // RTF_GATEWAY
			continue
		}
		gwLE, err := strconv.ParseUint(fields[2], 16, 32)
		if err != nil {
			continue
		}
		// /proc/net/route stores Gateway host-byte-order (little-endian).
		gw := net.IPv4(byte(gwLE), byte(gwLE>>8), byte(gwLE>>16), byte(gwLE>>24))
		return gw, nil
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan /proc/net/route: %w", err)
	}
	return nil, fmt.Errorf("no default route in /proc/net/route")
}

func (c *Client) tryHighLevel(ctx context.Context, localIP string) (string, int, error) {
	clients2, _, _ := internetgateway2.NewWANIPConnection2ClientsCtx(ctx)
	logging.Info("UPnP: WANIPConnection2: found %d", len(clients2))
	if len(clients2) > 0 {
		return c.mapWithIPConn2(ctx, clients2[0], localIP)
	}

	clients1, _, _ := internetgateway2.NewWANIPConnection1ClientsCtx(ctx)
	logging.Info("UPnP: WANIPConnection1: found %d", len(clients1))
	if len(clients1) > 0 {
		return c.mapWithIPConn1(ctx, clients1[0], localIP)
	}

	ppp, _, _ := internetgateway2.NewWANPPPConnection1ClientsCtx(ctx)
	logging.Info("UPnP: WANPPPConnection1: found %d", len(ppp))
	if len(ppp) > 0 {
		return c.mapWithPPP(ctx, ppp[0], localIP)
	}

	return "", 0, fmt.Errorf("no gateways found")
}

func (c *Client) tryRawSSDPAllInterfaces(ctx context.Context, localIP string) (string, int, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", 0, err
	}

	targets := []string{
		"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		"urn:schemas-upnp-org:device:InternetGatewayDevice:2",
		"urn:schemas-upnp-org:service:WANIPConnection:1",
		"urn:schemas-upnp-org:service:WANIPConnection:2",
		"urn:schemas-upnp-org:service:WANPPPConnection:1",
		"upnp:rootdevice",
	}

	for _, iface := range ifaces {
		if ctx.Err() != nil {
			return "", 0, ctx.Err()
		}
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagMulticast == 0 {
			continue
		}

		addrs, _ := iface.Addrs()
		var ifaceIP string
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil && !ipNet.IP.IsLoopback() {
				ifaceIP = ipNet.IP.String()
				break
			}
		}
		if ifaceIP == "" {
			continue
		}

		for _, target := range targets {
			if ctx.Err() != nil {
				return "", 0, ctx.Err()
			}
			locations := c.rawMSearch(ctx, ifaceIP, target)
			for _, loc := range locations {
				logging.Debug("UPnP: found device at %s via %s (%s)", loc, iface.Name, shortURN(target))

				devices, err := goupnp.DiscoverDevicesCtx(ctx, target)
				if err != nil {
					continue
				}
				for _, d := range devices {
					if d.Err != nil || d.Root == nil {
						continue
					}
					extIP, extPort, err := c.tryDeviceMapping(ctx, d.Root, localIP)
					if err == nil {
						return extIP, extPort, nil
					}
				}
			}
		}
	}

	return "", 0, fmt.Errorf("no gateways responded on any interface")
}

// M-SEARCH bound to a specific local IP.
func (c *Client) rawMSearch(ctx context.Context, localIP, searchTarget string) []string {
	msg := fmt.Sprintf(
		"M-SEARCH * HTTP/1.1\r\n"+
			"HOST: 239.255.255.250:1900\r\n"+
			"MAN: \"ssdp:discover\"\r\n"+
			"MX: 3\r\n"+
			"ST: %s\r\n"+
			"\r\n",
		searchTarget,
	)

	laddr, err := net.ResolveUDPAddr("udp4", localIP+":0")
	if err != nil {
		return nil
	}
	raddr, _ := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")

	conn, err := net.DialUDP("udp4", laddr, raddr)
	if err != nil {
		return nil
	}
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(4 * time.Second)
	if cd, ok := ctx.Deadline(); ok && cd.Before(deadline) {
		deadline = cd
	}
	_ = conn.SetDeadline(deadline)
	_, _ = conn.Write([]byte(msg))

	var locations []string
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		resp := string(buf[:n])
		for _, line := range strings.Split(resp, "\r\n") {
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "location:") {
				loc := strings.TrimSpace(line[len("location:"):])
				locations = append(locations, loc)
			}
		}
	}
	return locations
}

func (c *Client) tryDeviceMapping(ctx context.Context, device *goupnp.RootDevice, localIP string) (string, int, error) {
	svc2 := device.Device.FindService("urn:schemas-upnp-org:service:WANIPConnection:2")
	if len(svc2) > 0 {
		sc := goupnp.ServiceClient{SOAPClient: svc2[0].NewSOAPClient(), RootDevice: device, Service: svc2[0]}
		client := &internetgateway2.WANIPConnection2{ServiceClient: sc}
		return c.mapWithIPConn2(ctx, client, localIP)
	}

	svc1 := device.Device.FindService("urn:schemas-upnp-org:service:WANIPConnection:1")
	if len(svc1) > 0 {
		sc := goupnp.ServiceClient{SOAPClient: svc1[0].NewSOAPClient(), RootDevice: device, Service: svc1[0]}
		client := &internetgateway2.WANIPConnection1{ServiceClient: sc}
		return c.mapWithIPConn1(ctx, client, localIP)
	}

	ppp := device.Device.FindService("urn:schemas-upnp-org:service:WANPPPConnection:1")
	if len(ppp) > 0 {
		sc := goupnp.ServiceClient{SOAPClient: ppp[0].NewSOAPClient(), RootDevice: device, Service: ppp[0]}
		client := &internetgateway2.WANPPPConnection1{ServiceClient: sc}
		return c.mapWithPPP(ctx, client, localIP)
	}

	return "", 0, fmt.Errorf("no supported WAN service on device")
}

func (c *Client) mapWithIPConn2(ctx context.Context, client *internetgateway2.WANIPConnection2, localIP string) (string, int, error) {
	extIP, err := client.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("get external IP (v2): %w", err)
	}
	err = client.AddPortMappingCtx(ctx, "", uint16(c.externalPort), "UDP",
		uint16(c.internalPort), localIP, true, c.description, 0)
	if err != nil {
		return "", 0, fmt.Errorf("add port mapping (v2): %w", err)
	}
	logging.Info("UPnP: mapped %s:%d -> %s:%d (WANIPConnection2)", extIP, c.externalPort, localIP, c.internalPort)

	c.mu.Lock()
	c.v4cleanup = func() {
		dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := client.DeletePortMappingCtx(dctx, "", uint16(c.externalPort), "UDP"); err != nil {
			logging.Warn("UPnP: failed to remove port mapping (v2): %v", err)
		} else {
			logging.Info("UPnP: port mapping removed (WANIPConnection2)")
		}
	}
	c.mu.Unlock()

	return extIP, c.externalPort, nil
}

func (c *Client) mapWithIPConn1(ctx context.Context, client *internetgateway2.WANIPConnection1, localIP string) (string, int, error) {
	extIP, err := client.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("get external IP (v1): %w", err)
	}
	err = client.AddPortMappingCtx(ctx, "", uint16(c.externalPort), "UDP",
		uint16(c.internalPort), localIP, true, c.description, 0)
	if err != nil {
		return "", 0, fmt.Errorf("add port mapping (v1): %w", err)
	}
	logging.Info("UPnP: mapped %s:%d -> %s:%d (WANIPConnection1)", extIP, c.externalPort, localIP, c.internalPort)

	c.mu.Lock()
	c.v4cleanup = func() {
		dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := client.DeletePortMappingCtx(dctx, "", uint16(c.externalPort), "UDP"); err != nil {
			logging.Warn("UPnP: failed to remove port mapping (v1): %v", err)
		} else {
			logging.Info("UPnP: port mapping removed (WANIPConnection1)")
		}
	}
	c.mu.Unlock()

	return extIP, c.externalPort, nil
}

func (c *Client) mapWithPPP(ctx context.Context, client *internetgateway2.WANPPPConnection1, localIP string) (string, int, error) {
	extIP, err := client.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("get external IP (PPP): %w", err)
	}
	err = client.AddPortMappingCtx(ctx, "", uint16(c.externalPort), "UDP",
		uint16(c.internalPort), localIP, true, c.description, 0)
	if err != nil {
		return "", 0, fmt.Errorf("add port mapping (PPP): %w", err)
	}
	logging.Info("UPnP: mapped %s:%d -> %s:%d (WANPPPConnection1)", extIP, c.externalPort, localIP, c.internalPort)

	c.mu.Lock()
	c.v4cleanup = func() {
		dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := client.DeletePortMappingCtx(dctx, "", uint16(c.externalPort), "UDP"); err != nil {
			logging.Warn("UPnP: failed to remove port mapping (PPP): %v", err)
		} else {
			logging.Info("UPnP: port mapping removed (WANPPPConnection1)")
		}
	}
	c.mu.Unlock()

	return extIP, c.externalPort, nil
}

func shortURN(urn string) string {
	parts := strings.Split(urn, ":")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + ":" + parts[len(parts)-1]
	}
	return urn
}

func getLocalIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()
	return conn.LocalAddr().(*net.UDPAddr).IP.String(), nil
}

func (c *Client) InternalPort() int { return c.internalPort }
func (c *Client) ExternalPort() int { return c.externalPort }

// ("", 0) when no mapping is active. Active = cleanup fn is set.
func (c *Client) PublicEndpoint() (ip string, port int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.v4cleanup == nil {
		return "", 0
	}
	return c.lastExternalIP, c.externalPort
}

// RefreshV6Pinholes opens (or renews) one IPv6 firewall pinhole per address
// in addrs on the WireGuard port, and removes pinholes for addresses no longer
// present. IPv6 has no NAT, so this only punches the gateway firewall — the
// addresses themselves are already advertised as public6 candidates. PCP is
// tried first, then UPnP IGDv2 WANIPv6FirewallControl. Returns the first error
// encountered; callers treat failure as non-fatal (the router may support
// neither protocol).
func (c *Client) RefreshV6Pinholes(ctx context.Context, addrs []net.IP) error {
	desired := make(map[string]net.IP, len(addrs))
	for _, ip := range addrs {
		if ip.To4() == nil && ip.To16() != nil {
			desired[ip.String()] = ip
		}
	}

	// Drop pinholes whose address is no longer advertised (e.g. SLAAC churn).
	c.mu.Lock()
	var stale []func()
	deleted := false
	for k, p := range c.v6pinholes {
		if _, ok := desired[k]; !ok {
			if p.remove != nil {
				stale = append(stale, p.remove)
			}
			delete(c.v6pinholes, k)
			deleted = true
		}
	}
	c.mu.Unlock()
	if deleted {
		c.persistNonces()
	}
	for _, rm := range stale {
		rm()
	}

	if len(desired) == 0 {
		return nil
	}

	// One gateway lookup for the whole batch; the UPnP fallback doesn't need it.
	v6gw, gwErr := defaultV6Gateway()

	var firstErr error
	for key, ip := range desired {
		if err := c.ensureV6Pinhole(ctx, key, ip, v6gw, gwErr); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (c *Client) ensureV6Pinhole(ctx context.Context, key string, ip net.IP, v6gw netip.AddrPort, gwErr error) error {
	c.mu.Lock()
	existing := c.v6pinholes[key]
	c.mu.Unlock()

	// PCP first. Reuse the prior nonce so a renew extends the same mapping.
	pcpErr := errors.New("disabled")
	switch {
	case !c.pcpEnabled:
	case gwErr != nil:
		pcpErr = fmt.Errorf("no IPv6 gateway: %w", gwErr)
	default:
		nonce := pcp.Nonce{}
		if existing != nil {
			nonce = existing.nonce
		} else if n, err := pcp.NewNonce(); err == nil {
			nonce = n
		} else {
			return err
		}

		_, err := pcp.RequestMapping(ctx, v6gw, ip, ip, pcp.ProtoUDP,
			uint16(c.internalPort), uint16(c.internalPort), pinholeLeaseSeconds, nonce)
		if err != nil && existing != nil {
			// Keep the pinhole we already hold rather than risk a delete-then-readd
			// that breaks inbound for real if the re-add fails. Next tick retries.
			logging.Debug("PCP: gateway rejected v6 pinhole refresh for %s; keeping existing mapping: %v", ip, err)
			return nil
		}
		if err == nil {
			server := v6gw
			rm := func() {
				dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, err := pcp.RequestMapping(dctx, server, ip, ip, pcp.ProtoUDP,
					uint16(c.internalPort), uint16(c.internalPort), 0, nonce); err != nil {
					logging.Warn("PCP: failed to remove v6 pinhole for %s: %v", ip, err)
				} else {
					logging.Info("PCP: v6 pinhole removed for %s", ip)
				}
			}
			c.storePinhole(key, &pinhole{nonce: nonce, remove: rm})
			if existing == nil {
				logging.Info("PCP: opened IPv6 pinhole for [%s]:%d via %s", ip, c.internalPort, v6gw)
			}
			return nil
		}
		pcpErr = err
	}

	// Both attempts failed — name the address and add/renew stage so a
	// recurring failure is traceable to a specific candidate.
	stage := "new"
	if existing != nil {
		stage = "renew"
	}
	if upErr := c.tryUPnPPinhole(ctx, key, ip); upErr != nil {
		return fmt.Errorf("[%s] (%s) PCP: %v; UPnP: %w", ip, stage, pcpErr, upErr)
	}
	return nil
}

func (c *Client) tryUPnPPinhole(ctx context.Context, key string, ip net.IP) error {
	clients, _, err := internetgateway2.NewWANIPv6FirewallControl1ClientsCtx(ctx)
	if err != nil {
		return fmt.Errorf("UPnP IPv6 firewall discovery: %w", err)
	}
	if len(clients) == 0 {
		return fmt.Errorf("no IGDv2 IPv6 firewall control found")
	}
	fw := clients[0]

	// Refuse only when the gateway positively reports pinholes are off; an
	// error here is non-authoritative, so press on.
	if enabled, allowed, err := fw.GetFirewallStatusCtx(ctx); err == nil && (!enabled || !allowed) {
		return fmt.Errorf("IGDv2 firewall pinholes not permitted (enabled=%v allowed=%v)", enabled, allowed)
	}

	// RemoteHost "" + RemotePort 0 = any source.
	uid, err := fw.AddPinholeCtx(ctx, "", 0, ip.String(), uint16(c.internalPort), uint16(pcp.ProtoUDP), pinholeLeaseSeconds)
	if err != nil {
		return fmt.Errorf("AddPinhole: %w", err)
	}
	logging.Info("UPnP: opened IPv6 pinhole for [%s]:%d (id %d)", ip, c.internalPort, uid)

	rm := func() {
		dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := fw.DeletePinholeCtx(dctx, uid); err != nil {
			logging.Warn("UPnP: failed to remove v6 pinhole for %s: %v", ip, err)
		} else {
			logging.Info("UPnP: v6 pinhole removed for %s", ip)
		}
	}
	c.storePinhole(key, &pinhole{remove: rm})
	return nil
}

func (c *Client) storePinhole(key string, p *pinhole) {
	c.mu.Lock()
	c.v6pinholes[key] = p
	c.mu.Unlock()
	c.persistNonces()
}

const allZeroV6Hex = "00000000000000000000000000000000"

// defaultV6Gateway parses /proc/net/ipv6_route for the next-hop of the IPv6
// default route. A link-local gateway carries the egress interface as the
// netip zone so "[fe80::1%eth0]:5351" resolves.
func defaultV6Gateway() (netip.AddrPort, error) {
	f, err := os.Open("/proc/net/ipv6_route")
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("open /proc/net/ipv6_route: %w", err)
	}
	defer func() { _ = f.Close() }()
	return parseDefaultV6Gateway(f)
}

func parseDefaultV6Gateway(r io.Reader) (netip.AddrPort, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		// dest(32) destLen(2) src(32) srcLen(2) nexthop(32) metric refcnt use flags iface
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		if fields[0] != allZeroV6Hex || fields[1] != "00" {
			continue // not a default route
		}
		flags, err := strconv.ParseUint(fields[8], 16, 32)
		if err != nil || flags&0x1 == 0 { // RTF_UP
			continue
		}
		gw, err := parseHexV6(fields[4])
		if err != nil || gw.IsUnspecified() {
			continue
		}
		if gw.IsLinkLocalUnicast() {
			gw = gw.WithZone(fields[9])
		}
		return netip.AddrPortFrom(gw, pcp.ServerPort), nil
	}
	if err := sc.Err(); err != nil {
		return netip.AddrPort{}, fmt.Errorf("scan /proc/net/ipv6_route: %w", err)
	}
	return netip.AddrPort{}, fmt.Errorf("no default route in /proc/net/ipv6_route")
}

func parseHexV6(s string) (netip.Addr, error) {
	if len(s) != 32 {
		return netip.Addr{}, fmt.Errorf("bad IPv6 hex %q", s)
	}
	var b [16]byte
	for i := 0; i < 16; i++ {
		v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return netip.Addr{}, err
		}
		b[i] = byte(v)
	}
	return netip.AddrFrom16(b), nil
}

func ipToAddr(ip net.IP) (netip.Addr, bool) {
	if v4 := ip.To4(); v4 != nil {
		return netip.AddrFromSlice(v4)
	}
	return netip.AddrFromSlice(ip.To16())
}

var _ *http.Response // keep http import for goupnp
