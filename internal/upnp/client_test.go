package upnp

import (
	"context"
	"testing"
)

func TestNewClient(t *testing.T) {
	c := NewClient(51820)
	if c.internalPort != 51820 {
		t.Errorf("internalPort = %d, want 51820", c.internalPort)
	}
	if c.InternalPort() != 51820 {
		t.Errorf("InternalPort() = %d, want 51820", c.InternalPort())
	}
}

func TestTryMappingReturnsError(t *testing.T) {
	// On machines without a UPnP gateway (CI, dev laptops), TryMapping
	// will return an error. We just verify it doesn't panic.
	c := NewClient(51820)
	_, _, err := c.TryMapping(context.Background())
	if err == nil {
		t.Log("TryMapping succeeded — UPnP gateway found on network")
	} else {
		t.Logf("TryMapping error (expected without UPnP gateway): %v", err)
	}
}

func TestRenewMappingReturnsError(t *testing.T) {
	// Same as above — verify no panic, error is expected without a gateway.
	c := NewClient(51820)
	_, _, err := c.RenewMapping(context.Background())
	if err == nil {
		t.Log("RenewMapping succeeded — UPnP gateway found on network")
	} else {
		t.Logf("RenewMapping error (expected without UPnP gateway): %v", err)
	}
}

func TestPublicEndpointEmptyBeforeMapping(t *testing.T) {
	// PublicEndpoint must return ("", 0) when no mapping is installed —
	// the endpoints service relies on that to decide whether to emit a
	// public4 candidate in the signed envelope.
	c := NewClient(51820)
	ip, port := c.PublicEndpoint()
	if ip != "" || port != 0 {
		t.Errorf("PublicEndpoint() = (%q, %d), want (\"\", 0)", ip, port)
	}
}
