//go:build !linux

package endpoints

import (
	"context"
	"github.com/atreoLABS/atreoAGENT/internal/logging"
)

// startInterfaceWatcher is a no-op on non-Linux platforms. The periodic
// fallback in Service.Run is the only change source; the agent can still
// catch interface changes by restarting or by receiving a Trigger() from
// the UPnP renewal loop.
func startInterfaceWatcher(_ context.Context, _ *Service) func() {
	logging.Info("endpoints: netlink watcher not supported on this platform; relying on periodic refresh and UPnP-triggered refresh")
	return func() {}
}
