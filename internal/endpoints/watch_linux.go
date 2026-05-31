//go:build linux

package endpoints

import (
	"context"
	"github.com/atreoLABS/atreoAGENT/internal/logging"

	"golang.org/x/sys/unix"
)

// startInterfaceWatcher subscribes to RTMGRP_LINK | RTMGRP_IPV4_IFADDR |
// RTMGRP_IPV6_IFADDR on a netlink socket and calls svc.Trigger() on every
// received message. The caller is responsible for debouncing — netlink
// bursts multiple messages per interface event (RTM_NEWLINK + RTM_NEWADDR
// for v4 + RTM_NEWADDR for v6) and the service's Run loop collapses them.
//
// Returns a function the caller must invoke to unsubscribe and close the
// socket. On netlink-open failure, startInterfaceWatcher logs and returns a
// no-op stop fn — the periodic fallback still runs.
func startInterfaceWatcher(ctx context.Context, svc *Service) func() {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		logging.Warn("endpoints: netlink subscribe failed (%v); falling back to periodic refresh only", err)
		return func() {}
	}
	sa := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR,
	}
	if err := unix.Bind(fd, sa); err != nil {
		logging.Warn("endpoints: netlink bind failed (%v); falling back to periodic refresh only", err)
		_ = unix.Close(fd)
		return func() {}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65536)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				// EBADF means we closed the fd (stop path); anything else
				// is transient — retry on next loop iteration after a tiny
				// sleep-free yield via ctx check.
				if ctx.Err() != nil {
					return
				}
				logging.Error("endpoints: netlink recv: %v", err)
				return
			}
			if n > 0 {
				// Don't bother parsing — any message on this group is
				// reason enough to re-enumerate. Debounce happens in
				// Service.Run.
				svc.Trigger()
			}
		}
	}()

	return func() {
		// Closing the fd unblocks Recvfrom with EBADF, which terminates
		// the goroutine promptly.
		_ = unix.Close(fd)
		<-done
	}
}
