//go:build !linux

package endpoints

import "net"

// Interfaces returns the system's interface list without V6Flags — on non-
// Linux platforms there's no portable way to query IFA_F_TEMPORARY /
// IFA_F_DEPRECATED without platform-specific netlink work. The enumerator
// tolerates the missing data by keeping every global-scope v6 address.
func (realSource) Interfaces() ([]Interface, error) {
	sysIfs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(sysIfs))
	for _, si := range sysIfs {
		addrs, err := si.Addrs()
		if err != nil {
			continue
		}
		ips := make([]net.IPNet, 0, len(addrs))
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP != nil {
				ips = append(ips, *n)
			}
		}
		out = append(out, Interface{
			Name:  si.Name,
			Index: si.Index,
			Flags: si.Flags,
			Addrs: ips,
		})
	}
	return out, nil
}

// DefaultRoute is a no-op on non-Linux platforms. Callers treat (0, "") as
// "no preference" and fall back to returning LAN candidates in whatever
// order the enumerator yielded them.
func DefaultRoute() (ifIndex int, ifName string, err error) {
	return 0, "", nil
}
