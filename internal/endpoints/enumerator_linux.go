//go:build linux

package endpoints

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Linux-specific IFA_F_* values from the kernel netlink headers.
func init() {
	ifaFlagTemporary = unix.IFA_F_TEMPORARY
	ifaFlagDeprecated = unix.IFA_F_DEPRECATED
	ifaFlagPermanent = unix.IFA_F_PERMANENT
}

// Interfaces returns the system's interface list with V6Flags populated from
// netlink. V6Flags carries the per-address IFA_F_* bitmask (notably
// IFA_F_TEMPORARY and IFA_F_DEPRECATED) — data that stdlib `net` does not
// expose but that the enumerator needs to decide which v6 addresses are
// stable enough to advertise.
//
// Errors reading netlink (e.g. unusual kernels, seccomp) degrade to an empty
// V6Flags map rather than failing the whole enumeration — the enumerator
// then falls back to including every global-scope v6 address, which is
// slightly less precise but still correct.
func (realSource) Interfaces() ([]Interface, error) {
	sysIfs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	flagsByIfIdx := readIfaddrFlags()

	out := make([]Interface, 0, len(sysIfs))
	for _, si := range sysIfs {
		addrs, err := si.Addrs()
		if err != nil {
			// Per-interface errors aren't fatal; surface them by skipping.
			continue
		}
		ips := make([]net.IPNet, 0, len(addrs))
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP != nil {
				ips = append(ips, *n)
			}
		}
		out = append(out, Interface{
			Name:    si.Name,
			Index:   si.Index,
			Flags:   si.Flags,
			Addrs:   ips,
			V6Flags: flagsByIfIdx[si.Index],
		})
	}
	return out, nil
}

// readIfaddrFlags issues RTM_GETADDR over netlink and returns a nested map
// (ifIndex → ipString → flags). On any failure it returns an empty map — the
// enumerator treats absent flag data as "no info, keep the address".
func readIfaddrFlags() map[int]map[string]uint32 {
	out := map[int]map[string]uint32{}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return out
	}
	defer func() { _ = unix.Close(fd) }()

	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return out
	}

	req := make([]byte, unix.NLMSG_HDRLEN+unix.SizeofIfAddrmsg)
	nlh := (*unix.NlMsghdr)(unsafe.Pointer(&req[0]))
	nlh.Len = uint32(len(req))
	nlh.Type = unix.RTM_GETADDR
	nlh.Flags = unix.NLM_F_REQUEST | unix.NLM_F_DUMP
	nlh.Seq = 1
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return out
	}

	buf := make([]byte, 65536)
loop:
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return out
		}
		msgs, err := parseNetlinkMessages(buf[:n])
		if err != nil {
			return out
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				break loop
			case unix.NLMSG_ERROR:
				return out
			case unix.RTM_NEWADDR:
				if ifIdx, ip, flags, ok := parseIfaddr(m.Data); ok {
					byIP := out[ifIdx]
					if byIP == nil {
						byIP = map[string]uint32{}
						out[ifIdx] = byIP
					}
					byIP[ip.String()] = flags
				}
			}
		}
	}
	return out
}

type nlmsg struct {
	Header unix.NlMsghdr
	Data   []byte
}

func parseNetlinkMessages(buf []byte) ([]nlmsg, error) {
	var out []nlmsg
	for len(buf) >= unix.NLMSG_HDRLEN {
		h := *(*unix.NlMsghdr)(unsafe.Pointer(&buf[0]))
		if int(h.Len) < unix.NLMSG_HDRLEN || int(h.Len) > len(buf) {
			return nil, fmt.Errorf("malformed netlink header (len=%d, buflen=%d)", h.Len, len(buf))
		}
		data := buf[unix.NLMSG_HDRLEN:h.Len]
		out = append(out, nlmsg{Header: h, Data: data})
		aligned := (int(h.Len) + 3) &^ 3
		if aligned > len(buf) {
			break
		}
		buf = buf[aligned:]
	}
	return out, nil
}

// parseIfaddr extracts (ifIndex, ip, flags) from an RTM_NEWADDR payload.
// Returns ok=false on unrecognisable payloads — caller treats as "no data".
func parseIfaddr(data []byte) (ifIdx int, ip net.IP, flags uint32, ok bool) {
	if len(data) < unix.SizeofIfAddrmsg {
		return 0, nil, 0, false
	}
	msg := (*unix.IfAddrmsg)(unsafe.Pointer(&data[0]))
	ifIdx = int(msg.Index)
	flags = uint32(msg.Flags) // baseline; may be replaced by IFA_FLAGS attr below

	attrs := data[unix.SizeofIfAddrmsg:]
	for len(attrs) >= unix.SizeofRtAttr {
		rta := *(*unix.RtAttr)(unsafe.Pointer(&attrs[0]))
		if int(rta.Len) < unix.SizeofRtAttr || int(rta.Len) > len(attrs) {
			break
		}
		val := attrs[unix.SizeofRtAttr:rta.Len]
		switch rta.Type {
		case unix.IFA_ADDRESS:
			if len(val) == net.IPv4len || len(val) == net.IPv6len {
				ip = append(net.IP(nil), val...)
			}
		case unix.IFA_FLAGS:
			if len(val) >= 4 {
				flags = binary.LittleEndian.Uint32(val)
			}
		}
		aligned := (int(rta.Len) + 3) &^ 3
		if aligned > len(attrs) {
			break
		}
		attrs = attrs[aligned:]
	}
	if ip == nil {
		return 0, nil, 0, false
	}
	return ifIdx, ip, flags, true
}

// DefaultRoute returns the interface index and name that carries the default
// IPv4 route, parsed from /proc/net/route. Returns (0, "", nil) if no default
// route exists; returns an error only if /proc/net/route is itself unreadable.
//
// Parsing /proc/net/route avoids pulling in an external netlink library for a
// single lookup. The /proc format is a kernel-stable ABI.
func DefaultRoute() (ifIndex int, ifName string, err error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return 0, "", nil // empty file — no default route
	}
	// Columns: Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		// Destination == "00000000" && Mask == "00000000" → default route.
		if fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		name := fields[0]
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return 0, name, nil
		}
		return iface.Index, name, nil
	}
	return 0, "", scanner.Err()
}
