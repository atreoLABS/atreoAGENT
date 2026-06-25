package relay

import (
	"encoding/binary"
	"errors"
)

// Wire framing for the agent↔relay data association. MUST stay byte-identical
// to the relay's framing:
//
//	BIND:      0x01 || sessionToken(32)
//	DATA:      0x02 || tunnelID(8, big-endian) || opaque-WireGuard-bytes
//	KEEPALIVE: 0x03
//	CLOSE:     0x04 || tunnelID(8, big-endian)
const (
	frameBind      byte = 0x01
	frameData      byte = 0x02
	frameKeepalive byte = 0x03
	frameClose     byte = 0x04

	sessionTokenLen = 32
	tunnelIDLen     = 8
	dataHeaderLen   = 1 + tunnelIDLen
)

var errShortFrame = errors.New("relay: short frame")

func encodeBind(token []byte) []byte {
	b := make([]byte, 1+sessionTokenLen)
	b[0] = frameBind
	copy(b[1:], token)
	return b
}

func encodeKeepalive() []byte { return []byte{frameKeepalive} }

// encodeData writes a DATA frame into dst (reused to avoid per-packet allocs).
func encodeData(dst []byte, tunnelID uint64, payload []byte) []byte {
	if cap(dst) < dataHeaderLen+len(payload) {
		dst = make([]byte, dataHeaderLen+len(payload))
	}
	dst = dst[:dataHeaderLen+len(payload)]
	dst[0] = frameData
	binary.BigEndian.PutUint64(dst[1:], tunnelID)
	copy(dst[dataHeaderLen:], payload)
	return dst
}

type parsedFrame struct {
	typ      byte
	tunnelID uint64
	payload  []byte // aliases the read buffer
}

func parseFrame(buf []byte) (parsedFrame, error) {
	if len(buf) < 1 {
		return parsedFrame{}, errShortFrame
	}
	switch buf[0] {
	case frameData:
		if len(buf) < dataHeaderLen {
			return parsedFrame{}, errShortFrame
		}
		return parsedFrame{typ: frameData, tunnelID: binary.BigEndian.Uint64(buf[1:]), payload: buf[dataHeaderLen:]}, nil
	case frameClose:
		if len(buf) < 1+tunnelIDLen {
			return parsedFrame{}, errShortFrame
		}
		return parsedFrame{typ: frameClose, tunnelID: binary.BigEndian.Uint64(buf[1:])}, nil
	case frameKeepalive:
		return parsedFrame{typ: frameKeepalive}, nil
	default:
		return parsedFrame{}, errors.New("relay: unexpected frame type")
	}
}
