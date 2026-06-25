package relay

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// These assertions pin the wire format so it stays byte-identical to the relay.

func TestEncodeBind(t *testing.T) {
	token := bytes.Repeat([]byte{0x5a}, sessionTokenLen)
	b := encodeBind(token)
	if len(b) != 1+sessionTokenLen || b[0] != frameBind || !bytes.Equal(b[1:], token) {
		t.Fatalf("bind frame wrong: %v", b)
	}
}

func TestEncodeKeepalive(t *testing.T) {
	if b := encodeKeepalive(); len(b) != 1 || b[0] != frameKeepalive {
		t.Fatalf("keepalive frame wrong: %v", b)
	}
}

func TestEncodeDataLayout(t *testing.T) {
	payload := []byte("ciphertext")
	b := encodeData(nil, 0x1122334455667788, payload)
	if b[0] != frameData {
		t.Fatalf("type byte = %x", b[0])
	}
	if binary.BigEndian.Uint64(b[1:9]) != 0x1122334455667788 {
		t.Fatalf("tunnelID encoding wrong")
	}
	if !bytes.Equal(b[9:], payload) {
		t.Fatalf("payload misplaced")
	}
}

func TestParseDataAndClose(t *testing.T) {
	data := encodeData(nil, 7, []byte("xyz"))
	fr, err := parseFrame(data)
	if err != nil || fr.typ != frameData || fr.tunnelID != 7 || string(fr.payload) != "xyz" {
		t.Fatalf("parse data: %+v err=%v", fr, err)
	}

	closeFrame := []byte{frameClose, 0, 0, 0, 0, 0, 0, 0, 9}
	fr, err = parseFrame(closeFrame)
	if err != nil || fr.typ != frameClose || fr.tunnelID != 9 {
		t.Fatalf("parse close: %+v err=%v", fr, err)
	}
}

func TestParseRejectsBadFrames(t *testing.T) {
	for _, c := range [][]byte{{}, {frameData, 0x00}, {frameClose, 0x00}, {0x09}} {
		if _, err := parseFrame(c); err == nil {
			t.Errorf("expected error for %v", c)
		}
	}
}
