// Package canonjson produces a deterministic JSON encoding for crypto
// signing. Restricted subset of RFC 8785:
//
//  1. Object keys sorted by UTF-8 codepoint.
//  2. No insignificant whitespace.
//  3. Strings emit only JSON-required escapes.
//  4. Numbers use encoding/json default formatting.
//  5. `null` is forbidden — Marshal rejects it.
//  6. Arrays preserve input order.
//
// Goal: byte-for-byte agreement with every other implementation of this
// canonicaliser on the wire.
package canonjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

var ErrNullForbidden = errors.New("canonjson: null is forbidden in signed payloads")

// Round-trips through encoding/json so struct json tags are honoured.
func Marshal(v any) ([]byte, error) {
	first, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonjson: pre-marshal: %w", err)
	}
	return MarshalRaw(first)
}

// Canonicalises an existing JSON document.
func MarshalRaw(jsonBytes []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(jsonBytes))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, fmt.Errorf("canonjson: decode: %w", err)
	}
	if dec.More() {
		return nil, errors.New("canonjson: trailing data after top-level value")
	}
	var out bytes.Buffer
	if err := writeValue(&out, tree); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func writeValue(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		return ErrNullForbidden
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil
	case string:
		return writeString(buf, x)
	case json.Number:
		buf.WriteString(x.String())
		return nil
	case float64:
		// json.Number normally wins; this is for hand-built trees.
		b, err := json.Marshal(x)
		if err != nil {
			return err
		}
		buf.Write(b)
		return nil
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeValue(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		// Bytewise sort == UTF-8 codepoint order on well-formed UTF-8,
		// the order RFC 8785 mandates. Do not swap for Unicode sort.
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeValue(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	default:
		return fmt.Errorf("canonjson: unsupported type %T", v)
	}
}

// HTML escaping must be off — RFC 8785 forbids it; otherwise <, >, &
// emit as \u003c etc and diverge from other signers on the wire.
func writeString(buf *bytes.Buffer, s string) error {
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return err
	}
	// Encoder appends a trailing newline.
	out := tmp.Bytes()
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	buf.Write(out)
	return nil
}
