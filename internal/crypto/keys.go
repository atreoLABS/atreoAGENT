package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"crypto/sha256"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/nacl/box"

	"github.com/atreoLABS/atreoAGENT/internal/atomic"
	"github.com/atreoLABS/atreoAGENT/internal/canonjson"
)

type KeyManager struct {
	keysDir    string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// Loads from keysDir, or generates a new keypair if absent.
func NewKeyManager(keysDir string) (*KeyManager, error) {
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, fmt.Errorf("create keys dir: %w", err)
	}

	privPath := filepath.Join(keysDir, "ed25519.key")
	pubPath := filepath.Join(keysDir, "ed25519.pub")

	km := &KeyManager{keysDir: keysDir}

	privData, err := os.ReadFile(privPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read private key: %w", err)
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate keypair: %w", err)
		}
		km.privateKey = priv
		km.publicKey = pub

		if err := atomic.WriteFile(privPath, []byte(base64.StdEncoding.EncodeToString(priv)), 0600); err != nil {
			return nil, fmt.Errorf("write private key: %w", err)
		}
		if err := os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(pub)), 0600); err != nil {
			return nil, fmt.Errorf("write public key: %w", err)
		}
		return km, nil
	}

	priv, err := base64.StdEncoding.DecodeString(string(privData))
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	km.privateKey = ed25519.PrivateKey(priv)
	km.publicKey = km.privateKey.Public().(ed25519.PublicKey)

	return km, nil
}

func (km *KeyManager) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(km.publicKey)
}

// Treat as read-only.
func (km *KeyManager) PublicKey() ed25519.PublicKey {
	return km.publicKey
}

// Treat as read-only.
func (km *KeyManager) PrivateKey() ed25519.PrivateKey {
	return km.privateKey
}

// Sign returns a base64 signature over message.
func (km *KeyManager) Sign(message []byte) string {
	sig := ed25519.Sign(km.privateKey, message)
	return base64.StdEncoding.EncodeToString(sig)
}

func Verify(pubKeyBase64 string, message []byte, sigBase64 string) (bool, error) {
	pubKey, err := base64.StdEncoding.DecodeString(pubKeyBase64)
	if err != nil {
		return false, fmt.Errorf("decode public key: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigBase64)
	if err != nil {
		return false, fmt.Errorf("decode signature: %w", err)
	}
	return ed25519.Verify(ed25519.PublicKey(pubKey), message, sig), nil
}

// Same shape as atreoLINK → agent envelope used by tunnel commands.
type AuthEnvelope struct {
	SignerID  string          `json:"signerId"`
	Signature string          `json:"signature"`
	Payload   json.RawMessage `json:"payload"`
}

// Body cannot carry these — SignAgentAuth fills them and rejects collisions.
var reservedAuthPayloadKeys = map[string]struct{}{
	"deviceId": {},
	"intent":   {},
	"ts":       {},
}

// Intent is built as "<intentPrefix>-<deviceID>-<unixSeconds>"; atreoLINK
// rebuilds it from the URL it routes and the device it looked up.
func (km *KeyManager) SignAgentAuth(deviceID, intentPrefix string, body any) (AuthEnvelope, error) {
	ts := time.Now().Unix()
	intent := fmt.Sprintf("%s-%s-%d", intentPrefix, deviceID, ts)

	payload := map[string]any{
		"deviceId": deviceID,
		"intent":   intent,
		"ts":       ts,
	}

	if body != nil {
		bodyJSON, err := json.Marshal(body)
		if err != nil {
			return AuthEnvelope{}, fmt.Errorf("marshal body: %w", err)
		}
		if !bytes.Equal(bytes.TrimSpace(bodyJSON), []byte("null")) {
			dec := json.NewDecoder(bytes.NewReader(bodyJSON))
			dec.UseNumber()
			var bodyMap map[string]any
			if err := dec.Decode(&bodyMap); err != nil {
				return AuthEnvelope{}, fmt.Errorf("decode body to map: %w", err)
			}
			for k, v := range bodyMap {
				if _, reserved := reservedAuthPayloadKeys[k]; reserved {
					return AuthEnvelope{}, fmt.Errorf("SignAgentAuth: body cannot use reserved key %q", k)
				}
				payload[k] = v
			}
		}
	}

	canon, err := canonjson.Marshal(payload)
	if err != nil {
		return AuthEnvelope{}, fmt.Errorf("canonjson marshal payload: %w", err)
	}
	return AuthEnvelope{
		SignerID:  deviceID,
		Signature: km.Sign(canon),
		Payload:   json.RawMessage(canon),
	}, nil
}

// Intent: "tunnel:connect-<deviceID>-<ts>". Signature is base64-std;
// callers must URL-encode it for the query string.
func (km *KeyManager) SignWSConnectAuth(deviceID string) (intent string, ts int64, signature string, err error) {
	ts = time.Now().Unix()
	intent = fmt.Sprintf("tunnel:connect-%s-%d", deviceID, ts)

	canon, err := canonjson.Marshal(map[string]any{
		"deviceId": deviceID,
		"intent":   intent,
		"ts":       ts,
	})
	if err != nil {
		return "", 0, "", fmt.Errorf("canonjson marshal: %w", err)
	}
	return intent, ts, km.Sign(canon), nil
}

func GenerateNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func RandRead(b []byte) (int, error) {
	return rand.Read(b)
}

// Binds every wg-quick field so any change between agent-sign and
// client-build fails verification.
type ProvisionTranscriptInput struct {
	NonceHex            string
	ClientPubKeyB64     string
	DeviceID            string
	ServerPubKeyB64     string
	TunnelIP            string
	TunnelIPv6          string
	Endpoint            string
	AllowedIPs          string
	PersistentKeepalive int
}

//	sha256("atreos-wg-server-v2" || nonce_bytes || clientPubKey_bytes
//	       || deviceId || serverPubKey_bytes || tunnelIP || tunnelIPv6
//	       || endpoint || allowedIPs || persistentKeepalive)
//
// Strings appended as UTF-8; persistentKeepalive as decimal. tunnelIPv6 is the
// peer's IPv6 overlay address (empty string when the overlay is v4-only).
func serverTranscriptV2(in ProvisionTranscriptInput) ([]byte, error) {
	nonceBytes, err := hex.DecodeString(in.NonceHex)
	if err != nil {
		return nil, fmt.Errorf("decode nonce hex: %w", err)
	}
	clientPubKey, err := base64.StdEncoding.DecodeString(in.ClientPubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode client pubkey: %w", err)
	}
	serverPubKey, err := base64.StdEncoding.DecodeString(in.ServerPubKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode server pubkey: %w", err)
	}
	h := sha256.New()
	h.Write([]byte("atreos-wg-server-v2"))
	h.Write(nonceBytes)
	h.Write(clientPubKey)
	h.Write([]byte(in.DeviceID))
	h.Write(serverPubKey)
	h.Write([]byte(in.TunnelIP))
	h.Write([]byte(in.TunnelIPv6))
	h.Write([]byte(in.Endpoint))
	h.Write([]byte(in.AllowedIPs))
	h.Write([]byte(strconv.Itoa(in.PersistentKeepalive)))
	return h.Sum(nil), nil
}

// The client verifies against the agent's pinned Ed25519 identity pubkey.
func (km *KeyManager) SignProvisionResponse(in ProvisionTranscriptInput) (string, error) {
	transcript, err := serverTranscriptV2(in)
	if err != nil {
		return "", err
	}
	return km.Sign(transcript), nil
}

// libsodium sealed-box (anonymous sender). The agent only ever holds
// the recipient's pubkey, so compromising the agent does not expose
// past notifications.
func SealToUser(identityEdPubB64 string, plaintext []byte) (ciphertextB64 string, err error) {
	edPub, err := base64.StdEncoding.DecodeString(identityEdPubB64)
	if err != nil {
		return "", fmt.Errorf("decode identity pubkey: %w", err)
	}
	if len(edPub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("identity pubkey must be 32 bytes, got %d", len(edPub))
	}

	// Standard libsodium crypto_sign_ed25519_pk_to_curve25519 mapping.
	point, err := new(edwards25519.Point).SetBytes(edPub)
	if err != nil {
		return "", fmt.Errorf("parse ed25519 pubkey: %w", err)
	}
	var xPub [32]byte
	copy(xPub[:], point.BytesMontgomery())

	sealed, err := box.SealAnonymous(nil, plaintext, &xPub, rand.Reader)
	if err != nil {
		return "", fmt.Errorf("sealed-box seal: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}
