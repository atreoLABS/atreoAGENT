package notify

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/atreoLABS/atreoAGENT/internal/atomic"
)

// LoadOrGenerateAPIKey loads the API key from dataDir/notify_api_key,
// or generates a new 32-byte key if none exists.
func LoadOrGenerateAPIKey(dataDir string) (string, error) {
	path := filepath.Join(dataDir, "notify_api_key")
	data, err := os.ReadFile(path)
	if err == nil {
		key := strings.TrimSpace(string(data))
		if len(key) == 64 {
			return key, nil
		}
	}
	return GenerateAPIKey(dataDir)
}

// GenerateAPIKey creates a new 32-byte random API key and persists it.
func GenerateAPIKey(dataDir string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate api key: %w", err)
	}
	key := hex.EncodeToString(b)

	path := filepath.Join(dataDir, "notify_api_key")
	if err := atomic.WriteFile(path, []byte(key), 0600); err != nil {
		return "", fmt.Errorf("write api key: %w", err)
	}
	return key, nil
}
