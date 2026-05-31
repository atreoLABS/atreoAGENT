// Package atomic provides crash-safe file writes (temp + rename).
// Unrelated to sync/atomic.
package atomic

import (
	"fmt"
	"os"
)

// Parent directory must already exist.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("atomic rename %s: %w", path, err)
	}
	return nil
}
