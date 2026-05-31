// Package logging wraps log/slog with printf-style helpers.
package logging

import (
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
)

var levelVar slog.LevelVar

// Bind a handler at package init so calls made before Init() are still
// filtered (e.g. config.Load failures).
func init() {
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: &levelVar})
	slog.SetDefault(slog.New(h))
}

// Init sets the global log level. Empty string is treated as "info".
func Init(level string) error {
	l, err := ParseLevel(level)
	if err != nil {
		return err
	}
	levelVar.Set(l)
	return nil
}

// ParseLevel accepts debug|info|warn|warning|error (case-insensitive).
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q (want debug|info|warn|error)", s)
}

func Debug(format string, args ...any) { slog.Debug(fmt.Sprintf(format, args...)) }
func Info(format string, args ...any)  { slog.Info(fmt.Sprintf(format, args...)) }
func Warn(format string, args ...any)  { slog.Warn(fmt.Sprintf(format, args...)) }
func Error(format string, args ...any) { slog.Error(fmt.Sprintf(format, args...)) }

// Fatalf logs at error level then exits with status 1.
func Fatalf(format string, args ...any) {
	slog.Error(fmt.Sprintf(format, args...))
	os.Exit(1)
}

// StdLoggerAt returns a *log.Logger whose writes flow through slog at
// the given level. Use for net/http.Server.ErrorLog so TLS handshake /
// HTTP/2 preface chatter can be filtered out of info-level output.
func StdLoggerAt(level slog.Level) *log.Logger {
	return slog.NewLogLogger(slog.Default().Handler(), level)
}
