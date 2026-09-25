package etc

import (
	"io"
	"log/slog"
)

// NewLogHandler returns the log handler for SCANNER_LOG_FORMAT and SCANNER_LOG_LEVEL: readable
// key=value lines with a timestamp, or one JSON object per line for log collectors.
func NewLogHandler(w io.Writer) slog.Handler {
	opts := &slog.HandlerOptions{Level: LogLevel()}
	if LogFormat() == "json" {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}
