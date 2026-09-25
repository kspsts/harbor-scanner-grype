package etc

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTextLogs(t *testing.T) {
	t.Setenv("SCANNER_LOG_FORMAT", "text")
	var buf bytes.Buffer
	slog.New(NewLogHandler(&buf)).Info("Scan finished", slog.Int("vulnerabilities", 3))
	line := buf.String()
	assert.True(t, strings.HasPrefix(line, "time="), line)
	assert.Contains(t, line, `level=INFO msg="Scan finished" vulnerabilities=3`)
}

func TestJSONLogs(t *testing.T) {
	t.Setenv("SCANNER_LOG_FORMAT", "json")
	var buf bytes.Buffer
	slog.New(NewLogHandler(&buf)).Info("Scan finished", slog.Int("vulnerabilities", 3))
	var entry map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))
	assert.Equal(t, "Scan finished", entry["msg"])
	assert.Equal(t, float64(3), entry["vulnerabilities"])
}

func TestLogLevelFiltersDebug(t *testing.T) {
	t.Setenv("SCANNER_LOG_LEVEL", "info")
	var buf bytes.Buffer
	slog.New(NewLogHandler(&buf)).Debug("noise")
	assert.Empty(t, buf.String())
}
