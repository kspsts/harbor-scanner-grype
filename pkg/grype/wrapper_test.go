package grype

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/ext"
)

// fakeAmbassador runs testdata/fake-scanner.sh in place of grype and syft.
type fakeAmbassador struct {
	ext.Ambassador
	mode string
	log  string
}

func (f fakeAmbassador) LookPath(string) (string, error) {
	return filepath.Abs("testdata/fake-scanner.sh")
}

func (f fakeAmbassador) Environ() []string {
	return []string{"PATH=/usr/bin:/bin", "FAKE_MODE=" + f.mode, "FAKE_LOG=" + f.log}
}

func newTestWrapper(t *testing.T, mode string, registry etc.Registry) (*wrapper, string) {
	t.Helper()
	dir := t.TempDir()
	log := filepath.Join(dir, "call")
	w := &wrapper{
		config:     etc.Grype{Timeout: 3 * time.Second, TmpDir: filepath.Join(dir, "tmp"), Severity: "Unknown,Low,Medium,High,Critical"},
		registry:   registry,
		ambassador: fakeAmbassador{mode: mode, log: log},
	}
	return w, log
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

var harborRef = ImageRef{Name: "harbor.corp.local:443/library/nginx@sha256:abc", Auth: BasicAuth{Username: "robot$scan", Password: "s3cr3t"}}

func TestScanParsesReportAndPassesRegistrySettings(t *testing.T) {
	w, log := newTestWrapper(t, "report", etc.Registry{InsecureUseHTTP: false, InsecureSkipTLSVerify: true})

	report, err := w.Scan(harborRef, ScanOption{Format: FormatJSON})

	require.NoError(t, err)
	require.Len(t, report.Matches, 1)
	assert.Equal(t, "CVE-2024-0001", report.Matches[0].Vulnerability.ID)
	assert.Equal(t, 12.5, report.Matches[0].Vulnerability.Risk)

	args := readLines(t, log+".args")
	assert.Equal(t, []string{"harbor.corp.local:443/library/nginx@sha256:abc", "--output", "json", "--fail-on", "negligible"}, args)

	env := readLines(t, log+".env")
	assert.Contains(t, env, "GRYPE_REGISTRY_INSECURE_USE_HTTP=false")
	assert.Contains(t, env, "GRYPE_REGISTRY_INSECURE_SKIP_TLS_VERIFY=true")
	assert.Contains(t, env, "GRYPE_REGISTRY_AUTH_AUTHORITY=harbor.corp.local:443")
	assert.Contains(t, env, "GRYPE_REGISTRY_AUTH_USERNAME=robot$scan")
	assert.Contains(t, env, "GRYPE_REGISTRY_AUTH_PASSWORD=s3cr3t")
}

func TestScanAcceptsExitCode2WithReport(t *testing.T) {
	w, _ := newTestWrapper(t, "report-exit2", etc.Registry{})
	_, err := w.Scan(harborRef, ScanOption{Format: FormatJSON})
	assert.NoError(t, err, "--fail-on makes grype exit with 2 when it finds vulnerabilities")
}

func TestScanFailureCarriesStderr(t *testing.T) {
	w, _ := newTestWrapper(t, "fail", etc.Registry{})
	_, err := w.Scan(harborRef, ScanOption{Format: FormatJSON})
	assert.ErrorContains(t, err, "unauthorized: authentication required")
}

func TestScanTimesOut(t *testing.T) {
	w, _ := newTestWrapper(t, "sleep", etc.Registry{})
	w.config.Timeout = 200 * time.Millisecond
	started := time.Now()
	_, err := w.Scan(harborRef, ScanOption{Format: FormatJSON})
	assert.ErrorContains(t, err, "scan timed out after 200ms")
	assert.Less(t, time.Since(started), 3*time.Second)
}

func TestEachRunHasItsOwnTempDirRemovedAfterwards(t *testing.T) {
	w, _ := newTestWrapper(t, "tmpdir", etc.Registry{})
	sbom, err := w.ScanSBOM(harborRef, ScanOption{Format: FormatSPDX})
	require.NoError(t, err)

	tmp := sbom.(map[string]any)["tmp"].(string)
	assert.True(t, strings.HasPrefix(tmp, filepath.Join(w.config.TmpDir, "scan-")), tmp)
	_, statErr := os.Stat(tmp)
	assert.True(t, os.IsNotExist(statErr), "the temp dir is removed after the run")
}

func TestSBOMUsesSyftSettingsAndBearerToken(t *testing.T) {
	w, log := newTestWrapper(t, "tmpdir", etc.Registry{InsecureUseHTTP: false, InsecureSkipTLSVerify: false})
	ref := ImageRef{Name: "registry:8080/library/nginx@sha256:abc", Auth: BearerAuth{Token: "harbor-token"}, NonSSL: true}

	_, err := w.ScanSBOM(ref, ScanOption{Format: FormatCycloneDX})
	require.NoError(t, err)

	assert.Equal(t, []string{"registry:8080/library/nginx@sha256:abc", "--output", "cyclonedx"}, readLines(t, log+".args"))
	env := readLines(t, log+".env")
	assert.Contains(t, env, "SYFT_REGISTRY_INSECURE_USE_HTTP=true", "a plain-HTTP registry from Harbor's request needs HTTP")
	assert.Contains(t, env, "SYFT_REGISTRY_INSECURE_SKIP_TLS_VERIFY=false")
	assert.Contains(t, env, "SYFT_REGISTRY_AUTH_AUTHORITY=registry:8080")
	assert.Contains(t, env, "SYFT_REGISTRY_AUTH_TOKEN=harbor-token")
}

func TestDBStatusReadsInvalidDatabase(t *testing.T) {
	w, log := newTestWrapper(t, "dbstatus", etc.Registry{})
	status, err := w.DBStatus()
	require.NoError(t, err)
	assert.Equal(t, []string{"db", "status", "-o", "json"}, readLines(t, log+".args"))
	assert.Equal(t, "v6.1.9", status.SchemaVersion)
	assert.Equal(t, time.Date(2026, 9, 15, 6, 31, 36, 0, time.UTC), status.Built)
	assert.False(t, status.Valid)
	assert.Contains(t, status.Error, "max allowed age")
}

func TestRemoveStaleTempDirs(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "scan-123", "layers"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "keep-me"), 0o700))

	RemoveStaleTempDirs(dir)

	_, err := os.Stat(filepath.Join(dir, "scan-123"))
	assert.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(dir, "keep-me"))
	assert.NoError(t, err)
}
