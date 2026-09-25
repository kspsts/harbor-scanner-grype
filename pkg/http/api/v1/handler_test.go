package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/job"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/persistence"
)

type fakeWrapper struct{ grype.Wrapper }

func (fakeWrapper) GetVersion() (grype.VersionInfo, error) {
	return grype.VersionInfo{Version: "0.117.0"}, nil
}

func (fakeWrapper) DBStatus() (grype.DBStatus, error) {
	return grype.DBStatus{Built: time.Date(2026, 9, 22, 6, 30, 41, 0, time.UTC), Valid: true}, nil
}

// fakeExploitDBInfo stands in for *exploitdb.Watcher: ok mirrors whether a list has been loaded.
type fakeExploitDBInfo struct {
	updated time.Time
	cves    int
	ok      bool
}

func (f fakeExploitDBInfo) Info() (time.Time, int, bool) { return f.updated, f.cves, f.ok }

func newTestHandler() http.Handler {
	return NewAPIHandler(etc.BuildInfo{}, etc.Config{API: etc.API{Key: "adapter-key"}}, nil, nil, fakeWrapper{}, nil)
}

func call(h http.Handler, method, path string, headers map[string]string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// metadataProperties calls /api/v1/metadata with a valid key and decodes the response properties.
func metadataProperties(t *testing.T, h http.Handler) map[string]string {
	t.Helper()
	rec := call(h, http.MethodGet, "/api/v1/metadata", map[string]string{"Authorization": "Bearer adapter-key"}, "")
	require.Equal(t, http.StatusOK, rec.Code)
	var metadata struct {
		Properties map[string]string `json:"properties"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &metadata))
	return metadata.Properties
}

func TestAPIRequiresKey(t *testing.T) {
	h := newTestHandler()
	assert.Equal(t, http.StatusUnauthorized, call(h, http.MethodGet, "/api/v1/metadata", nil, "").Code)
	assert.Equal(t, http.StatusUnauthorized, call(h, http.MethodGet, "/api/v1/metadata",
		map[string]string{"Authorization": "Bearer wrong"}, "").Code)
	assert.Equal(t, http.StatusUnauthorized, call(h, http.MethodPost, "/api/v1/scan", nil, "{}").Code)
}

func TestAPIAcceptsBearerAndAPIKeyHeader(t *testing.T) {
	h := newTestHandler()
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/metadata",
		map[string]string{"Authorization": "Bearer adapter-key"}, "").Code)
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/metadata",
		map[string]string{"X-ScannerAdapter-API-Key": "adapter-key"}, "").Code)
	// with the key the request reaches the handler, which rejects the broken body
	assert.Equal(t, http.StatusBadRequest, call(h, http.MethodPost, "/api/v1/scan",
		map[string]string{"Authorization": "Bearer adapter-key"}, "not json").Code)
}

// The key is trimmed on both paths: Harbor's own UI has been seen to leave stray whitespace around
// a pasted key, and a Bearer value always carries the space that separates it from "Bearer".
func TestAPIKeyIsTrimmed(t *testing.T) {
	h := newTestHandler()
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/metadata",
		map[string]string{"X-ScannerAdapter-API-Key": "  adapter-key  "}, "").Code)
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/api/v1/metadata",
		map[string]string{"Authorization": "Bearer   adapter-key  "}, "").Code)
}

func TestProbesNeedNoKey(t *testing.T) {
	h := newTestHandler()
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/probe/healthy", nil, "").Code)
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/probe/ready", nil, "").Code)
}

func TestMetricsNeedsNoKey(t *testing.T) {
	config := etc.Config{API: etc.API{Key: "adapter-key", MetricsEnabled: true}}
	h := NewAPIHandler(etc.BuildInfo{}, config, nil, nil, fakeWrapper{}, nil)
	assert.Equal(t, http.StatusOK, call(h, http.MethodGet, "/metrics", nil, "").Code)
}

func TestMetadataReportsDatabaseDate(t *testing.T) {
	props := metadataProperties(t, newTestHandler())
	assert.Equal(t, "2026-09-22T06:30:41Z", props["harbor.scanner-adapter/vulnerability-database-updated-at"])
}

// SCANNER_GRYPE_INSECURE no longer affects anything (see pkg/grype.wrapper.registryEnv), so it must
// not be reported either; the real registry TLS/HTTP flags take its place.
func TestMetadataDropsInsecureAndReportsRealRegistryFlags(t *testing.T) {
	config := etc.Config{
		API:      etc.API{Key: "adapter-key"},
		Registry: etc.Registry{InsecureUseHTTP: false, InsecureSkipTLSVerify: true},
	}
	props := metadataProperties(t, NewAPIHandler(etc.BuildInfo{}, config, nil, nil, fakeWrapper{}, nil))

	assert.NotContains(t, props, "env.SCANNER_GRYPE_INSECURE")
	assert.Equal(t, "false", props["env.SCANNER_REGISTRY_INSECURE_USE_HTTP"])
	assert.Equal(t, "true", props["env.SCANNER_REGISTRY_INSECURE_SKIP_TLS_VERIFY"])
}

func TestMetadataReportsRiskModeAndPolicyThresholdsOnlyInPolicyMode(t *testing.T) {
	formula := etc.Config{
		API:  etc.API{Key: "adapter-key"},
		Risk: etc.RiskConfig{Risk: etc.RiskConfigData{Enabled: true, Mode: "formula"}},
	}
	props := metadataProperties(t, NewAPIHandler(etc.BuildInfo{}, formula, nil, nil, fakeWrapper{}, nil))
	assert.Equal(t, "true", props["env.SCANNER_RISK_ENABLED"])
	assert.Equal(t, "formula", props["env.SCANNER_RISK_MODE"])
	assert.NotContains(t, props, "env.SCANNER_POLICY_CRITICAL")

	policyMode := etc.Config{
		API:    etc.API{Key: "adapter-key"},
		Risk:   etc.RiskConfig{Risk: etc.RiskConfigData{Enabled: true, Mode: "policy"}},
		Policy: etc.Policy{Critical: 70, High: 30, Medium: 10},
	}
	props = metadataProperties(t, NewAPIHandler(etc.BuildInfo{}, policyMode, nil, nil, fakeWrapper{}, nil))
	assert.Equal(t, "policy", props["env.SCANNER_RISK_MODE"])
	assert.Equal(t, "70", props["env.SCANNER_POLICY_CRITICAL"])
	assert.Equal(t, "30", props["env.SCANNER_POLICY_HIGH"])
	assert.Equal(t, "10", props["env.SCANNER_POLICY_MEDIUM"])
}

func TestMetadataOmitsExploitDBPropertiesUntilAListIsLoaded(t *testing.T) {
	config := etc.Config{API: etc.API{Key: "adapter-key"}}

	props := metadataProperties(t, NewAPIHandler(etc.BuildInfo{}, config, nil, nil, fakeWrapper{}, nil))
	assert.NotContains(t, props, "harbor.scanner-adapter/exploitdb-updated-at")
	assert.NotContains(t, props, "harbor.scanner-adapter/exploitdb-cve-count")

	notYetLoaded := fakeExploitDBInfo{ok: false}
	props = metadataProperties(t, NewAPIHandler(etc.BuildInfo{}, config, nil, nil, fakeWrapper{}, notYetLoaded))
	assert.NotContains(t, props, "harbor.scanner-adapter/exploitdb-updated-at")
	assert.NotContains(t, props, "harbor.scanner-adapter/exploitdb-cve-count")
}

func TestMetadataReportsExploitDBInfoWhenAListIsLoaded(t *testing.T) {
	exploits := fakeExploitDBInfo{updated: time.Date(2026, 9, 24, 3, 0, 0, 0, time.UTC), cves: 45231, ok: true}
	config := etc.Config{API: etc.API{Key: "adapter-key"}}
	props := metadataProperties(t, NewAPIHandler(etc.BuildInfo{}, config, nil, nil, fakeWrapper{}, exploits))

	assert.Equal(t, "2026-09-24T03:00:00Z", props["harbor.scanner-adapter/exploitdb-updated-at"])
	assert.Equal(t, "45231", props["harbor.scanner-adapter/exploitdb-cve-count"])
}

// fakeStore knows one queued job and records the awaited marks.
type fakeStore struct {
	persistence.Store
	marked []time.Duration
}

func (f *fakeStore) Get(_ context.Context, key job.ScanJobKey) (*job.ScanJob, error) {
	if key.ID != "job-1" {
		return nil, nil
	}
	return &job.ScanJob{Key: key, Status: job.Queued}, nil
}

func (f *fakeStore) MarkAwaited(_ context.Context, _ job.ScanJobKey, ttl time.Duration) error {
	f.marked = append(f.marked, ttl)
	return nil
}

func TestPollingForAQueuedReportKeepsItAwaited(t *testing.T) {
	store := &fakeStore{}
	config := etc.Config{API: etc.API{Key: "adapter-key"}, Harbor: etc.Harbor{PollTimeout: 2 * time.Minute}}
	h := NewAPIHandler(etc.BuildInfo{}, config, nil, store, fakeWrapper{}, nil)

	rec := call(h, http.MethodGet, "/api/v1/scan/job-1/report", map[string]string{
		"Authorization": "Bearer adapter-key",
		"Accept":        "application/vnd.security.vulnerability.report; version=1.1",
	}, "")

	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, []time.Duration{2 * time.Minute}, store.marked)
}
