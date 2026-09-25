package scan

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
)

func basic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func scanRequest(url, authorization string) harbor.ScanRequest {
	return harbor.ScanRequest{Registry: harbor.Registry{URL: url, Authorization: authorization}}
}

func TestRegistryAuth(t *testing.T) {
	registry := etc.Registry{Username: "robot$scanner", Password: "account-secret", TrustedHosts: etc.HostList{"harbor.corp.local"}}
	c := &controller{registry: registry}
	account := grype.BasicAuth{Username: "robot$scanner", Password: "account-secret"}

	tests := []struct {
		name string
		req  harbor.ScanRequest
		want grype.RegistryAuth
	}{
		{"Basic from Harbor is used as is", scanRequest("https://harbor.corp.local", basic("robot$harbor+scan", "p:a:ss")),
			grype.BasicAuth{Username: "robot$harbor+scan", Password: "p:a:ss"}},
		{"Bearer for a trusted host gets the account", scanRequest("https://harbor.corp.local", "Bearer harbor-token"), account},
		{"no credentials for a trusted host gets the account", scanRequest("https://HARBOR.corp.local", ""), account},
		{"Bearer for another host stays a token", scanRequest("https://evil.example.com", "Bearer harbor-token"),
			grype.BearerAuth{Token: "harbor-token"}},
		{"no credentials for another host stays anonymous", scanRequest("https://evil.example.com", ""), grype.NoAuth{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.registryAuth(tt.req)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRegistryAuthWithoutAccount(t *testing.T) {
	c := &controller{registry: etc.Registry{TrustedHosts: etc.HostList{"harbor.corp.local"}}}
	got, err := c.registryAuth(scanRequest("https://harbor.corp.local", ""))
	require.NoError(t, err)
	assert.Equal(t, grype.NoAuth{}, got)
}

func TestRegistryAuthRejectsUnknownScheme(t *testing.T) {
	c := &controller{}
	_, err := c.registryAuth(scanRequest("https://harbor.corp.local", "Digest abc"))
	assert.ErrorContains(t, err, "unrecognized authorization type")
}

func TestRegistryAuthDoesNotLogSecrets(t *testing.T) {
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)

	c := &controller{registry: etc.Registry{Username: "robot$scanner", Password: "account-secret", TrustedHosts: etc.HostList{"harbor.corp.local"}}}
	_, _ = c.registryAuth(scanRequest("https://harbor.corp.local", basic("robot$harbor+scan", "harbor-secret")))
	_, _ = c.registryAuth(scanRequest("https://harbor.corp.local", "Bearer harbor-token"))
	_, _ = c.registryAuth(scanRequest("https://other.example.com", "Bearer harbor-token"))

	for _, secret := range []string{"harbor-secret", "account-secret", "harbor-token", basic("robot$harbor+scan", "harbor-secret")} {
		assert.NotContains(t, buf.String(), secret)
	}
}

// TestScanRequestLogDoesNotContainAuthorization proves that the "Received scan request from
// Harbor" log line, previously logged with the raw Authorization header under "registry_auth",
// carries neither the header nor any credential.
func TestScanRequestLogDoesNotContainAuthorization(t *testing.T) {
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(previous)

	req := harbor.ScanRequest{
		Registry: harbor.Registry{URL: "https://harbor.corp.local", Authorization: basic("robot$harbor+scan", "harbor-secret")},
		Artifact: harbor.Artifact{Repository: "library/nginx", Digest: "sha256:abc"},
	}
	logScanRequest(&req)

	line := buf.String()
	assert.Contains(t, line, "Received scan request from Harbor")
	assert.NotContains(t, line, "harbor-secret")
	assert.NotContains(t, line, "Authorization")
	assert.NotContains(t, line, basic("robot$harbor+scan", "harbor-secret"))
}
