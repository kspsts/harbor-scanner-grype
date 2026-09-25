package etc

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostMap(t *testing.T) {
	clearScannerEnv(t)
	t.Setenv("SCANNER_REGISTRY_HOST_MAP", "localhost=nginx:8080, Harbor.Corp.Local=harbor.corp.local:443")
	config, err := GetConfig()
	require.NoError(t, err)
	assert.Equal(t, HostMap{"localhost": "nginx:8080", "harbor.corp.local": "harbor.corp.local:443"}, config.Registry.HostMap)
}

func TestHostMapRejectsMalformedPairs(t *testing.T) {
	clearScannerEnv(t)
	t.Setenv("SCANNER_REGISTRY_HOST_MAP", "localhost")
	_, err := GetConfig()
	assert.ErrorContains(t, err, "SCANNER_REGISTRY_HOST_MAP")
}

func TestTrustedHosts(t *testing.T) {
	clearScannerEnv(t)
	t.Setenv("SCANNER_REGISTRY_TRUSTED_HOSTS", "harbor.corp.local, core")
	config, err := GetConfig()
	require.NoError(t, err)
	assert.True(t, config.Registry.Trusted("HARBOR.corp.local"))
	assert.True(t, config.Registry.Trusted("core"))
	assert.False(t, config.Registry.Trusted("evil.example.com"))
	assert.False(t, config.Registry.Trusted(""))
}

func TestTrustedHostsRejectsMalformedEntry(t *testing.T) {
	clearScannerEnv(t)
	t.Setenv("SCANNER_REGISTRY_TRUSTED_HOSTS", "not a host")
	_, err := GetConfig()
	assert.ErrorContains(t, err, "SCANNER_REGISTRY_TRUSTED_HOSTS")
}

func TestRegistryInsecureUseHTTPBlankErrors(t *testing.T) {
	clearScannerEnv(t)
	t.Setenv("SCANNER_REGISTRY_INSECURE_USE_HTTP", "")
	_, err := GetConfig()
	assert.ErrorContains(t, err, "SCANNER_REGISTRY_INSECURE_USE_HTTP")
}

// TestHostMapValidation is a compact table test of normalizeHost and validateTarget, exercised
// through HostMap.UnmarshalText: the HostMap key grammar, the target grammar (including a
// bracketed IPv6 target), duplicate detection after normalization, and that a credential embedded
// in a target is rejected without being echoed back.
func TestHostMapValidation(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    HostMap
		wantErr string
	}{
		{"lower-cases and trims one trailing dot", "Harbor.Corp.Local.=harbor.corp.local:443", HostMap{"harbor.corp.local": "harbor.corp.local:443"}, ""},
		{"bracketed IPv6 key stored without brackets", "[::1]=nginx:8080", HostMap{"::1": "nginx:8080"}, ""},
		{"bracketed IPv6 target kept as given", "registry=[::1]:5000", HostMap{"registry": "[::1]:5000"}, ""},
		{"target without a port is allowed", "core=registry", HostMap{"core": "registry"}, ""},
		{"rejects slash in key", "ho/st=target", nil, "SCANNER_REGISTRY_HOST_MAP"},
		{"rejects @ in key", "ho@st=target", nil, "SCANNER_REGISTRY_HOST_MAP"},
		{"rejects whitespace in key", "ho st=target", nil, "SCANNER_REGISTRY_HOST_MAP"},
		{"rejects a bare (unbracketed) colon in key", "::1=target", nil, "SCANNER_REGISTRY_HOST_MAP"},
		{"rejects a URL scheme in target", "host=https://target", nil, "SCANNER_REGISTRY_HOST_MAP"},
		{"rejects slash in target", "host=tar/get", nil, "SCANNER_REGISTRY_HOST_MAP"},
		{"rejects = in target", "host=tar=get", nil, "SCANNER_REGISTRY_HOST_MAP"},
		{"rejects empty host in target", "host=:5000", nil, "SCANNER_REGISTRY_HOST_MAP"},
		{"rejects port 0", "host=target:0", nil, "port must be 1-65535"},
		{"rejects port above 65535", "host=target:70000", nil, "port must be 1-65535"},
		{"rejects a non-numeric port", "host=target:abc", nil, "port must be 1-65535"},
		{"a case-only duplicate is an error", "Foo=a,foo=b", nil, `duplicate host "foo"`},
		{"rejects credentials in target", "host=secret-user:secret-pass@target", nil, "target contains credentials"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m HostMap
			err := m.UnmarshalText([]byte(tt.input))
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.NotContains(t, err.Error(), "secret-user", "a credential in the target must never be echoed back")
				assert.NotContains(t, err.Error(), "secret-pass", "a credential in the target must never be echoed back")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, m)
		})
	}
}

func TestRegistryValidate(t *testing.T) {
	assert.NoError(t, Registry{}.validate())
	assert.NoError(t, Registry{Username: "robot", Password: "pw"}.validate())
	assert.ErrorContains(t, Registry{Username: "robot"}.validate(), "SCANNER_REGISTRY_PASSWORD")
	assert.ErrorContains(t, Registry{Password: "pw"}.validate(), "SCANNER_REGISTRY_USERNAME")
}

func TestGetConfigRejectsUsernameWithoutPassword(t *testing.T) {
	clearScannerEnv(t)
	t.Setenv("SCANNER_REGISTRY_USERNAME", "robot")
	_, err := GetConfig()
	assert.ErrorContains(t, err, "SCANNER_REGISTRY_PASSWORD")
}

func TestRegistryAccountUnused(t *testing.T) {
	assert.False(t, Registry{}.AccountUnused())
	assert.False(t, Registry{Username: "robot", TrustedHosts: HostList{"harbor.corp.local"}}.AccountUnused())
	assert.True(t, Registry{Username: "robot"}.AccountUnused())
}

func TestRegistryRedactsSecretsInLogsAndFormatting(t *testing.T) {
	r := Registry{Username: "robot", Password: "super-secret", HostMap: HostMap{"a": "b"}}

	formatted := fmt.Sprintf("%+v", r)
	assert.NotContains(t, formatted, "super-secret")
	assert.Contains(t, formatted, "robot", "non-secret fields still show")

	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("msg", slog.Any("registry", r))
	assert.NotContains(t, buf.String(), "super-secret")
}
