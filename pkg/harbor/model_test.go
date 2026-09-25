package harbor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
)

func request(url string) ScanRequest {
	return ScanRequest{
		Registry: Registry{URL: url},
		Artifact: Artifact{Repository: "library/nginx", Digest: "sha256:abc"},
	}
}

func TestGetImageRef(t *testing.T) {
	hostMap := etc.HostMap{
		"localhost":         "nginx:8080",
		"harbor.corp.local": "harbor.corp.local:443",
		"core":              "registry",
		"ipv6-target":       "[::1]:5000",
	}
	tests := []struct {
		url    string
		ref    string
		nonSSL bool
	}{
		{"https://harbor.example.com", "harbor.example.com:443/library/nginx@sha256:abc", false},
		{"http://harbor.example.com", "harbor.example.com:80/library/nginx@sha256:abc", true},
		{"https://harbor.example.com:8443", "harbor.example.com:8443/library/nginx@sha256:abc", false},
		{"http://localhost", "nginx:8080/library/nginx@sha256:abc", true},
		{"https://Harbor.Corp.Local", "harbor.corp.local:443/library/nginx@sha256:abc", false},
		{"http://core:8080", "registry:8080/library/nginx@sha256:abc", true},
		{"http://ipv6-target", "[::1]:5000/library/nginx@sha256:abc", true},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			ref, nonSSL, err := request(tt.url).GetImageRef(hostMap)
			require.NoError(t, err)
			assert.Equal(t, tt.ref, ref)
			assert.Equal(t, tt.nonSSL, nonSSL)
		})
	}
}

func TestGetImageRefWithoutMap(t *testing.T) {
	ref, _, err := request("http://localhost").GetImageRef(nil)
	require.NoError(t, err)
	assert.Equal(t, "localhost:80/library/nginx@sha256:abc", ref, "nothing is rewritten unless configured")
}

func TestGetImageRefRejectsBadURL(t *testing.T) {
	_, _, err := request("http://[::1").GetImageRef(nil)
	assert.ErrorContains(t, err, "parsing registry URL")
}
