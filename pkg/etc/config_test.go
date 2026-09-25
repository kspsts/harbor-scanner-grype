package etc

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caarlos0/env/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clearScannerEnv removes every SCANNER_* variable from the process environment for the duration
// of the test, so tests that call GetConfig do not depend on what happens to be set in the
// developer's (or CI's) shell, and sets SCANNER_API_KEY, which GetConfig requires. t.Setenv
// registers the restore; the direct os.Unsetenv makes the variable actually absent, which matters
// because caarlos0/env treats "absent" (envDefault applies) differently from "set to empty"
// (notEmpty fields reject it).
func clearScannerEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "SCANNER_") {
			t.Setenv(k, "") // registers the restore
			os.Unsetenv(k)
		}
	}
	t.Setenv("SCANNER_API_KEY", "test-key-0123456789")
}

func TestGetConfig(t *testing.T) {
	clearScannerEnv(t)
	// Set some test environment variables
	t.Setenv("SCANNER_LOG_LEVEL", "debug")
	t.Setenv("SCANNER_GRYPE_CACHE_DIR", "/test/cache")
	t.Setenv("SCANNER_GRYPE_SEVERITY", "High,Critical")

	config, err := GetConfig()
	assert.NoError(t, err)
	assert.Equal(t, "/test/cache", config.Grype.CacheDir)
	assert.Equal(t, "High,Critical", config.Grype.Severity)
}

func TestLogLevel(t *testing.T) {
	tests := []struct {
		envValue string
		expected slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"error", slog.LevelError},
		{"", slog.LevelInfo}, // default
	}

	for _, test := range tests {
		if test.envValue != "" {
			t.Setenv("SCANNER_LOG_LEVEL", test.envValue)
		} else {
			os.Unsetenv("SCANNER_LOG_LEVEL")
		}
		assert.Equal(t, test.expected, LogLevel())
	}
}

func TestAPIIsTLSEnabled(t *testing.T) {
	api := API{
		TLSCertificate: "",
		TLSKey:         "",
	}
	assert.False(t, api.IsTLSEnabled())

	api.TLSCertificate = "/path/to/cert"
	api.TLSKey = "/path/to/key"
	assert.True(t, api.IsTLSEnabled())
}

func TestGrypeConfigDefaults(t *testing.T) {
	clearScannerEnv(t)
	var config Grype
	require.NoError(t, env.Parse(&config))

	// Test default values
	assert.Equal(t, "/home/scanner/.cache/grype", config.CacheDir)
	assert.Equal(t, "/home/scanner/.cache/reports", config.ReportsDir)
	assert.False(t, config.DebugMode)
	assert.Equal(t, "Unknown,Low,Medium,High,Critical", config.Severity)
	assert.False(t, config.IgnoreUnfixed)
	assert.False(t, config.OnlyFixed)
	assert.False(t, config.SkipUpdate)
	assert.False(t, config.OfflineScan)
	assert.False(t, config.Insecure)
	assert.Equal(t, 15*time.Minute, config.Timeout)
	assert.Equal(t, "/tmp/scanner", config.TmpDir)
	assert.False(t, config.AddCPEsIfNone)
	assert.False(t, config.ByCVE)
	assert.Equal(t, "json", config.Output)
}

func TestPolicyDefaults(t *testing.T) {
	clearScannerEnv(t)
	config, err := GetConfig()
	require.NoError(t, err)
	assert.Equal(t, Policy{
		Critical:        70,
		High:            30,
		Medium:          10,
		ExploitDBFile:   "/home/scanner/.cache/exploitdb/files_exploits.csv",
		ExploitDBMaxAge: 336 * time.Hour,
	}, config.Policy)
}

func TestRiskEnvOverridesDefaults(t *testing.T) {
	clearScannerEnv(t)
	// Enabled defaults to true, so setting it "false" (rather than repeating the default "true")
	// is what proves this override is actually applied.
	t.Setenv("SCANNER_RISK_ENABLED", "false")
	t.Setenv("SCANNER_RISK_MODE", "policy")
	t.Setenv("SCANNER_RISK_HIGH", "60")
	t.Setenv("SCANNER_POLICY_HIGH", "25")

	config, err := GetConfig()
	require.NoError(t, err)
	assert.False(t, config.Risk.Risk.Enabled)
	assert.Equal(t, "policy", config.Risk.Risk.Mode)
	assert.Equal(t, 60.0, config.Risk.Risk.Thresholds.High)
	assert.Equal(t, 25.0, config.Policy.High)
}

func TestRiskModeMustBeKnown(t *testing.T) {
	clearScannerEnv(t)
	t.Setenv("SCANNER_RISK_MODE", "magic")
	_, err := GetConfig()
	assert.ErrorContains(t, err, "SCANNER_RISK_MODE")
}

func TestRiskConfigDataPolicyMode(t *testing.T) {
	assert.True(t, RiskConfigData{Enabled: true, Mode: "policy"}.PolicyMode())
	assert.False(t, RiskConfigData{Enabled: false, Mode: "policy"}.PolicyMode(), "disabled")
	assert.False(t, RiskConfigData{Enabled: true, Mode: "formula"}.PolicyMode(), "formula mode")
}

func TestPolicyThresholdsMustBeOrdered(t *testing.T) {
	clearScannerEnv(t)
	t.Setenv("SCANNER_POLICY_HIGH", "80")
	_, err := GetConfig()
	assert.ErrorContains(t, err, "SCANNER_POLICY_CRITICAL")
}

func TestPolicyThresholdsMustBeValid(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{"above 100", map[string]string{"SCANNER_POLICY_CRITICAL": "150"}, "SCANNER_POLICY_"},
		{"zero medium", map[string]string{"SCANNER_POLICY_MEDIUM": "0"}, "SCANNER_POLICY_"},
		{"negative medium", map[string]string{"SCANNER_POLICY_MEDIUM": "-5"}, "SCANNER_POLICY_"},
		{"two decimals", map[string]string{"SCANNER_POLICY_HIGH": "30.05"}, "at most one decimal"},
		{"more precision than one decimal", map[string]string{"SCANNER_POLICY_HIGH": "30.00000000001"}, "at most one decimal"},
		{"not a number", map[string]string{"SCANNER_POLICY_HIGH": "NaN"}, "SCANNER_POLICY_"},
		{"equal high, medium", map[string]string{"SCANNER_POLICY_HIGH": "10"}, "SCANNER_POLICY_"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearScannerEnv(t)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			_, err := GetConfig()
			assert.ErrorContains(t, err, c.wantErr)
		})
	}
}

func TestPolicyThresholdsAcceptOneDecimalAnd100(t *testing.T) {
	clearScannerEnv(t)
	t.Setenv("SCANNER_POLICY_CRITICAL", "100")
	t.Setenv("SCANNER_POLICY_HIGH", "12.5")
	t.Setenv("SCANNER_POLICY_MEDIUM", "0.1")
	config, err := GetConfig()
	require.NoError(t, err)
	assert.Equal(t, 12.5, config.Policy.High)
}

func TestPolicyHighBlankErrors(t *testing.T) {
	clearScannerEnv(t)
	t.Setenv("SCANNER_POLICY_HIGH", "")
	_, err := GetConfig()
	assert.ErrorContains(t, err, "SCANNER_POLICY_HIGH")
	assert.ErrorContains(t, err, "should not be empty")
}

func TestExploitDBMaxAgeValidation(t *testing.T) {
	t.Run("blank errors", func(t *testing.T) {
		clearScannerEnv(t)
		t.Setenv("SCANNER_EXPLOITDB_MAX_AGE", "")
		_, err := GetConfig()
		assert.ErrorContains(t, err, "SCANNER_EXPLOITDB_MAX_AGE")
		assert.ErrorContains(t, err, "should not be empty")
	})

	t.Run("negative errors", func(t *testing.T) {
		clearScannerEnv(t)
		t.Setenv("SCANNER_EXPLOITDB_MAX_AGE", "-1h")
		_, err := GetConfig()
		assert.ErrorContains(t, err, "SCANNER_EXPLOITDB_MAX_AGE")
	})

	t.Run("zero is accepted", func(t *testing.T) {
		clearScannerEnv(t)
		t.Setenv("SCANNER_EXPLOITDB_MAX_AGE", "0")
		config, err := GetConfig()
		require.NoError(t, err)
		assert.Equal(t, time.Duration(0), config.Policy.ExploitDBMaxAge)
	})
}

// skipIfAppRiskConfigExists skips a test that controls risk-config.yaml through the working
// directory: LoadRiskConfig reads /app/risk-config.yaml first, so where that file exists, as in
// the runtime image, it would be read instead of the test's own file (or its absence).
func skipIfAppRiskConfigExists(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/app/risk-config.yaml"); err == nil {
		t.Skip("/app/risk-config.yaml exists and takes precedence")
	}
}

// chdirToTempDir changes the process's working directory into a fresh temp dir for the rest of
// the test, restoring the previous directory in t.Cleanup, and returns the dir. Go 1.22 (this
// project's toolchain) has no t.Chdir. LoadRiskConfig looks at /app/risk-config.yaml first and
// falls back to the relative "risk-config.yaml", resolved against the working directory set here;
// the test is skipped where /app/risk-config.yaml exists (skipIfAppRiskConfigExists).
func chdirToTempDir(t *testing.T) string {
	t.Helper()
	skipIfAppRiskConfigExists(t)
	dir := t.TempDir()

	oldWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() {
		assert.NoError(t, os.Chdir(oldWd))
	})
	return dir
}

// chdirToTempRiskConfig writes risk-config.yaml into a fresh temp dir and makes that dir the
// working directory for the rest of the test (see chdirToTempDir).
func chdirToTempRiskConfig(t *testing.T, yamlContent string) {
	t.Helper()
	dir := chdirToTempDir(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "risk-config.yaml"), []byte(yamlContent), 0644))
}

func TestRiskConfigYAMLPrecedence(t *testing.T) {
	// high uses a value distinctive from the repository's own risk-config.yaml (which also has
	// mode "formula" and high 70): otherwise this test would pass even if the temp file were
	// never actually read.
	chdirToTempRiskConfig(t, `risk:
  mode: "Formula"
  enabled: true
  thresholds: {critical: 85, high: 71.5, medium: 50, low: 0.01}
`)

	t.Run("mode is normalised from the file", func(t *testing.T) {
		clearScannerEnv(t)
		config, err := GetConfig()
		require.NoError(t, err)
		assert.Equal(t, "formula", config.Risk.Risk.Mode)
		assert.Equal(t, 71.5, config.Risk.Risk.Thresholds.High)
	})

	t.Run("SCANNER_RISK_HIGH overrides the file", func(t *testing.T) {
		clearScannerEnv(t)
		t.Setenv("SCANNER_RISK_HIGH", "60")
		config, err := GetConfig()
		require.NoError(t, err)
		assert.Equal(t, 60.0, config.Risk.Risk.Thresholds.High)
	})

	t.Run("SCANNER_RISK_MODE overrides the file", func(t *testing.T) {
		clearScannerEnv(t)
		t.Setenv("SCANNER_RISK_MODE", "policy")
		config, err := GetConfig()
		require.NoError(t, err)
		assert.Equal(t, "policy", config.Risk.Risk.Mode)
	})
}

func TestRiskConfigDisabledWithoutModeLoadsOK(t *testing.T) {
	chdirToTempRiskConfig(t, `risk:
  enabled: false
`)
	clearScannerEnv(t)
	config, err := GetConfig()
	require.NoError(t, err)
	assert.False(t, config.Risk.Risk.Enabled)
}

// A risk-config.yaml that cannot be read or parsed stops the start with an error that names the
// file: falling back to the built-in defaults would silently run in their cvss mode instead of the
// mode the file sets.
func TestBrokenRiskConfigStopsTheStart(t *testing.T) {
	t.Run("YAML syntax error", func(t *testing.T) {
		chdirToTempRiskConfig(t, "risk: {mode: [policy\n")
		clearScannerEnv(t)
		_, err := GetConfig()
		assert.ErrorContains(t, err, "risk-config.yaml")
	})

	t.Run("not readable", func(t *testing.T) {
		dir := chdirToTempDir(t)
		require.NoError(t, os.Mkdir(filepath.Join(dir, "risk-config.yaml"), 0o755))
		clearScannerEnv(t)
		_, err := GetConfig()
		assert.ErrorContains(t, err, "risk-config.yaml")
	})
}

// Without any risk-config.yaml the built-in defaults still apply.
func TestMissingRiskConfigUsesDefaults(t *testing.T) {
	chdirToTempDir(t)
	clearScannerEnv(t)
	config, err := GetConfig()
	require.NoError(t, err)
	assert.Equal(t, getDefaultRiskConfig(), config.Risk)
}

func TestRiskNumbersMustBeFinite(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		wantErr string // empty means GetConfig must succeed
	}{
		{
			name: "NaN default EPSS",
			env: map[string]string{
				"SCANNER_RISK_ENABLED":      "true",
				"SCANNER_RISK_MODE":         "formula",
				"SCANNER_RISK_DEFAULT_EPSS": "NaN",
			},
			wantErr: "SCANNER_RISK_DEFAULT_EPSS",
		},
		{
			name: "+Inf high threshold",
			env: map[string]string{
				"SCANNER_RISK_ENABLED": "true",
				"SCANNER_RISK_MODE":    "formula",
				"SCANNER_RISK_HIGH":    "+Inf",
			},
			wantErr: "SCANNER_RISK_HIGH",
		},
		{
			name: "NaN ignored when risk is disabled",
			env: map[string]string{
				"SCANNER_RISK_ENABLED": "false",
				"SCANNER_RISK_HIGH":    "NaN",
			},
			wantErr: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearScannerEnv(t)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			_, err := GetConfig()
			if c.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, c.wantErr)
			}
		})
	}
}

// Each SCANNER_RISK_* number sets its own field and is reported under its own variable and
// risk-config.yaml path when it is not a number, or not a finite one.
func TestRiskNumbersReachTheirFields(t *testing.T) {
	cases := []struct {
		env, yamlPath string
		field         func(RiskConfigData) float64
	}{
		{"SCANNER_RISK_CRITICAL", "risk.thresholds.critical", func(r RiskConfigData) float64 { return r.Thresholds.Critical }},
		{"SCANNER_RISK_HIGH", "risk.thresholds.high", func(r RiskConfigData) float64 { return r.Thresholds.High }},
		{"SCANNER_RISK_MEDIUM", "risk.thresholds.medium", func(r RiskConfigData) float64 { return r.Thresholds.Medium }},
		{"SCANNER_RISK_LOW", "risk.thresholds.low", func(r RiskConfigData) float64 { return r.Thresholds.Low }},
		{"SCANNER_RISK_CVSS_CRITICAL", "risk.cvss_thresholds.critical", func(r RiskConfigData) float64 { return r.CVSSThresholds.Critical }},
		{"SCANNER_RISK_CVSS_HIGH", "risk.cvss_thresholds.high", func(r RiskConfigData) float64 { return r.CVSSThresholds.High }},
		{"SCANNER_RISK_CVSS_MEDIUM", "risk.cvss_thresholds.medium", func(r RiskConfigData) float64 { return r.CVSSThresholds.Medium }},
		{"SCANNER_RISK_CVSS_LOW", "risk.cvss_thresholds.low", func(r RiskConfigData) float64 { return r.CVSSThresholds.Low }},
		{"SCANNER_RISK_DEFAULT_EPSS", "risk.defaults.epss", func(r RiskConfigData) float64 { return r.Defaults.EPSS }},
		{"SCANNER_RISK_DEFAULT_CVSS", "risk.defaults.cvss", func(r RiskConfigData) float64 { return r.Defaults.CVSS }},
	}
	for _, c := range cases {
		t.Run(c.env, func(t *testing.T) {
			clearScannerEnv(t)
			t.Setenv("SCANNER_RISK_ENABLED", "true")
			t.Setenv("SCANNER_RISK_MODE", "formula")

			t.Setenv(c.env, "42.5")
			config, err := GetConfig()
			require.NoError(t, err)
			assert.Equal(t, 42.5, c.field(config.Risk.Risk))

			t.Setenv(c.env, "abc")
			_, err = GetConfig()
			assert.EqualError(t, err, c.env+`: strconv.ParseFloat: parsing "abc": invalid syntax`)

			t.Setenv(c.env, "NaN")
			_, err = GetConfig()
			assert.EqualError(t, err, c.env+" (or "+c.yamlPath+" in risk-config.yaml) must be a finite number, got NaN")
		})
	}
}

func TestRegistryDefaults(t *testing.T) {
	clearScannerEnv(t)
	config, err := GetConfig()
	require.NoError(t, err)
	assert.True(t, config.Registry.InsecureUseHTTP)
	assert.True(t, config.Registry.InsecureSkipTLSVerify)
	assert.Empty(t, config.Registry.HostMap)
	assert.Empty(t, config.Registry.TrustedHosts)
	assert.Equal(t, 5*time.Second, config.RedisPool.ReadTimeout)
	assert.Equal(t, 5*time.Second, config.RedisPool.WriteTimeout)
	assert.Equal(t, 5*time.Second, config.RedisPool.ConnectionTimeout)
}

func TestAPIKeyIsRequired(t *testing.T) {
	clearScannerEnv(t)
	t.Setenv("SCANNER_API_KEY", "")
	os.Unsetenv("SCANNER_API_KEY")
	_, err := GetConfig()
	assert.ErrorContains(t, err, "SCANNER_API_KEY")

	t.Setenv("SCANNER_API_KEY", "   ")
	_, err = GetConfig()
	assert.ErrorContains(t, err, "SCANNER_API_KEY", "a blank key is not a key")
}

func TestAPIKeyIsStoredTrimmed(t *testing.T) {
	clearScannerEnv(t)
	t.Setenv("SCANNER_API_KEY", "  test-key-0123456789  ")
	config, err := GetConfig()
	require.NoError(t, err)
	assert.Equal(t, "test-key-0123456789", config.API.Key)
}

func TestAPIKeyMustBeLongEnough(t *testing.T) {
	clearScannerEnv(t)
	t.Setenv("SCANNER_API_KEY", "short-key-12")
	_, err := GetConfig()
	assert.ErrorContains(t, err, "at least 16 characters")

	t.Setenv("SCANNER_API_KEY", "0123456789abcdef") // exactly 16 characters
	_, err = GetConfig()
	assert.NoError(t, err)
}

func TestGrypeTimeoutValidation(t *testing.T) {
	t.Run("blank errors", func(t *testing.T) {
		clearScannerEnv(t)
		t.Setenv("SCANNER_GRYPE_TIMEOUT", "")
		_, err := GetConfig()
		assert.ErrorContains(t, err, "SCANNER_GRYPE_TIMEOUT")
	})

	t.Run("negative errors", func(t *testing.T) {
		clearScannerEnv(t)
		t.Setenv("SCANNER_GRYPE_TIMEOUT", "-5m")
		_, err := GetConfig()
		assert.ErrorContains(t, err, "SCANNER_GRYPE_TIMEOUT")
	})
}

func TestGrypeTmpDirBlankErrors(t *testing.T) {
	clearScannerEnv(t)
	t.Setenv("SCANNER_GRYPE_TMP_DIR", "")
	_, err := GetConfig()
	assert.ErrorContains(t, err, "SCANNER_GRYPE_TMP_DIR")
}

func TestAPIRedactsSecretsInLogsAndFormatting(t *testing.T) {
	a := API{Addr: ":8090", Key: "super-secret-key"}

	formatted := fmt.Sprintf("%+v", a)
	assert.NotContains(t, formatted, "super-secret-key")
	assert.Contains(t, formatted, ":8090", "non-secret fields still show")

	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("msg", slog.Any("api", a))
	assert.NotContains(t, buf.String(), "super-secret-key")
}

// TestConfigRedactsSecretsInOutput proves the redaction reaches through the whole Config, not just
// the Registry and API types directly: both fmt's own struct-field recursion (used by
// slog's TextHandler for a value that is not itself an slog.LogValuer) and a direct String() call
// must never leak SCANNER_API_KEY or SCANNER_REGISTRY_PASSWORD.
func TestConfigRedactsSecretsInOutput(t *testing.T) {
	clearScannerEnv(t)
	t.Setenv("SCANNER_REGISTRY_USERNAME", "robot")
	t.Setenv("SCANNER_REGISTRY_PASSWORD", "registry-secret-pw")
	cfg, err := GetConfig()
	require.NoError(t, err)

	formatted := fmt.Sprintf("%+v", cfg)
	assert.NotContains(t, formatted, "registry-secret-pw")
	assert.NotContains(t, formatted, "test-key-0123456789")

	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("config", slog.Any("config", cfg))
	assert.NotContains(t, buf.String(), "registry-secret-pw")
	assert.NotContains(t, buf.String(), "test-key-0123456789")
}

func TestQueueDefaults(t *testing.T) {
	clearScannerEnv(t)
	config, err := GetConfig()
	require.NoError(t, err)
	assert.Equal(t, 24*time.Hour, config.RedisStore.PendingJobTTL)
	assert.Equal(t, time.Hour, config.RedisStore.ScanJobTTL)
	assert.Equal(t, 2*time.Minute, config.Harbor.PollTimeout)
}

func TestPendingJobTTLValidation(t *testing.T) {
	t.Run("blank errors", func(t *testing.T) {
		clearScannerEnv(t)
		t.Setenv("SCANNER_STORE_REDIS_PENDING_JOB_TTL", "")
		_, err := GetConfig()
		assert.ErrorContains(t, err, "SCANNER_STORE_REDIS_PENDING_JOB_TTL")
	})

	t.Run("zero errors", func(t *testing.T) {
		clearScannerEnv(t)
		t.Setenv("SCANNER_STORE_REDIS_PENDING_JOB_TTL", "0")
		_, err := GetConfig()
		assert.ErrorContains(t, err, "SCANNER_STORE_REDIS_PENDING_JOB_TTL must be positive")
	})

	t.Run("negative errors", func(t *testing.T) {
		clearScannerEnv(t)
		t.Setenv("SCANNER_STORE_REDIS_PENDING_JOB_TTL", "-1h")
		_, err := GetConfig()
		assert.ErrorContains(t, err, "SCANNER_STORE_REDIS_PENDING_JOB_TTL must be positive")
	})
}

func TestHarborPollTimeoutValidation(t *testing.T) {
	t.Run("blank errors", func(t *testing.T) {
		clearScannerEnv(t)
		t.Setenv("SCANNER_HARBOR_POLL_TIMEOUT", "")
		_, err := GetConfig()
		assert.ErrorContains(t, err, "SCANNER_HARBOR_POLL_TIMEOUT")
	})

	t.Run("zero errors", func(t *testing.T) {
		clearScannerEnv(t)
		t.Setenv("SCANNER_HARBOR_POLL_TIMEOUT", "0s")
		_, err := GetConfig()
		assert.ErrorContains(t, err, "SCANNER_HARBOR_POLL_TIMEOUT must be positive")
	})
}

func TestLogFormat(t *testing.T) {
	tests := []struct {
		envValue string
		expected string
	}{
		{"JSON", "json"},
		{"json", "json"},
		{" json ", "json"},
		{"text", "text"},
		{"bogus", "text"},
		{"", "text"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.envValue), func(t *testing.T) {
			t.Setenv("SCANNER_LOG_FORMAT", tt.envValue)
			assert.Equal(t, tt.expected, LogFormat())
		})
	}
}
