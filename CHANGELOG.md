# Changelog

## [Unreleased] - Policy mode

### Added
- **Policy mode** (`SCANNER_RISK_MODE=policy`): five rules (KEV, malicious packages, grype risk ladder, no EPSS, public exploits) set the Harbor level, and the reason with its date is written in front of the vulnerability description. See `RISK_CALCULATION.md`.
- **Exploit-DB**: the `files_exploits.csv` list is read from `SCANNER_EXPLOITDB_FILE`, re-read after the nightly update, and its exploits are linked from the vulnerability.
- **Settings**: `SCANNER_POLICY_CRITICAL/HIGH/MEDIUM`, `SCANNER_EXPLOITDB_FILE`, `SCANNER_EXPLOITDB_MAX_AGE`, and `SCANNER_RISK_*` variables that override `risk-config.yaml`.

### Changed
- **One report row per grype match, in every mode**: a CVE found in several packages (for example libcrypto3, libssl3 and openssl) now shows each package instead of repeating the first one, so Harbor's totals grow after a rescan.
- **Stricter start-up checks**: with risk enabled, a missing or unknown mode (`SCANNER_RISK_MODE` from the environment, or `mode` in `risk-config.yaml`) now stops the start, where it used to fall back silently to grype's severity. The mode is now case-insensitive, so a `mode: "Formula"` or `mode: "CVSS"` that used to fall back to grype's severity now applies the formula or the CVSS thresholds. A `risk-config.yaml` that cannot be read or parsed now stops the start too, where it used to fall back silently to the built-in defaults (`cvss` mode); without the file the built-in defaults still apply. Invalid or blank policy settings stop it as well.

## [Unreleased] - Risk Calculation Feature

### Added
- **Risk Calculation Formula**: Implemented `Risk = EPSS × (CVSS/10)` for vulnerability severity assessment
- **Configurable Risk Thresholds**: YAML-based configuration for criticality levels
- **EPSS Support**: Integration with Exploit Prediction Scoring System data
- **CVSS Priority**: Prefer CVSS v3.x over v2.0 scores
- **Default Value Handling**: Graceful fallback for missing EPSS/CVSS data
- **Risk Configuration File**: `risk-config.yaml` with customizable thresholds
- **Comprehensive Testing**: Full test coverage for risk calculation logic

### Changed
- **Severity Mapping**: Now uses calculated risk instead of direct Grype severity
- **Transformer Interface**: Updated to accept risk configuration
- **Docker Build**: Includes risk configuration file in container image

### Configuration
- **Default Thresholds**:
  - Critical: ≥ 75%
  - High: ≥ 50%
  - Medium: ≥ 25%
  - Low: ≥ 10%
  - Unknown: < 10%
- **Default Values**:
  - EPSS: 0.1 (10% probability)
  - CVSS: 5.0 (medium severity)

### Files Modified
- `pkg/etc/config.go` - Added risk configuration structures
- `pkg/grype/model.go` - Added EPSS data structure
- `pkg/scan/transformer.go` - Implemented risk calculation logic
- `cmd/scanner-grype/main.go` - Updated transformer initialization
- `Dockerfile` - Added risk configuration file
- `go.mod` - Added yaml.v2 dependency

### Files Added
- `risk-config.yaml` - Risk calculation configuration
- `pkg/scan/transformer_test.go` - Comprehensive test suite
- `RISK_CALCULATION.md` - Detailed documentation

### Backward Compatibility
- Risk calculation can be disabled via `risk.enabled: false`
- Falls back to original Grype severity mapping when disabled
- No breaking changes to existing API
