package grype

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/ext"
)

type Format string

const (
	grypeCmd = "grype"
	syftCmd  = "syft"

	FormatJSON      Format = "json"
	FormatSPDX      Format = "spdx-json"
	FormatCycloneDX Format = "cyclonedx"

	// tempDirPrefix names the per-run directories inside SCANNER_GRYPE_TMP_DIR.
	tempDirPrefix = "scan-"
)

type ImageRef struct {
	Name   string
	Auth   RegistryAuth
	NonSSL bool
}

type ScanOption struct {
	Format Format
}

// RegistryAuth wraps registry credentials.
type RegistryAuth interface {
}

type NoAuth struct {
}

type BasicAuth struct {
	Username string
	Password string
}

type BearerAuth struct {
	Token string
}

// DBStatus is what `grype db status -o json` reports about the vulnerability database.
type DBStatus struct {
	SchemaVersion string    `json:"schemaVersion"`
	From          string    `json:"from"`
	Built         time.Time `json:"built"`
	Path          string    `json:"path"`
	Valid         bool      `json:"valid"`
	Error         string    `json:"error"`
}

type Wrapper interface {
	Scan(imageRef ImageRef, opt ScanOption) (Report, error)
	ScanSBOM(imageRef ImageRef, opt ScanOption) (any, error)
	GetVersion() (VersionInfo, error)
	DBStatus() (DBStatus, error)
}

type wrapper struct {
	config     etc.Grype
	registry   etc.Registry
	ambassador ext.Ambassador
}

func NewWrapper(config etc.Grype, registry etc.Registry, ambassador ext.Ambassador) Wrapper {
	return &wrapper{
		config:     config,
		registry:   registry,
		ambassador: ambassador,
	}
}

func (w *wrapper) Scan(imageRef ImageRef, opt ScanOption) (Report, error) {
	stdout, err := w.run(grypeCmd, w.scanArgs(imageRef, opt), w.registryEnv("GRYPE", imageRef), grypeExitOK)
	if err != nil {
		return Report{}, err
	}
	return w.parseReportFromStdout(opt.Format, stdout)
}

func (w *wrapper) ScanSBOM(imageRef ImageRef, opt ScanOption) (any, error) {
	args := []string{imageRef.Name, "--output", string(opt.Format)}
	stdout, err := w.run(syftCmd, args, w.registryEnv("SYFT", imageRef), syftExitOK)
	if err != nil {
		return nil, err
	}
	var sbom any
	if err := json.Unmarshal(stdout, &sbom); err != nil {
		return nil, xerrors.Errorf("sbom json decode error: %w", err)
	}
	return sbom, nil
}

// DBStatus runs `grype db status -o json`. For an invalid database grype exits non-zero but still
// prints the status, which is what callers want to show.
func (w *wrapper) DBStatus() (DBStatus, error) {
	printed := func(_ int, stdout []byte) bool { return len(bytes.TrimSpace(stdout)) > 0 }
	stdout, err := w.run(grypeCmd, []string{"db", "status", "-o", "json"}, nil, printed)
	if err != nil {
		return DBStatus{}, err
	}
	var status DBStatus
	if err := json.Unmarshal(stdout, &status); err != nil {
		return DBStatus{}, xerrors.Errorf("parsing grype db status: %w", err)
	}
	return status, nil
}

// grypeExitOK: with --fail-on grype exits with 2 when it finds vulnerabilities at or above the
// threshold, and the report on stdout is complete. Any other non-zero code is a failure.
func grypeExitOK(code int, stdout []byte) bool {
	return code == 0 || (code == 2 && len(bytes.TrimSpace(stdout)) > 0)
}

func syftExitOK(code int, _ []byte) bool {
	return code == 0
}

// run starts a scanner tool with SCANNER_GRYPE_TIMEOUT and a temporary directory of its own inside
// SCANNER_GRYPE_TMP_DIR, and returns its stdout. stderr carries the tool's log and is used only for
// the error message. The environment holds registry credentials, so it is never logged, and stdout
// (the report itself) is logged at most by its size, never its content.
func (w *wrapper) run(tool string, args, env []string, exitOK func(code int, stdout []byte) bool) ([]byte, error) {
	path, err := w.ambassador.LookPath(tool)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(w.config.TmpDir, 0o700); err != nil {
		return nil, xerrors.Errorf("creating %s: %w", w.config.TmpDir, err)
	}
	tmp, err := os.MkdirTemp(w.config.TmpDir, tempDirPrefix)
	if err != nil {
		return nil, xerrors.Errorf("creating a temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	ctx, cancel := context.WithTimeout(context.Background(), w.config.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(append(w.ambassador.Environ(), "TMPDIR="+tmp), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	// tool may itself spawn children (a shell script, or grype/syft invoking a helper). Killing
	// only the direct child on timeout would leave those running and holding the stdout/stderr
	// pipes open, so Wait would block past the deadline until they exit on their own. Running the
	// tool in its own process group and killing the whole group on cancel avoids that; WaitDelay is
	// a bound of last resort if some descendant still manages to outlive the kill.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second

	slog.Debug("Running "+tool, slog.String("args", strings.Join(args, " ")))
	err = cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, xerrors.Errorf("scan timed out after %s", w.config.Timeout)
	}
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || !exitOK(exitErr.ExitCode(), stdout.Bytes()) {
			return nil, xerrors.Errorf("running %s: %v: %s", tool, err, lastLines(stderr.String(), 5))
		}
	}
	slog.Debug("Finished "+tool, slog.Int("stdout_bytes", stdout.Len()))
	return stdout.Bytes(), nil
}

// registryEnv passes the registry settings to grype or syft (prefix GRYPE or SYFT). A registry that
// Harbor names with http:// always needs plain HTTP, whatever SCANNER_REGISTRY_INSECURE_USE_HTTP says.
func (w *wrapper) registryEnv(prefix string, ref ImageRef) []string {
	env := []string{
		fmt.Sprintf("%s_REGISTRY_INSECURE_USE_HTTP=%t", prefix, w.registry.InsecureUseHTTP || ref.NonSSL),
		fmt.Sprintf("%s_REGISTRY_INSECURE_SKIP_TLS_VERIFY=%t", prefix, w.registry.InsecureSkipTLSVerify),
	}
	authority := registryHost(ref.Name)
	switch auth := ref.Auth.(type) {
	case BasicAuth:
		env = append(env,
			prefix+"_REGISTRY_AUTH_AUTHORITY="+authority,
			prefix+"_REGISTRY_AUTH_USERNAME="+auth.Username,
			prefix+"_REGISTRY_AUTH_PASSWORD="+auth.Password)
	case BearerAuth:
		env = append(env,
			prefix+"_REGISTRY_AUTH_AUTHORITY="+authority,
			prefix+"_REGISTRY_AUTH_TOKEN="+auth.Token)
	}
	return env
}

// scanArgs builds grype's command line from SCANNER_GRYPE_* settings.
func (w *wrapper) scanArgs(imageRef ImageRef, opt ScanOption) []string {
	args := []string{imageRef.Name, "--output", string(opt.Format)}

	if w.config.Severity != "" {
		// --fail-on takes one level: the first of SCANNER_GRYPE_SEVERITY, in grype's terms.
		first := strings.TrimSpace(strings.Split(w.config.Severity, ",")[0])
		if first != "" {
			severity := "negligible"
			switch strings.ToLower(first) {
			case "low", "medium", "high", "critical":
				severity = strings.ToLower(first)
			}
			args = append(args, "--fail-on", severity)
		}
	}
	if w.config.IgnoreUnfixed {
		args = append(args, "--ignore-unfixed")
	}
	if w.config.OnlyFixed {
		args = append(args, "--only-fixed")
	}
	if w.config.SkipUpdate {
		args = append(args, "--skip-db-update")
	}
	if w.config.OfflineScan {
		args = append(args, "--offline")
	}
	if w.config.ConfigFile != "" {
		args = append(args, "--config", w.config.ConfigFile)
	}
	if w.config.FailOnSeverity != "" {
		args = append(args, "--fail-on", w.config.FailOnSeverity)
	}
	if w.config.AddCPEsIfNone {
		args = append(args, "--add-cpes-if-none")
	}
	if w.config.ByCVE {
		args = append(args, "--by-cve")
	}
	if w.config.Platform != "" {
		args = append(args, "--platform", w.config.Platform)
	}
	if w.config.Distro != "" {
		args = append(args, "--distro", w.config.Distro)
	}
	if w.config.ExcludeAddl != "" {
		args = append(args, "--exclude-addl", w.config.ExcludeAddl)
	}
	if w.config.DebugMode {
		args = append(args, "--verbose")
	}
	return args
}

// registryHost is the host[:port] part of an image reference.
func registryHost(imageRef string) string {
	host, _, _ := strings.Cut(imageRef, "/")
	return host
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// RemoveStaleTempDirs deletes the per-run directories left by scans that were killed together with
// the container. Call it at start-up, before any scan runs.
func RemoveStaleTempDirs(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), tempDirPrefix) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if err := os.RemoveAll(path); err != nil {
			slog.Warn("Failed to remove a stale temp dir", slog.String("path", path), slog.String("err", err.Error()))
		}
	}
}

func (w *wrapper) parseReportFromStdout(format Format, stdout []byte) (Report, error) {
	switch format {
	case FormatJSON:
		return w.parseJSONReportFromBytes(stdout)
	case FormatSPDX, FormatCycloneDX:
		return w.parseSBOMFromBytes(stdout)
	}
	return Report{}, xerrors.Errorf("unsupported format %s", format)
}

// parseJSONReportFromBytes decodes grype's JSON report. It keeps only Matches: the transformer
// builds Harbor's vulnerability list from report.Matches (one item per match, so a CVE found in
// three packages stays three items), and a separate flattened Vulnerabilities slice would only
// invite a caller to read the wrong one and lose the package it was found in.
func (w *wrapper) parseJSONReportFromBytes(data []byte) (Report, error) {
	var scanReport ScanReport
	if err := json.Unmarshal(data, &scanReport); err != nil {
		return Report{}, xerrors.Errorf("report json decode error: %w", err)
	}
	return Report{Matches: scanReport.Matches}, nil
}

func (w *wrapper) parseSBOMFromBytes(data []byte) (Report, error) {
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return Report{}, xerrors.Errorf("sbom json decode error: %w", err)
	}
	return Report{SBOM: doc}, nil
}

func (w *wrapper) GetVersion() (VersionInfo, error) {
	name, err := w.ambassador.LookPath(grypeCmd)
	if err != nil {
		return VersionInfo{}, fmt.Errorf("failed preparing grype version command: %w", err)
	}
	versionOutput, err := w.ambassador.RunCmd(exec.Command(name, "version", "--output", "json"))
	if err != nil {
		return VersionInfo{}, fmt.Errorf("failed running grype version command: %w: %v", err, string(versionOutput))
	}
	var vi VersionInfo
	if err := json.Unmarshal(versionOutput, &vi); err != nil {
		return VersionInfo{}, fmt.Errorf("failed parsing grype version output: %w", err)
	}
	return vi, nil
}
