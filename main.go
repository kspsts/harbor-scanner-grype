package main

import (
	"context"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
	_ "time/tzdata" // embed the IANA zone database so the explanation's date follows TZ even when the image has no zoneinfo files

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/exploitdb"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/ext"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/persistence/redis"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/policy"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/queue"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/redisx"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/scan"
)

func main() {
	// Log format and level from SCANNER_LOG_FORMAT and SCANNER_LOG_LEVEL
	slog.SetDefault(slog.New(etc.NewLogHandler(os.Stdout)))

	// Load configuration
	config, err := etc.GetConfig()
	if err != nil {
		slog.Error("Failed to load configuration", slog.String("err", err.Error()))
		os.Exit(1)
	}
	warnAboutRegistrySettings(config.Registry)

	// Create build info
	buildInfo := etc.BuildInfo{
		Version: "dev",
		Commit:  "none",
		Date:    "unknown",
	}

	slog.Info("Starting harbor-scanner-grype",
		slog.String("version", buildInfo.Version),
		slog.String("commit", buildInfo.Commit),
		slog.String("built_at", buildInfo.Date))

	// Create Redis client
	rdb, err := redisx.NewClient(config.RedisPool)
	if err != nil {
		slog.Error("Failed to create Redis client", slog.String("err", err.Error()))
		os.Exit(1)
	}

	// Test Redis connection
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		slog.Error("Failed to connect to Redis", slog.String("err", err.Error()))
		os.Exit(1)
	}
	slog.Info("Connected to Redis", slog.String("addr", redisAddrForLog(config.RedisPool.URL)))

	// Create ambassador
	ambassador := ext.DefaultAmbassador()

	// Create Grype wrapper
	grypeWrapper := grype.NewWrapper(config.Grype, config.Registry, ambassador)

	// Scans killed together with the previous container leave their temp dirs behind.
	grype.RemoveStaleTempDirs(config.Grype.TmpDir)

	if status, err := grypeWrapper.DBStatus(); err != nil {
		slog.Warn("Failed to read the vulnerability DB status", slog.String("err", err.Error()))
	} else {
		slog.Info("Vulnerability DB",
			slog.String("built", status.Built.UTC().Format(time.RFC3339)),
			slog.String("schema", status.SchemaVersion),
			slog.Bool("valid", status.Valid),
			slog.String("error", status.Error))
	}

	// Create store
	store := redis.NewStore(config.RedisStore, rdb)

	// Create transformer. The Exploit-DB list is only read in the policy mode. exploitWatcher is
	// kept separately (as its concrete type) so the API handler can report the list's freshness
	// from /api/v1/metadata; it is nil outside policy mode, which its Info method handles safely.
	var exploitWatcher *exploitdb.Watcher
	var exploits policy.ExploitLookup
	if config.Risk.Risk.PolicyMode() {
		exploitWatcher = exploitdb.NewWatcher(config.Policy.ExploitDBFile, time.Minute, config.Policy.ExploitDBMaxAge)
		exploits = exploitWatcher
		slog.Info("Severity policy enabled",
			slog.Float64("critical_from", config.Policy.Critical),
			slog.Float64("high_from", config.Policy.High),
			slog.Float64("medium_from", config.Policy.Medium))
	}
	transformer := scan.NewTransformer(&scan.SystemClock{}, config.Risk, policy.Thresholds{
		Critical: config.Policy.Critical,
		High:     config.Policy.High,
		Medium:   config.Policy.Medium,
	}, exploits)

	// Create controller
	controller := scan.NewController(store, grypeWrapper, transformer, config.Registry)

	// Create enqueuer
	enqueuer := queue.NewEnqueuer(config.JobQueue, rdb, store, config.Harbor.PollTimeout)

	// Create worker
	worker := queue.NewWorker(config.JobQueue, rdb, store, controller, config.Harbor.PollTimeout)

	// Create API handler
	handler := v1.NewAPIHandler(buildInfo, config, enqueuer, store, grypeWrapper, exploitWatcher)

	// Create HTTP server
	server, err := api.NewServer(config.API, handler)
	if err != nil {
		slog.Error("Failed to create HTTP server", slog.String("err", err.Error()))
		os.Exit(1)
	}

	// Start worker
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	worker.Start(ctx)
	slog.Info("Starting worker")

	// Start HTTP server
	slog.Info("Starting API server")
	go func() {
		if err := server.ListenAndServe(); err != nil {
			slog.Error("HTTP server error", slog.String("err", err.Error()))
			cancel()
		}
	}()

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	slog.Info("Shutdown signal received")

	// Stop accepting scan requests first, then let the scans in progress finish. Scans still running
	// when the container is killed are requeued on the next start.
	server.Shutdown()
	worker.Stop()
	cancel()

	slog.Info("Harbor Scanner Grype stopped")
}

// warnAboutRegistrySettings flags registry settings that are easy to leave misconfigured: with
// certificate checks off, anyone who can answer for a trusted host name receives the registry
// credentials; with an account set but no trusted hosts, the account is silently never used.
func warnAboutRegistrySettings(r etc.Registry) {
	if r.InsecureSkipTLSVerify {
		if r.Username != "" {
			slog.Warn("SCANNER_REGISTRY_INSECURE_SKIP_TLS_VERIFY is true: registry certificate checks are off, so the configured registry account can be sent to any host that answers for a trusted name")
		} else {
			slog.Warn("SCANNER_REGISTRY_INSECURE_SKIP_TLS_VERIFY is true: registry certificate checks are off")
		}
	}
	if r.AccountUnused() {
		slog.Warn("SCANNER_REGISTRY_USERNAME is set but SCANNER_REGISTRY_TRUSTED_HOSTS is empty, so the account is never used")
	}
}

// redisAddrForLog is config.RedisPool.URL with any password it carries removed, safe to log: just
// the host[:port]. It falls back to "redis" when the URL cannot be parsed or names no host, rather
// than risk logging a malformed value verbatim.
func redisAddrForLog(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "redis"
	}
	return u.Host
}
