package v1

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"github.com/samber/lo"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/job"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/persistence"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/queue"
	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	pathVarScanRequestID = "scan_request_id"

	propertyScannerType = "harbor.scanner-adapter/scanner-type"
)

var decoder = schema.NewDecoder()

// exploitDBInfo reports the update time and CVE count of the currently loaded Exploit-DB list, as
// *exploitdb.Watcher does. A nil value is fine: GetMetadata then omits the Exploit-DB properties.
type exploitDBInfo interface {
	Info() (updated time.Time, cves int, ok bool)
}

type requestHandler struct {
	info     etc.BuildInfo
	config   etc.Config
	enqueuer queue.Enqueuer
	store    persistence.Store
	wrapper  grype.Wrapper
	exploits exploitDBInfo
	api.BaseHandler
}

// NewAPIHandler builds the scanner's HTTP router. exploits is the Exploit-DB list watcher used to
// report its freshness from GetMetadata; it is nil when not running in policy mode.
func NewAPIHandler(info etc.BuildInfo, config etc.Config, enqueuer queue.Enqueuer, store persistence.Store, wrapper grype.Wrapper, exploits exploitDBInfo) http.Handler {
	handler := &requestHandler{
		info:     info,
		config:   config,
		enqueuer: enqueuer,
		store:    store,
		wrapper:  wrapper,
		exploits: exploits,
	}

	router := mux.NewRouter()
	router.Use(handler.logRequest)

	apiV1Router := router.PathPrefix("/api/v1").Subrouter()
	apiV1Router.Use(handler.requireAPIKey(config.API.Key))
	apiV1Router.Methods(http.MethodPost).Path("/scan").HandlerFunc(handler.AcceptScanRequest)
	apiV1Router.Methods(http.MethodGet).Path("/scan/{scan_request_id}/report").HandlerFunc(handler.GetScanReport)
	apiV1Router.Methods(http.MethodGet).Path("/metadata").HandlerFunc(handler.GetMetadata)

	probeRouter := router.PathPrefix("/probe").Subrouter()
	probeRouter.Methods(http.MethodGet).Path("/healthy").HandlerFunc(handler.GetHealthy)
	probeRouter.Methods(http.MethodGet).Path("/ready").HandlerFunc(handler.GetReady)

	if config.API.MetricsEnabled {
		router.Methods(http.MethodGet).Path("/metrics").Handler(promhttp.Handler())
	}

	return router
}

func (h *requestHandler) logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("Request",
			slog.String("addr", r.RemoteAddr),
			slog.String("proto", r.Proto),
			slog.String("method", r.Method),
			slog.String("uri", r.URL.RequestURI()),
		)
		next.ServeHTTP(w, r)
	})
}

// requireAPIKey rejects requests to the scanner API without the key Harbor was registered with,
// sent as "Authorization: Bearer <key>" or "X-ScannerAdapter-API-Key: <key>". Keys are compared in
// constant time, and neither the given nor the configured key is ever logged.
func (h *requestHandler) requireAPIKey(key string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			given := strings.TrimSpace(req.Header.Get("X-ScannerAdapter-API-Key"))
			if kind, value, ok := strings.Cut(req.Header.Get("Authorization"), " "); ok && strings.EqualFold(kind, "Bearer") {
				given = strings.TrimSpace(value)
			}
			if key == "" || subtle.ConstantTimeCompare([]byte(given), []byte(key)) != 1 {
				slog.Warn("Rejected a request without a valid API key",
					slog.String("addr", req.RemoteAddr), slog.String("uri", req.URL.RequestURI()))
				h.WriteJSONError(res, api.Error{HTTPCode: http.StatusUnauthorized, Message: "missing or invalid API key"})
				return
			}
			next.ServeHTTP(res, req)
		})
	}
}

func (h *requestHandler) AcceptScanRequest(res http.ResponseWriter, req *http.Request) {
	var scanRequest harbor.ScanRequest
	if err := json.NewDecoder(req.Body).Decode(&scanRequest); err != nil {
		slog.Error("Error while unmarshalling scan request", slog.String("err", err.Error()))
		h.WriteJSONError(res, api.Error{
			HTTPCode: http.StatusBadRequest,
			Message:  fmt.Sprintf("unmarshalling scan request: %s", err.Error()),
		})
		return
	}

	if validationError := h.ValidateScanRequest(scanRequest); validationError != nil {
		slog.Error("Error while validating scan request", slog.String("err", validationError.Message))
		h.WriteJSONError(res, *validationError)
		return
	}

	// Set the default value for capability type if not specified.
	if len(scanRequest.Capabilities) == 0 {
		scanRequest.Capabilities = append(scanRequest.Capabilities, harbor.Capability{
			Type: harbor.CapabilityTypeVulnerability,
			ProducesMIMETypes: []api.MIMEType{
				api.MimeTypeSecurityVulnerabilityReport,
			},
		})
	}

	scanJobID, err := h.enqueuer.Enqueue(req.Context(), scanRequest)
	if err != nil {
		slog.Error("Error while enqueuing scan job", slog.String("err", err.Error()))
		h.WriteJSONError(res, api.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("enqueuing scan job: %s", err.Error()),
		})
		return
	}

	scanResponse := harbor.ScanResponse{ID: scanJobID}

	h.WriteJSON(res, scanResponse, api.MimeTypeScanResponse, http.StatusAccepted)
}

func (h *requestHandler) ValidateScanRequest(req harbor.ScanRequest) *api.Error {
	if err := h.validateCapabilities(req.Capabilities); err != nil {
		return err
	}

	if req.Registry.URL == "" {
		return &api.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing registry.url",
		}
	}

	if _, err := url.ParseRequestURI(req.Registry.URL); err != nil {
		return &api.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "invalid registry.url",
		}
	}

	if req.Artifact.Repository == "" {
		return &api.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing artifact.repository",
		}
	}

	if req.Artifact.Digest == "" {
		return &api.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing artifact.digest",
		}
	}

	return nil
}

func (h *requestHandler) validateCapabilities(capabilities []harbor.Capability) *api.Error {
	for _, c := range capabilities {
		if len(c.ProducesMIMETypes) == 0 {
			return &api.Error{
				HTTPCode: http.StatusBadRequest,
				Message:  `"enabled_capabilities.produces_mime_types" is missing"`,
			}
		}

		if c.Type != harbor.CapabilityTypeVulnerability && c.Type != harbor.CapabilityTypeSBOM {
			return &api.Error{
				HTTPCode: http.StatusUnprocessableEntity,
				Message:  "invalid scan type",
			}
		}

		if c.Type == harbor.CapabilityTypeSBOM {
			params := lo.FromPtr(c.Parameters)
			if len(params.SBOMMediaTypes) == 0 {
				return &api.Error{
					HTTPCode: http.StatusUnprocessableEntity,
					Message:  "missing SBOM media type",
				}
			}

			for _, mediaType := range params.SBOMMediaTypes {
				if !slices.Contains(harbor.SupportedSBOMMediaTypes, mediaType) {
					return &api.Error{
						HTTPCode: http.StatusUnprocessableEntity,
						Message:  fmt.Sprintf("unsupported SBOM media type: %q", mediaType),
					}
				}
			}
		}
	}
	return nil
}

func (h *requestHandler) GetScanReport(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	scanJobID, ok := vars[pathVarScanRequestID]
	if !ok {
		slog.Error("scan request id is missing")
		h.WriteJSONError(res, api.Error{
			HTTPCode: http.StatusBadRequest,
			Message:  "missing scan request id",
		})
		return
	}
	reqLog := slog.With(slog.String("scan_job_id", scanJobID))

	var reportMIMEType api.MIMEType
	if err := reportMIMEType.Parse(req.Header.Get(api.HeaderAccept)); err != nil {
		reqLog.Error("Error while parsing the Accept header", slog.String("err", err.Error()))
		h.WriteJSONError(res, api.Error{
			HTTPCode: http.StatusUnsupportedMediaType,
			Message:  fmt.Sprintf("unsupported media type: %q", req.Header.Get(api.HeaderAccept)),
		})
		return
	}
	reqLog = reqLog.With(slog.String("mime_type", reportMIMEType.String()))

	// Decode the query parameters into the struct
	var query harbor.ScanReportQuery
	if err := decoder.Decode(&query, req.URL.Query()); err != nil {
		reqLog.Error("Error while parsing query parameters", slog.String("err", err.Error()))
		h.WriteJSONError(res, api.Error{
			HTTPCode: http.StatusBadRequest,
			Message:  fmt.Sprintf("query parameter error: %s", err),
		})
		return
	} else if reportMIMEType.Equal(api.MimeTypeSecuritySBOMReport) && query.SBOMMediaType == "" {
		slog.Error("SBOM media type is missing")
		h.WriteJSONError(res, api.Error{
			HTTPCode: http.StatusBadRequest,
			Message:  "missing SBOM media type",
		})
		return
	} else if query.SBOMMediaType != "" {
		reqLog = reqLog.With(slog.String("sbom_media_type", string(query.SBOMMediaType)))
	}

	scanJob, err := h.store.Get(req.Context(), job.ScanJobKey{
		ID:        scanJobID,
		MIMEType:  reportMIMEType,
		MediaType: query.SBOMMediaType,
	})
	if err != nil {
		reqLog.Error("Error while getting scan job")
		h.WriteJSONError(res, api.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("getting scan job: %v", err),
		})
		return
	}

	if scanJob == nil {
		reqLog.Error("Cannot find scan job")
		h.WriteJSONError(res, api.Error{
			HTTPCode: http.StatusNotFound,
			Message:  fmt.Sprintf("cannot find scan job: %v", scanJobID),
		})
		return
	}

	scanJobLog := reqLog.With(slog.String("scan_job_status", scanJob.Status.String()))

	if scanJob.Status == job.Queued || scanJob.Status == job.Pending {
		// Harbor still waits for this report: keep the job from being skipped.
		if err := h.store.MarkAwaited(req.Context(), scanJob.Key, h.config.Harbor.PollTimeout); err != nil {
			scanJobLog.Warn("Failed to mark the scan job as awaited", slog.String("err", err.Error()))
		}
		scanJobLog.Debug("Scan job has not finished yet")
		res.Header().Add("Location", req.URL.String())
		res.WriteHeader(http.StatusFound)
		return
	}

	if scanJob.Status == job.Failed {
		scanJobLog.Error("Scan job failed", slog.String("err", scanJob.Error))
		h.WriteJSONError(res, api.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  scanJob.Error,
		})
		return
	}

	if scanJob.Status != job.Finished {
		scanJobLog.Error("Unexpected scan job status")
		h.WriteJSONError(res, api.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("unexpected status %v of scan job %v", scanJob.Status, scanJob.Key.ID),
		})
		return
	}

	h.WriteJSON(res, scanJob.Report, reportMIMEType, http.StatusOK)
}

func (h *requestHandler) GetMetadata(res http.ResponseWriter, _ *http.Request) {
	properties := map[string]string{
		propertyScannerType: "os-package-vulnerability",

		"org.label-schema.version":    h.info.Version,
		"org.label-schema.build-date": h.info.Date,
		"org.label-schema.vcs-ref":    h.info.Commit,
		"org.label-schema.vcs":        "https://github.com/aquasecurity/harbor-scanner-grype",

		"env.SCANNER_GRYPE_SKIP_UPDATE":    strconv.FormatBool(h.config.Grype.SkipUpdate),
		"env.SCANNER_GRYPE_OFFLINE_SCAN":   strconv.FormatBool(h.config.Grype.OfflineScan),
		"env.SCANNER_GRYPE_IGNORE_UNFIXED": strconv.FormatBool(h.config.Grype.IgnoreUnfixed),
		"env.SCANNER_GRYPE_DEBUG_MODE":     strconv.FormatBool(h.config.Grype.DebugMode),
		"env.SCANNER_GRYPE_SEVERITY":       h.config.Grype.Severity,
		"env.SCANNER_GRYPE_TIMEOUT":        h.config.Grype.Timeout.String(),

		// The registry flags actually used by grype and syft (see pkg/grype.wrapper.registryEnv);
		// SCANNER_GRYPE_INSECURE no longer affects anything and is not reported.
		"env.SCANNER_REGISTRY_INSECURE_USE_HTTP":        strconv.FormatBool(h.config.Registry.InsecureUseHTTP),
		"env.SCANNER_REGISTRY_INSECURE_SKIP_TLS_VERIFY": strconv.FormatBool(h.config.Registry.InsecureSkipTLSVerify),

		"env.SCANNER_RISK_ENABLED": strconv.FormatBool(h.config.Risk.Risk.Enabled),
		"env.SCANNER_RISK_MODE":    h.config.Risk.Risk.Mode,
	}

	// The policy thresholds only mean something in policy mode: showing them otherwise would
	// suggest they are in effect when they are not.
	if h.config.Risk.Risk.PolicyMode() {
		properties["env.SCANNER_POLICY_CRITICAL"] = formatThreshold(h.config.Policy.Critical)
		properties["env.SCANNER_POLICY_HIGH"] = formatThreshold(h.config.Policy.High)
		properties["env.SCANNER_POLICY_MEDIUM"] = formatThreshold(h.config.Policy.Medium)
	}

	vi, err := h.wrapper.GetVersion()
	if err != nil {
		slog.Error("Error while retrieving grype version", slog.String("err", err.Error()))
	}

	if err == nil {
		properties["grype.version"] = vi.Version
		properties["grype.buildDate"] = vi.BuildDate.Format(time.RFC3339)
		properties["grype.gitCommit"] = vi.GitCommit
		properties["grype.gitTag"] = vi.GitTag
		properties["grype.platform"] = vi.Platform
		properties["grype.compiler"] = vi.Compiler
		properties["grype.goVersion"] = vi.GoVersion
		properties["grype.libVersion"] = vi.LibVersion
	}

	if status, err := h.wrapper.DBStatus(); err != nil {
		slog.Warn("Failed to read the vulnerability DB status", slog.String("err", err.Error()))
	} else if !status.Built.IsZero() {
		properties["harbor.scanner-adapter/vulnerability-database-updated-at"] = status.Built.UTC().Format(time.RFC3339)
	}

	// The Exploit-DB list's own freshness, separate from grype's vulnerability database above.
	// h.exploits is nil outside policy mode, and Info reports ok=false until a list has loaded.
	if h.exploits != nil {
		if updated, cves, ok := h.exploits.Info(); ok {
			properties["harbor.scanner-adapter/exploitdb-updated-at"] = updated.UTC().Format(time.RFC3339)
			properties["harbor.scanner-adapter/exploitdb-cve-count"] = strconv.Itoa(cves)
		}
	}

	metadata := &harbor.ScannerAdapterMetadata{
		Scanner: harbor.GetScannerMetadata(),
		Capabilities: []harbor.Capability{
			{
				Type: harbor.CapabilityTypeVulnerability,
				ConsumesMIMETypes: []string{
					api.MimeTypeOCIImageManifest.String(),
					api.MimeTypeDockerImageManifestV2.String(),
				},
				ProducesMIMETypes: []api.MIMEType{
					api.MimeTypeSecurityVulnerabilityReport,
				},
			},
			{
				Type: harbor.CapabilityTypeSBOM,
				ConsumesMIMETypes: []string{
					api.MimeTypeOCIImageManifest.String(),
					api.MimeTypeDockerImageManifestV2.String(),
				},
				ProducesMIMETypes: []api.MIMEType{
					api.MimeTypeSecuritySBOMReport,
				},
				AdditionalAttributes: &harbor.CapabilityAttributes{
					SBOMMediaTypes: []api.MediaType{
						api.MediaTypeSPDX,
						api.MediaTypeCycloneDX,
					},
				},
			},
		},
		Properties: properties,
	}
	h.WriteJSON(res, metadata, api.MimeTypeMetadata, http.StatusOK)
}

// formatThreshold formats a SCANNER_POLICY_* threshold the way it was configured (at most one
// decimal; see Policy.validate), without a forced trailing ".0".
func formatThreshold(v float64) string {
	return strconv.FormatFloat(v, 'f', -1, 64)
}

func (h *requestHandler) GetHealthy(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
}

func (h *requestHandler) GetReady(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
}
