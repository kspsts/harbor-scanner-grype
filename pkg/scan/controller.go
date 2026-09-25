package scan

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net/url"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/grype"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/job"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/persistence"
)

type Controller interface {
	Scan(ctx context.Context, scanJobKey job.ScanJobKey, request *harbor.ScanRequest) error
}

type controller struct {
	store       persistence.Store
	wrapper     grype.Wrapper
	transformer Transformer
	registry    etc.Registry
}

func NewController(store persistence.Store, wrapper grype.Wrapper, transformer Transformer, registry etc.Registry) Controller {
	return &controller{
		store:       store,
		wrapper:     wrapper,
		transformer: transformer,
		registry:    registry,
	}
}

// Scan runs one scan job and stores its report. A failed scan is stored as Failed and its error
// returned, so the worker can log it.
func (c *controller) Scan(ctx context.Context, scanJobKey job.ScanJobKey, request *harbor.ScanRequest) error {
	if err := c.scan(ctx, scanJobKey, request); err != nil {
		if updateErr := c.store.UpdateStatus(ctx, scanJobKey, job.Failed, err.Error()); updateErr != nil {
			return xerrors.Errorf("%v; updating scan job as failed: %w", err, updateErr)
		}
		return err
	}
	return nil
}

func (c *controller) scan(ctx context.Context, scanJobKey job.ScanJobKey, req *harbor.ScanRequest) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = xerrors.Errorf("scan panicked: %v", r)
		}
	}()

	logScanRequest(req)

	err = c.store.UpdateStatus(ctx, scanJobKey, job.Pending, "")
	if err != nil {
		return xerrors.Errorf("updating scan job status: %v", err)
	}

	imageRef, nonSSL, err := req.GetImageRef(c.registry.HostMap)
	if err != nil {
		return err
	}

	auth, err := c.registryAuth(*req)
	if err != nil {
		return err
	}

	ref := grype.ImageRef{
		Name:   imageRef,
		Auth:   auth,
		NonSSL: nonSSL,
	}

	// Check if this is an SBOM scan request
	if scanJobKey.MIMEType.Equal(api.MimeTypeSecuritySBOMReport) {
		// Generate SBOM using Syft
		sbom, err := c.wrapper.ScanSBOM(ref, grype.ScanOption{
			Format: determineFormat(scanJobKey.MediaType),
		})
		if err != nil {
			return xerrors.Errorf("running sbom scan: %v", err)
		}

		harborScanReport := c.transformer.TransformSBOM(scanJobKey.MediaType, lo.FromPtr(req), sbom)
		if err = c.store.UpdateReport(ctx, scanJobKey, harborScanReport); err != nil {
			return xerrors.Errorf("saving sbom report: %v", err)
		}
	} else {
		// Generate vulnerability report using Grype
		scanReport, err := c.wrapper.Scan(ref, grype.ScanOption{
			Format: determineFormat(scanJobKey.MediaType),
		})
		if err != nil {
			return xerrors.Errorf("running grype wrapper: %v", err)
		}

		harborScanReport := c.transformer.Transform(scanJobKey.MediaType, lo.FromPtr(req), scanReport)
		if err = c.store.UpdateReport(ctx, scanJobKey, harborScanReport); err != nil {
			return xerrors.Errorf("saving scan report: %v", err)
		}
	}

	if err = c.store.UpdateStatus(ctx, scanJobKey, job.Finished, ""); err != nil {
		return xerrors.Errorf("updating scan job status: %v", err)
	}

	return
}

// logScanRequest logs the incoming scan request from Harbor. It never logs the Authorization header
// or any credential derived from it: see registryAuth.
func logScanRequest(req *harbor.ScanRequest) {
	slog.Info("Received scan request from Harbor",
		slog.String("registry_url", req.Registry.URL),
		slog.String("artifact_repository", req.Artifact.Repository),
		slog.String("artifact_digest", req.Artifact.Digest),
		slog.String("artifact_mime_type", req.Artifact.MimeType),
		slog.Int("capabilities_count", len(req.Capabilities)),
	)
}

// registryAuth picks the credentials for the registry in Harbor's scan request. Harbor's Basic
// credentials are used as they are. When Harbor sends a Bearer token or nothing, the configured
// account is used, but only for SCANNER_REGISTRY_TRUSTED_HOSTS; any other host gets the token as it
// is, or no credentials. Secrets never reach the log.
func (c *controller) registryAuth(req harbor.ScanRequest) (grype.RegistryAuth, error) {
	host := ""
	if u, err := url.Parse(req.Registry.URL); err == nil {
		host = u.Hostname()
	}
	kind, value, _ := strings.Cut(strings.TrimSpace(req.Registry.Authorization), " ")
	useAccount := c.registry.Username != "" && c.registry.Trusted(host)

	var auth grype.RegistryAuth
	var source string
	switch {
	case strings.EqualFold(kind, "Basic"):
		decoded, err := decodeBasicAuth(value)
		if err != nil {
			return nil, err
		}
		auth, source = decoded, "Harbor (Basic)"
	case (kind == "" || strings.EqualFold(kind, "Bearer")) && useAccount:
		auth, source = grype.BasicAuth{Username: c.registry.Username, Password: c.registry.Password}, "SCANNER_REGISTRY_USERNAME"
	case strings.EqualFold(kind, "Bearer"):
		auth, source = grype.BearerAuth{Token: strings.TrimSpace(value)}, "Harbor (Bearer)"
	case kind == "":
		auth, source = grype.NoAuth{}, "none"
	default:
		return nil, xerrors.Errorf("unrecognized authorization type %q", kind)
	}
	slog.Debug("Registry credentials", slog.String("registry", host), slog.String("source", source))
	return auth, nil
}

func decodeBasicAuth(value string) (grype.RegistryAuth, error) {
	creds, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return nil, xerrors.Errorf("decoding Basic credentials: %w", err)
	}
	user, pass, ok := strings.Cut(string(creds), ":")
	if !ok {
		return nil, xerrors.New("Basic credentials are not user:password")
	}
	return grype.BasicAuth{Username: user, Password: pass}, nil
}

func determineFormat(m api.MediaType) grype.Format {
	switch m {
	case api.MediaTypeSPDX:
		return grype.FormatSPDX
	case api.MediaTypeCycloneDX:
		return grype.FormatCycloneDX
	default:
		return grype.FormatJSON
	}
}
