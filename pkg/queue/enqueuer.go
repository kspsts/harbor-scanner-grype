package queue

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/job"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/persistence"
)

type Enqueuer interface {
	Enqueue(ctx context.Context, request harbor.ScanRequest) (string, error)
}

type enqueuer struct {
	namespace   string
	rdb         *redis.Client
	store       persistence.Store
	pollTimeout time.Duration
}

func NewEnqueuer(config etc.JobQueue, rdb *redis.Client, store persistence.Store, pollTimeout time.Duration) Enqueuer {
	return &enqueuer{
		namespace:   config.Namespace,
		rdb:         rdb,
		store:       store,
		pollTimeout: pollTimeout,
	}
}

func (e *enqueuer) Enqueue(ctx context.Context, request harbor.ScanRequest) (string, error) {
	scanJobID := uuid.New().String()

	// Determine media type and MIME type from capabilities
	var mediaType api.MediaType
	var mimeType api.MIMEType = api.MimeTypeSecurityVulnerabilityReport // default
	for _, capability := range request.Capabilities {
		if capability.Type == harbor.CapabilityTypeSBOM && capability.Parameters != nil {
			if len(capability.Parameters.SBOMMediaTypes) > 0 {
				mediaType = capability.Parameters.SBOMMediaTypes[0]
				mimeType = api.MimeTypeSecuritySBOMReport
				break
			}
		}
	}
	scanJobKey := job.ScanJobKey{ID: scanJobID, MIMEType: mimeType, MediaType: mediaType}

	if err := e.store.Create(ctx, &job.ScanJob{Key: scanJobKey}); err != nil {
		return "", xerrors.Errorf("creating scan job: %w", err)
	}
	// Harbor starts polling for the report right away; until then the job counts as awaited.
	if err := e.store.MarkAwaited(ctx, scanJobKey, e.pollTimeout); err != nil {
		return "", err
	}

	queued := Job{Key: scanJobKey, Args: Args{ScanRequest: &request}, EnqueuedAt: time.Now().UTC()}
	payload, err := json.Marshal(queued)
	if err != nil {
		return "", xerrors.Errorf("marshalling job: %w", err)
	}
	length, err := e.rdb.LPush(ctx, queueKey(e.namespace), payload).Result()
	if err != nil {
		return "", xerrors.Errorf("queueing job: %w", err)
	}

	slog.Info("Scan queued",
		slog.String("scan_job_id", scanJobID),
		slog.String("image", imageName(queued)),
		slog.Int64("queued", length))
	return scanJobID, nil
}
