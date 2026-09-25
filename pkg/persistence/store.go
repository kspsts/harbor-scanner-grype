package persistence

import (
	"context"
	"time"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/job"
)

type Store interface {
	Create(ctx context.Context, scanJob *job.ScanJob) error
	Get(ctx context.Context, key job.ScanJobKey) (*job.ScanJob, error)
	UpdateStatus(ctx context.Context, key job.ScanJobKey, status job.Status, errorMsg string) error
	UpdateReport(ctx context.Context, key job.ScanJobKey, report *harbor.ScanReport) error
	// MarkAwaited records that Harbor still waits for the report; the mark expires after ttl.
	MarkAwaited(ctx context.Context, key job.ScanJobKey, ttl time.Duration) error
	// IsAwaited reports whether Harbor asked for the report within the last MarkAwaited ttl.
	IsAwaited(ctx context.Context, key job.ScanJobKey) (bool, error)
}
