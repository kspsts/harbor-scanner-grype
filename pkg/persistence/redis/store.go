package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/job"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/persistence"
)

type store struct {
	namespace  string
	pendingTTL time.Duration
	doneTTL    time.Duration
	rdb        *redis.Client
}

func NewStore(config etc.RedisStore, rdb *redis.Client) persistence.Store {
	return &store{
		namespace:  config.Namespace,
		pendingTTL: config.PendingJobTTL,
		doneTTL:    config.ScanJobTTL,
		rdb:        rdb,
	}
}

// ttl keeps queued and running jobs for PendingJobTTL, so a long "Scan all" queue does not expire
// before it is processed, and finished jobs for ScanJobTTL.
func (s *store) ttl(status job.Status) time.Duration {
	if status == job.Finished || status == job.Failed {
		return s.doneTTL
	}
	return s.pendingTTL
}

func (s *store) Create(ctx context.Context, scanJob *job.ScanJob) error {
	key := s.redisKey(scanJob.Key)

	scanJob.Status = job.Queued
	scanJobData, err := json.Marshal(scanJob)
	if err != nil {
		return xerrors.Errorf("marshalling scan job: %w", err)
	}

	if err := s.rdb.Set(ctx, key, scanJobData, s.ttl(job.Queued)).Err(); err != nil {
		return xerrors.Errorf("storing scan job: %w", err)
	}

	slog.Debug("Created scan job", slog.String("key", key))
	return nil
}

func (s *store) Get(ctx context.Context, key job.ScanJobKey) (*job.ScanJob, error) {
	redisKey := s.redisKey(key)

	scanJobData, err := s.rdb.Get(ctx, redisKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, xerrors.Errorf("getting scan job: %w", err)
	}

	var scanJob job.ScanJob
	if err := json.Unmarshal([]byte(scanJobData), &scanJob); err != nil {
		return nil, xerrors.Errorf("unmarshalling scan job: %w", err)
	}

	return &scanJob, nil
}

func (s *store) UpdateStatus(ctx context.Context, key job.ScanJobKey, status job.Status, errorMsg string) error {
	redisKey := s.redisKey(key)

	scanJob, err := s.Get(ctx, key)
	if err != nil {
		return xerrors.Errorf("getting scan job for status update: %w", err)
	}
	if scanJob == nil {
		return xerrors.Errorf("scan job not found: %s", key.ID)
	}

	scanJob.Status = status
	scanJob.Error = errorMsg

	scanJobData, err := json.Marshal(scanJob)
	if err != nil {
		return xerrors.Errorf("marshalling scan job for status update: %w", err)
	}

	if err := s.rdb.Set(ctx, redisKey, scanJobData, s.ttl(status)).Err(); err != nil {
		return xerrors.Errorf("updating scan job status: %w", err)
	}

	slog.Debug("Updated scan job status",
		slog.String("key", redisKey),
		slog.String("status", status.String()),
		slog.String("error", errorMsg))
	return nil
}

func (s *store) UpdateReport(ctx context.Context, key job.ScanJobKey, report *harbor.ScanReport) error {
	redisKey := s.redisKey(key)

	scanJob, err := s.Get(ctx, key)
	if err != nil {
		return xerrors.Errorf("getting scan job for report update: %w", err)
	}
	if scanJob == nil {
		return xerrors.Errorf("scan job not found: %s", key.ID)
	}

	scanJob.Report = report

	scanJobData, err := json.Marshal(scanJob)
	if err != nil {
		return xerrors.Errorf("marshalling scan job for report update: %w", err)
	}

	if err := s.rdb.Set(ctx, redisKey, scanJobData, s.ttl(scanJob.Status)).Err(); err != nil {
		return xerrors.Errorf("updating scan job report: %w", err)
	}

	slog.Debug("Updated scan job report", slog.String("key", redisKey))
	return nil
}

func (s *store) redisKey(key job.ScanJobKey) string {
	return fmt.Sprintf("%s:scan-job:%s", s.namespace, key.ID)
}

func (s *store) MarkAwaited(ctx context.Context, key job.ScanJobKey, ttl time.Duration) error {
	if err := s.rdb.Set(ctx, s.awaitedKey(key), "", ttl).Err(); err != nil {
		return xerrors.Errorf("marking scan job as awaited: %w", err)
	}
	return nil
}

func (s *store) IsAwaited(ctx context.Context, key job.ScanJobKey) (bool, error) {
	n, err := s.rdb.Exists(ctx, s.awaitedKey(key)).Result()
	if err != nil {
		return false, xerrors.Errorf("checking whether scan job is awaited: %w", err)
	}
	return n > 0, nil
}

func (s *store) awaitedKey(key job.ScanJobKey) string {
	return fmt.Sprintf("%s:awaited:%s", s.namespace, key.ID)
}
