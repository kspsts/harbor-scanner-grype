// Package queue runs scan jobs through two Redis lists: jobs wait in "<namespace>:queue", a worker
// moves one atomically to "<namespace>:processing" and removes it there when the scan is over. Jobs
// left in processing by a stopped container go back to the queue on the next start.
package queue

import (
	"time"

	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/job"
)

// Job is what travels through the Redis lists.
type Job struct {
	Key        job.ScanJobKey
	Args       Args
	EnqueuedAt time.Time
}

type Args struct {
	ScanRequest *harbor.ScanRequest
}

func (j Job) ID() string {
	return j.Key.ID
}

func queueKey(namespace string) string {
	return namespace + ":queue"
}

func processingKey(namespace string) string {
	return namespace + ":processing"
}

// imageName is what the scan log shows for a job: repository@digest.
func imageName(j Job) string {
	if j.Args.ScanRequest == nil {
		return ""
	}
	return j.Args.ScanRequest.Artifact.Repository + "@" + j.Args.ScanRequest.Artifact.Digest
}
