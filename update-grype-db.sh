#!/bin/sh
# Updates the Grype vulnerability database. Run by cron on GRYPE_DB_UPDATE_SCHEDULE;
# scans do not update the database themselves. Output goes to /var/log/grype-update.log,
# which start.sh also forwards to the container log, in the adapter's key=value format.

log() {
    level=$1
    shift
    echo "time=$(date '+%Y-%m-%dT%H:%M:%S%z') level=$level msg=\"$*\""
}

log INFO "Vulnerability DB update started"
started=$(date +%s)

if output=$(/usr/local/bin/grype db update 2>&1); then
    status=$(/usr/local/bin/grype db status 2>&1 | tr -s ' \n' ' ')
    log INFO "Vulnerability DB update finished in $(( $(date +%s) - started ))s: $(echo "$output" | tail -n 1 | tr -d '"'). $status"
else
    log ERROR "Vulnerability DB update failed after $(( $(date +%s) - started ))s: $(echo "$output" | tail -n 3 | tr '\n' ' ' | tr -d '"')"
    exit 1
fi
