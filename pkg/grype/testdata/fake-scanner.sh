#!/bin/sh
# Stands in for grype and syft in tests: records its arguments and environment,
# then behaves as FAKE_MODE says.
printf '%s\n' "$@" > "$FAKE_LOG.args"
env > "$FAKE_LOG.env"
case "$FAKE_MODE" in
report)
	echo '{"matches":[{"vulnerability":{"id":"CVE-2024-0001","severity":"High","risk":12.5},"artifact":{"name":"openssl","version":"3.0.1"}}]}'
	;;
report-exit2)
	echo '{"matches":[]}'
	echo "[0002] ERROR discovered vulnerabilities at or above the severity threshold" >&2
	exit 2
	;;
fail)
	echo "[0001] ERROR unauthorized: authentication required" >&2
	exit 1
	;;
sleep)
	sleep 5
	;;
tmpdir)
	echo "{\"tmp\":\"$TMPDIR\"}"
	;;
dbstatus)
	echo '{"schemaVersion":"v6.1.9","from":"manual import","built":"2026-09-15T06:31:36Z","path":"/db","valid":false,"error":"the vulnerability database was built 1 week ago (max allowed age is 5 days)"}'
	exit 1
	;;
esac
