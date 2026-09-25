#!/bin/sh
# Container entrypoint. Runs as root to set up /etc/hosts and cron,
# then starts the adapter as the unprivileged scanner user.
set -eu

# SCANNER_EXTRA_HOSTS="host=ip,host2=ip2": names the container cannot resolve via DNS.
for pair in $(echo "${SCANNER_EXTRA_HOSTS:-}" | tr ',' ' '); do
    host="${pair%%=*}"
    ip="${pair#*=}"
    if [ -z "$host" ] || [ -z "$ip" ] || [ "$host" = "$pair" ]; then
        echo "Ignoring malformed SCANNER_EXTRA_HOSTS entry: $pair" >&2
        continue
    fi
    grep -qxF "$ip $host" /etc/hosts || echo "$ip $host" >> /etc/hosts
done

# Exploit-DB list for SCANNER_RISK_MODE=policy: the copy baked into the image seeds the volume,
# the nightly job below keeps it fresh.
exploitdb_file="${SCANNER_EXPLOITDB_FILE:-/home/scanner/.cache/exploitdb/files_exploits.csv}"
mkdir -p "$(dirname "$exploitdb_file")"
if [ ! -s "$exploitdb_file" ] && [ -s /usr/local/share/exploitdb/files_exploits.csv ]; then
    # -p keeps the build date, so an old image's copy is reported by SCANNER_EXPLOITDB_MAX_AGE.
    cp -p /usr/local/share/exploitdb/files_exploits.csv "$exploitdb_file"
fi
chown -R scanner:scanner "$(dirname "$exploitdb_file")"

# Nightly vulnerability DB update, then the Exploit-DB list. Scans run with GRYPE_DB_AUTO_UPDATE=false,
# so the slow link to the DB server is used only on this schedule (interpreted in TZ). crond runs the
# job as the scanner user with the container environment (TZ, proxy settings, GRYPE_*, SCANNER_*).
echo "${GRYPE_DB_UPDATE_SCHEDULE:-0 0 * * *} /usr/local/bin/update-grype-db.sh >> /var/log/grype-update.log 2>&1; /usr/local/bin/update-exploitdb.sh >> /var/log/grype-update.log 2>&1" \
    > /etc/crontabs/scanner
# Level 9: only crond errors; the update scripts log their own start and result.
crond -f -l 9 -L /dev/stderr &
# The update log also goes to the container log.
tail -n 0 -F /var/log/grype-update.log &

export HOME=/home/scanner
exec su-exec scanner /home/scanner/bin/scanner-grype
