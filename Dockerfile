# syntax=docker/dockerfile:1
# Harbor Scanner Grype, built from source.
#   docker build -t ant1freeze/harbor-scanner-grype:latest .
#   docker buildx build --platform linux/amd64 -t ant1freeze/harbor-scanner-grype:latest --load .
# A grype-db.tar.zst next to this file is imported instead of downloading the vulnerability DB.

FROM --platform=$BUILDPLATFORM golang:1.22-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" -o /out/scanner-grype .

FROM alpine:3.24.1
ARG TARGETARCH=amd64
ARG GRYPE_VERSION=0.117.0
ARG SYFT_VERSION=1.51.1

RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates curl su-exec tzdata

RUN set -eu; \
    arch="${TARGETARCH:-amd64}"; \
    for tool in "grype:${GRYPE_VERSION}" "syft:${SYFT_VERSION}"; do \
      name="${tool%%:*}"; version="${tool##*:}"; \
      base="https://github.com/anchore/${name}/releases/download/v${version}"; \
      file="${name}_${version}_linux_${arch}.tar.gz"; \
      curl -fsSL --retry 5 --retry-delay 3 -o "/tmp/${file}" "${base}/${file}"; \
      curl -fsSL --retry 5 --retry-delay 3 "${base}/${name}_${version}_checksums.txt" \
        | grep " ${file}\$" | (cd /tmp && sha256sum -c -); \
      tar -xzf "/tmp/${file}" -C /usr/local/bin "${name}"; \
      rm -f "/tmp/${file}"; \
    done

RUN adduser -u 10000 -D -g '' scanner

COPY --from=build /out/scanner-grype /home/scanner/bin/scanner-grype
COPY grype-config.yaml /home/scanner/.grype.yaml
COPY risk-config.yaml /app/risk-config.yaml
COPY --chmod=755 start.sh update-grype-db.sh update-exploitdb.sh /usr/local/bin/

RUN mkdir -p /home/scanner/.cache/grype /home/scanner/.cache/reports /home/scanner/.cache/exploitdb \
      /usr/local/share/exploitdb && \
    chown -R scanner:scanner /home/scanner && \
    install -o scanner -g scanner -m 644 /dev/null /var/log/grype-update.log

# Exploit-DB list baked into the image; start.sh copies it to the volume on the first start.
RUN curl -fsSL --retry 5 --retry-delay 3 -o /usr/local/share/exploitdb/files_exploits.csv \
      https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv && \
    head -n 1 /usr/local/share/exploitdb/files_exploits.csv | grep -q '^id,.*codes'

WORKDIR /home/scanner
ENV PATH=/home/scanner/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    GRYPE_VERSION=0.117.0 \
    GRYPE_DB_CACHE_DIR=/home/scanner/.cache/grype \
    SCANNER_LOG_LEVEL=info

USER scanner
RUN --mount=type=bind,target=/ctx \
    if [ -f /ctx/grype-db.tar.zst ]; then grype db import /ctx/grype-db.tar.zst; else grype db update; fi
USER root

ENV GRYPE_DB_AUTO_UPDATE=false \
    GRYPE_CHECK_FOR_APP_UPDATE=false \
    SYFT_CHECK_FOR_APP_UPDATE=false

EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/start.sh"]
