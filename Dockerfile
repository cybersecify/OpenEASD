# OpenEASD — split images: web (slim, no scanner tools) + worker (Ubuntu, all tools).
#   web    = python:3.12-slim — UI/API + PDF reports (WeasyPrint). No scanners.
#   worker = ubuntu:24.04     — DBOS worker + the full, validated scanner matrix
#                               (nmap NSE, naabu, amass, PD tools, nuclei templates).
# Worker stays Ubuntu because that is the base the tool matrix was validated on
# (nmap version, libpcap, NSE scripts). Each image builds its own venv — two
# different bases can't safely share one venv, so the small duplicate install is
# deliberate.
#
# Build a specific image:
#   docker buildx build --target web    -t openeasd-web    .
#   docker buildx build --target worker -t openeasd-worker .

# ---------------------------------------------------------------------------
# Stage 1: frontend build → static bundle (build-time only; no Node at runtime)
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM node:20-slim AS frontend-builder
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --prefer-offline
COPY frontend/ ./
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2: download pre-built security tool binaries (static Go)
# ---------------------------------------------------------------------------
FROM debian:12-slim AS tools-builder

ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tools

ARG SUBFINDER_VERSION=2.6.6
ARG DNSX_VERSION=1.2.1
ARG NAABU_VERSION=2.6.1
ARG HTTPX_VERSION=1.6.5
ARG NUCLEI_VERSION=3.2.9
ARG AMASS_VERSION=4.2.0
ARG ALTERX_VERSION=0.0.4
ARG KATANA_VERSION=1.6.1
ARG GITLEAKS_VERSION=8.30.1

RUN curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${TARGETARCH}.zip" \
    -o subfinder.zip && unzip subfinder.zip subfinder && rm subfinder.zip
RUN curl -fsSL "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_${TARGETARCH}.zip" \
    -o dnsx.zip && unzip dnsx.zip dnsx && rm dnsx.zip
RUN curl -fsSL "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_${TARGETARCH}.zip" \
    -o naabu.zip && unzip naabu.zip naabu && rm naabu.zip
RUN curl -fsSL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${TARGETARCH}.zip" \
    -o httpx.zip && unzip httpx.zip httpx && rm httpx.zip
RUN curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${TARGETARCH}.zip" \
    -o nuclei.zip && unzip nuclei.zip nuclei && rm nuclei.zip
RUN curl -fsSL "https://github.com/projectdiscovery/alterx/releases/download/v${ALTERX_VERSION}/alterx_${ALTERX_VERSION}_linux_${TARGETARCH}.zip" \
    -o alterx.zip && unzip alterx.zip alterx && rm alterx.zip
RUN curl -fsSL "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${TARGETARCH}.zip" \
    -o katana.zip && unzip katana.zip katana && rm katana.zip
RUN curl -fsSL "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_Linux_${TARGETARCH}.zip" \
    -o amass.zip && unzip amass.zip && mv amass_Linux_${TARGETARCH}/amass . && rm -rf amass.zip amass_Linux_${TARGETARCH}
RUN GLARCH="$([ "$TARGETARCH" = "amd64" ] && echo x64 || echo arm64)" \
    && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GLARCH}.tar.gz" \
    -o gitleaks.tar.gz && tar -xzf gitleaks.tar.gz gitleaks && rm gitleaks.tar.gz
RUN chmod +x subfinder dnsx naabu httpx nuclei amass alterx katana gitleaks

# ---------------------------------------------------------------------------
# Stage 2b/2c: build subzy + gau from source (cross-compiled, static)
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.27 AS subzy-builder
ARG TARGETOS
ARG TARGETARCH
ARG SUBZY_VERSION=v1.2.1
ENV CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH
RUN go install -ldflags="-s -w" github.com/PentestPad/subzy@${SUBZY_VERSION} \
    && if [ -d /go/bin/${TARGETOS}_${TARGETARCH} ]; then mv /go/bin/${TARGETOS}_${TARGETARCH}/subzy /subzy; else mv /go/bin/subzy /subzy; fi

FROM --platform=$BUILDPLATFORM golang:1.27 AS history-builder
ARG TARGETOS
ARG TARGETARCH
ARG GAU_VERSION=v2.2.4
ENV CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH
RUN go install github.com/lc/gau/v2/cmd/gau@${GAU_VERSION} \
    && mkdir -p /history-tools \
    && (mv /go/bin/${TARGETOS}_${TARGETARCH}/gau /history-tools/ 2>/dev/null || mv /go/bin/gau /history-tools/)

# ===========================================================================
# WEB runtime — python:3.12-slim. UI/API + PDF reports. NO scanner tools.
# ===========================================================================
FROM python:3.12-slim AS web

ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    VIRTUAL_ENV=/app/.venv PATH="/app/.venv/bin:/root/.local/bin:${PATH}" \
    OPENEASD_ROLE=web

# Build deps (for any source-built wheels) + WeasyPrint runtime libs.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libffi-dev libssl-dev git curl ca-certificates \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
    libxml2 libxslt1.1 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

WORKDIR /app
RUN uv venv /app/.venv
COPY pyproject.toml ./
COPY apps/ apps/
COPY openeasd/ openeasd/
RUN uv pip install -e ".[prod]" && uv pip install git+https://github.com/initstring/cloud_enum.git
COPY manage.py main.py ./
COPY templates/ templates/
COPY config/ config/
COPY docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh
COPY --from=frontend-builder /build/frontend/dist/ frontend/dist/
RUN SECRET_KEY=build-time-placeholder python manage.py collectstatic --noinput

ARG OPENEASD_VERSION=dev
ARG OPENEASD_GIT_SHA=unknown
ARG OPENEASD_BUILD_DATE=unknown
ENV OPENEASD_VERSION=$OPENEASD_VERSION OPENEASD_GIT_SHA=$OPENEASD_GIT_SHA OPENEASD_BUILD_DATE=$OPENEASD_BUILD_DATE

VOLUME ["/app/logs"]
EXPOSE 8000
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["gunicorn", "openeasd.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-"]

# ===========================================================================
# WORKER runtime — ubuntu:24.04. DBOS worker + full scanner matrix.
# Ubuntu is deliberate: the tools were validated on it. No frontend/WeasyPrint.
# ===========================================================================
FROM ubuntu:24.04 AS worker

ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    VIRTUAL_ENV=/app/.venv PATH="/app/.venv/bin:/usr/local/bin:/root/.local/bin:${PATH}" \
    OPENEASD_ROLE=worker

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.12 python3.12-venv python3-pip \
    build-essential libffi-dev libssl-dev python3-dev \
    curl ca-certificates git nmap libxml2 libxslt1.1 \
    && rm -rf /var/lib/apt/lists/*
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# Scanner binaries (static Go) + subzy + gau
COPY --from=tools-builder /tools/ /usr/local/bin/
COPY --from=subzy-builder /subzy /usr/local/bin/subzy
COPY --from=history-builder /history-tools/ /usr/local/bin/

WORKDIR /app
RUN uv venv /app/.venv
COPY pyproject.toml ./
COPY apps/ apps/
COPY openeasd/ openeasd/
RUN uv pip install -e ".[prod]" && uv pip install git+https://github.com/initstring/cloud_enum.git
COPY manage.py main.py ./
COPY templates/ templates/
COPY config/ config/
COPY docker-entrypoint.sh ./
RUN chmod +x docker-entrypoint.sh

# Bake nuclei templates so the first scan never fetches them mid-run.
RUN nuclei -update-templates && test -d /root/nuclei-templates

ARG OPENEASD_VERSION=dev
ARG OPENEASD_GIT_SHA=unknown
ARG OPENEASD_BUILD_DATE=unknown
ENV OPENEASD_VERSION=$OPENEASD_VERSION OPENEASD_GIT_SHA=$OPENEASD_GIT_SHA OPENEASD_BUILD_DATE=$OPENEASD_BUILD_DATE

VOLUME ["/app/logs"]
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["python", "manage.py", "dbos_worker"]
