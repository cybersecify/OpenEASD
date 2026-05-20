# OpenEASD — Ubuntu 24.04 LTS
# Multi-platform build (linux/amd64 + linux/arm64):
#   docker buildx build --platform linux/amd64,linux/arm64 -t openeasd:latest --push .
# Single-platform local load:
#   docker buildx build --platform linux/amd64 --load -t openeasd .

# ---------------------------------------------------------------------------
# Stage 1: frontend build (platform-agnostic — Node runs natively)
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM ubuntu:24.04 AS frontend-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --prefer-offline

COPY frontend/ ./
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 2: download pre-built security tool binaries for the target platform
# ---------------------------------------------------------------------------
FROM ubuntu:24.04 AS tools-builder

# TARGETARCH is injected by buildx: 'amd64' or 'arm64'
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tools

# ProjectDiscovery tool versions — bump as needed
ARG SUBFINDER_VERSION=2.6.6
ARG DNSX_VERSION=1.2.1
ARG NAABU_VERSION=2.6.1
ARG HTTPX_VERSION=1.6.5
ARG NUCLEI_VERSION=3.2.9
ARG AMASS_VERSION=4.2.0

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

RUN curl -fsSL "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_Linux_${TARGETARCH}.zip" \
    -o amass.zip && unzip amass.zip && mv amass_Linux_${TARGETARCH}/amass . && rm -rf amass.zip amass_Linux_${TARGETARCH}

RUN chmod +x subfinder dnsx naabu httpx nuclei amass

# ---------------------------------------------------------------------------
# Stage 3: runtime
# ---------------------------------------------------------------------------
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.12 python3.12-venv python3-pip \
    curl ca-certificates \
    nmap \
    # xhtml2pdf / pycairo / svglib build deps
    build-essential libffi-dev libssl-dev libxml2 libxslt1.1 \
    libcairo2-dev pkg-config python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

# Copy security tool binaries
COPY --from=tools-builder /tools/ /usr/local/bin/
ENV PATH="/usr/local/bin:${PATH}"

WORKDIR /app

# Create virtualenv
RUN uv venv /app/.venv
ENV VIRTUAL_ENV=/app/.venv
ENV PATH="/app/.venv/bin:${PATH}"

# Install Python dependencies — copy only what pip needs so this layer is cached
# unless dependencies change (not every code change)
COPY pyproject.toml ./
COPY apps/ apps/
COPY openeasd/ openeasd/
RUN uv pip install -e ".[prod]"

# Copy remaining source
COPY manage.py main.py ./
COPY templates/ templates/
COPY config/ config/

# Copy built frontend from frontend-builder stage
COPY --from=frontend-builder /build/frontend/dist/ frontend/dist/

# Collect static files
RUN SECRET_KEY=build-time-placeholder python manage.py collectstatic --noinput

VOLUME ["/app/data", "/app/logs"]
EXPOSE 8000

CMD ["python", "main.py"]
