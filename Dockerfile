# OpenEASD — Ubuntu 24.04 LTS
# Multi-stage: builder installs tools and builds frontend, runtime is lean.

# ---------------------------------------------------------------------------
# Stage 1: frontend build
# ---------------------------------------------------------------------------
FROM ubuntu:24.04 AS frontend-builder

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
# Stage 2: Go tools (subfinder, dnsx, naabu, httpx, nuclei, amass)
# ---------------------------------------------------------------------------
FROM ubuntu:24.04 AS tools-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go
ARG GO_VERSION=1.22.4
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
    | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:${PATH}"

# Install ProjectDiscovery tools via pdtm
RUN go install github.com/projectdiscovery/pdtm/cmd/pdtm@latest
ENV PATH="/root/go/bin:${PATH}"

RUN pdtm -install subfinder && \
    pdtm -install dnsx && \
    pdtm -install naabu && \
    pdtm -install httpx && \
    pdtm -install nuclei

# Install amass
RUN go install github.com/owasp-amass/amass/v4/...@master

# ---------------------------------------------------------------------------
# Stage 3: runtime
# ---------------------------------------------------------------------------
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# System packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Python runtime
    python3.12 python3.12-venv python3-pip \
    # uv (fast Python package manager)
    curl ca-certificates \
    # nmap (system tool, not pdtm)
    nmap \
    # PDF rendering dependencies for xhtml2pdf
    libffi-dev libssl-dev libxml2 libxslt1.1 \
    # Misc
    git \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

# Copy Go binaries from tools-builder stage
COPY --from=tools-builder /root/.pdtm/go/bin/ /usr/local/bin/pdtm-tools/
COPY --from=tools-builder /root/go/bin/amass /usr/local/bin/amass
ENV PATH="/usr/local/bin/pdtm-tools:${PATH}"

# Create app directory
WORKDIR /app

# Install Python dependencies first (cached layer)
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# Copy application source
COPY manage.py main.py ./
COPY openeasd/ openeasd/
COPY apps/ apps/
COPY templates/ templates/
COPY config/ config/

# Copy built frontend from frontend-builder stage
COPY --from=frontend-builder /build/frontend/dist/ frontend/dist/

# Collect static files (SECRET_KEY only needed at runtime, dummy value is fine here)
RUN SECRET_KEY=build-time-placeholder uv run manage.py collectstatic --noinput

# Persistent data directory (SQLite DB, media, logs)
VOLUME ["/app/data", "/app/logs"]

# Expose Django port
EXPOSE 8000

# Entrypoint: auto-migrate, create admin if needed, start server + worker
CMD ["uv", "run", "python", "main.py"]
