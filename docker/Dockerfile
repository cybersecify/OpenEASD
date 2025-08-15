# OpenEASD Dockerfile - Optimized for ARM64 (Mac M1/M2)
FROM python:3.11-slim-bullseye

# Set platform for ARM64 compatibility
ARG TARGETPLATFORM=linux/arm64

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive
ENV OPENEASD_HOME=/app

# Create app directory
WORKDIR $OPENEASD_HOME

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    unzip \
    ca-certificates \
    dnsutils \
    nmap \
    gcc \
    python3-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r openeasd && useradd -r -g openeasd -d $OPENEASD_HOME -s /bin/bash openeasd

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Note: Security tools (Subfinder, Naabu, Nuclei) will be run via separate Docker containers
# This avoids ARM64 compatibility issues during build

# Copy application code
COPY src/ ./src/
COPY prefect_flows/ ./prefect_flows/
COPY config/ ./config/
COPY main.py .

# Create necessary directories
RUN mkdir -p data logs reports && \
    chown -R openeasd:openeasd $OPENEASD_HOME

# Copy entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Switch to non-root user
USER openeasd

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')" || exit 1

# Expose ports
EXPOSE 8000 4200

# Set entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# Default command
CMD ["python", "main.py"]