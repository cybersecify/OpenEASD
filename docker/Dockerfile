# OpenEASD Django Dockerfile - Optimized for ARM64 (Mac M1/M2)
FROM python:3.11-slim-bullseye

ARG TARGETPLATFORM=linux/arm64

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive
ENV OPENEASD_HOME=/app
ENV DJANGO_SETTINGS_MODULE=openeasd.settings

WORKDIR $OPENEASD_HOME

# System dependencies
RUN apt-get update && apt-get install -y \
    curl wget git unzip ca-certificates \
    dnsutils nmap gcc python3-dev build-essential \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd -r openeasd && useradd -r -g openeasd -d $OPENEASD_HOME -s /bin/bash openeasd

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Application code
COPY apps/ ./apps/
COPY openeasd/ ./openeasd/
COPY src/ ./src/
COPY config/ ./config/
COPY manage.py .

# Directories
RUN mkdir -p data logs staticfiles && \
    chown -R openeasd:openeasd $OPENEASD_HOME

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER openeasd

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
CMD ["web"]
