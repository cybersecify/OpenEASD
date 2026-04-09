#!/bin/bash
# OpenEASD Django Entrypoint Script
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()   { echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"; }
error() { echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"; }
warn()  { echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"; }

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   OpenEASD (Django) Starting Up...    ${NC}"
echo -e "${BLUE}========================================${NC}"

export DJANGO_SETTINGS_MODULE=${DJANGO_SETTINGS_MODULE:-"openeasd.settings"}
export PYTHONPATH=${PYTHONPATH:-"/app"}

mkdir -p /app/data /app/logs /app/staticfiles

log "Running Django migrations..."
python manage.py migrate --noinput

# Update Nuclei templates if available
if command -v nuclei >/dev/null 2>&1; then
    nuclei -update-templates -silent 2>/dev/null || warn "Failed to update Nuclei templates"
fi

# Verify security tools
tools=("subfinder" "naabu" "nuclei" "nmap")
for tool in "${tools[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        log "✓ $tool available"
    else
        warn "✗ $tool not found (Docker-based fallback will be used)"
    fi
done

case "${1:-web}" in
    web)
        log "Starting Django development server..."
        exec python manage.py runserver 0.0.0.0:8000
        ;;
    gunicorn)
        log "Starting Gunicorn WSGI server..."
        exec gunicorn openeasd.wsgi:application \
            --bind 0.0.0.0:8000 --workers 4 --timeout 120 \
            --access-logfile - --error-logfile -
        ;;
    celery-worker)
        log "Starting Celery worker..."
        exec celery -A openeasd worker --loglevel=info --concurrency=4
        ;;
    celery-beat)
        log "Starting Celery Beat scheduler..."
        exec celery -A openeasd beat --loglevel=info \
            --scheduler django_celery_beat.schedulers:DatabaseScheduler
        ;;
    scan)
        DOMAIN="${2:-}"
        SCAN_TYPE="${3:-full}"
        if [ -z "$DOMAIN" ]; then
            error "Usage: entrypoint.sh scan <domain> [full|incremental]"
            exit 1
        fi
        log "Running ${SCAN_TYPE} scan for: ${DOMAIN}"
        exec python manage.py run_scan --domain "$DOMAIN" --scan-type "$SCAN_TYPE"
        ;;
    daily-scan)
        log "Running daily incremental scans..."
        exec python manage.py run_daily_scan
        ;;
    weekly-scan)
        log "Running weekly full scans..."
        exec python manage.py run_weekly_scan
        ;;
    shell|bash)
        exec /bin/bash
        ;;
    django-shell)
        exec python manage.py shell
        ;;
    test)
        log "Running tests..."
        exec python -m pytest tests/ -v
        ;;
    migrate)
        log "Migration complete."
        ;;
    *)
        exec "$@"
        ;;
esac
