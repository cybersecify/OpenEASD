#!/bin/bash
# OpenEASD Docker Entrypoint Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}       OpenEASD Starting Up...         ${NC}"
echo -e "${BLUE}========================================${NC}"

# Function to log messages
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

# Set default environment variables if not provided
export DATABASE_URL=${DATABASE_URL:-"sqlite:///app/data/openeasd.db"}
export PREFECT_API_URL=${PREFECT_API_URL:-"http://localhost:4200/api"}
export PYTHONPATH=${PYTHONPATH:-"/app/src"}

log "Environment Configuration:"
log "- Database URL: ${DATABASE_URL}"
log "- Prefect API URL: ${PREFECT_API_URL}"
log "- Python Path: ${PYTHONPATH}"

# Create necessary directories
log "Creating necessary directories..."
mkdir -p /app/data /app/logs /app/reports /app/data/backups

# Check if configuration files exist
if [ ! -f "/app/config/default_config.yaml" ]; then
    warn "Configuration file not found. Using default settings."
else
    log "Configuration file found: /app/config/default_config.yaml"
fi

# Initialize database if it doesn't exist
if [ ! -f "/app/data/openeasd.db" ]; then
    log "Initializing database..."
    python -c "
from src.core.database import DatabaseManager
try:
    db = DatabaseManager('/app/data/openeasd.db')
    print('Database initialized successfully')
except Exception as e:
    print(f'Database initialization failed: {e}')
    exit(1)
    " || {
        error "Database initialization failed!"
        exit 1
    }
else
    log "Database already exists: /app/data/openeasd.db"
fi

# Wait for Prefect server to be ready (if running in compose)
if [ "${PREFECT_API_URL}" != "http://localhost:4200/api" ]; then
    log "Waiting for Prefect server to be ready..."
    timeout=60
    elapsed=0
    
    while ! curl -f "${PREFECT_API_URL}/health" >/dev/null 2>&1; do
        if [ $elapsed -ge $timeout ]; then
            error "Prefect server not ready after ${timeout}s timeout"
            break
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    
    if curl -f "${PREFECT_API_URL}/health" >/dev/null 2>&1; then
        log "Prefect server is ready"
    else
        warn "Prefect server may not be available"
    fi
fi

# Update Nuclei templates
log "Updating Nuclei templates..."
if command -v nuclei >/dev/null 2>&1; then
    nuclei -update-templates -silent || warn "Failed to update Nuclei templates"
    log "Nuclei templates updated"
else
    warn "Nuclei not found in PATH"
fi

# Verify tool installations
log "Verifying security tools..."
tools=("subfinder" "naabu" "nuclei" "nmap")
for tool in "${tools[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        version=$("$tool" --version 2>/dev/null | head -n1 || echo "version unknown")
        log "✓ $tool: $version"
    else
        warn "✗ $tool: not found"
    fi
done

# Set up Python path and verify imports
log "Verifying Python imports..."
python -c "
import sys
sys.path.insert(0, '/app/src')
try:
    from core.database import DatabaseManager
    from core.config_manager import ConfigManager
    from utils.tool_wrapper import ToolManager
    print('✓ All core modules imported successfully')
except ImportError as e:
    print(f'✗ Import error: {e}')
    exit(1)
" || {
    error "Python module import failed!"
    exit 1
}

# Handle different startup modes
case "${1:-}" in
    "prefect-server")
        log "Starting Prefect server..."
        exec prefect server start --host 0.0.0.0
        ;;
    "prefect-agent")
        log "Starting Prefect agent..."
        exec prefect agent start --work-queue default
        ;;
    "scan")
        if [ -z "${2:-}" ]; then
            error "Domain parameter required for scan mode"
            error "Usage: docker run ... scan <domain>"
            exit 1
        fi
        log "Running scan for domain: $2"
        exec python -c "
from prefect_flows.daily_scan_flow import daily_incremental_scan_flow
result = daily_incremental_scan_flow('$2')
print(f'Scan completed: {result}')
        "
        ;;
    "weekly-scan")
        if [ -z "${2:-}" ]; then
            error "Domain parameter required for weekly scan mode"
            exit 1
        fi
        log "Running weekly scan for domain: $2"
        exec python -c "
from prefect_flows.weekly_scan_flow import weekly_full_scan_flow
result = weekly_full_scan_flow('$2')
print(f'Weekly scan completed: {result}')
        "
        ;;
    "shell"|"bash")
        log "Starting interactive shell..."
        exec /bin/bash
        ;;
    "test")
        log "Running tests..."
        cd /app
        exec python -m pytest tests/ -v
        ;;
    *)
        log "Starting OpenEASD main application..."
        
        # Start Prefect server in background if not already running
        if ! curl -f "${PREFECT_API_URL}/health" >/dev/null 2>&1; then
            log "Starting local Prefect server in background..."
            nohup prefect server start --host 0.0.0.0 >/dev/null 2>&1 &
            PREFECT_PID=$!
            
            # Wait for server to start
            log "Waiting for Prefect server to start..."
            sleep 15
            
            # Register cleanup
            trap "kill $PREFECT_PID 2>/dev/null || true" EXIT
        fi
        
        # Execute the provided command or default to main.py
        log "Starting FastAPI application..."
        if [ $# -eq 0 ]; then
            exec python main.py
        else
            exec "$@"
        fi
        ;;
esac