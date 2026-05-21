#!/usr/bin/env bash
# OpenEASD standalone install script
# Supports: Ubuntu 22.04/24.04, Debian 12, macOS 13+
#
# Usage:
#   sudo ./install.sh                 # Linux (full install + systemd)
#   sudo ./install.sh --skip-amass    # skip amass build (saves ~10 min)
#   sudo ./install.sh --no-systemd    # install without systemd services
#        ./install.sh                 # macOS (no sudo needed)

set -euo pipefail

# ── Flags ─────────────────────────────────────────────────────────────
SKIP_AMASS=0
NO_SYSTEMD=0
for arg in "$@"; do
    case "$arg" in
        --skip-amass)  SKIP_AMASS=1 ;;
        --no-systemd)  NO_SYSTEMD=1 ;;
        --help|-h)
            sed -n '2,7p' "$0" | sed 's/^# //'
            exit 0
            ;;
        *) echo "Unknown option: $arg"; exit 1 ;;
    esac
done

# ── Colours ───────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}▸${NC} $*"; }
ok()      { echo -e "${GREEN}✓${NC} $*"; }
warn()    { echo -e "${YELLOW}⚠${NC} $*"; }
section() { echo -e "\n${BOLD}── $* ──────────────────────────────────────${NC}"; }
die()     { echo -e "${RED}✗ ERROR:${NC} $*" >&2; exit 1; }

# ── OS detection ──────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$OSTYPE" == "linux-gnu"* ]] && command -v apt-get &>/dev/null; then
    OS="debian"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    die "Unsupported OS. Only Debian/Ubuntu and macOS are supported."
fi

if [[ "$OS" == "debian" ]]; then
    [[ "$EUID" -ne 0 ]] && die "Run with sudo on Linux: sudo ./install.sh"
    INSTALL_USER="${SUDO_USER:-$USER}"
    [[ "$INSTALL_USER" == "root" ]] && INSTALL_USER="root"
    INSTALL_HOME=$(getent passwd "$INSTALL_USER" | cut -d: -f6)
else
    INSTALL_USER="$USER"
    INSTALL_HOME="$HOME"
    [[ "$EUID" -eq 0 ]] && die "Do not run as root on macOS."
fi

PD_BIN="$INSTALL_HOME/.pdtm/go/bin"
GO_BIN="$INSTALL_HOME/go/bin"

echo ""
echo -e "${BOLD}  OpenEASD — Standalone Install${NC}"
echo "  OS: $OS | User: $INSTALL_USER | Dir: $SCRIPT_DIR"
[[ $SKIP_AMASS -eq 1 ]] && echo "  Flags: --skip-amass"
[[ $NO_SYSTEMD -eq 1 ]] && echo "  Flags: --no-systemd"
echo "  ─────────────────────────────────────────────"

# Helper: run a command as the non-root install user
as_user() {
    if [[ "$INSTALL_USER" == "root" || "$EUID" -ne 0 ]]; then
        bash -c "$*"
    else
        sudo -u "$INSTALL_USER" bash -c "$*"
    fi
}

# Helper: add a line to a file if not already present
append_if_missing() {
    local line="$1" file="$2"
    grep -qxF "$line" "$file" 2>/dev/null || echo "$line" >> "$file"
}

# ──────────────────────────────────────────────────────────────────────
section "1 / 9  System packages"
# ──────────────────────────────────────────────────────────────────────

if [[ "$OS" == "debian" ]]; then
    info "Updating apt..."
    apt-get update -qq

    info "Installing system dependencies..."
    apt-get install -y -qq \
        git curl wget ca-certificates gnupg \
        build-essential gcc \
        python3 python3-pip \
        nmap \
        libcairo2-dev \
        golang-go

    # Node.js 20 LTS via NodeSource
    if ! command -v node &>/dev/null || [[ "$(node -v | cut -d. -f1 | tr -d v)" -lt 18 ]]; then
        info "Installing Node.js 20 LTS..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash - -qq
        apt-get install -y -qq nodejs
    else
        ok "Node.js $(node -v) already installed"
    fi

    ok "System packages installed"

else  # macOS
    if ! command -v brew &>/dev/null; then
        die "Homebrew is required. Install from https://brew.sh"
    fi
    info "Installing system dependencies via Homebrew..."
    brew install nmap go node python@3.12 cairo pkg-config 2>/dev/null || true
    ok "System packages installed"
fi

# ──────────────────────────────────────────────────────────────────────
section "2 / 9  uv (Python package manager)"
# ──────────────────────────────────────────────────────────────────────

if as_user "command -v uv &>/dev/null"; then
    ok "uv already installed: $(as_user 'uv --version')"
else
    info "Installing uv..."
    as_user "curl -LsSf https://astral.sh/uv/install.sh | sh"
    ok "uv installed"
fi

UV_CMD="$INSTALL_HOME/.local/bin/uv"
[[ ! -f "$UV_CMD" ]] && UV_CMD="uv"

# ──────────────────────────────────────────────────────────────────────
section "3 / 9  ProjectDiscovery tools (subfinder, dnsx, naabu, httpx, nuclei)"
# ──────────────────────────────────────────────────────────────────────

if as_user "command -v pdtm &>/dev/null"; then
    ok "pdtm already installed"
else
    info "Installing pdtm..."
    as_user "cd /tmp && curl -sSfL https://github.com/projectdiscovery/pdtm/releases/latest/download/pdtm_\$(uname -s | tr '[:upper:]' '[:lower:]')_\$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').zip -o pdtm.zip && unzip -o pdtm.zip pdtm -d \"\$HOME/.local/bin/\" && rm pdtm.zip && chmod +x \"\$HOME/.local/bin/pdtm\""
fi

PDTM_CMD="$INSTALL_HOME/.local/bin/pdtm"
[[ ! -f "$PDTM_CMD" ]] && PDTM_CMD="pdtm"

for tool in subfinder dnsx naabu httpx nuclei; do
    if [[ -f "$PD_BIN/$tool" ]]; then
        ok "$tool already installed"
    else
        info "Installing $tool..."
        as_user "$PDTM_CMD -i $tool -p '$PD_BIN' 2>/dev/null || $PDTM_CMD -i $tool"
    fi
done

ok "ProjectDiscovery tools ready"

# ──────────────────────────────────────────────────────────────────────
section "4 / 9  Amass"
# ──────────────────────────────────────────────────────────────────────

if [[ $SKIP_AMASS -eq 1 ]]; then
    warn "Skipping amass (--skip-amass). Active subdomain enumeration will be unavailable."
elif as_user "command -v amass &>/dev/null" || [[ -f "$GO_BIN/amass" ]]; then
    ok "amass already installed"
else
    info "Installing amass via go (this takes a few minutes)..."
    as_user "GOPATH=\"$INSTALL_HOME/go\" go install -v github.com/owasp-amass/amass/v4/...@master 2>&1 | tail -3"
    ok "amass installed"
fi

# ──────────────────────────────────────────────────────────────────────
section "5 / 9  Python dependencies"
# ──────────────────────────────────────────────────────────────────────

info "Installing Python dependencies..."
cd "$SCRIPT_DIR"
as_user "cd '$SCRIPT_DIR' && '$UV_CMD' sync"
ok "Python dependencies installed"

# ──────────────────────────────────────────────────────────────────────
section "6 / 9  Frontend build"
# ──────────────────────────────────────────────────────────────────────

info "Installing Node.js packages..."
as_user "cd '$SCRIPT_DIR/frontend' && npm ci --silent"
info "Building frontend..."
as_user "cd '$SCRIPT_DIR/frontend' && npm run build"
ok "Frontend built → frontend/dist/"

# ──────────────────────────────────────────────────────────────────────
section "7 / 9  Environment configuration"
# ──────────────────────────────────────────────────────────────────────

ENV_FILE="$SCRIPT_DIR/.env"

if [[ -f "$ENV_FILE" ]]; then
    ok ".env already exists — skipping generation"
else
    info "Generating .env..."

    # Generate a secure SECRET_KEY
    SECRET_KEY=$(python3 -c "import secrets, string; print(''.join(secrets.choice(string.ascii_letters + string.digits + '!@#\$%^&*(-_=+)') for _ in range(50)))")

    # Detect host IP
    if [[ "$OS" == "debian" ]]; then
        HOST_IP=$(hostname -I | awk '{print $1}')
    else
        HOST_IP=$(ipconfig getifaddr en0 2>/dev/null || echo "127.0.0.1")
    fi

    cat > "$ENV_FILE" <<EOF
# OpenEASD configuration
# Edit ALLOWED_HOSTS and CSRF_TRUSTED_ORIGINS with your actual domain/IP

SECRET_KEY=$SECRET_KEY
DEBUG=False
ALLOWED_HOSTS=localhost,127.0.0.1,$HOST_IP
CSRF_TRUSTED_ORIGINS=http://localhost:8000,http://$HOST_IP:8000

# Database (relative to project root)
DB_NAME=data/openeasd.db

# Tool paths (defaults work if installed via pdtm + brew/apt)
# TOOL_SUBFINDER=$PD_BIN/subfinder
# TOOL_DNSX=$PD_BIN/dnsx
# TOOL_NAABU=$PD_BIN/naabu
# TOOL_HTTPX=$PD_BIN/httpx
# TOOL_NUCLEI=$PD_BIN/nuclei
# TOOL_AMASS=$GO_BIN/amass
# TOOL_NMAP=/usr/bin/nmap
EOF

    chown "$INSTALL_USER" "$ENV_FILE" 2>/dev/null || true
    chmod 600 "$ENV_FILE"
    ok ".env written (SECRET_KEY generated, ALLOWED_HOSTS includes $HOST_IP)"
    warn "Edit .env to add your domain to ALLOWED_HOSTS and CSRF_TRUSTED_ORIGINS before going live"
fi

# ──────────────────────────────────────────────────────────────────────
section "8 / 9  Database setup"
# ──────────────────────────────────────────────────────────────────────

mkdir -p "$SCRIPT_DIR/data" "$SCRIPT_DIR/logs"
chown "$INSTALL_USER" "$SCRIPT_DIR/data" "$SCRIPT_DIR/logs" 2>/dev/null || true

as_user "cd '$SCRIPT_DIR' && '$UV_CMD' run manage.py migrate --run-syncdb"
as_user "cd '$SCRIPT_DIR' && '$UV_CMD' run manage.py collectstatic --noinput --clear"

# Create admin user if no users exist
as_user "cd '$SCRIPT_DIR' && '$UV_CMD' run python - <<'PYEOF'
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'openeasd.settings')
django.setup()
from django.contrib.auth import get_user_model
from apps.core.dashboard.models import UserProfile
U = get_user_model()
if not U.objects.exists():
    u = U.objects.create_superuser('admin', 'admin@localhost', 'admin')
    p, _ = UserProfile.objects.get_or_create(user=u)
    p.must_change_password = True; p.save()
    print('Admin user created (username: admin, password: admin — change on first login)')
else:
    print('Users already exist — skipping admin creation')
PYEOF"

ok "Database ready"

# ──────────────────────────────────────────────────────────────────────
section "9 / 9  Capabilities & services"
# ──────────────────────────────────────────────────────────────────────

if [[ "$OS" == "debian" ]]; then
    # Grant NET_RAW to nmap and naabu so they run without root
    NMAP_BIN=$(command -v nmap 2>/dev/null || echo "")
    NAABU_BIN="$PD_BIN/naabu"

    if [[ -n "$NMAP_BIN" ]]; then
        setcap cap_net_raw+ep "$NMAP_BIN"
        ok "cap_net_raw set on nmap ($NMAP_BIN)"
    fi

    if [[ -f "$NAABU_BIN" ]]; then
        setcap cap_net_raw+ep "$NAABU_BIN"
        ok "cap_net_raw set on naabu ($NAABU_BIN)"
    fi

    if [[ $NO_SYSTEMD -eq 0 ]]; then
        # Resolve absolute uv path for systemd (which doesn't inherit PATH)
        UV_ABS="$INSTALL_HOME/.local/bin/uv"
        [[ ! -f "$UV_ABS" ]] && UV_ABS=$(as_user "command -v uv")

        PD_BIN_ABS="$PD_BIN"
        GO_BIN_ABS="$GO_BIN"
        NMAP_DIR=$(dirname "$NMAP_BIN")

        info "Creating systemd services..."

        cat > /etc/systemd/system/openeasd-web.service <<EOF
[Unit]
Description=OpenEASD web server (gunicorn)
After=network.target
Wants=openeasd-worker.service

[Service]
Type=simple
User=$INSTALL_USER
WorkingDirectory=$SCRIPT_DIR
EnvironmentFile=$ENV_FILE
Environment=PATH=$PD_BIN_ABS:$GO_BIN_ABS:$NMAP_DIR:/usr/local/bin:/usr/bin:/bin
ExecStart=$UV_ABS run gunicorn openeasd.wsgi:application --bind 0.0.0.0:8000 --workers 2 --timeout 120 --access-logfile -
Restart=on-failure
RestartSec=5
StandardOutput=append:$SCRIPT_DIR/logs/web.log
StandardError=append:$SCRIPT_DIR/logs/web.log

[Install]
WantedBy=multi-user.target
EOF

        cat > /etc/systemd/system/openeasd-worker.service <<EOF
[Unit]
Description=OpenEASD background worker (django-q2)
After=network.target

[Service]
Type=simple
User=$INSTALL_USER
WorkingDirectory=$SCRIPT_DIR
EnvironmentFile=$ENV_FILE
Environment=PATH=$PD_BIN_ABS:$GO_BIN_ABS:$NMAP_DIR:/usr/local/bin:/usr/bin:/bin
ExecStart=$UV_ABS run manage.py qcluster
Restart=on-failure
RestartSec=5
StandardOutput=append:$SCRIPT_DIR/logs/worker.log
StandardError=append:$SCRIPT_DIR/logs/worker.log

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        systemctl enable openeasd-web openeasd-worker
        systemctl restart openeasd-web openeasd-worker
        ok "systemd services enabled and started"
    fi

else  # macOS — print launchd / manual start instructions
    warn "macOS: skipping NET_RAW (Homebrew nmap works without it)"
    warn "macOS: no systemd — start manually (see summary below)"
fi

# ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}  ✓ Install complete${NC}"
echo "  ─────────────────────────────────────────────"

if [[ "$OS" == "debian" && $NO_SYSTEMD -eq 0 ]]; then
    echo -e "  App:    ${GREEN}http://$(hostname -I | awk '{print $1}'):8000${NC}"
    echo ""
    echo "  Manage services:"
    echo "    sudo systemctl status openeasd-web openeasd-worker"
    echo "    sudo systemctl restart openeasd-web"
    echo "    sudo journalctl -u openeasd-web -f"
    echo ""
    echo "  Logs:"
    echo "    tail -f $SCRIPT_DIR/logs/web.log"
    echo "    tail -f $SCRIPT_DIR/logs/worker.log"
else
    echo "  Start the app (two terminals):"
    echo ""
    echo "    cd $SCRIPT_DIR"
    echo "    uv run gunicorn openeasd.wsgi:application --bind 0.0.0.0:8000 --workers 2"
    echo ""
    echo "    cd $SCRIPT_DIR"
    echo "    uv run manage.py qcluster"
    echo ""
    echo -e "  App:    ${GREEN}http://localhost:8000${NC}"
fi

echo ""
echo "  First login: admin / admin  (you will be forced to change the password)"
echo "  Edit .env to update ALLOWED_HOSTS and CSRF_TRUSTED_ORIGINS for your domain."
echo ""
