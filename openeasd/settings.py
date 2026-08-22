"""
Django settings for OpenEASD project.

OpenEASD - Automated External Attack Surface Detection
Company: Cybersecify | Author: Rathnakara G N
"""

import sys
from datetime import timedelta
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from decouple import config

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = config("SECRET_KEY", default="django-insecure-change-me-in-production")

DEBUG = config("DEBUG", default=False, cast=bool)


def _validate_secret_key(secret_key: str, debug: bool) -> None:
    """Fail fast in production on an unset/placeholder SECRET_KEY.

    The key also signs JWTs (NINJA_JWT["SIGNING_KEY"] below), so the well-known
    default would let anyone forge access/refresh tokens for any user. DEBUG
    builds keep the default for local dev.
    """
    if not debug and secret_key.startswith("django-insecure"):
        raise ImproperlyConfigured(
            "SECRET_KEY is unset or still the insecure default while DEBUG=False. "
            "Generate one with `openssl rand -hex 32` and set it via the SECRET_KEY "
            "environment variable. This key also signs JWT access/refresh tokens, so "
            "the default value allows anyone to forge authentication tokens."
        )


# Skip enforcement under the test runner: pytest-django imports settings before
# any conftest/env hook can set a key, and token-signing key strength is
# irrelevant to tests. The logic itself is covered by unit tests that call
# _validate_secret_key directly.
if "pytest" not in sys.modules:
    _validate_secret_key(SECRET_KEY, DEBUG)

ALLOWED_HOSTS = config("ALLOWED_HOSTS", default="localhost,127.0.0.1").split(",")

# --- Production HTTPS / security hardening (DEBUG=False only) ---
def _security_settings(debug: bool) -> dict:
    """Production security flags. Pure + testable (see test_settings_security).

    - SECURE_PROXY_SSL_HEADER is always set: behind a TLS-terminating proxy
      (Caddy/nginx/Cloudflare) it lets Django see the original HTTPS scheme; with
      no proxy it is simply never matched, so it is harmless.
    - The rest apply only outside DEBUG. Cookies are secure-by-default (an
      HTTP-only deploy should fix TLS, not weaken this). SSL redirect + HSTS
      default OFF because enabling them before TLS is terminated breaks the site
      (redirect loop / HSTS pin) — turn them on via env once TLS is in front.
    """
    flags = {"SECURE_PROXY_SSL_HEADER": ("HTTP_X_FORWARDED_PROTO", "https")}
    if not debug:
        flags.update(
            SESSION_COOKIE_SECURE=config("SESSION_COOKIE_SECURE", default=True, cast=bool),
            CSRF_COOKIE_SECURE=config("CSRF_COOKIE_SECURE", default=True, cast=bool),
            SECURE_CONTENT_TYPE_NOSNIFF=True,
            SECURE_SSL_REDIRECT=config("SECURE_SSL_REDIRECT", default=False, cast=bool),
            SECURE_HSTS_SECONDS=config("SECURE_HSTS_SECONDS", default=0, cast=int),
            SECURE_HSTS_INCLUDE_SUBDOMAINS=config("SECURE_HSTS_INCLUDE_SUBDOMAINS", default=True, cast=bool),
            SECURE_HSTS_PRELOAD=config("SECURE_HSTS_PRELOAD", default=False, cast=bool),
        )
    return flags


globals().update(_security_settings(DEBUG))

# Allow Vite dev server to make CSRF-protected POST requests in development
CSRF_TRUSTED_ORIGINS = config(
    "CSRF_TRUSTED_ORIGINS",
    default="http://localhost:5173,http://127.0.0.1:5173",
).split(",")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Third party
    "django_q",
    # Local apps
    "apps.core.dashboard",
    "apps.core.assets",
    "apps.core.web_assets",
    "apps.core.service_detection",
    "apps.core.findings",
    "apps.core.scans",
    "apps.core.domains",
    "apps.core.workflows",
    "apps.core.scheduler",
    "apps.core.notifications",
    "apps.core.insights",
    "apps.core.reports",
    "ninja_jwt",
    "ninja_jwt.token_blacklist",
    "apps.domain_security",
    "apps.hudson_rock",
    "apps.subfinder",
    "apps.amass",
    "apps.asn_discovery",
    "apps.alterx",
    "apps.dnsx",
    "apps.takeover_check",
    "apps.cloud_assets",
    "apps.naabu",
    # Web tools — disabled for non-web focus (re-enable for full scan)
    "apps.httpx",
    "apps.historical_urls",
    "apps.katana",
    "apps.nmap",
    "apps.tls_checker",
    "apps.ssh_checker",
    "apps.nuclei",
    "apps.nuclei_network",
    "apps.web_checker",
    "apps.js_secrets",
    "apps.cve_intel",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "openeasd.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates", BASE_DIR / "frontend" / "dist"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "openeasd.wsgi.application"
ASGI_APPLICATION = "openeasd.asgi.application"

# Database
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / config("DB_NAME", default="data/openeasd.db"),
        "OPTIONS": {
            "timeout": 30,  # seconds to wait for write lock under concurrent phase execution
        },
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Kolkata"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [
    BASE_DIR / "frontend" / "dist",
]
STORAGES = {
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

MEDIA_URL = "media/"
MEDIA_ROOT = BASE_DIR / "data" / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Scan schedule (24h clock, uses TIME_ZONE above)
SCAN_DAILY_HOUR = config("SCAN_DAILY_HOUR", default=2, cast=int)
SCAN_DAILY_MINUTE = config("SCAN_DAILY_MINUTE", default=0, cast=int)

# Set to False on extra gunicorn workers so only one process runs the scheduler
SCHEDULER_ENABLED = config("SCHEDULER_ENABLED", default=True, cast=bool)

# Master switch for unattended scanning (daily scan + per-domain monitoring).
# Default True preserves self-hosted behaviour. Set False for a manual-only
# deployment (e.g. a managed instance that must never scan without an explicit,
# per-request approval) — no auto-scan schedules are registered, and any that
# already exist are removed on the next scheduler startup. Manual/API scans are
# unaffected. Independent of the authorization gate below, which blocks
# unauthorized domains even when this is True.
SCHEDULED_SCANS_ENABLED = config("SCHEDULED_SCANS_ENABLED", default=True, cast=bool)

# OpenEASD Configuration
OPENEASD_CONFIG_DIR = BASE_DIR / "config"
OPENEASD_DATA_DIR = BASE_DIR / "data"
OPENEASD_LOGS_DIR = BASE_DIR / "logs"

# Ensure required directories exist at startup
for _dir in [OPENEASD_DATA_DIR, OPENEASD_LOGS_DIR]:
    _dir.mkdir(parents=True, exist_ok=True)

# Django-Q2 task queue — ORM broker uses the existing Django DB (SQLite)
#
# Timer alignment (all three must agree or scans die mid-run):
#   timeout  — worker hard-kill; MUST exceed a real full scan's wall-clock.
#   retry    — re-queue window; MUST be > timeout or the broker re-runs a task
#              that is still executing. max_attempts:1 makes this moot but the
#              constraint is enforced anyway.
#   watchdog — reap_stuck_scans (SCAN_TIMEOUT_MINUTES) must be >= timeout so it
#              only reaps genuinely orphaned scans (dead worker), never a healthy
#              long-running one.
# The old defaults (timeout 3600 / retry 7200) killed every large scan: a full
# scan runs past 1h, timeout kills it, then retry re-queues a zombie at exactly
# 2h. max_attempts:1 is the real "no retries" switch the retry comment claimed.
# Derived, not guessed: the worst-case sum of per-tool caps (same-phase tools run
# in parallel) is ~3.4h — dominated by nuclei_network's 1h cap in phase 7. Set the
# worker hard-kill above that ceiling so "every tool within its cap => scan always
# completes" is a guarantee, not a hope. 4h leaves ~35m margin over the ceiling.
Q_TASK_TIMEOUT = config("Q_TASK_TIMEOUT", default=14400, cast=int)   # 4h hard cap per scan task
Q_TASK_RETRY = config("Q_TASK_RETRY", default=Q_TASK_TIMEOUT + 1200, cast=int)
# Guard: retry <= timeout causes the broker to re-run a task while it's still
# running. Force retry strictly above timeout regardless of env misconfiguration.
if Q_TASK_RETRY <= Q_TASK_TIMEOUT:
    Q_TASK_RETRY = Q_TASK_TIMEOUT + 1200

Q_CLUSTER = {
    "name": "openeasd",
    "workers": 1,       # SQLite is single-writer; >1 workers causes race conditions on task pickup
    "orm": "default",   # uses Django DB — no Redis needed
    "timeout": Q_TASK_TIMEOUT,
    "retry": Q_TASK_RETRY,
    "max_attempts": 1,  # a killed scan is dead, not retried — never re-queue it
    "catch_up": False,  # skip missed tasks on worker restart
}

# Scanner timeouts (seconds) — override in .env if needed
SCANNER_DNS_TIMEOUT = config("SCANNER_DNS_TIMEOUT", default=5, cast=int)
SCANNER_HTTP_TIMEOUT = config("SCANNER_HTTP_TIMEOUT", default=10, cast=int)

# Alert channels — set either or both in .env to enable
SLACK_WEBHOOK_URL = config("SLACK_WEBHOOK_URL", default="")
MS_TEAMS_WEBHOOK_URL = config("MS_TEAMS_WEBHOOK_URL", default="")

# Minimum severity to trigger an alert: critical / high / medium / low
ALERT_SEVERITY_THRESHOLD = config("ALERT_SEVERITY_THRESHOLD", default="high")

# Report CTA — optional call-to-action rendered at the end of PDF and CSV
# exports. Both default to empty (self-hosters get a clean report with no
# upsell). Operators of hosted-snapshot deployments can set these to point
# report readers at a follow-up resource. The CTA block is rendered only
# when BOTH url and text are non-empty.
REPORT_CTA_URL = config("REPORT_CTA_URL", default="")
REPORT_CTA_TEXT = config("REPORT_CTA_TEXT", default="")

# Tool paths — defaults resolve via PATH so the same setting works for:
#   - Container deploys (tools in /usr/local/bin, per Dockerfile)
#   - Local dev with pdtm (~/.pdtm/go/bin is added to PATH by pdtm install)
#   - Local dev with system-installed tools (apt/brew/go install — anywhere on PATH)
# Override individually via env (TOOL_SUBFINDER=/full/path) when PATH won't do.
TOOL_SUBFINDER = config("TOOL_SUBFINDER", default="subfinder")
TOOL_DNSX = config("TOOL_DNSX", default="dnsx")
TOOL_NAABU = config("TOOL_NAABU", default="naabu")
TOOL_HTTPX = config("TOOL_HTTPX", default="httpx")
TOOL_GAU = config("TOOL_GAU", default="gau")
TOOL_WAYBACKURLS = config("TOOL_WAYBACKURLS", default="waybackurls")
TOOL_KATANA = config("TOOL_KATANA", default="katana")
TOOL_NMAP = config("TOOL_NMAP", default="nmap")
TOOL_NUCLEI = config("TOOL_NUCLEI", default="nuclei")
TOOL_AMASS = config("TOOL_AMASS", default="amass")
TOOL_ALTERX = config("TOOL_ALTERX", default="alterx")
TOOL_CLOUD_ENUM = config("TOOL_CLOUD_ENUM", default="cloud_enum")
TOOL_GITLEAKS = config("TOOL_GITLEAKS", default="gitleaks")

# Honest scanner identity. Sent as the User-Agent on the tools that probe the
# target's web surface (httpx, katana, nuclei) so a customer can deliberately
# allowlist us. Some nuclei templates hard-set their own UA; those are not
# overridden. See docs/specs/2026-08-16-waf-coverage-honest-scope.md (C3).
OPENEASD_USER_AGENT = config(
    "OPENEASD_USER_AGENT",
    default="OpenEASD/1.0 (+https://cybersecify.com/openeasd)",
)

# Low-memory mode for small hosts (≈1 GB RAM). When true, same-phase tools run
# sequentially instead of concurrently (bounds peak memory) and nuclei uses a
# lower concurrency/rate-limit. Prevents the kernel OOM-killing nuclei/amass on
# a 1 GB droplet, at the cost of a slower scan. See the deploy docs.
LOW_MEMORY = config("OPENEASD_LOW_MEMORY", default=False, cast=bool)

# Hudson Rock (Cavalier) OSINT API base — free, keyless infostealer-exposure
# intelligence. OSS use permitted by Hudson Rock co-founder Alon Gal. Overridable
# for testing / self-hosting.
HUDSON_ROCK_BASE_URL = config(
    "HUDSON_ROCK_BASE_URL",
    default="https://cavalier.hudsonrock.com/api/json/v2/osint-tools",
)

# Build provenance — baked into the image at build time (see Dockerfile ARG/ENV
# + the CI publish job's build-args). Lets a deployer verify exactly what
# version/commit/date the running image was built from, via GET /health/ and
# GET /api/version/. Defaults render cleanly for local (non-image) runs.
OPENEASD_VERSION = config("OPENEASD_VERSION", default="dev")
OPENEASD_GIT_SHA = config("OPENEASD_GIT_SHA", default="unknown")
OPENEASD_BUILD_DATE = config("OPENEASD_BUILD_DATE", default="unknown")

# Logging
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{asctime} {levelname} {name} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
            "level": "WARNING",
        },
        "console_access": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
            "level": "INFO",
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": BASE_DIR / "logs" / "openeasd.log",
            "formatter": "verbose",
            "level": "DEBUG",
        },
    },
    "root": {
        "handlers": ["console", "file"],
        "level": "INFO",
    },
    "loggers": {
        "apps": {
            "handlers": ["console", "file"],
            "level": "DEBUG" if DEBUG else "INFO",
            "propagate": False,
        },
        "src": {
            "handlers": ["file"],
            "level": "INFO",
            "propagate": False,
        },
        "django_q": {
            "handlers": ["file"],
            "level": "INFO",
            "propagate": False,
        },
        "django.server": {
            "handlers": ["console_access", "file"],
            "level": "INFO",
            "propagate": False,
        },
        "django.request": {
            "handlers": ["console", "file"],
            "level": "WARNING",
            "propagate": False,
        },
        "weasyprint": {
            "handlers": ["file"],
            "level": "WARNING",
            "propagate": False,
        },
        "fontTools": {
            "handlers": ["file"],
            "level": "WARNING",
            "propagate": False,
        },
    },
}

# Caches
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}


# Auth
LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/login/"

# ninja-jwt token configuration
NINJA_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=60),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "ROTATE_REFRESH_TOKENS": False,
    "BLACKLIST_AFTER_ROTATION": False,
    "UPDATE_LAST_LOGIN": False,
}

# Enable WAL journal mode for SQLite so parallel phase-7 tool threads
# can write concurrently without hitting "database is locked" errors.
from django.db.backends.signals import connection_created  # noqa: E402


def _set_sqlite_wal(sender, connection, **kwargs):
    if connection.vendor == "sqlite":
        connection.cursor().execute("PRAGMA journal_mode=WAL;")


connection_created.connect(_set_sqlite_wal)
