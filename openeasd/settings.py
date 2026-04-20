"""
Django settings for OpenEASD project.

OpenEASD - Automated External Attack Surface Detection
Company: Cybersecify | Author: Rathnakara G N
"""

import os
from pathlib import Path
from decouple import config

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = config("SECRET_KEY", default="django-insecure-change-me-in-production")

JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 60
JWT_REFRESH_TOKEN_EXPIRE_DAYS = 7

DEBUG = config("DEBUG", default=False, cast=bool)

ALLOWED_HOSTS = config("ALLOWED_HOSTS", default="localhost,127.0.0.1,0.0.0.0").split(",")

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
    "django_htmx",
    "django_apscheduler",
    "huey.contrib.djhuey",
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
    "apps.core.api.tokens",
    "apps.domain_security",
    "apps.subfinder",
    "apps.amass",
    "apps.dnsx",
    "apps.naabu",
    # Web tools — disabled for non-web focus (re-enable for full scan)
    "apps.httpx",
    "apps.nmap",
    "apps.tls_checker",
    "apps.ssh_checker",
    "apps.nuclei",
    "apps.nuclei_network",
    "apps.web_checker",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django_htmx.middleware.HtmxMiddleware",
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

MEDIA_URL = "media/"
MEDIA_ROOT = BASE_DIR / "data" / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# APScheduler
APSCHEDULER_DATETIME_FORMAT = "N j, Y, f:s a"
APSCHEDULER_RUN_NOW_TIMEOUT = 25  # seconds

# Scan schedule (24h clock, uses TIME_ZONE above)
SCAN_DAILY_HOUR = config("SCAN_DAILY_HOUR", default=2, cast=int)
SCAN_DAILY_MINUTE = config("SCAN_DAILY_MINUTE", default=0, cast=int)

# Set to False on extra gunicorn workers so only one process runs the scheduler
SCHEDULER_ENABLED = config("SCHEDULER_ENABLED", default=True, cast=bool)

# OpenEASD Configuration
OPENEASD_CONFIG_DIR = BASE_DIR / "config"
OPENEASD_DATA_DIR = BASE_DIR / "data"
OPENEASD_LOGS_DIR = BASE_DIR / "logs"

# Ensure required directories exist at startup
for _dir in [OPENEASD_DATA_DIR, OPENEASD_LOGS_DIR]:
    _dir.mkdir(parents=True, exist_ok=True)

# Huey task queue — uses a separate SQLite DB to avoid write contention
HUEY = {
    "huey_class": "huey.SqliteHuey",
    "name": "openeasd",
    "filename": str(OPENEASD_DATA_DIR / "huey.db"),
    "immediate": False,  # always queue — scans are too long for synchronous execution
    "consumer": {
        "workers": 2,
        "worker_type": "thread",
    },
}

# Scanner timeouts (seconds) — override in .env if needed
SCANNER_DNS_TIMEOUT = config("SCANNER_DNS_TIMEOUT", default=5, cast=int)
SCANNER_HTTP_TIMEOUT = config("SCANNER_HTTP_TIMEOUT", default=10, cast=int)

# Alert channels — set either or both in .env to enable
SLACK_WEBHOOK_URL = config("SLACK_WEBHOOK_URL", default="")
MS_TEAMS_WEBHOOK_URL = config("MS_TEAMS_WEBHOOK_URL", default="")

# Minimum severity to trigger an alert: critical / high / medium / low
ALERT_SEVERITY_THRESHOLD = config("ALERT_SEVERITY_THRESHOLD", default="high")

# Tool paths — ProjectDiscovery tools installed via pdtm at ~/.pdtm/go/bin/
_PDTM_BIN = os.path.expanduser("~/.pdtm/go/bin")
TOOL_SUBFINDER = config("TOOL_SUBFINDER", default=f"{_PDTM_BIN}/subfinder")
TOOL_DNSX = config("TOOL_DNSX", default=f"{_PDTM_BIN}/dnsx")
TOOL_NAABU = config("TOOL_NAABU", default=f"{_PDTM_BIN}/naabu")
TOOL_HTTPX = config("TOOL_HTTPX", default=f"{_PDTM_BIN}/httpx")
TOOL_NMAP = config("TOOL_NMAP", default="nmap")
TOOL_NUCLEI = config("TOOL_NUCLEI", default=f"{_PDTM_BIN}/nuclei")

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
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": BASE_DIR / "logs" / "openeasd.log",
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
    "loggers": {
        "apps": {
            "handlers": ["console", "file"],
            "level": "DEBUG" if DEBUG else "INFO",
            "propagate": False,
        },
        "src": {
            "handlers": ["console"],
            "level": "INFO",
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
LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/accounts/login/"
