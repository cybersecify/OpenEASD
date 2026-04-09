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

DEBUG = config("DEBUG", default=False, cast=bool)

ALLOWED_HOSTS = config("ALLOWED_HOSTS", default="localhost,127.0.0.1,0.0.0.0").split(",")

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
    # Local apps
    "apps.core",
    "apps.scans",
    "apps.subfinder",
    "apps.naabu",
    "apps.nmap",
    "apps.nuclei",
    "apps.dns_analyzer",
    "apps.ssl_checker",
    "apps.email_security",
    "apps.alerts",
    "apps.workflow",
    "apps.domains",
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
        "DIRS": [BASE_DIR / "templates"],
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
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# APScheduler
APSCHEDULER_DATETIME_FORMAT = "N j, Y, f:s a"
APSCHEDULER_RUN_NOW_TIMEOUT = 25  # seconds

# Scan schedule (24h clock, UTC)
SCAN_DAILY_HOUR = config("SCAN_DAILY_HOUR", default=2, cast=int)
SCAN_DAILY_MINUTE = config("SCAN_DAILY_MINUTE", default=0, cast=int)

# OpenEASD Configuration
OPENEASD_CONFIG_DIR = BASE_DIR / "config"
OPENEASD_DATA_DIR = BASE_DIR / "data"
OPENEASD_LOGS_DIR = BASE_DIR / "logs"

# Slack notifications
SLACK_WEBHOOK_URL = config("SLACK_WEBHOOK_URL", default="")
SLACK_BOT_TOKEN = config("SLACK_BOT_TOKEN", default="")
SLACK_CHANNEL = config("SLACK_CHANNEL", default="#security-alerts")

# Alert thresholds
ALERT_SEVERITY_THRESHOLD = config("ALERT_SEVERITY_THRESHOLD", default="high")

# Tool paths (Docker-based by default)
TOOL_SUBFINDER = config("TOOL_SUBFINDER", default="subfinder")
TOOL_NAABU = config("TOOL_NAABU", default="naabu")
TOOL_NMAP = config("TOOL_NMAP", default="nmap")
TOOL_NUCLEI = config("TOOL_NUCLEI", default="nuclei")
USE_DOCKER_TOOLS = config("USE_DOCKER_TOOLS", default=True, cast=bool)

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
