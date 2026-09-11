"""Notifications API — webhook config, alert history, test dispatch."""

import logging

from ninja import Router, Schema
from ninja.errors import HttpError
from apps.core.console.api.auth import JWTAuth

logger = logging.getLogger(__name__)

router = Router(auth=JWTAuth())


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class NotificationConfigIn(Schema):
    # Write-only, like the credentials/AI config endpoints: None = leave unchanged,
    # "" = clear (→ env-var fallback), "value" = set. Defaulting to None (not "")
    # is what lets the UI save the threshold alone without wiping a stored webhook
    # it can no longer read back.
    slack_webhook_url:  str | None = None
    teams_webhook_url:  str | None = None
    severity_threshold: str | None = None


class TestIn(Schema):
    channel: str  # "slack" or "teams"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _webhook_source(db_value: str, env_setting: str) -> str:
    """Where a webhook resolves from: 'db' | 'env' | 'none' (mirrors the
    credentials resolver's DB-wins-over-env contract)."""
    from django.conf import settings
    if db_value:
        return "db"
    if getattr(settings, env_setting, ""):
        return "env"
    return "none"


def _serialize_config(cfg) -> dict:
    # Webhook URLs are SECRETS — anyone holding one can post into the channel — so
    # they are write-only: never returned. Surface only presence + resolution
    # source, exactly like /api/credentials/ and /api/ai/config/. `*_configured`
    # reflects effective availability (DB or env fallback).
    slack_src = _webhook_source(cfg.slack_webhook_url, "SLACK_WEBHOOK_URL")
    teams_src = _webhook_source(cfg.teams_webhook_url, "MS_TEAMS_WEBHOOK_URL")
    return {
        "slack_configured":    slack_src != "none",
        "teams_configured":    teams_src != "none",
        "slack_source":        slack_src,
        "teams_source":        teams_src,
        "severity_threshold":  cfg.severity_threshold,
    }


VALID_THRESHOLDS = {"critical", "high", "medium", "low"}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/config/")
def get_config(request):
    from apps.core.console.notifications.models import NotificationConfig
    return _serialize_config(NotificationConfig.get())


@router.post("/config/")
def save_config(request, data: NotificationConfigIn):
    from apps.core.console.notifications.models import NotificationConfig

    # Validate before mutating so a bad threshold can't partially apply.
    if data.severity_threshold is not None and data.severity_threshold not in VALID_THRESHOLDS:
        raise HttpError(400, f"severity_threshold must be one of {sorted(VALID_THRESHOLDS)}")

    cfg = NotificationConfig.get()
    changed = []
    # None = unchanged; "" = clear; "value" = set. Only touch fields the caller sent,
    # so saving the threshold alone preserves webhooks the UI can no longer read back.
    if data.severity_threshold is not None:
        cfg.severity_threshold = data.severity_threshold
        changed.append("severity_threshold")
    if data.slack_webhook_url is not None:
        cfg.slack_webhook_url = data.slack_webhook_url.strip()
        changed.append("slack_webhook_url")
    if data.teams_webhook_url is not None:
        cfg.teams_webhook_url = data.teams_webhook_url.strip()
        changed.append("teams_webhook_url")
    if changed:
        cfg.save(update_fields=changed)
        logger.info("[notifications] Config updated (%s)", ", ".join(changed))
    return _serialize_config(cfg)


@router.post("/test/")
def test_notification(request, data: TestIn):
    """Send a test message to Slack or Teams using the current config."""
    import requests as req_lib
    from apps.core.console.notifications.dispatcher import _get_slack_url, _get_teams_url

    channel = data.channel.lower()
    if channel not in ("slack", "teams"):
        raise HttpError(400, "channel must be 'slack' or 'teams'")

    if channel == "slack":
        url = _get_slack_url()
        if not url:
            raise HttpError(400, "Slack webhook URL is not configured")
        payload = {
            "text": ":shield: *OpenEASD test alert* — webhook is working correctly.",
            "blocks": [{
                "type": "section",
                "text": {"type": "mrkdwn", "text": ":shield: *OpenEASD test alert* — Slack integration is configured and working."},
            }],
        }
    else:
        url = _get_teams_url()
        if not url:
            raise HttpError(400, "Teams webhook URL is not configured")
        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": "30c074",
            "summary": "OpenEASD test alert",
            "sections": [{"activityTitle": "**OpenEASD test alert**", "activitySubtitle": "Teams integration is configured and working.", "markdown": True}],
        }

    try:
        resp = req_lib.post(url, json=payload, timeout=10)
        resp.raise_for_status()
        return {"ok": True, "channel": channel}
    except Exception as e:
        raise HttpError(502, f"Webhook delivery failed: {e}")


@router.get("/alerts/")
def list_alerts(request, page: int = 1, page_size: int = 25):
    from apps.core.console.notifications.models import Alert

    qs = Alert.objects.select_related("session").order_by("-sent_at")
    total = qs.count()
    offset = (page - 1) * page_size
    items = qs[offset:offset + page_size]

    return {
        "count": total,
        "page": page,
        "page_size": page_size,
        "results": [
            {
                "id":                a.id,
                "domain":            a.session.domain,
                "session_uuid":      str(a.session.uuid),
                "alert_type":        a.alert_type,
                "severity_threshold": a.severity_threshold,
                "status":            a.status,
                "message":           a.message,
                "error_message":     a.error_message,
                "sent_at":           a.sent_at.isoformat(),
            }
            for a in items
        ],
    }
