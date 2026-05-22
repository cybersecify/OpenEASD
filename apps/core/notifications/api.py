"""Notifications API — webhook config, alert history, test dispatch."""

import logging

from ninja import Router, Schema
from ninja.errors import HttpError
from ninja_jwt.authentication import JWTAuth

logger = logging.getLogger(__name__)

router = Router(auth=JWTAuth())


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class NotificationConfigIn(Schema):
    slack_webhook_url:  str = ""
    teams_webhook_url:  str = ""
    severity_threshold: str = "high"


class TestIn(Schema):
    channel: str  # "slack" or "teams"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _serialize_config(cfg) -> dict:
    return {
        "slack_configured":    bool(cfg.slack_webhook_url),
        "teams_configured":    bool(cfg.teams_webhook_url),
        # Return URLs so the form can show current values (user set them intentionally)
        "slack_webhook_url":   cfg.slack_webhook_url,
        "teams_webhook_url":   cfg.teams_webhook_url,
        "severity_threshold":  cfg.severity_threshold,
    }


VALID_THRESHOLDS = {"critical", "high", "medium", "low"}


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/config/")
def get_config(request):
    from apps.core.notifications.models import NotificationConfig
    return _serialize_config(NotificationConfig.get())


@router.post("/config/")
def save_config(request, data: NotificationConfigIn):
    from apps.core.notifications.models import NotificationConfig

    if data.severity_threshold not in VALID_THRESHOLDS:
        raise HttpError(400, f"severity_threshold must be one of {sorted(VALID_THRESHOLDS)}")

    cfg = NotificationConfig.get()
    cfg.slack_webhook_url  = data.slack_webhook_url.strip()
    cfg.teams_webhook_url  = data.teams_webhook_url.strip()
    cfg.severity_threshold = data.severity_threshold
    cfg.save()
    logger.info("[notifications] Config updated")
    return _serialize_config(cfg)


@router.post("/test/")
def test_notification(request, data: TestIn):
    """Send a test message to Slack or Teams using the current config."""
    import requests as req_lib
    from apps.core.notifications.dispatcher import _get_slack_url, _get_teams_url

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
    from apps.core.notifications.models import Alert

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
