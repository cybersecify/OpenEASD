"""
Alert dispatcher for OpenEASD.

Supports Slack (incoming webhook) and Microsoft Teams (Power Automate webhook).
Both channels fire independently — if both are configured, both receive the alert.

Settings required (set in .env):
  SLACK_WEBHOOK_URL      — Slack incoming webhook URL
  MS_TEAMS_WEBHOOK_URL   — Teams Power Automate / Office 365 Connector webhook URL
  ALERT_SEVERITY_THRESHOLD — minimum severity to alert on (default: high)
"""

import logging

import requests
from django.conf import settings
from django.utils import timezone as django_tz

from apps.core.constants import SEVERITY_RANK
from .models import Alert

logger = logging.getLogger(__name__)

SEVERITY_ORDER = SEVERITY_RANK
SEV_COLORS = {"critical": "FF0000", "high": "FF6600", "medium": "FFA500", "low": "0078D7"}


# ---------------------------------------------------------------------------
# Finding aggregation
# ---------------------------------------------------------------------------

def _get_qualifying_findings(session, threshold_level: int) -> list:
    """Return domain findings at or above the threshold severity."""
    from apps.core.findings.models import Finding

    findings = []
    try:
        for f in Finding.objects.filter(session=session, source="domain_security"):
            if SEVERITY_ORDER.get(f.severity, 0) >= threshold_level:
                findings.append({
                    "severity": f.severity,
                    "title": f.title,
                    "host": f.target,
                    "check_type": f.check_type,
                })
    except Exception as e:
        logger.warning(f"[alerts] Could not read findings: {e}")
    return findings


def _group_by_severity(findings: list) -> dict:
    grouped: dict[str, list] = {}
    for f in findings:
        grouped.setdefault(f["severity"], []).append(f)
    return grouped


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------

def _build_slack_payload(session, grouped: dict, threshold: str) -> dict:
    """Build Slack Block Kit message."""
    total = sum(len(v) for v in grouped.values())
    header = f":shield: *OpenEASD Alert* — `{session.domain}`"
    meta = f"Scan #{session.id} | {django_tz.now().strftime('%Y-%m-%d %H:%M')} UTC | threshold: {threshold}"

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": f"Security Alert — {session.domain}"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"{header}\n{meta}\n*{total} finding(s) found*"}},
        {"type": "divider"},
    ]

    for sev in ["critical", "high", "medium", "low"]:
        items = grouped.get(sev, [])
        if not items:
            continue
        emoji = {"critical": ":red_circle:", "high": ":orange_circle:", "medium": ":yellow_circle:", "low": ":white_circle:"}[sev]
        lines = [f"{emoji} *{sev.upper()}* ({len(items)} finding(s))"]
        for f in items[:5]:
            lines.append(f"  • {f['title']} `{f['check_type']}`")
        if len(items) > 5:
            lines.append(f"  _…and {len(items) - 5} more_")
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}})

    return {"blocks": blocks}


def _send_slack(session, grouped: dict, threshold: str) -> tuple[str, str]:
    url = getattr(settings, "SLACK_WEBHOOK_URL", "")
    if not url:
        return "skipped", ""

    payload = _build_slack_payload(session, grouped, threshold)
    # Plain text fallback for notifications
    payload["text"] = f"OpenEASD alert for {session.domain} — {sum(len(v) for v in grouped.values())} finding(s)"

    try:
        resp = requests.post(url, json=payload, timeout=10)
        resp.raise_for_status()
        logger.info(f"[alerts:{session.id}] Slack alert sent")
        return "sent", ""
    except Exception as e:
        logger.error(f"[alerts:{session.id}] Slack failed: {e}")
        return "failed", str(e)


# ---------------------------------------------------------------------------
# Microsoft Teams
# ---------------------------------------------------------------------------

def _build_teams_payload(session, grouped: dict, threshold: str) -> dict:
    """Build Teams Adaptive Card via the legacy Office 365 Connector format (works with Power Automate too)."""
    total = sum(len(v) for v in grouped.values())
    top_sev = next((s for s in ["critical", "high", "medium", "low"] if s in grouped), "low")
    color = SEV_COLORS.get(top_sev, "0078D7")

    facts = []
    for sev in ["critical", "high", "medium", "low"]:
        items = grouped.get(sev, [])
        if not items:
            continue
        titles = ", ".join(f["title"] for f in items[:3])
        if len(items) > 3:
            titles += f" (+{len(items) - 3} more)"
        facts.append({"name": sev.upper(), "value": titles})

    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": color,
        "summary": f"OpenEASD Alert — {session.domain}",
        "sections": [
            {
                "activityTitle": f"**OpenEASD Security Alert** — {session.domain}",
                "activitySubtitle": (
                    f"Scan #{session.id} | "
                    f"{django_tz.now().strftime('%Y-%m-%d %H:%M')} UTC | "
                    f"{total} finding(s) | threshold: {threshold}"
                ),
                "facts": facts,
                "markdown": True,
            }
        ],
    }


def _send_teams(session, grouped: dict, threshold: str) -> tuple[str, str]:
    url = getattr(settings, "MS_TEAMS_WEBHOOK_URL", "")
    if not url:
        return "skipped", ""

    payload = _build_teams_payload(session, grouped, threshold)

    try:
        resp = requests.post(url, json=payload, timeout=10)
        resp.raise_for_status()
        logger.info(f"[alerts:{session.id}] Teams alert sent")
        return "sent", ""
    except Exception as e:
        logger.error(f"[alerts:{session.id}] Teams failed: {e}")
        return "failed", str(e)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def dispatch_alerts(session_id: int, severity_threshold: str = "high") -> None:
    """
    Send alerts to all configured channels (Slack and/or Teams).
    Each channel is attempted independently — one failing does not block the other.
    """
    from apps.core.scans.models import ScanSession
    session = ScanSession.objects.get(id=session_id)
    threshold_level = SEVERITY_ORDER.get(severity_threshold, 3)

    findings = _get_qualifying_findings(session, threshold_level)
    if not findings:
        logger.info(f"[alerts:{session_id}] No findings above '{severity_threshold}' — no alert sent")
        return

    grouped = _group_by_severity(findings)

    # Fire Slack
    slack_status, slack_err = _send_slack(session, grouped, severity_threshold)
    summary = (
        f"{sum(len(v) for v in grouped.values())} finding(s): "
        + ", ".join(f"{sev}={len(items)}" for sev, items in grouped.items())
    )

    if slack_status != "skipped":
        try:
            Alert.objects.create(
                session=session,
                alert_type="slack",
                severity_threshold=severity_threshold,
                message=summary,
                status=slack_status,
                error_message=slack_err,
            )
        except Exception as e:
            logger.error(f"[alerts:{session_id}] Failed to save Slack alert record: {e}")

    # Fire Teams
    teams_status, teams_err = _send_teams(session, grouped, severity_threshold)
    if teams_status != "skipped":
        try:
            Alert.objects.create(
                session=session,
                alert_type="teams",
                severity_threshold=severity_threshold,
                message=summary,
                status=teams_status,
                error_message=teams_err,
            )
        except Exception as e:
            logger.error(f"[alerts:{session_id}] Failed to save Teams alert record: {e}")
