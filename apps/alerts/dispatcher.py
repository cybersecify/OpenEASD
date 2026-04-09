import logging

from django.conf import settings
from django.utils import timezone as django_tz

from .models import Alert

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _get_all_findings(session, threshold_level: int) -> list:
    """Aggregate findings above threshold from all tool apps."""
    findings = []

    try:
        for f in session.nuclei_findings.all():
            if SEVERITY_ORDER.get(f.severity, 0) >= threshold_level:
                findings.append({"severity": f.severity, "title": f.template_name or f.template_id, "host": f.host})
    except Exception:
        pass

    try:
        for f in session.domain_findings.all():
            if SEVERITY_ORDER.get(f.severity, 0) >= threshold_level:
                findings.append({"severity": f.severity, "title": f.title, "host": f.domain})
    except Exception:
        pass

    return findings


def dispatch_alerts(session_id: int, severity_threshold: str = "high"):
    from apps.scans.models import ScanSession
    session = ScanSession.objects.get(id=session_id)
    threshold_level = SEVERITY_ORDER.get(severity_threshold, 3)

    qualifying = _get_all_findings(session, threshold_level)
    if not qualifying:
        logger.info(f"[alerts:{session_id}] No findings above {severity_threshold} threshold")
        return

    grouped: dict[str, list] = {}
    for f in qualifying:
        grouped.setdefault(f["severity"], []).append(f)

    lines = [
        f"*OpenEASD Security Alert* — {session.domain}",
        f"Scan #{session_id} | {django_tz.now().strftime('%Y-%m-%d %H:%M UTC')}",
        "",
    ]
    for sev in ["critical", "high", "medium", "low"]:
        if sev in grouped:
            lines.append(f"*{sev.upper()}* ({len(grouped[sev])} findings)")
            for f in grouped[sev][:5]:
                lines.append(f"  • {f['title']} @ {f['host']}")
            if len(grouped[sev]) > 5:
                lines.append(f"  … and {len(grouped[sev]) - 5} more")
            lines.append("")

    full_message = "\n".join(lines)
    slack_url = settings.SLACK_WEBHOOK_URL
    alert_status = "pending"
    error_msg = ""

    if slack_url:
        try:
            import httpx
            resp = httpx.post(slack_url, json={"text": full_message}, timeout=10)
            resp.raise_for_status()
            alert_status = "sent"
            logger.info(f"[alerts:{session_id}] Slack alert sent")
        except Exception as e:
            alert_status = "failed"
            error_msg = str(e)
            logger.error(f"[alerts:{session_id}] Slack alert failed: {e}")

    Alert.objects.create(
        session=session,
        alert_type="slack",
        severity_threshold=severity_threshold,
        message=full_message,
        status=alert_status,
        error_message=error_msg,
    )
