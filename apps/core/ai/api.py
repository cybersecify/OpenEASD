"""AI API — config + consent, connection test, audit log.

Credentials are BYOK env-only (D-014): this API returns presence booleans,
never the values. Consent semantics follow D-013 as amended: an explicit
consent_accepted stamp is required to enable; disabling never touches the
recorded consent (revocation = no new calls).
"""

import logging
import time
import uuid as uuid_lib

from ninja import Router, Schema
from ninja.errors import HttpError

from apps.core.api.auth import JWTAuth

logger = logging.getLogger(__name__)

router = Router(auth=JWTAuth())


class ConfigIn(Schema):
    enabled: bool
    consent_accepted: bool = False
    # Credentials are WRITE-ONLY: None = leave unchanged, "" = clear the
    # saved value (falling back to env), anything else = save it.
    cloudflare_account_id: str | None = None
    cloudflare_api_token: str | None = None


def _serialize_config() -> dict:
    from . import client
    from .models import AISettings

    cfg = AISettings.get()
    return {
        "available": client.is_configured(),
        "account_id_set": bool(client.account_id()),
        "api_token_set": bool(client.api_token()),
        "account_id_saved": bool(cfg.cloudflare_account_id.strip()),
        "api_token_saved": bool(cfg.cloudflare_api_token.strip()),
        "enabled": cfg.enabled,
        "consent_given": cfg.consent_given_at is not None,
        "consent_given_at": cfg.consent_given_at.isoformat() if cfg.consent_given_at else None,
        "consent_current": cfg.consent_current,
        "model": client.resolve_model(),
        "triage_enabled": cfg.triage_enabled,
        "orchestration_enabled": cfg.orchestration_enabled,
        "summaries_enabled": cfg.summaries_enabled,
        "max_agent_iterations": cfg.max_agent_iterations,
        "max_subscans_per_scan": cfg.max_subscans_per_scan,
        "max_findings_per_prompt": cfg.max_findings_per_prompt,
    }


@router.get("/config/")
def get_config(request):
    return _serialize_config()


@router.post("/config/")
def save_config(request, data: ConfigIn):
    from . import client
    from .models import AISettings

    cfg = AISettings.get()

    # Save credentials first so "enter credentials + enable" works in one POST.
    cred_fields = []
    if data.cloudflare_account_id is not None:
        cfg.cloudflare_account_id = data.cloudflare_account_id.strip()
        cred_fields.append("cloudflare_account_id")
    if data.cloudflare_api_token is not None:
        cfg.cloudflare_api_token = data.cloudflare_api_token.strip()
        cred_fields.append("cloudflare_api_token")
    if cred_fields:
        cfg.save(update_fields=cred_fields)
        logger.info("[ai] credentials updated (%s) by %s",
                    ", ".join(cred_fields), getattr(request.user, "username", "?"))

    if data.enabled:
        if not client.is_configured():
            raise HttpError(
                400,
                "Add your Cloudflare account ID and API token first (here, or "
                "via CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_API_TOKEN env vars).",
            )
        if not cfg.consent_current and not data.consent_accepted:
            raise HttpError(400, "CONSENT_REQUIRED")
        if data.consent_accepted:
            cfg.record_consent(getattr(request.user, "username", "") or "")
        cfg.enabled = True
        cfg.save(update_fields=["enabled"])
        logger.info("[ai] enabled by %s", getattr(request.user, "username", "?"))
    else:
        # Disabling always succeeds and never touches consent (D-013 4d:
        # revocation = no new calls; the consent record itself is history).
        cfg.enabled = False
        cfg.save(update_fields=["enabled"])
        logger.info("[ai] disabled by %s", getattr(request.user, "username", "?"))

    return _serialize_config()


@router.post("/test/")
def test_connection(request):
    """One trivial Workers AI call to verify the credentials work.

    Allowed before consent: the prompt is a fixed string and carries no scan
    data. Audited like every call (purpose='test', no session).
    """
    from . import client
    from .schemas import SummaryOut

    if not client.is_configured():
        raise HttpError(
            400,
            "Add your Cloudflare account ID and API token first (on this page, "
            "or via CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_API_TOKEN env vars).",
        )

    started = time.monotonic()
    out = client.chat_json(
        [{"role": "user", "content": 'Reply with exactly this JSON object: {"text": "OK"}'}],
        SummaryOut,
        purpose="test",
        max_tokens=50,
    )
    latency_ms = int((time.monotonic() - started) * 1000)
    if out is None:
        raise HttpError(502, "Cloudflare Workers AI call failed — check the audit log for details.")
    return {"ok": True, "model": client.resolve_model(), "latency_ms": latency_ms}


def _serialize_triage(triage) -> dict:
    items = []
    for item in triage.items.select_related("finding").all():
        finding = item.finding
        items.append({
            "rank": item.rank,
            "finding_id": finding.id if finding else None,
            "title": finding.title if finding else item.finding_key.split(":", 2)[-1],
            "severity": finding.severity if finding else None,
            "target": finding.target if finding else None,
            "priority": item.priority,
            "rationale": item.rationale,
        })
    return {
        "summary": triage.overview,
        "model": triage.model,
        "generated_at": triage.created_at.isoformat(),
        "items": items,
    }


def _serialize_decisions(session) -> list[dict]:
    from .models import AgentRun

    run = AgentRun.objects.filter(root_session=session).prefetch_related("actions").first()
    if run is None:
        return []
    return [
        {
            "timestamp": a.created_at.isoformat(),
            "iteration": a.iteration,
            "action": a.action_type,
            "status": a.status,
            "rationale": a.rationale,
            "denial_reason": a.denial_reason or None,
            "subscan_uuid": str(a.subscan_session.uuid) if a.subscan_session else None,
        }
        for a in run.actions.all()
    ]


def _get_session_or_404(session_uuid):
    from apps.core.scans.models import ScanSession

    session = ScanSession.objects.filter(uuid=session_uuid).first()
    if session is None:
        raise HttpError(404, "Scan session not found")
    return session


@router.get("/triage/{session_uuid}/")
def get_triage(request, session_uuid: uuid_lib.UUID):
    from .guard import is_ai_active
    from .models import AITriage

    session = _get_session_or_404(session_uuid)

    if not is_ai_active():
        return {"status": "disabled", "triage": None, "decisions": [], "error": None}

    triage = AITriage.objects.filter(session=session).first()
    decisions = _serialize_decisions(session)

    if triage is None:
        return {"status": "absent", "triage": None, "decisions": decisions, "error": None}
    if triage.status == "running":
        return {"status": "running", "triage": None, "decisions": decisions, "error": None}
    if triage.status == "failed":
        return {
            "status": "failed", "triage": None, "decisions": decisions,
            "error": "Analysis call failed — see the AI Call Log for details.",
        }
    return {
        "status": "complete",
        "triage": _serialize_triage(triage),
        "decisions": decisions,
        "error": None,
    }


@router.post("/triage/{session_uuid}/run/")
def run_triage_now(request, session_uuid: uuid_lib.UUID):
    from .guard import is_ai_active
    from .models import AITriage
    from .tasks import enqueue_triage

    session = _get_session_or_404(session_uuid)

    if not is_ai_active():
        raise HttpError(400, "Enable analysis (with consent) on the AI Analysis page first.")
    if session.status in ("pending", "running"):
        raise HttpError(409, "Scan is still running — triage runs automatically when it finishes.")
    if AITriage.objects.filter(session=session, status="running").exists():
        raise HttpError(409, "A triage run is already in flight for this scan.")

    # In-flight marker so the UI can poll; the task replaces it with the result.
    AITriage.objects.update_or_create(session=session, defaults={"status": "running"})
    enqueue_triage(session.id)
    return {"ok": True, "status": "running"}


@router.get("/audit/")
def list_audit(request, page: int = 1, page_size: int = 25):
    from .models import AIInvocation

    qs = AIInvocation.objects.select_related("session").order_by("-created_at")
    total = qs.count()
    offset = (page - 1) * page_size
    items = qs[offset:offset + page_size]

    return {
        "count": total,
        "page": page,
        "page_size": page_size,
        "results": [
            {
                "id": inv.id,
                "created_at": inv.created_at.isoformat(),
                "session_uuid": str(inv.session_uuid) if inv.session_uuid else None,
                "domain": inv.session.domain if inv.session else None,
                "purpose": inv.purpose,
                "model": inv.model,
                "tokens_in": inv.prompt_tokens,
                "tokens_out": inv.completion_tokens,
                "finding_count": len(inv.finding_ids or []),
                "status": inv.status,
                "duration_ms": inv.duration_ms,
            }
            for inv in items
        ],
    }
