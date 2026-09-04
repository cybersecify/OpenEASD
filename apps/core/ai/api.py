"""AI API — config + consent, connection test, audit log.

Credentials are BYOK env-only (D-014): this API returns presence booleans,
never the values. Consent semantics follow D-013 as amended: an explicit
consent_accepted stamp is required to enable; disabling never touches the
recorded consent (revocation = no new calls).
"""

import logging
import time

from ninja import Router, Schema
from ninja.errors import HttpError

from apps.core.api.auth import JWTAuth

logger = logging.getLogger(__name__)

router = Router(auth=JWTAuth())


class ConfigIn(Schema):
    enabled: bool
    consent_accepted: bool = False


def _serialize_config() -> dict:
    from django.conf import settings

    from . import client
    from .models import AISettings

    cfg = AISettings.get()
    return {
        "available": client.is_configured(),
        "account_id_set": bool(getattr(settings, "CLOUDFLARE_ACCOUNT_ID", "")),
        "api_token_set": bool(getattr(settings, "CLOUDFLARE_API_TOKEN", "")),
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

    if data.enabled:
        if not client.is_configured():
            raise HttpError(
                400,
                "Set CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN in the "
                "environment first (they are never stored in the database).",
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
            "Set CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN in the environment first.",
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
