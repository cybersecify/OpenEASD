"""Cloudflare Workers AI client — the ONLY module that talks LLM HTTP.

BYOK (D-014): CLOUDFLARE_ACCOUNT_ID + CLOUDFLARE_API_TOKEN come from the
environment only; with either missing, is_configured() is False and every
caller must behave as if the AI subsystem did not exist.

Design contract (mirrors apps/shodan/collector.py):
  * FAIL-GRACEFUL, ALWAYS. Any timeout / non-200 / exhausted 429 / JSON or
    schema error is logged and returns None; chat_json never raises. AI can
    never fail, delay-classify, or block a scan.
  * Sends the honest OpenEASD User-Agent.
  * AUDIT WITHOUT BODIES: every logical call writes exactly one AIInvocation
    row via _audit(), whose signature takes METADATA ONLY — persisting the
    prompt or response is structurally impossible from here (D-013 4c).
  * Per-scan call budget (CLOUDFLARE_AI_MAX_CALLS_PER_SCAN) is enforced here,
    so no caller can loop past it.
"""

import json
import logging
import time

import requests
from django.conf import settings
from pydantic import ValidationError

from .schemas import json_schema_for

logger = logging.getLogger(__name__)

_MAX_RETRIES = 1  # extra attempts after a 429/5xx
_DEFAULT_BACKOFF = 2  # seconds, when no Retry-After header
_MAX_BACKOFF = 10  # cap the honoured Retry-After so we never stall a scan
_API_BASE = "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/run/{model}"


def _timeout() -> int:
    return getattr(settings, "CLOUDFLARE_AI_TIMEOUT", 60)


def _user_agent() -> str:
    return getattr(settings, "OPENEASD_USER_AGENT", "OpenEASD/1.0")


def account_id() -> str:
    """Effective account id: DB-saved value wins, env var is fallback
    (NotificationConfig webhook precedent)."""
    from .models import AISettings

    saved = AISettings.get().cloudflare_account_id.strip()
    return saved or getattr(settings, "CLOUDFLARE_ACCOUNT_ID", "")


def api_token() -> str:
    """Effective API token: DB-saved value wins, env var is fallback."""
    from .models import AISettings

    saved = AISettings.get().cloudflare_api_token.strip()
    return saved or getattr(settings, "CLOUDFLARE_API_TOKEN", "")


def is_configured() -> bool:
    """Both an account id and an API token are available (DB or env)."""
    return bool(account_id() and api_token())


def resolve_model() -> str:
    """AISettings.model_override (DB) wins over CLOUDFLARE_AI_MODEL (env)."""
    from .models import AISettings

    override = AISettings.get().model_override.strip()
    return override or getattr(
        settings, "CLOUDFLARE_AI_MODEL", "@cf/meta/llama-3.3-70b-instruct-fp8-fast"
    )


def _calls_used(session) -> int:
    from .models import AIInvocation

    return AIInvocation.objects.filter(session_uuid=session.uuid).count()


def _audit(*, session, purpose: str, model: str, status: str, usage: dict | None,
           finding_ids, duration_ms: int | None) -> None:
    """Write one AIInvocation row. Metadata only — no body parameters exist."""
    from .models import AIInvocation

    usage = usage or {}
    try:
        AIInvocation.objects.create(
            session=session,
            session_uuid=session.uuid if session is not None else None,
            purpose=purpose,
            model=model,
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
            total_tokens=usage.get("total_tokens"),
            finding_ids=list(finding_ids or []),
            status=status,
            duration_ms=duration_ms,
        )
    except Exception:  # noqa: BLE001 — an audit hiccup must never break a call path
        logger.exception("ai: failed to write AIInvocation audit row")


def _post_json(url: str, payload: dict) -> tuple[dict | None, str, int]:
    """POST to Workers AI. Returns (parsed envelope | None, status_label,
    duration_ms). Never raises. 429/5xx get one capped-backoff retry.
    status_label in {ok, timeout, http_error, rate_limited, bad_json}.
    """
    headers = {
        "Authorization": f"Bearer {api_token()}",
        "Content-Type": "application/json",
        "User-Agent": _user_agent(),
    }
    started = time.monotonic()

    def _elapsed() -> int:
        return int((time.monotonic() - started) * 1000)

    for attempt in range(_MAX_RETRIES + 1):
        try:
            resp = requests.post(  # nosec B113 — timeout IS set (via _timeout(); bandit can't see through the call)
                url, json=payload, headers=headers, timeout=_timeout()
            )
        except requests.Timeout:
            logger.warning("ai: workers-ai call timed out after %ss", _timeout())
            return None, "timeout", _elapsed()
        except requests.RequestException as exc:
            logger.warning("ai: workers-ai request failed: %s", exc)
            return None, "http_error", _elapsed()

        if resp.status_code == 429 or resp.status_code >= 500:
            label = "rate_limited" if resp.status_code == 429 else "http_error"
            if attempt >= _MAX_RETRIES:
                logger.warning("ai: workers-ai HTTP %s, retries exhausted", resp.status_code)
                return None, label, _elapsed()
            backoff = _DEFAULT_BACKOFF
            retry_after = resp.headers.get("Retry-After")
            if retry_after:
                try:
                    backoff = min(int(retry_after), _MAX_BACKOFF)
                except (ValueError, TypeError):
                    backoff = _DEFAULT_BACKOFF
            time.sleep(backoff)
            continue

        if resp.status_code != 200:
            logger.warning("ai: workers-ai returned HTTP %s", resp.status_code)
            return None, "http_error", _elapsed()

        try:
            return resp.json(), "ok", _elapsed()
        except ValueError:
            logger.warning("ai: workers-ai returned non-JSON body")
            return None, "bad_json", _elapsed()

    return None, "http_error", _elapsed()


def _extract_response(envelope: dict) -> tuple[dict | None, dict | None]:
    """(response_dict, usage) from a Workers AI envelope. response may arrive
    as a dict (json_schema mode) or as a JSON string — handle both."""
    if not isinstance(envelope, dict) or not envelope.get("success", False):
        return None, None
    result = envelope.get("result") or {}
    usage = result.get("usage") if isinstance(result.get("usage"), dict) else None
    response = result.get("response")
    if isinstance(response, dict):
        return response, usage
    if isinstance(response, str):
        try:
            parsed = json.loads(response)
        except ValueError:
            return None, usage
        return (parsed, usage) if isinstance(parsed, dict) else (None, usage)
    return None, usage


def chat_json(messages: list[dict], schema_model, *, purpose: str, session=None,
              finding_ids=(), max_tokens: int = 2048) -> dict | None:
    """One structured-output chat completion against Cloudflare Workers AI.

    Returns the schema-validated dict, or None on any failure. Never raises.
    One corrective retry on schema mismatch (a fresh call, also audited).
    """
    if not is_configured():
        return None

    cap = getattr(settings, "CLOUDFLARE_AI_MAX_CALLS_PER_SCAN", 10)
    if session is not None and _calls_used(session) >= cap:
        logger.warning(
            "ai: per-scan call budget (%s) exhausted for session %s — refusing %s call",
            cap, session.id, purpose,
        )
        return None

    model = resolve_model()
    url = _API_BASE.format(account_id=account_id(), model=model)
    schema = json_schema_for(schema_model)
    attempt_messages = list(messages)

    for schema_attempt in range(2):  # initial + one corrective retry
        payload = {
            "messages": attempt_messages,
            "response_format": {"type": "json_schema", "json_schema": schema},
            "max_tokens": max_tokens,
        }
        envelope, status, duration_ms = _post_json(url, payload)

        if envelope is None:
            _audit(session=session, purpose=purpose, model=model, status=status,
                   usage=None, finding_ids=finding_ids, duration_ms=duration_ms)
            return None

        response, usage = _extract_response(envelope)
        if response is not None:
            try:
                validated = schema_model.model_validate(response)
                _audit(session=session, purpose=purpose, model=model, status="ok",
                       usage=usage, finding_ids=finding_ids, duration_ms=duration_ms)
                return validated.model_dump()
            except ValidationError as exc:
                error_detail = str(exc)[:500]
        else:
            error_detail = "response was not a JSON object"

        _audit(session=session, purpose=purpose, model=model, status="schema_mismatch",
               usage=usage, finding_ids=finding_ids, duration_ms=duration_ms)

        if schema_attempt == 0:
            # Budget the retry too — a corrective call is still a call.
            if session is not None and _calls_used(session) >= cap:
                logger.warning("ai: budget exhausted before schema retry (session %s)", session.id)
                return None
            attempt_messages = attempt_messages + [{
                "role": "user",
                "content": (
                    "Your previous reply did not match the required JSON schema: "
                    f"{error_detail}. Reply with only the JSON object, no prose."
                ),
            }]

    logger.warning("ai: %s call failed schema validation twice — giving up", purpose)
    return None
