"""Credentials API — /api/credentials/ (spec C4).

Write-only: the stored key values are NEVER returned — only presence booleans and
a db|env|none source per key. On write, None=unchanged, ""=clear (→ env fallback),
"value"=set.
"""

from ninja import Router, Schema

from apps.core.console.api.auth import JWTAuth

from .models import FIELD_BY_SETTING, ToolCredentials
from .resolver import credential_source

router = Router(auth=JWTAuth())


class CredentialsIn(Schema):
    shodan_api_key: str | None = None
    hibp_api_key: str | None = None
    github_token: str | None = None
    github_secret: str | None = None
    dns_history_api_url: str | None = None


def _serialize() -> dict:
    """Presence booleans + resolution source per key — never the values."""
    cfg = ToolCredentials.get()
    configured = {
        field: bool(getattr(cfg, field, "")) for field in FIELD_BY_SETTING.values()
    }
    source = {field: credential_source(name) for name, field in FIELD_BY_SETTING.items()}
    return {"configured": configured, "source": source}


@router.get("/")
def get_credentials(request):
    return _serialize()


@router.post("/")
def save_credentials(request, data: CredentialsIn):
    cfg = ToolCredentials.get()
    changed = []
    for field in FIELD_BY_SETTING.values():
        value = getattr(data, field)
        if value is not None:  # None = leave unchanged; "" = clear
            setattr(cfg, field, value)
            changed.append(field)
    if changed:
        cfg.save(update_fields=[*changed, "updated_at"])
    return _serialize()
