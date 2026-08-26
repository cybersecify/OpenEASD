"""gitleaks result analysis — maps report records to unified Finding model.

gitleaks JSON report format (one object per leak):
{
  "RuleID": "aws-access-token",
  "Description": "AWS Access Key",
  "File": "/tmp/xxxx/3.js",
  "Secret": "AKIA................",
  "Match": "aws_key = \"AKIA................\"",
  "StartLine": 42,
  ...
}

Redaction is a hard requirement: the full secret must never land in the DB or
report. We store only a redacted preview of the secret and a scrubbed match.
"""

import logging

from apps.core.findings.models import Finding

logger = logging.getLogger(__name__)


def _redact(value) -> str:
    """Redact a secret/match so the full value never leaves this function.

    Short values are fully masked; longer ones keep a tiny prefix/suffix so an
    operator can eyeball-match without the plaintext being recoverable.
    """
    if not value:
        return ""
    value = str(value)
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}***{value[-2:]} ({len(value)} chars)"


def _scrub_match(match, secret) -> str:
    """Return a truncated match with the raw secret removed."""
    if not match:
        return ""
    match = str(match)
    if secret:
        match = match.replace(str(secret), _redact(secret))
    return match[:120]


def _build_finding(session, rec: dict, url_fk=None) -> Finding:
    rule_id = rec.get("RuleID") or rec.get("Description") or "unknown-rule"
    source_url = rec.get("_source_url") or ""
    secret = rec.get("Secret") or ""
    match = rec.get("Match") or ""
    start_line = rec.get("StartLine")

    title = f"Hardcoded secret in JavaScript ({rule_id})"
    if len(title) > 250:
        title = title[:247] + "..."

    description = (
        f"gitleaks rule '{rule_id}' matched a likely hardcoded secret in the "
        f"JavaScript asset served at {source_url or 'an unknown URL'}. "
        f"Secrets shipped in client-served code are readable by anyone who "
        f"loads the page."
    )

    return Finding(
        session=session,
        source="js_secrets",
        check_type="exposed_secret",
        severity="high",
        title=title,
        description=description,
        remediation=(
            "Rotate the exposed credential and remove it from client-served "
            "code. Move secrets to server-side configuration and never ship "
            "them in JavaScript bundles."
        ),
        url=url_fk,
        target=source_url[:255],
        extra={
            "rule_id": rule_id,
            "description": rec.get("Description", ""),
            "source_url": source_url,
            "line": start_line,
            "secret_preview": _redact(secret),
            "match_preview": _scrub_match(match, secret),
        },
    )


def analyze(session, records: list[dict]) -> list[Finding]:
    """Build Finding objects from gitleaks records.

    Deduplicates by (RuleID, source URL) — gitleaks can report the same rule
    firing on the same file more than once. Links to the URL asset when the
    JS URL is a known URL row for this session.
    """
    from apps.core.web_assets.models import URL

    if not records:
        return []

    url_map = {u.url: u for u in URL.objects.filter(session=session)}

    seen: set[tuple[str, str]] = set()
    findings: list[Finding] = []

    for rec in records:
        rule_id = rec.get("RuleID") or rec.get("Description") or "unknown-rule"
        source_url = rec.get("_source_url") or ""
        dedup_key = (rule_id, source_url)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        url_fk = url_map.get(source_url)
        findings.append(_build_finding(session, rec, url_fk))

    logger.info(
        f"[js_secrets:{session.id}] {len(findings)} secret findings "
        f"({len(records) - len(findings)} duplicates removed)"
    )
    return findings
