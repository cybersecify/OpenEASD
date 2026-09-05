"""GitHub-secret analysis — maps gitleaks records to unified Findings.

Uses the SAME ``check_type="exposed_secret"`` as js_secrets so both secret
sources group together in the report, and REUSES js_secrets' redaction verbatim
(``_redact`` / ``_scrub_match``) — copied here rather than imported because tools
never import from each other (shared data flows through core). The hard rule
holds: the full secret must NEVER land in the DB or the report; only a redacted
preview + a scrubbed match are stored.

gitleaks JSON report format (one object per leak):
{
  "RuleID": "aws-access-token",
  "Description": "AWS Access Key",
  "File": "/tmp/xxxx/3.txt",
  "Secret": "AKIA................",
  "Match": "aws_key = \"AKIA................\"",
  "StartLine": 42,
  ...
}
"""

import logging

from apps.core.findings.models import Finding

logger = logging.getLogger(__name__)


def _redact(value) -> str:
    """Redact a secret/match so the full value never leaves this function.

    Short values are fully masked; longer ones keep a tiny prefix/suffix so an
    operator can eyeball-match without the plaintext being recoverable.
    (Verbatim from apps/js_secrets/analyzer.py.)
    """
    if not value:
        return ""
    value = str(value)
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}***{value[-2:]} ({len(value)} chars)"


def _scrub_match(match, secret) -> str:
    """Return a truncated match with the raw secret removed.
    (Verbatim from apps/js_secrets/analyzer.py.)"""
    if not match:
        return ""
    match = str(match)
    if secret:
        match = match.replace(str(secret), _redact(secret))
    return match[:120]


def _build_finding(session, rec: dict) -> Finding:
    rule_id = rec.get("RuleID") or rec.get("Description") or "unknown-rule"
    source_url = rec.get("_source_url") or ""
    repo = rec.get("_repo") or ""
    secret = rec.get("Secret") or ""
    match = rec.get("Match") or ""
    start_line = rec.get("StartLine")

    title = f"Secret exposed in public GitHub ({rule_id})"
    if len(title) > 250:
        title = title[:247] + "..."

    where = f"the public GitHub repository {repo}" if repo else "a public GitHub repository"
    description = (
        f"gitleaks rule '{rule_id}' matched a likely hardcoded secret in {where}"
        f"{' at ' + source_url if source_url else ''}. Secrets committed to public "
        f"GitHub are readable by anyone and are routinely harvested by automated "
        f"scanners within minutes of being pushed."
    )

    return Finding(
        session=session,
        source="github_secrets",
        check_type="exposed_secret",
        severity="high",
        title=title,
        description=description,
        remediation=(
            "Treat the credential as compromised: rotate it immediately, then "
            "purge it from the repository's history (it stays in git history even "
            "after deletion). Move secrets to server-side configuration or a "
            "secrets manager and never commit them."
        ),
        target=source_url[:255] or repo[:255],
        extra={
            "rule_id": rule_id,
            "description": rec.get("Description", ""),
            "repo": repo,
            "source_url": source_url,
            "line": start_line,
            "origin": "github",
            "secret_preview": _redact(secret),
            "match_preview": _scrub_match(match, secret),
        },
    )


def analyze(session, records: list[dict]) -> list[Finding]:
    """Build Finding objects from gitleaks records.

    Deduplicates by (RuleID, source URL, line) — the same rule can fire on the
    same file more than once, and the same secret can appear in multiple repos.
    """
    if not records:
        return []

    seen: set[tuple] = set()
    findings: list[Finding] = []

    for rec in records:
        if not isinstance(rec, dict):
            continue
        rule_id = rec.get("RuleID") or rec.get("Description") or "unknown-rule"
        source_url = rec.get("_source_url") or ""
        line = rec.get("StartLine")
        dedup_key = (rule_id, source_url, line)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        findings.append(_build_finding(session, rec))

    logger.info(
        "[github_secrets:%s] %d secret finding(s) (%d duplicates removed)",
        session.id, len(findings), len(records) - len(findings),
    )
    return findings
