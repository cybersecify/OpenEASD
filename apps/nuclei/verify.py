"""Re-probe verifier for nuclei findings — re-runs the single matched template.

Real finding shape (confirmed by reading apps/nuclei/analyzer.py, not just the
design brief's guess — which for once matched reality): ``analyzer._build_finding``
stores the matched template's id in ``extra["template_id"]`` (copied straight
from nuclei's own "template-id" JSON field) on every nuclei Finding, regardless
of check_type — nuclei only ever emits two check_types here ("cve" when the
template's classification carries CVE ids, else "web"), so there is no
per-check_type family to dispatch on like web_checker/tls_checker/ssh_checker;
one rule covers every nuclei finding.

``finding.target`` is ``_parse_host_target()``'s output (nuclei's own
"matched-at", falling back to "host"). Because collector.py always runs nuclei
with "-type http" against a URL list built from ``URL.objects`` (never bare
hosts/IPs), this is always a full URL — no scheme reconstruction is needed
here, unlike tls_checker/ssh_checker's "ip:port" targets.

Active (touches the target) — gated upstream by DomainAuthorization in
verify_session, same as the tool itself.

collector.py's own ``collect()`` isn't reusable as-is for a single
template/URL re-probe: it always builds the FULL session target list and runs
the FULL template set (or whatever ``-severity`` scopes). So ``_rerun_template``
below is a new, minimal, single-template/single-URL invocation, but it is
built out of collector.py's own conventions rather than a fresh ad hoc
subprocess call: the ``TOOL_NUCLEI`` binary setting, ``run_capped`` (the same
escape-proof timeout wrapper nuclei needs because it can spawn helpers that
escape the process group — see proc.py's docstring), ``-disable-update-check``
(never touch the network for templates mid-verification), and the honest
``OPENEASD_USER_AGENT`` header. It stays a thin, directly patchable wrapper so
tests never invoke the real binary.
"""
import json
import logging

from django.conf import settings

from apps.core.engine.verification.verdict import Verdict
from apps.core.engine.workflows.proc import run_capped

logger = logging.getLogger(__name__)

# Single-template, single-URL re-probe — far below collector.py's full-scan
# TIMEOUT (a whole session's worth of targets and templates); this only ever
# runs one template against one URL.
_TIMEOUT = 60
_REQUEST_TIMEOUT = 5  # seconds per HTTP request (nuclei -timeout)


def _rerun_template(template_id: str, url: str) -> list[dict]:
    """Re-run nuclei with just ``template_id`` against ``url``.

    Returns parsed JSONL hit records in the same shape as collector.collect()
    (raw nuclei JSON dicts, one per match). Raises on binary-missing/timeout/
    other subprocess errors — callers turn any exception into an honest
    INCONCLUSIVE rather than a guess.
    """
    binary = getattr(settings, "TOOL_NUCLEI", "nuclei")
    cmd = [
        binary, "-u", url, "-id", template_id, "-jsonl", "-silent", "-no-color",
        "-disable-update-check",
        "-timeout", str(_REQUEST_TIMEOUT),
        "-retries", "1",
        "-H", f"User-Agent: {getattr(settings, 'OPENEASD_USER_AGENT', 'OpenEASD/1.0')}",
    ]
    result = run_capped(cmd, _TIMEOUT)

    hits = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        try:
            hits.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return hits


def verify_finding(finding) -> Verdict:
    """Re-probe a single nuclei finding by re-running its one matched template.

    Verified iff the same template_id matches again against the finding's
    URL; inconclusive if there's no template_id/target to re-probe with, the
    template no longer matches, or the re-run fails/times out — never a guess.
    """
    template_id = (finding.extra or {}).get("template_id")
    if not template_id or not finding.target:
        return Verdict(Verdict.INCONCLUSIVE, detail="missing template_id or target")

    try:
        hits = _rerun_template(template_id, finding.target)
    except Exception as exc:  # noqa: BLE001 — any re-run failure -> inconclusive, never raise
        return Verdict(Verdict.INCONCLUSIVE, detail=f"nuclei re-run failed: {exc}")

    for hit in hits:
        hit_template = hit.get("template-id") or hit.get("templateID") or ""
        if hit_template == template_id:
            return Verdict(
                Verdict.VERIFIED,
                evidence=f"matched-at {hit.get('matched-at', finding.target)}",
            )
    return Verdict(Verdict.INCONCLUSIVE, detail="template no longer matches")
