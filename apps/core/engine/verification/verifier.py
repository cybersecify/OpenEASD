"""Deterministic finding-verification orchestrator.

Runs at scan finalize (before the issue rollup). Re-probes medium+ findings via
each tool's registered verifier; active re-probes require DomainAuthorization.
Fail-graceful and idempotent. See docs/specs/2026-09-15-finding-verification.md.
"""
import logging

from django.conf import settings
from django.utils import timezone

from apps.core.constants import SEVERITY_RANK
from apps.core.engine.workflows.registry import get_tool_active, get_tool_verifiers

from .verdict import Verdict

logger = logging.getLogger(__name__)


def _meets_threshold(severity: str, threshold: str) -> bool:
    """True if `severity` is at or above `threshold` on SEVERITY_RANK's scale.

    SEVERITY_RANK is higher-is-more-severe (critical=4 ... info=0), so meeting
    a threshold means the finding's rank is >= the threshold's rank. An unknown
    severity ranks below everything (-1); an unknown threshold ranks above
    everything (99) so nothing accidentally qualifies.
    """
    return SEVERITY_RANK.get(severity, -1) >= SEVERITY_RANK.get(threshold, 99)


def _authorized_for(session) -> bool:
    """True if the session's domain has an active DomainAuthorization.

    Mirrors the single source of truth used by the scan-start gate and the
    subscan gate in apps/core/engine/scans/api.py:
    `DomainAuthorization.is_authorized(domain_name)`. Reusing the classmethod
    (rather than re-deriving a .filter(...).exists() query) keeps this in sync
    with any future change to what "authorized" means (see the classmethod's
    own docstring re: F3 drift risk).
    """
    from apps.core.data.domains.models import DomainAuthorization

    return DomainAuthorization.is_authorized(session.domain)


def _apply(finding, verdict: Verdict) -> None:
    finding.verification_status = verdict.verdict
    finding.verified_at = timezone.now() if verdict.verdict == Verdict.VERIFIED else None
    extra = dict(finding.extra or {})
    extra["verification"] = {
        "method": "reprobe",
        "verdict": verdict.verdict,
        "checked_at": timezone.now().isoformat(),
        "evidence": verdict.evidence,
        "detail": verdict.detail,
    }
    finding.extra = extra
    finding.save(update_fields=["verification_status", "verified_at", "extra"])


def verify_session(session, *, threshold: str | None = None) -> None:
    """Re-probe this session's findings at/above `threshold` and record a verdict.

    Fail-graceful: a verifier that raises never propagates — it becomes an
    inconclusive verdict and the scan continues. Idempotent: re-running
    overwrites the three verification fields, never appends. Tools without a
    registered verifier are left "unverified" (never re-probed, never faked).
    Active tools require DomainAuthorization before re-probing; without it the
    finding is marked inconclusive and the verifier is never called.
    """
    threshold = threshold or getattr(settings, "FINDING_VERIFICATION_MIN_SEVERITY", "medium")
    verifiers = get_tool_verifiers()
    active = get_tool_active()
    authorized = None  # computed lazily only if an active tool needs it

    qs = session.findings.exclude(source="scan_coverage")
    n_verified = n_inconclusive = 0
    for f in qs:
        if not _meets_threshold(f.severity, threshold):
            continue
        verifier = verifiers.get(f.source)
        if verifier is None:
            continue  # honestly unverified — no re-prober for this tool
        if active.get(f.source, True):  # active tools need authorization
            if authorized is None:
                authorized = _authorized_for(session)
            if not authorized:
                _apply(f, Verdict(Verdict.INCONCLUSIVE,
                                  detail="verification skipped: no authorization"))
                n_inconclusive += 1
                continue
        try:
            verdict = verifier(f)
        except Exception:  # noqa: BLE001 — fail-graceful; a verifier never fails a scan
            logger.exception("[verify:%s] verifier for %s raised", session.id, f.source)
            verdict = Verdict(Verdict.INCONCLUSIVE, detail="verifier error")
        _apply(f, verdict)
        if verdict.verdict == Verdict.VERIFIED:
            n_verified += 1
        else:
            n_inconclusive += 1

    logger.info("[verify:%s] %d verified / %d inconclusive (threshold=%s)",
                session.id, n_verified, n_inconclusive, threshold)


def verify_one_finding(finding) -> Verdict:
    """Re-verify a single finding on demand (used by the per-finding API).

    Mirrors verify_session's per-finding logic exactly, without the severity
    threshold gate (an explicit on-demand request always runs, regardless of
    severity). Fail-graceful: a raising verifier becomes an inconclusive
    verdict. Active tools require DomainAuthorization before re-probing.
    """
    verifiers = get_tool_verifiers()
    verifier = verifiers.get(finding.source)
    if verifier is None:
        verdict = Verdict(Verdict.INCONCLUSIVE, detail="no verifier for this tool")
    elif get_tool_active().get(finding.source, True) and not _authorized_for(finding.session):
        verdict = Verdict(Verdict.INCONCLUSIVE, detail="verification skipped: no authorization")
    else:
        try:
            verdict = verifier(finding)
        except Exception:  # noqa: BLE001 — fail-graceful; a verifier never fails the request
            logger.exception("[verify:%s] verifier for %s raised", finding.session_id, finding.source)
            verdict = Verdict(Verdict.INCONCLUSIVE, detail="verifier error")
    _apply(finding, verdict)
    return verdict
