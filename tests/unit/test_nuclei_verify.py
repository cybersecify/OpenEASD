"""Tests for the nuclei re-probe verifier.

Real finding shape (confirmed by reading apps/nuclei/analyzer.py): unlike the
web_checker/tls_checker/ssh_checker verifiers, the design brief's guess here
matched reality — ``analyzer._build_finding`` stores the matched template's
id in ``extra["template_id"]`` (nuclei's own "template-id" field) on every
nuclei Finding, regardless of check_type (only two check_types exist: "cve"
when the template carries CVE ids, else "web"). ``finding.target`` is
``_parse_host_target()``'s output (nuclei's "matched-at", falling back to
"host") which, because collector.py only ever runs nuclei with "-type http"
against URLs, is always a full URL — no scheme reconstruction needed.
"""
import pytest
from unittest.mock import patch


def _finding(check_type="cve", target="https://example.com", extra=None):
    from apps.core.data.findings.models import Finding
    from apps.core.engine.scans.models import ScanSession
    s = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
    return Finding.objects.create(
        session=s, source="nuclei", check_type=check_type,
        severity="high", title="CVE-2024-1234", target=target,
        extra=extra if extra is not None else {"template_id": "CVE-2024-1234"},
    )


@pytest.mark.django_db
def test_template_matches_again_is_verified():
    from apps.nuclei.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.nuclei.verify._rerun_template",
               return_value=[{"template-id": "CVE-2024-1234", "matched-at": "https://example.com/x"}]):
        v = verify_finding(f)
    assert v.verdict == Verdict.VERIFIED
    # Exact evidence for the mocked hit (avoids a bare-host substring check).
    assert v.evidence == "matched-at https://example.com/x"


@pytest.mark.django_db
def test_no_match_is_inconclusive():
    from apps.nuclei.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.nuclei.verify._rerun_template", return_value=[]):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


@pytest.mark.django_db
def test_different_template_hit_is_inconclusive():
    """A re-run that hits some OTHER template (shouldn't happen with -id, but
    guard against a permissive parse) must not be mistaken for a re-match."""
    from apps.nuclei.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.nuclei.verify._rerun_template",
               return_value=[{"template-id": "some-other-template", "matched-at": "https://example.com/x"}]):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


@pytest.mark.django_db
def test_missing_template_id_is_inconclusive():
    from apps.nuclei.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding(extra={})
    with patch("apps.nuclei.verify._rerun_template") as mock_rerun:
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE
    mock_rerun.assert_not_called()


@pytest.mark.django_db
def test_missing_target_is_inconclusive():
    from apps.nuclei.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding(target="")
    with patch("apps.nuclei.verify._rerun_template") as mock_rerun:
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE
    mock_rerun.assert_not_called()


@pytest.mark.django_db
def test_binary_error_is_inconclusive():
    from apps.nuclei.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding()
    with patch("apps.nuclei.verify._rerun_template", side_effect=OSError("nuclei missing")):
        v = verify_finding(f)
    assert v.verdict == Verdict.INCONCLUSIVE


@pytest.mark.django_db
def test_web_check_type_is_also_covered():
    """No per-check_type family here — check_type="web" (non-CVE templates)
    re-probes the same way as check_type="cve"."""
    from apps.nuclei.verify import verify_finding
    from apps.core.engine.verification.verdict import Verdict
    f = _finding(check_type="web", extra={"template_id": "tech-detect"})
    with patch("apps.nuclei.verify._rerun_template",
               return_value=[{"template-id": "tech-detect", "matched-at": "https://example.com/"}]):
        v = verify_finding(f)
    assert v.verdict == Verdict.VERIFIED


@pytest.mark.django_db
def test_verifier_registered_in_tool_meta():
    from apps.core.engine.workflows import registry as R
    verifiers = R.get_tool_verifiers()
    assert "nuclei" in verifiers
    assert callable(verifiers["nuclei"])
