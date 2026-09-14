"""Tests for the Finding.check_id stable per-rule identity (roadmap item 1).

check_id is the cross-scan identity the Issue register keys on (item 2). Granular
tools get "{source}:{check_type}" backfilled at finalize; coarse + CVE/secret tools
set it explicitly per rule at construction, and the backfill must not clobber those.
"""

import pytest

from apps.core.data.findings.checkid import backfill_check_ids
from apps.core.data.findings.models import Finding
from apps.core.engine.scans.models import ScanSession

pytestmark = pytest.mark.django_db


def _session(domain="example.com"):
    return ScanSession.objects.create(domain=domain, status="completed", scan_type="full")


def _finding(session, **kw):
    defaults = dict(source="tls_checker", check_type="sha1_cert_signature",
                    severity="medium", title="t", target="host:443")
    defaults.update(kw)
    return Finding.objects.create(session=session, **defaults)


class TestBackfill:
    def test_granular_tool_gets_source_colon_check_type(self):
        s = _session()
        f = _finding(s, source="tls_checker", check_type="sha1_cert_signature", check_id="")
        n = backfill_check_ids(s)
        f.refresh_from_db()
        assert f.check_id == "tls_checker:sha1_cert_signature"
        assert n == 1

    def test_explicit_check_id_is_preserved(self):
        s = _session()
        f = _finding(s, source="nmap", check_type="cve", check_id="nmap:CVE-2021-44228")
        backfill_check_ids(s)
        f.refresh_from_db()
        assert f.check_id == "nmap:CVE-2021-44228"  # not overwritten to "nmap:cve"

    def test_blank_check_type_still_stable(self):
        s = _session()
        f = _finding(s, source="scan_coverage", check_type="", check_id="")
        backfill_check_ids(s)
        f.refresh_from_db()
        assert f.check_id == "scan_coverage:"

    def test_only_touches_the_given_session(self):
        s1, s2 = _session("a.com"), _session("b.com")
        f2 = _finding(s2, check_id="")
        backfill_check_ids(s1)
        f2.refresh_from_db()
        assert f2.check_id == ""  # other session untouched

    def test_idempotent(self):
        s = _session()
        _finding(s, source="web_checker", check_type="missing_hsts", check_id="")
        assert backfill_check_ids(s) == 1
        assert backfill_check_ids(s) == 0  # second run finds nothing blank
        assert Finding.objects.get(session=s).check_id == "web_checker:missing_hsts"

    def test_mixed_session_backfills_only_blanks(self):
        s = _session()
        _finding(s, source="web_checker", check_type="directory_listing", check_id="")
        _finding(s, source="nuclei", check_type="cve", check_id="nuclei:CVE-2023-1")
        n = backfill_check_ids(s)
        assert n == 1  # only the blank one
        ids = set(Finding.objects.filter(session=s).values_list("check_id", flat=True))
        assert ids == {"web_checker:directory_listing", "nuclei:CVE-2023-1"}


class TestExplicitAnalyzers:
    """The CVE/secret analyzers must set a per-rule check_id (not the coarse bucket),
    so two distinct rules on the same target don't collapse to one Issue."""

    def test_js_secrets_builds_per_rule_check_id(self):
        from apps.js_secrets.analyzer import _build_finding
        s = _session()
        f = _build_finding(s, {"RuleID": "aws-access-token", "Secret": "x", "Match": "x"})
        assert f.check_id == "js_secrets:aws-access-token"
        # distinct rules → distinct identity (same check_type/target)
        g = _build_finding(s, {"RuleID": "generic-api-key", "Secret": "x", "Match": "x"})
        assert f.check_id != g.check_id

    def test_github_secrets_builds_per_rule_check_id(self):
        from apps.github_secrets.analyzer import _build_finding
        s = _session()
        f = _build_finding(s, {"RuleID": "slack-token", "Secret": "x", "Match": "x"})
        assert f.check_id == "github_secrets:slack-token"

    def test_nuclei_builds_per_template_or_cve_check_id(self):
        from apps.nuclei.analyzer import _build_finding
        s = _session()
        # no CVE → keyed on template id
        f = _build_finding(s, {"template-id": "exposed-panel",
                               "info": {"name": "X", "severity": "medium"}})
        assert f.check_id == "nuclei:exposed-panel"
        # CVE present → keyed on the CVE
        g = _build_finding(s, {"template-id": "t",
                               "info": {"name": "X", "severity": "high",
                                        "classification": {"cve-id": ["CVE-2023-0001"]}}})
        assert g.check_id == "nuclei:CVE-2023-0001"
