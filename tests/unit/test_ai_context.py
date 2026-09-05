"""Unit tests for apps/core/ai/context.py — prompt-context builders."""

import json

import pytest

from apps.core.ai import context


def _session(**kw):
    from apps.core.scans.models import ScanSession
    defaults = dict(domain="example.com", scan_type="full")
    defaults.update(kw)
    return ScanSession.objects.create(**defaults)


def _finding(session, severity="high", title="t", **extra):
    from apps.core.findings.models import Finding
    return Finding.objects.create(
        session=session, source="nmap", check_type="cve", severity=severity,
        title=title, description="d" * 500, target="example.com", extra=extra,
    )


@pytest.mark.django_db
class TestSelectFindings:
    def test_severity_ranked_and_capped(self):
        sess = _session()
        _finding(sess, "low", "low1")
        crit = _finding(sess, "critical", "crit1")
        med = _finding(sess, "medium", "med1")
        high = _finding(sess, "high", "high1")
        out = context.select_findings(sess, cap=3)
        assert [f.id for f in out] == [crit.id, high.id, med.id]

    def test_info_excluded(self):
        sess = _session()
        _finding(sess, "info", "informational")
        keep = _finding(sess, "low", "keep")
        out = context.select_findings(sess, cap=50)
        assert [f.id for f in out] == [keep.id]

    def test_only_this_session(self):
        sess1, sess2 = _session(), _session(domain="other.com")
        mine = _finding(sess1, "high", "mine")
        _finding(sess2, "critical", "theirs")
        assert [f.id for f in context.select_findings(sess1, 50)] == [mine.id]


@pytest.mark.django_db
class TestFindingBrief:
    def test_description_truncated(self):
        sess = _session()
        brief = context.finding_brief(_finding(sess))
        assert len(brief["description"]) == 300

    def test_extra_keys_only_when_set(self):
        sess = _session()
        with_cve = context.finding_brief(
            _finding(sess, cve="CVE-2024-1234", cvss_score=9.8, kev=True))
        assert with_cve["cve"] == "CVE-2024-1234"
        assert with_cve["kev"] is True
        without = context.finding_brief(_finding(sess, title="plain"))
        assert "cve" not in without and "kev" not in without


@pytest.mark.django_db
class TestMessages:
    def test_triage_messages_carry_ids_and_facts(self):
        sess = _session()
        sess.endpoints_probed = 10
        sess.endpoints_blocked = 4
        f = _finding(sess, "critical", "big one")
        msgs = context.build_triage_messages(sess, [f])
        assert msgs[0]["role"] == "system"
        payload = json.loads(msgs[1]["content"].split("\n\n", 1)[1])
        assert payload["scan"]["domain"] == "example.com"
        assert payload["scan"]["endpoints_blocked"] == 4
        assert payload["findings"][0]["id"] == f.id

    def test_summary_messages_kinds_differ(self):
        sess = _session()
        alert = context.build_summary_messages(sess, "alert", "overview text")
        report = context.build_summary_messages(sess, "report", "overview text")
        assert "2 plain" in alert[1]["content"]
        assert "executive summary" in report[1]["content"]
        assert "overview text" in alert[1]["content"]
