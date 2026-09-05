"""Unit tests for apps/core/ai/triage.py."""

import pytest
from unittest.mock import patch

from apps.core.ai.models import AITriage, AITriageItem
from apps.core.ai.triage import run_triage


def _session():
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(domain="example.com", scan_type="full")


def _finding(session, severity="high", title="t"):
    from apps.core.findings.models import Finding
    return Finding.objects.create(
        session=session, source="nmap", check_type="cve", severity=severity,
        title=title, target="example.com",
    )


def _out(*items, overview="overview"):
    return {"overview": overview, "items": list(items)}


@pytest.mark.django_db
class TestRunTriage:
    def test_no_findings_returns_none(self):
        sess = _session()
        with patch("apps.core.ai.triage.client.chat_json") as call:
            assert run_triage(sess) is None
        call.assert_not_called()
        assert AITriage.objects.count() == 0

    def test_happy_path_persists_ranked_items(self):
        sess = _session()
        f1, f2 = _finding(sess, "critical", "one"), _finding(sess, "high", "two")
        out = _out(
            {"finding_id": f2.id, "priority": "fix_now", "rationale": "worse in practice"},
            {"finding_id": f1.id, "priority": "plan", "rationale": "mitigated"},
        )
        with patch("apps.core.ai.triage.client.chat_json", return_value=out):
            triage = run_triage(sess)
        assert triage.status == "completed"
        assert triage.overview == "overview"
        items = list(triage.items.all())
        assert [(i.rank, i.finding_id, i.priority) for i in items] == [
            (1, f2.id, "fix_now"), (2, f1.id, "plan"),
        ]
        assert items[0].finding_key.startswith("nmap:cve:two")

    def test_hallucinated_and_duplicate_ids_dropped(self):
        sess = _session()
        f1 = _finding(sess, "high", "real")
        out = _out(
            {"finding_id": 999999, "priority": "fix_now", "rationale": "made up"},
            {"finding_id": f1.id, "priority": "plan", "rationale": "ok"},
            {"finding_id": f1.id, "priority": "monitor", "rationale": "again"},
        )
        with patch("apps.core.ai.triage.client.chat_json", return_value=out):
            triage = run_triage(sess)
        items = list(triage.items.all())
        assert len(items) == 1
        assert items[0].finding_id == f1.id and items[0].rank == 1

    def test_llm_failure_records_failed_triage(self):
        sess = _session()
        _finding(sess)
        with patch("apps.core.ai.triage.client.chat_json", return_value=None):
            triage = run_triage(sess)
        assert triage.status == "failed"
        assert triage.items.count() == 0

    def test_rerun_replaces_items(self):
        sess = _session()
        f1 = _finding(sess, "high", "one")
        out1 = _out({"finding_id": f1.id, "priority": "fix_now", "rationale": "r"})
        out2 = _out({"finding_id": f1.id, "priority": "monitor", "rationale": "calmer"})
        with patch("apps.core.ai.triage.client.chat_json", return_value=out1):
            run_triage(sess)
        with patch("apps.core.ai.triage.client.chat_json", return_value=out2):
            triage = run_triage(sess)
        assert AITriage.objects.count() == 1
        assert AITriageItem.objects.count() == 1
        assert triage.items.get().priority == "monitor"

    def test_failure_after_success_clears_items(self):
        sess = _session()
        f1 = _finding(sess)
        out = _out({"finding_id": f1.id, "priority": "fix_now", "rationale": "r"})
        with patch("apps.core.ai.triage.client.chat_json", return_value=out):
            run_triage(sess)
        with patch("apps.core.ai.triage.client.chat_json", return_value=None):
            triage = run_triage(sess)
        assert triage.status == "failed"
        assert AITriageItem.objects.count() == 0
