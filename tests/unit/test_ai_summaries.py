"""Unit tests for apps/core/ai/summaries.py."""

import pytest
from unittest.mock import patch

from apps.core.ai.models import AISummary, AITriage
from apps.core.ai.summaries import run_summaries


def _session():
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(domain="example.com", scan_type="full")


@pytest.mark.django_db
class TestRunSummaries:
    def test_both_kinds_written(self):
        sess = _session()
        with patch("apps.core.ai.summaries.client.chat_json",
                   return_value={"text": "  summary text  "}):
            run_summaries(sess)
        kinds = set(AISummary.objects.values_list("kind", flat=True))
        assert kinds == {"report", "alert"}
        assert AISummary.objects.get(kind="report").text == "summary text"

    def test_failure_leaves_absent(self):
        sess = _session()
        with patch("apps.core.ai.summaries.client.chat_json", return_value=None):
            run_summaries(sess)
        assert AISummary.objects.count() == 0

    def test_partial_failure_keeps_other_kind(self):
        sess = _session()
        with patch("apps.core.ai.summaries.client.chat_json",
                   side_effect=[{"text": "report ok"}, None]):
            run_summaries(sess)
        assert set(AISummary.objects.values_list("kind", flat=True)) == {"report"}

    def test_empty_text_treated_as_failure(self):
        sess = _session()
        with patch("apps.core.ai.summaries.client.chat_json", return_value={"text": "   "}):
            run_summaries(sess)
        assert AISummary.objects.count() == 0

    def test_triage_overview_feeds_prompt(self):
        sess = _session()
        AITriage.objects.create(session=sess, status="completed", overview="the overview")
        with patch("apps.core.ai.summaries.client.chat_json",
                   return_value={"text": "ok"}) as call:
            run_summaries(sess)
        sent = call.call_args_list[0][0][0][1]["content"]
        assert "the overview" in sent

    def test_failed_triage_overview_not_used(self):
        sess = _session()
        AITriage.objects.create(session=sess, status="failed", overview="stale")
        with patch("apps.core.ai.summaries.client.chat_json",
                   return_value={"text": "ok"}) as call:
            run_summaries(sess)
        assert "stale" not in call.call_args_list[0][0][0][1]["content"]

    def test_rerun_updates_in_place(self):
        sess = _session()
        with patch("apps.core.ai.summaries.client.chat_json", return_value={"text": "v1"}):
            run_summaries(sess)
        with patch("apps.core.ai.summaries.client.chat_json", return_value={"text": "v2"}):
            run_summaries(sess)
        assert AISummary.objects.filter(kind="alert").count() == 1
        assert AISummary.objects.get(kind="alert").text == "v2"
