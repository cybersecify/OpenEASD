"""Pipeline-level AI invariants (safety invariants 1 and 5).

AI-off must leave _finalize_session byte-identical to pre-AI behavior; any
AI failure must be swallowed by the hook boundary.
"""

import pytest
from unittest.mock import patch

from apps.core.ai.models import (
    AIInvocation,
    AISettings,
    AISummary,
    AITriage,
)
from apps.core.scans.pipeline import _finalize_session


def _session(**kw):
    from apps.core.scans.models import ScanSession
    defaults = dict(domain="example.com", scan_type="full", status="running")
    defaults.update(kw)
    return ScanSession.objects.create(**defaults)


def _finding(session):
    from apps.core.findings.models import Finding
    return Finding.objects.create(
        session=session, source="nmap", check_type="cve", severity="high",
        title="t", target="example.com",
    )


def _activate_ai(settings):
    settings.CLOUDFLARE_ACCOUNT_ID = "acct"
    settings.CLOUDFLARE_API_TOKEN = "tok"
    cfg = AISettings.get()
    cfg.enabled = True
    cfg.save()
    cfg.record_consent("admin")
    return cfg


@pytest.mark.django_db
class TestAiOffInvariant:
    """Invariant 1: with the gate closed, finalize leaves zero AI traces."""

    def test_no_env_no_ai_rows_no_http(self, settings):
        settings.CLOUDFLARE_ACCOUNT_ID = ""
        settings.CLOUDFLARE_API_TOKEN = ""
        sess = _session()
        _finding(sess)
        with patch("apps.core.ai.client.requests.post") as post:
            _finalize_session(sess)
        post.assert_not_called()
        assert AIInvocation.objects.count() == 0
        assert AITriage.objects.count() == 0
        assert AISummary.objects.count() == 0
        sess.refresh_from_db()
        assert sess.status == "completed"

    def test_env_set_but_disabled(self, settings):
        settings.CLOUDFLARE_ACCOUNT_ID = "acct"
        settings.CLOUDFLARE_API_TOKEN = "tok"
        AISettings.get()  # exists, enabled=False by default
        sess = _session()
        _finding(sess)
        with patch("apps.core.ai.client.requests.post") as post:
            _finalize_session(sess)
        post.assert_not_called()
        assert AIInvocation.objects.count() == 0

    def test_enabled_but_no_consent(self, settings):
        settings.CLOUDFLARE_ACCOUNT_ID = "acct"
        settings.CLOUDFLARE_API_TOKEN = "tok"
        cfg = AISettings.get()
        cfg.enabled = True
        cfg.save()
        sess = _session()
        _finding(sess)
        with patch("apps.core.ai.client.requests.post") as post:
            _finalize_session(sess)
        post.assert_not_called()


@pytest.mark.django_db
class TestHookWiring:
    def test_triage_and_summaries_run_when_active(self, settings):
        _activate_ai(settings)
        sess = _session()
        _finding(sess)
        with patch("apps.core.ai.triage.run_triage") as triage, \
             patch("apps.core.ai.summaries.run_summaries") as summaries:
            _finalize_session(sess)
        triage.assert_called_once()
        summaries.assert_called_once()

    def test_sub_toggles_honored(self, settings):
        cfg = _activate_ai(settings)
        cfg.triage_enabled = False
        cfg.summaries_enabled = False
        cfg.save()
        sess = _session()
        _finding(sess)
        with patch("apps.core.ai.triage.run_triage") as triage, \
             patch("apps.core.ai.summaries.run_summaries") as summaries:
            _finalize_session(sess)
        triage.assert_not_called()
        summaries.assert_not_called()

    def test_ai_runs_before_alert_dispatch(self, settings):
        _activate_ai(settings)
        sess = _session()
        _finding(sess)
        order = []
        with patch("apps.core.ai.hooks.run_ai_post_scan",
                   side_effect=lambda s: order.append("ai")), \
             patch("apps.core.scans.pipeline._dispatch_alerts",
                   side_effect=lambda s: order.append("alerts")):
            _finalize_session(sess)
        assert order == ["ai", "alerts"]

    def test_subscan_skips_ai(self, settings):
        _activate_ai(settings)
        parent = _session(status="completed")
        sub = _session(scan_type="subscan", parent_session=parent)
        _finding(sub)
        with patch("apps.core.ai.hooks.run_ai_post_scan") as hook:
            _finalize_session(sub)
        hook.assert_not_called()


@pytest.mark.django_db
class TestFailureSwallowing:
    """Invariant 5: no AI failure mode escapes hooks.py or changes the scan."""

    def test_triage_exception_swallowed(self, settings):
        _activate_ai(settings)
        sess = _session()
        _finding(sess)
        with patch("apps.core.ai.triage.run_triage", side_effect=RuntimeError("boom")):
            _finalize_session(sess)  # must not raise
        sess.refresh_from_db()
        assert sess.status == "completed"
        assert sess.total_findings == 1

    def test_settings_lookup_exception_swallowed(self, settings):
        _activate_ai(settings)
        sess = _session()
        _finding(sess)
        with patch("apps.core.ai.hooks.logger") as log, \
             patch("apps.core.ai.guard.is_ai_active", side_effect=RuntimeError("db gone")):
            _finalize_session(sess)
        assert log.exception.called
        sess.refresh_from_db()
        assert sess.status == "completed"

    def test_client_failure_still_dispatches_alerts(self, settings):
        _activate_ai(settings)
        sess = _session()
        _finding(sess)
        with patch("apps.core.ai.client.chat_json", return_value=None), \
             patch("apps.core.scans.pipeline._dispatch_alerts") as alerts:
            _finalize_session(sess)
        alerts.assert_called_once()
