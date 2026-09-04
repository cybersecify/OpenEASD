"""Unit tests for apps/core/ai/models.py — singleton config, audit-log
no-bodies invariant, and relational constraints."""

import pytest
from django.db import IntegrityError, models as dj_models

from apps.core.ai.models import (
    CURRENT_CONSENT_VERSION,
    AIInvocation,
    AISettings,
    AISummary,
    AITriage,
)


def _session():
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(domain="example.com", scan_type="full")


@pytest.mark.django_db
class TestAISettings:
    def test_get_is_singleton(self):
        a = AISettings.get()
        b = AISettings.get()
        assert a.pk == b.pk == 1
        assert AISettings.objects.count() == 1

    def test_defaults_are_off(self):
        cfg = AISettings.get()
        assert cfg.enabled is False
        assert cfg.consent_given_at is None
        assert cfg.consent_current is False

    def test_record_consent_stamps_fields(self):
        cfg = AISettings.get()
        cfg.record_consent("admin")
        cfg.refresh_from_db()
        assert cfg.consent_given_at is not None
        assert cfg.consent_by == "admin"
        assert cfg.consent_version == CURRENT_CONSENT_VERSION
        assert cfg.consent_current is True

    def test_stale_consent_version_not_current(self):
        cfg = AISettings.get()
        cfg.record_consent("admin")
        cfg.consent_version = CURRENT_CONSENT_VERSION - 1
        cfg.save()
        assert cfg.consent_current is False


@pytest.mark.django_db
class TestAIInvocationInvariants:
    def test_no_textfield_on_audit_model(self):
        """INVARIANT 3: prompt/response bodies are structurally impossible to
        persist — the audit model must have no TextField at all."""
        text_fields = [f for f in AIInvocation._meta.get_fields()
                       if isinstance(f, dj_models.TextField)]
        assert text_fields == []

    def test_audit_survives_session_deletion(self):
        sess = _session()
        row = AIInvocation.objects.create(session=sess, session_uuid=sess.uuid,
                                          purpose="triage", model="m", status="ok")
        sess_uuid = sess.uuid
        sess.delete()
        row.refresh_from_db()
        assert row.session is None
        assert row.session_uuid == sess_uuid


@pytest.mark.django_db
class TestRelationalConstraints:
    def test_one_triage_per_session(self):
        sess = _session()
        AITriage.objects.create(session=sess, status="completed")
        with pytest.raises(IntegrityError):
            AITriage.objects.create(session=sess, status="failed")

    def test_one_summary_per_kind_per_session(self):
        sess = _session()
        AISummary.objects.create(session=sess, kind="report", text="a")
        AISummary.objects.create(session=sess, kind="alert", text="b")
        with pytest.raises(IntegrityError):
            AISummary.objects.create(session=sess, kind="report", text="c")

    def test_triage_cascades_with_session(self):
        sess = _session()
        triage = AITriage.objects.create(session=sess, status="completed")
        triage.items.create(rank=1, priority="fix_now", rationale="x")
        sess.delete()
        assert AITriage.objects.count() == 0
