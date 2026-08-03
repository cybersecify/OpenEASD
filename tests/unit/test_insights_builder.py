"""Unit tests for rebuild_finding_type_summaries — upsert + prune behavior."""

import pytest
from unittest.mock import patch
from django.utils import timezone


def _completed_session(domain, subdomain_offset=0):
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(
        domain=domain, scan_type="full", status="completed", end_time=timezone.now(),
    )


def _finding(session, title, check_type="dns", severity="high", source="domain_security"):
    from apps.core.findings.models import Finding
    return Finding.objects.create(
        session=session, source=source, target=session.domain,
        check_type=check_type, severity=severity, title=title,
        description="d", remediation="r",
    )


@pytest.mark.django_db
class TestRebuildFindingTypeSummaries:
    def test_upserts_current_finding_type(self, db):
        from apps.core.domains.models import Domain
        from apps.core.insights.builder import rebuild_finding_type_summaries
        from apps.core.insights.models import FindingTypeSummary

        Domain.objects.create(name="agg.com", is_active=True)
        s = _completed_session("agg.com")
        _finding(s, "Missing SPF")

        rebuild_finding_type_summaries()

        row = FindingTypeSummary.objects.get(title="Missing SPF", check_type="dns")
        assert row.occurrence_count == 1

    def test_prunes_type_absent_from_latest_scan(self, db):
        """A finding type present in an old scan but not the latest is pruned."""
        from apps.core.domains.models import Domain
        from apps.core.insights.builder import rebuild_finding_type_summaries
        from apps.core.insights.models import FindingTypeSummary

        Domain.objects.create(name="agg.com", is_active=True)
        s1 = _completed_session("agg.com")
        _finding(s1, "Old Issue")
        rebuild_finding_type_summaries()
        assert FindingTypeSummary.objects.filter(title="Old Issue").exists()

        # Newer scan for the same domain no longer has "Old Issue".
        s2 = _completed_session("agg.com")
        _finding(s2, "New Issue")
        rebuild_finding_type_summaries()

        assert not FindingTypeSummary.objects.filter(title="Old Issue").exists()
        assert FindingTypeSummary.objects.filter(title="New Issue").exists()

    def test_prunes_all_when_no_findings_remain(self, db):
        """With no findings anywhere, every summary row is pruned."""
        from apps.core.insights.builder import rebuild_finding_type_summaries
        from apps.core.insights.models import FindingTypeSummary

        FindingTypeSummary.objects.create(
            title="Ghost", check_type="dns", severity="high",
            occurrence_count=5, last_seen=timezone.now(),
        )
        rebuild_finding_type_summaries()

        assert FindingTypeSummary.objects.count() == 0

    def test_skips_prune_when_aggregation_errors(self, db):
        """If aggregation raises, existing rows are preserved (not wrongly deleted)."""
        from apps.core.findings.models import Finding
        from apps.core.insights.builder import rebuild_finding_type_summaries
        from apps.core.insights.models import FindingTypeSummary

        FindingTypeSummary.objects.create(
            title="Keep Me", check_type="dns", severity="high",
            occurrence_count=1, last_seen=timezone.now(),
        )
        with patch.object(Finding.objects, "filter", side_effect=RuntimeError("boom")):
            rebuild_finding_type_summaries()

        assert FindingTypeSummary.objects.filter(title="Keep Me").exists()
