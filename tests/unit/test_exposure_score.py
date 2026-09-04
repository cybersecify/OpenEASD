"""
Unit tests for the Exposure Score feature.

Covers:
  - the pure scoring functions (formula, saturation, per-severity weight, grade bands)
  - the trend delta (up / down / flat / no-previous-scan)
  - the insights builder populating exposure_score / exposure_grade on ScanSummary
  - the insights + dashboard API exposing the fields + trend
  - the PDF report context carrying the score / grade / trend
"""

import pytest
from unittest.mock import patch
from django.contrib.auth.models import User
from django.test import Client
from django.utils import timezone

from apps.core.insights.scoring import (
    WEIGHT_CRITICAL,
    WEIGHT_HIGH,
    WEIGHT_MEDIUM,
    WEIGHT_LOW,
    SCORE_MAX,
    compute_exposure_score,
    grade_for_score,
    exposure_trend,
)


# ---------------------------------------------------------------------------
# Scoring formula
# ---------------------------------------------------------------------------

class TestComputeExposureScore:
    def test_clean_scan_is_zero(self):
        assert compute_exposure_score() == 0
        assert compute_exposure_score(0, 0, 0, 0) == 0

    def test_info_only_is_zero(self):
        # info findings are never passed in — a clean count set stays 0.
        assert compute_exposure_score(critical=0, high=0, medium=0, low=0) == 0

    def test_single_critical_weight(self):
        assert compute_exposure_score(critical=1) == round(WEIGHT_CRITICAL)

    def test_single_high_weight(self):
        assert compute_exposure_score(high=1) == round(WEIGHT_HIGH)

    def test_single_medium_weight(self):
        assert compute_exposure_score(medium=1) == round(WEIGHT_MEDIUM)

    def test_two_lows_round_to_one(self):
        # 2 * 0.5 = 1.0
        assert compute_exposure_score(low=2) == 1

    def test_single_low_rounds_to_zero_or_one(self):
        # 0.5 rounds to 0 under banker's rounding (round(0.5) == 0 in Python 3).
        assert compute_exposure_score(low=1) == 0

    def test_weighted_sum_combination(self):
        # 1*25 + 2*8 + 3*2 + 4*0.5 = 25 + 16 + 6 + 2 = 49
        assert compute_exposure_score(critical=1, high=2, medium=3, low=4) == 49

    def test_saturates_at_100(self):
        assert compute_exposure_score(critical=100) == SCORE_MAX
        assert compute_exposure_score(critical=4) == SCORE_MAX  # 4*25 = 100 exactly
        assert compute_exposure_score(critical=5) == SCORE_MAX  # 125 -> capped

    def test_negative_inputs_clamped(self):
        assert compute_exposure_score(critical=-3, high=-1) == 0

    def test_none_inputs_treated_as_zero(self):
        assert compute_exposure_score(critical=None, high=None, medium=None, low=None) == 0


# ---------------------------------------------------------------------------
# Letter grade bands
# ---------------------------------------------------------------------------

class TestGradeForScore:
    @pytest.mark.parametrize("score,grade", [
        (0, "A"), (10, "A"), (19, "A"),
        (20, "B"), (39, "B"),
        (40, "C"), (59, "C"),
        (60, "D"), (79, "D"),
        (80, "F"), (100, "F"),
    ])
    def test_bands(self, score, grade):
        assert grade_for_score(score) == grade

    def test_clean_scan_is_grade_a(self):
        assert grade_for_score(compute_exposure_score()) == "A"

    def test_saturated_score_is_grade_f(self):
        assert grade_for_score(compute_exposure_score(critical=10)) == "F"


# ---------------------------------------------------------------------------
# Trend delta
# ---------------------------------------------------------------------------

class TestExposureTrend:
    def test_no_previous_is_flat(self):
        t = exposure_trend(30, None)
        assert t["direction"] == "flat"
        assert t["previous_score"] is None
        assert t["change"] == 0
        assert t["score"] == 30
        assert t["grade"] == grade_for_score(30)

    def test_worsening_is_up(self):
        t = exposure_trend(50, 30)
        assert t["direction"] == "up"
        assert t["change"] == 20
        assert t["previous_score"] == 30

    def test_improving_is_down(self):
        t = exposure_trend(10, 40)
        assert t["direction"] == "down"
        assert t["change"] == -30

    def test_unchanged_is_flat(self):
        t = exposure_trend(25, 25)
        assert t["direction"] == "flat"
        assert t["change"] == 0


# ---------------------------------------------------------------------------
# Builder integration — ScanSummary gets populated
# ---------------------------------------------------------------------------

def _finding(session, severity, title, source="web_checker", check_type="x"):
    from apps.core.findings.models import Finding
    return Finding.objects.create(
        session=session, source=source, target=session.domain,
        check_type=check_type, severity=severity, title=title,
        description="d", remediation="r",
    )


@pytest.mark.django_db
class TestBuilderPopulatesExposure:
    def _session(self, domain="exp.example.com"):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(
            domain=domain, scan_type="full", status="completed",
            end_time=timezone.now(),
        )

    def test_clean_scan_scores_zero_grade_a(self, db):
        from apps.core.insights.builder import build_insights
        from apps.core.insights.models import ScanSummary

        s = self._session()
        build_insights(s)
        summary = ScanSummary.objects.get(session=s)
        assert summary.exposure_score == 0
        assert summary.exposure_grade == "A"

    def test_findings_produce_expected_score(self, db):
        from apps.core.insights.builder import build_insights
        from apps.core.insights.models import ScanSummary

        s = self._session()
        _finding(s, "critical", "c1")
        _finding(s, "high", "h1")
        _finding(s, "high", "h2")
        _finding(s, "info", "i1")  # info contributes 0
        build_insights(s)
        summary = ScanSummary.objects.get(session=s)
        # 1*25 + 2*8 = 41
        assert summary.exposure_score == 41
        assert summary.exposure_grade == "C"

    def test_score_saturates_in_builder(self, db):
        from apps.core.insights.builder import build_insights
        from apps.core.insights.models import ScanSummary

        s = self._session()
        for i in range(6):
            _finding(s, "critical", f"c{i}")
        build_insights(s)
        summary = ScanSummary.objects.get(session=s)
        assert summary.exposure_score == 100
        assert summary.exposure_grade == "F"


# ---------------------------------------------------------------------------
# API — insights + dashboard expose the fields
# ---------------------------------------------------------------------------

@pytest.fixture
def api_client(db):
    from ninja_jwt.tokens import RefreshToken
    user = User.objects.create_user("expuser", password="x")
    token = str(RefreshToken.for_user(user).access_token)
    c = Client()
    c.defaults["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    return c


def _domain_and_summary(domain, score, when, critical=0, high=0):
    from apps.core.domains.models import Domain
    from apps.core.scans.models import ScanSession
    from apps.core.insights.models import ScanSummary
    from apps.core.insights.scoring import grade_for_score

    Domain.objects.get_or_create(name=domain, defaults={"is_active": True})
    session = ScanSession.objects.create(
        domain=domain, scan_type="full", status="completed", end_time=when,
    )
    return ScanSummary.objects.create(
        session=session, domain=domain, scan_date=when,
        critical_count=critical, high_count=high, total_findings=critical + high,
        exposure_score=score, exposure_grade=grade_for_score(score),
    )


@pytest.mark.django_db
class TestInsightsAPIExposure:
    def test_scan_trend_entries_carry_exposure(self, api_client):
        now = timezone.now()
        _domain_and_summary("a.example.com", 41, now, critical=1, high=2)
        resp = api_client.get("/api/insights/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_trend"]
        entry = data["scan_trend"][-1]
        assert entry["exposure_score"] == 41
        assert entry["exposure_grade"] == "C"

    def test_top_level_exposure_trend_up(self, api_client):
        import datetime
        base = timezone.now()
        # older scan of same domain, then newer with a higher (worse) score
        _domain_and_summary("b.example.com", 20, base - datetime.timedelta(days=1))
        _domain_and_summary("b.example.com", 55, base)
        resp = api_client.get("/api/insights/")
        exposure = resp.json()["exposure"]
        assert exposure["domain"] == "b.example.com"
        assert exposure["score"] == 55
        assert exposure["previous_score"] == 20
        assert exposure["direction"] == "up"
        assert exposure["change"] == 35

    def test_exposure_none_when_no_summaries(self, api_client):
        from apps.core.domains.models import Domain
        Domain.objects.create(name="empty.example.com", is_active=True)
        resp = api_client.get("/api/insights/")
        assert resp.json()["exposure"] is None


@pytest.mark.django_db
class TestDashboardAPIExposure:
    def test_domain_status_carries_exposure(self, api_client):
        now = timezone.now()
        _domain_and_summary("d.example.com", 41, now, critical=1, high=2)
        resp = api_client.get("/api/dashboard/")
        assert resp.status_code == 200
        statuses = {s["domain"]: s for s in resp.json()["domain_status"]}
        assert statuses["d.example.com"]["exposure_score"] == 41
        assert statuses["d.example.com"]["exposure_grade"] == "C"


# ---------------------------------------------------------------------------
# PDF report context — exposure block
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestReportExposureContext:
    def _authed(self):
        user = User.objects.create_user("reportexp", password="x")
        c = Client()
        c.force_login(user)
        return c

    def _session_with_findings(self, domain="rep.example.com"):
        from apps.core.scans.models import ScanSession
        s = ScanSession.objects.create(
            domain=domain, scan_type="full", status="completed",
            end_time=timezone.now(), total_findings=3,
        )
        _finding(s, "critical", "c1")
        _finding(s, "high", "h1")
        _finding(s, "high", "h2")
        return s

    def _capture_html(self, client, session):
        captured = {}

        def capture(html):
            captured["html"] = html
            return b"%PDF-1.7"

        with patch("apps.core.reports.views._render_pdf", side_effect=capture):
            resp = client.get(f"/reports/{session.uuid}/pdf/")
        assert resp.status_code == 200
        return captured["html"]

    def test_exposure_block_renders(self, db):
        client = self._authed()
        session = self._session_with_findings()
        html = self._capture_html(client, session)
        assert "Exposure Score" in html
        # 1 critical (25) + 2 high (16) = 41 -> grade C
        assert "41/100" in html
        assert "Grade C" in html

    def test_baseline_when_no_previous(self, db):
        client = self._authed()
        session = self._session_with_findings()
        html = self._capture_html(client, session)
        assert "baseline" in html

    def test_trend_up_when_previous_lower(self, db):
        client = self._authed()
        import datetime
        # a prior, cleaner summary for the same domain
        _domain_and_summary(
            "rep.example.com", 10, timezone.now() - datetime.timedelta(days=1)
        )
        session = self._session_with_findings()
        html = self._capture_html(client, session)
        assert "posture worsened" in html
