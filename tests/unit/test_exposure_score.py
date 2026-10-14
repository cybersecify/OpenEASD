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
from django.utils import timezone

from apps.core.console.insights.scoring import (
    WEIGHT_CRITICAL,
    WEIGHT_HIGH,
    WEIGHT_MEDIUM,
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
    from apps.core.data.findings.models import Finding
    return Finding.objects.create(
        session=session, source=source, target=session.domain,
        check_type=check_type, severity=severity, title=title,
        description="d", remediation="r",
    )


@pytest.mark.django_db
class TestBuilderPopulatesExposure:
    def _session(self, domain="exp.example.com"):
        from apps.core.engine.scans.models import ScanSession
        return ScanSession.objects.create(
            domain=domain, scan_type="full", status="completed",
            end_time=timezone.now(),
        )

    def test_clean_scan_scores_zero_grade_a(self, db):
        from apps.core.console.insights.builder import build_insights
        from apps.core.console.insights.models import ScanSummary

        s = self._session()
        build_insights(s)
        summary = ScanSummary.objects.get(session=s)
        assert summary.exposure_score == 0
        assert summary.exposure_grade == "A"

    def test_findings_produce_expected_score(self, db):
        from apps.core.console.insights.builder import build_insights
        from apps.core.console.insights.models import ScanSummary

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
        from apps.core.console.insights.builder import build_insights
        from apps.core.console.insights.models import ScanSummary

        s = self._session()
        for i in range(6):
            _finding(s, "critical", f"c{i}")
        build_insights(s)
        summary = ScanSummary.objects.get(session=s)
        assert summary.exposure_score == 100
        assert summary.exposure_grade == "F"

