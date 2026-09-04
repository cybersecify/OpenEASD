"""
Exposure Score — a single 0-100 executive-friendly risk number per scan.

The score is a *saturating weighted sum* of a scan's findings by severity:
higher = worse. It exists to give a non-technical reader (a buyer, an exec) one
number and a letter grade they can track over time, without reading the finding
list. It is deliberately simple and tunable — the weights below are the only
knobs.

    raw   = 25*critical + 8*high + 2*medium + 0.5*low
    score = min(100, round(raw))          # info findings contribute 0

A clean scan (no critical/high/medium/low findings) scores 0 → grade A.
A single critical alone (25) already lands a B; four criticals (100) saturate at F.
"""

# Per-severity weights. Named constants so the curve is tunable in one place.
# `info` findings intentionally contribute nothing.
WEIGHT_CRITICAL = 25.0
WEIGHT_HIGH = 8.0
WEIGHT_MEDIUM = 2.0
WEIGHT_LOW = 0.5

SCORE_MAX = 100

# Letter-grade bands, keyed by the *inclusive lower bound* of the score.
# 0-19 A (clean/low), 20-39 B, 40-59 C, 60-79 D, 80-100 F.
_GRADE_BANDS = [
    (80, "F"),
    (60, "D"),
    (40, "C"),
    (20, "B"),
    (0, "A"),
]


def compute_exposure_score(critical: int = 0, high: int = 0, medium: int = 0, low: int = 0) -> int:
    """Return the 0-100 exposure score for a set of per-severity finding counts.

    Saturating weighted sum, capped at ``SCORE_MAX``. A clean scan returns 0.
    Negative inputs are clamped to 0 (defensive — counts should never be negative).
    """
    critical = max(0, int(critical or 0))
    high = max(0, int(high or 0))
    medium = max(0, int(medium or 0))
    low = max(0, int(low or 0))

    raw = (
        WEIGHT_CRITICAL * critical
        + WEIGHT_HIGH * high
        + WEIGHT_MEDIUM * medium
        + WEIGHT_LOW * low
    )
    return min(SCORE_MAX, round(raw))


def grade_for_score(score: int) -> str:
    """Map a 0-100 exposure score to a letter grade (A best, F worst)."""
    score = max(0, int(score or 0))
    for lower_bound, grade in _GRADE_BANDS:
        if score >= lower_bound:
            return grade
    return "A"  # unreachable — the 0 band always matches


def exposure_trend(current: int | None, previous: int | None) -> dict:
    """Describe how the exposure score moved vs the same domain's previous scan.

    Returns a dict with the numeric change and a direction. Because higher = worse,
    ``direction`` is ``"up"`` when the score rose (posture got worse), ``"down"``
    when it fell (improved), and ``"flat"`` when unchanged or there is no baseline.

        {"score", "grade", "previous_score", "change", "direction"}
    """
    score = max(0, int(current or 0))
    grade = grade_for_score(score)

    if previous is None:
        return {
            "score": score,
            "grade": grade,
            "previous_score": None,
            "change": 0,
            "direction": "flat",
        }

    previous = max(0, int(previous))
    change = score - previous
    if change > 0:
        direction = "up"
    elif change < 0:
        direction = "down"
    else:
        direction = "flat"
    return {
        "score": score,
        "grade": grade,
        "previous_score": previous,
        "change": change,
        "direction": direction,
    }
