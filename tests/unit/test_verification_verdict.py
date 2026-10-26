from apps.core.engine.verification.verdict import Verdict, UNVERIFIED, VERIFICATION_STATUSES


def test_verdict_constructs_with_defaults():
    v = Verdict(Verdict.VERIFIED)
    assert v.verdict == "verified"
    assert v.evidence == "" and v.detail == ""


def test_verdict_carries_evidence_and_detail():
    v = Verdict(Verdict.INCONCLUSIVE, evidence="HTTP 000", detail="unreachable")
    assert v.verdict == "inconclusive"
    assert v.evidence == "HTTP 000" and v.detail == "unreachable"


def test_status_vocabulary_is_closed():
    assert UNVERIFIED == "unverified"
    assert set(VERIFICATION_STATUSES) == {"unverified", "verified", "inconclusive"}
