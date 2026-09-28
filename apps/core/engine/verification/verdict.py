"""Verdict value object for finding verification.

A verifier returns a Verdict; the orchestrator maps it onto the Finding's
verification fields. Deterministic layer only — the AI layer never constructs one.
"""
from dataclasses import dataclass

UNVERIFIED = "unverified"
VERIFICATION_STATUSES = ("unverified", "verified", "inconclusive")


@dataclass(frozen=True)
class Verdict:
    VERIFIED = "verified"
    INCONCLUSIVE = "inconclusive"

    verdict: str
    evidence: str = ""
    detail: str = ""
