"""Unit tests for apps/typosquat — candidate generation, passive DNS registration
checks, analyzer Finding shape/severity, scanner.

typosquat is a passive, no-key threat-surface tool: it generates lookalike
candidates from the apex domain and checks which are registered / weaponizable
via public DNS. It must be fail-graceful (never raise a resolver error) and never
fail a scan.
"""

from unittest.mock import patch

import dns.resolver
import pytest

from apps.typosquat.analyzer import analyze
from apps.typosquat.collector import (
    MAX_CANDIDATES,
    collect,
    generate_candidates,
)
from apps.typosquat.scanner import run_typosquat


def _session(domain="example.com"):
    from apps.core.scans.models import ScanSession
    return ScanSession.objects.create(domain=domain, scan_type="full")


# ---------------------------------------------------------------------------
# Candidate generation
# ---------------------------------------------------------------------------

class TestGenerateCandidates:
    def test_returns_candidate_dicts(self):
        cands = generate_candidates("example.com")
        assert cands
        assert all("candidate" in c and "technique" in c for c in cands)

    def test_never_includes_original(self):
        names = {c["candidate"] for c in generate_candidates("example.com")}
        assert "example.com" not in names

    def test_all_candidates_unique(self):
        names = [c["candidate"] for c in generate_candidates("example.com")]
        assert len(names) == len(set(names))

    def test_omission_technique_present(self):
        names = {c["candidate"] for c in generate_candidates("example.com")}
        # dropping the leading 'e' yields "xample.com"
        assert "xample.com" in names

    def test_transposition_technique_present(self):
        names = {c["candidate"] for c in generate_candidates("example.com")}
        # swap first two chars of "example" -> "xeample"
        assert "xeample.com" in names

    def test_repetition_technique_present(self):
        names = {c["candidate"] for c in generate_candidates("example.com")}
        # double the leading 'e' -> "eexample"
        assert "eexample.com" in names

    def test_hyphenation_technique_present(self):
        names = {c["candidate"] for c in generate_candidates("example.com")}
        assert "e-xample.com" in names

    def test_homoglyph_technique_present(self):
        names = {c["candidate"] for c in generate_candidates("example.com")}
        # 'a' -> '4' homoglyph in "example" -> "ex4mple"
        assert "ex4mple.com" in names

    def test_tld_swap_present_and_tagged(self):
        cands = generate_candidates("example.com")
        net = [c for c in cands if c["candidate"] == "example.net"]
        assert net
        assert net[0]["technique"] == "tld_swap"

    def test_tld_swap_does_not_repeat_own_tld(self):
        names = [c["candidate"] for c in generate_candidates("example.com")
                 if c["technique"] == "tld_swap"]
        assert "example.com" not in names

    def test_strips_leading_www(self):
        names = {c["candidate"] for c in generate_candidates("www.example.com")}
        # generation should behave as if apex is example.com
        assert "example.net" in names
        assert "www.example.com" not in names

    def test_empty_domain_returns_empty(self):
        assert generate_candidates("") == []

    def test_cap_enforced(self):
        # A long name generates far more than MAX_CANDIDATES permutations.
        cands = generate_candidates("abcdefghijklmnopqrstuvwxyz.com")
        assert len(cands) == MAX_CANDIDATES

    def test_cap_logs_truncation(self):
        # Truncation must never be silent — it logs an INFO line.
        with patch("apps.typosquat.collector.logger.info") as log:
            generate_candidates("abcdefghijklmnopqrstuvwxyz.com")
        assert any("truncating" in str(call.args[0]).lower() for call in log.call_args_list)


# ---------------------------------------------------------------------------
# Collector — passive DNS registration check
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestCollector:
    def test_no_candidates_returns_empty(self):
        assert collect(_session(domain="")) == []

    def test_registered_with_a_record_reported(self):
        sess = _session("example.com")

        def fake_resolve(name, rdtype):
            if rdtype == "A":
                return ["93.184.216.34"]
            raise dns.resolver.NoAnswer()

        with patch("apps.typosquat.collector.generate_candidates",
                   return_value=[{"candidate": "examp1e.com", "technique": "typo"}]), \
             patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve):
            results = collect(sess)
        assert len(results) == 1
        rec = results[0]
        assert rec["candidate"] == "examp1e.com"
        assert rec["has_a"] is True
        assert rec["resolved_ips"] == ["93.184.216.34"]
        assert rec["technique"] == "typo"

    def test_unregistered_nxdomain_skipped(self):
        sess = _session("example.com")
        with patch("apps.typosquat.collector.generate_candidates",
                   return_value=[{"candidate": "nope.com", "technique": "typo"}]), \
             patch("dns.resolver.Resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
            assert collect(sess) == []

    def test_timeout_never_raises_and_skips(self):
        sess = _session("example.com")
        with patch("apps.typosquat.collector.generate_candidates",
                   return_value=[{"candidate": "slow.com", "technique": "typo"}]), \
             patch("dns.resolver.Resolver.resolve", side_effect=dns.resolver.LifetimeTimeout()):
            assert collect(sess) == []  # must not raise

    def test_mx_only_is_registered(self):
        sess = _session("example.com")

        def fake_resolve(name, rdtype):
            if rdtype == "MX":
                return ["10 mail.examp1e.com."]
            raise dns.resolver.NoAnswer()

        with patch("apps.typosquat.collector.generate_candidates",
                   return_value=[{"candidate": "examp1e.com", "technique": "typo"}]), \
             patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve):
            results = collect(sess)
        assert results[0]["has_mx"] is True
        assert results[0]["has_a"] is False

    def test_ns_only_registered_but_not_weaponizable(self):
        sess = _session("example.com")

        def fake_resolve(name, rdtype):
            if rdtype == "NS":
                return ["ns1.parking.com."]
            raise dns.resolver.NoAnswer()

        with patch("apps.typosquat.collector.generate_candidates",
                   return_value=[{"candidate": "examp1e.com", "technique": "typo"}]), \
             patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve):
            results = collect(sess)
        assert results[0]["has_ns"] is True
        assert results[0]["has_a"] is False
        assert results[0]["has_mx"] is False


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestAnalyzer:
    def test_weaponizable_is_medium(self):
        sess = _session("example.com")
        results = [{"candidate": "examp1e.com", "technique": "typo",
                    "has_a": True, "has_mx": False, "has_ns": False,
                    "resolved_ips": ["1.2.3.4"]}]
        findings = analyze(sess, results)
        assert len(findings) == 1
        f = findings[0]
        assert f.source == "typosquat"
        assert f.check_type == "lookalike_domain"
        assert f.severity == "medium"
        assert f.target == "examp1e.com"
        assert f.extra["resolved_ips"] == ["1.2.3.4"]
        assert f.extra["technique"] == "typo"

    def test_mx_is_also_medium(self):
        sess = _session("example.com")
        results = [{"candidate": "examp1e.com", "technique": "typo",
                    "has_a": False, "has_mx": True, "has_ns": False,
                    "resolved_ips": []}]
        assert analyze(sess, results)[0].severity == "medium"

    def test_ns_only_is_low(self):
        sess = _session("example.com")
        results = [{"candidate": "examp1e.com", "technique": "typo",
                    "has_a": False, "has_mx": False, "has_ns": True,
                    "resolved_ips": []}]
        assert analyze(sess, results)[0].severity == "low"

    def test_one_finding_per_candidate(self):
        sess = _session("example.com")
        results = [
            {"candidate": "a.com", "technique": "typo", "has_a": True,
             "has_mx": False, "has_ns": False, "resolved_ips": []},
            {"candidate": "b.com", "technique": "tld_swap", "has_a": False,
             "has_mx": False, "has_ns": True, "resolved_ips": []},
        ]
        findings = analyze(sess, results)
        assert {f.target for f in findings} == {"a.com", "b.com"}

    def test_skips_non_dict_and_candidateless(self):
        sess = _session("example.com")
        results = ["junk", {"technique": "typo"}]  # no candidate key
        assert analyze(sess, results) == []

    def test_empty_results(self):
        assert analyze(_session("example.com"), []) == []


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestScanner:
    def test_saves_findings(self):
        from apps.core.findings.models import Finding
        sess = _session("example.com")
        with patch("apps.typosquat.scanner.collect", return_value=[
            {"candidate": "examp1e.com", "technique": "typo", "has_a": True,
             "has_mx": False, "has_ns": False, "resolved_ips": ["1.2.3.4"]},
        ]):
            saved = run_typosquat(sess)
        assert len(saved) == 1
        assert Finding.objects.filter(session=sess, source="typosquat").count() == 1

    def test_empty_when_no_data(self):
        sess = _session("example.com")
        with patch("apps.typosquat.scanner.collect", return_value=[]):
            assert run_typosquat(sess) == []

    def test_never_raises_on_collect_error(self):
        sess = _session("example.com")
        with patch("apps.typosquat.scanner.collect", side_effect=RuntimeError("boom")):
            assert run_typosquat(sess) == []  # swallowed — must never fail a scan
