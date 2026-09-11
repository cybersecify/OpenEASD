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
    from apps.core.engine.scans.models import ScanSession
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
        assert names & {"xample.com"}

    def test_transposition_technique_present(self):
        names = {c["candidate"] for c in generate_candidates("example.com")}
        # swap first two chars of "example" -> "xeample"
        assert names & {"xeample.com"}

    def test_repetition_technique_present(self):
        names = {c["candidate"] for c in generate_candidates("example.com")}
        # double the leading 'e' -> "eexample"
        assert names & {"eexample.com"}

    def test_hyphenation_technique_present(self):
        names = {c["candidate"] for c in generate_candidates("example.com")}
        assert names & {"e-xample.com"}

    def test_homoglyph_technique_present(self):
        names = {c["candidate"] for c in generate_candidates("example.com")}
        # 'a' -> '4' homoglyph in "example" -> "ex4mple"
        assert names & {"ex4mple.com"}

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
        assert names & {"example.net"}
        assert not (names & {"www.example.com"})

    def test_split_apex_handles_multi_label_suffix(self):
        from apps.typosquat.collector import _split_apex
        assert _split_apex("example.com") == ("example", "com")
        assert _split_apex("example.co.uk") == ("example", "co.uk")
        assert _split_apex("mybank.com.au") == ("mybank", "com.au")
        assert _split_apex("www.example.co.uk") == ("example", "co.uk")

    def test_cctld_tld_swap_uses_registrable_name(self):
        # PSL/ccTLD: the old last-dot split produced garbage like "example.co.net";
        # the whole public suffix must be swapped, yielding real lookalikes.
        names = {c["candidate"] for c in generate_candidates("example.co.uk")
                 if c["technique"] == "tld_swap"}
        assert {"example.com", "example.net", "example.org"} <= names
        assert not any(n.startswith("example.co.") for n in names)  # no example.co.<tld> garbage

    def test_cctld_char_mutation_keeps_full_suffix(self):
        # Character techniques mutate the registrable label and keep the full
        # ".co.uk" suffix — the old last-dot split mutated the "co" label too.
        # Use set-intersection (like the other technique tests) rather than
        # `"host" in names`, which CodeQL misreads as URL-substring sanitization.
        names = {c["candidate"] for c in generate_candidates("example.co.uk")}
        assert names & {"xample.co.uk"}     # omission on "example", suffix intact
        assert names & {"e-xample.co.uk"}   # hyphenation on "example", suffix intact
        # Garbage the old bug produced (mutating the "co" label) must be absent.
        assert not (names & {"example.c.uk", "exampleco.uk"})

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
             patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve), \
             patch("apps.typosquat.collector.requests.get") as get:
            get.return_value = type("R", (), {"text": "<html>hi</html>", "url": "https://examp1e.com/"})()
            results = collect(sess)
        assert len(results) == 1
        rec = results[0]
        assert rec["candidate"] == "examp1e.com"
        assert rec["has_a"] is True
        assert rec["resolved_ips"] == ["93.184.216.34"]
        assert rec["technique"] == "typo"
        # A-record lookalikes get a homepage probe (no login form / brand here).
        assert rec["content_checked"] is True
        assert rec["login_form"] is False

    def test_login_form_and_brand_flagged_as_weaponized(self):
        sess = _session("example.com")

        def fake_resolve(name, rdtype):
            if rdtype == "A":
                return ["1.2.3.4"]
            raise dns.resolver.NoAnswer()

        html = "<html><form action='/login' class=signin>example bank</form></html>"
        with patch("apps.typosquat.collector.generate_candidates",
                   return_value=[{"candidate": "examp1e.com", "technique": "typo"}]), \
             patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve), \
             patch("apps.typosquat.collector.requests.get") as get:
            get.return_value = type("R", (), {"text": html, "url": "https://examp1e.com/"})()
            rec = collect(sess)[0]
        assert rec["login_form"] is True
        assert rec["brand_mentioned"] is True   # "example" appears on the page

    def test_content_fetch_failure_is_graceful(self):
        sess = _session("example.com")

        def fake_resolve(name, rdtype):
            if rdtype == "A":
                return ["1.2.3.4"]
            raise dns.resolver.NoAnswer()

        with patch("apps.typosquat.collector.generate_candidates",
                   return_value=[{"candidate": "examp1e.com", "technique": "typo"}]), \
             patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve), \
             patch("apps.typosquat.collector.requests.get", side_effect=Exception("boom")):
            rec = collect(sess)[0]   # must not raise
        assert rec["content_checked"] is False
        assert rec["login_form"] is False

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

    def test_login_form_elevates_to_high(self):
        sess = _session("example.com")
        results = [{"candidate": "examp1e.com", "technique": "typo",
                    "has_a": True, "has_mx": False, "has_ns": False,
                    "resolved_ips": ["1.2.3.4"], "login_form": True,
                    "content_checked": True}]
        f = analyze(sess, results)[0]
        assert f.severity == "high"
        assert f.extra["login_form"] is True
        assert "takedown" in f.description.lower()

    def test_brand_mention_alone_stays_medium(self):
        # A brand string on the page is a review signal, not proof of
        # impersonation — short brands collide with unrelated orgs' real names
        # (e.g. a scan for "amnic" hit the Armenia Network Information Centre).
        sess = _session("example.com")
        results = [{"candidate": "examp1e.com", "technique": "typo",
                    "has_a": True, "has_mx": False, "has_ns": False,
                    "resolved_ips": ["1.2.3.4"], "brand_mentioned": True,
                    "brand_mention_count": 4, "content_checked": True}]
        f = analyze(sess, results)[0]
        assert f.severity == "medium"
        assert "review it manually" in f.description

    def test_parked_lookalike_is_low_even_with_a_and_mx(self):
        # Parking-lot A/MX records are registrar defaults, not the buyer's
        # phishing infrastructure.
        sess = _session("example.com")
        results = [{"candidate": "examp1e.com", "technique": "typo",
                    "has_a": True, "has_mx": True, "has_ns": False,
                    "resolved_ips": ["76.223.54.146"], "parked": True,
                    "content_checked": True}]
        f = analyze(sess, results)[0]
        assert f.severity == "low"
        assert "parking" in f.description.lower()
        assert f.extra["parked"] is True

    def test_login_form_on_parked_page_still_high(self):
        # A confirmed phishing page outranks the parked signal.
        sess = _session("example.com")
        results = [{"candidate": "examp1e.com", "technique": "typo",
                    "has_a": True, "has_mx": False, "has_ns": False,
                    "resolved_ips": ["1.2.3.4"], "parked": True,
                    "login_form": True, "content_checked": True}]
        assert analyze(sess, results)[0].severity == "high"

    def test_weaponizable_without_content_signal_stays_medium(self):
        sess = _session("example.com")
        results = [{"candidate": "examp1e.com", "technique": "typo",
                    "has_a": True, "has_mx": False, "has_ns": False,
                    "resolved_ips": ["1.2.3.4"], "content_checked": True,
                    "login_form": False, "brand_mentioned": False}]
        assert analyze(sess, results)[0].severity == "medium"

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
        from apps.core.data.findings.models import Finding
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


@pytest.mark.django_db
class TestCollectorConcurrency:
    """The registration + homepage passes run concurrently (ThreadPoolExecutor)
    but must stay deterministic: results follow candidate order, and every
    registered candidate is still checked."""

    def test_results_preserve_candidate_order(self):
        from apps.typosquat import collector
        sess = _session("example.com")
        cands = [
            {"candidate": "aaa.com", "technique": "typo"},
            {"candidate": "bbb.com", "technique": "typo"},
            {"candidate": "ccc.com", "technique": "typo"},
        ]

        # aaa + ccc register (A record), bbb is NXDOMAIN → dropped.
        def fake_resolve(name, rdtype):
            if name in ("aaa.com", "ccc.com") and rdtype == "A":
                return ["1.2.3.4"]
            return []

        with patch("apps.typosquat.collector.generate_candidates", return_value=cands), \
             patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve), \
             patch("apps.typosquat.collector.requests.get") as get:
            get.return_value.text = "<html></html>"
            get.return_value.url = "https://x/"
            results = collector.collect(sess)

        assert [r["candidate"] for r in results] == ["aaa.com", "ccc.com"]

    def test_all_registered_candidates_checked_when_many(self):
        from apps.typosquat import collector
        sess = _session("example.com")
        cands = [{"candidate": f"c{i}.com", "technique": "typo"} for i in range(50)]

        def fake_resolve(name, rdtype):
            return ["1.2.3.4"] if rdtype == "A" else []  # all register

        with patch("apps.typosquat.collector.generate_candidates", return_value=cands), \
             patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve), \
             patch("apps.typosquat.collector.requests.get") as get:
            get.return_value.text = "<html></html>"
            get.return_value.url = "https://x/"
            results = collector.collect(sess)

        assert len(results) == 50
        assert {r["candidate"] for r in results} == {f"c{i}.com" for i in range(50)}
        # homepage fetches capped at CONTENT_MAX_FETCHES
        assert sum(1 for r in results if r.get("content_checked")) == collector.CONTENT_MAX_FETCHES
