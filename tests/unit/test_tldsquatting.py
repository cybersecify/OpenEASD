"""Unit tests for apps/tldsquatting — candidate generation, passive DNS registration
checks, analyzer Finding shape/severity, scanner.

tldsquatting is a passive, no-key threat-surface tool: it generates lookalike
candidates from the apex domain and checks which are registered / weaponizable
via public DNS. It must be fail-graceful (never raise a resolver error) and never
fail a scan.
"""

from unittest.mock import Mock, patch

import dns.resolver
import pytest
from django.test import override_settings

# Character-mutation techniques are OFF by default (TLD cybersquatting is the focus);
# tests that exercise them opt in explicitly.
_typos_on = override_settings(TLDSQUATTING_INCLUDE_TYPOS=True)

from apps.tldsquatting.analyzer import analyze
from apps.tldsquatting.collector import (
    MAX_CANDIDATES,
    _TLDS,
    _fetch_priority,
    collect,
    generate_candidates,
)
from apps.tldsquatting.scanner import run_tldsquatting


def _session(domain="example.com"):
    from apps.core.engine.scans.models import ScanSession
    return ScanSession.objects.create(domain=domain, scan_type="full")


# ---------------------------------------------------------------------------
# Expanded TLD breadth (the tldsquatting enhancement over the old typosquat)
# ---------------------------------------------------------------------------

class TestTldBreadth:
    def test_tld_list_loads_broad_set(self):
        # Bundled tlds.txt should give hundreds of TLDs, not a handful.
        assert len(_TLDS) > 100

    def test_tld_swap_candidates_drawn_from_loaded_list(self):
        swaps = {
            c["candidate"].split(".", 1)[1]
            for c in generate_candidates("example.com")
            if c["technique"] == "tld_swap"
        }
        # Every TLD-swap suffix must come from the loaded set, and there should
        # be many of them (broad coverage).
        assert swaps
        assert swaps <= set(_TLDS)
        assert len(swaps) > 50

    @_typos_on
    def test_tld_swap_prioritised_within_cap(self):
        # A long name blows past the cap; TLD-swaps are emitted first so they
        # survive truncation (the high-value "exact name, other TLD" signal).
        cands = generate_candidates("abcdefghijklmnopqrstuvwxyz.com")
        assert len(cands) == MAX_CANDIDATES
        assert any(c["technique"] == "tld_swap" for c in cands)


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

    def test_char_mutations_off_by_default(self):
        # Brand Threat is TLD cybersquatting only by default: no char-mutation
        # (typo/homoglyph/…) candidates unless TLDSQUATTING_INCLUDE_TYPOS is set.
        cands = generate_candidates("example.com")
        assert cands  # tld_swaps still generated
        assert all(c["technique"] == "tld_swap" for c in cands)
        assert "xample.com" not in {c["candidate"] for c in cands}  # no omission typo

    @_typos_on
    def test_omission_technique_present(self):
        names = {c["candidate"] for c in generate_candidates("example.com")}
        # dropping the leading 'e' yields "xample.com"
        assert names & {"xample.com"}

    @_typos_on
    def test_transposition_technique_present(self):
        names = {c["candidate"] for c in generate_candidates("example.com")}
        # swap first two chars of "example" -> "xeample"
        assert names & {"xeample.com"}

    @_typos_on
    def test_repetition_technique_present(self):
        names = {c["candidate"] for c in generate_candidates("example.com")}
        # double the leading 'e' -> "eexample"
        assert names & {"eexample.com"}

    @_typos_on
    def test_hyphenation_technique_present(self):
        names = {c["candidate"] for c in generate_candidates("example.com")}
        assert names & {"e-xample.com"}

    @_typos_on
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
        from apps.tldsquatting.collector import _split_apex
        assert _split_apex("example.com") == ("example", "com")
        assert _split_apex("example.co.uk") == ("example", "co.uk")
        assert _split_apex("mybank.com.au") == ("mybank", "com.au")
        assert _split_apex("www.example.co.uk") == ("example", "co.uk")

    def test_cctld_tld_swap_uses_registrable_name(self):
        # PSL/ccTLD: the whole public suffix is swapped (registrable name is
        # "example", not "example.co"), yielding real lookalikes on other TLDs.
        # The bundled TLD list includes multi-label ccTLD registries (co.jp,
        # com.au, …), so "example.co.jp" is a legitimate candidate — what must
        # never happen is re-emitting the ORIGINAL suffix.
        names = {c["candidate"] for c in generate_candidates("example.co.uk")
                 if c["technique"] == "tld_swap"}
        assert {"example.com", "example.net", "example.org"} <= names
        assert "example.co.uk" not in names  # never the original apex

    @_typos_on
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

    @_typos_on
    def test_cap_enforced(self):
        # A long name generates far more than MAX_CANDIDATES permutations.
        cands = generate_candidates("abcdefghijklmnopqrstuvwxyz.com")
        assert len(cands) == MAX_CANDIDATES

    @_typos_on
    def test_cap_logs_truncation(self):
        # Truncation must never be silent — it logs an INFO line.
        with patch("apps.tldsquatting.collector.logger.info") as log:
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

        with patch("apps.tldsquatting.collector.generate_candidates",
                   return_value=[{"candidate": "examp1e.com", "technique": "typo"}]), \
             patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve), \
             patch("apps.tldsquatting.collector.requests.get") as get:
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
        with patch("apps.tldsquatting.collector.generate_candidates",
                   return_value=[{"candidate": "examp1e.com", "technique": "typo"}]), \
             patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve), \
             patch("apps.tldsquatting.collector.requests.get") as get:
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

        with patch("apps.tldsquatting.collector.generate_candidates",
                   return_value=[{"candidate": "examp1e.com", "technique": "typo"}]), \
             patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve), \
             patch("apps.tldsquatting.collector.requests.get", side_effect=Exception("boom")):
            rec = collect(sess)[0]   # must not raise
        assert rec["content_checked"] is False
        assert rec["login_form"] is False

    def test_unregistered_nxdomain_skipped(self):
        sess = _session("example.com")
        with patch("apps.tldsquatting.collector.generate_candidates",
                   return_value=[{"candidate": "nope.com", "technique": "typo"}]), \
             patch("dns.resolver.Resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
            assert collect(sess) == []

    def test_timeout_never_raises_and_skips(self):
        sess = _session("example.com")
        with patch("apps.tldsquatting.collector.generate_candidates",
                   return_value=[{"candidate": "slow.com", "technique": "typo"}]), \
             patch("dns.resolver.Resolver.resolve", side_effect=dns.resolver.LifetimeTimeout()):
            assert collect(sess) == []  # must not raise

    def test_mx_only_is_registered(self):
        sess = _session("example.com")

        def fake_resolve(name, rdtype):
            if rdtype == "MX":
                return ["10 mail.examp1e.com."]
            raise dns.resolver.NoAnswer()

        with patch("apps.tldsquatting.collector.generate_candidates",
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

        with patch("apps.tldsquatting.collector.generate_candidates",
                   return_value=[{"candidate": "examp1e.com", "technique": "typo"}]), \
             patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve):
            results = collect(sess)
        assert results[0]["has_ns"] is True
        assert results[0]["has_a"] is False
        assert results[0]["has_mx"] is False


# ---------------------------------------------------------------------------
# Content-fetch prioritization (spend the capped budget on the suspicious ones)
# ---------------------------------------------------------------------------

class TestFetchPriority:
    def _recent(self):
        from datetime import datetime, timedelta, timezone
        return (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")

    def test_email_capable_ranks_first(self):
        # MX + SPF/DMARC (configured sender identity) outranks a plain A-only
        # website regardless of generation order.
        email = {"candidate": "a.com", "has_a": True, "has_mx": True, "has_spf": True}
        plain = {"candidate": "b.com", "has_a": True}
        assert _fetch_priority(email) > _fetch_priority(plain)

    def test_recent_ranks_above_old(self):
        recent = {"candidate": "a.com", "has_a": True, "created": self._recent()}
        old = {"candidate": "b.com", "has_a": True, "created": "2001-01-01"}
        assert _fetch_priority(recent) > _fetch_priority(old)

    def test_pre_existing_ranks_last(self):
        pre = {"candidate": "a.com", "has_a": True, "has_mx": True, "has_spf": True,
               "predates_target": True}
        inert = {"candidate": "b.com", "has_a": True}
        assert _fetch_priority(pre) < _fetch_priority(inert)

    def test_stable_sort_preserves_order_within_tier(self):
        a = {"candidate": "a.com", "has_a": True}
        b = {"candidate": "b.com", "has_a": True}
        ordered = sorted([a, b], key=_fetch_priority, reverse=True)
        assert [r["candidate"] for r in ordered] == ["a.com", "b.com"]

    @pytest.mark.django_db
    def test_collect_fetches_suspicious_candidate_within_cap(self):
        # Two registered lookalikes, fetch budget of 1, email-capable one emitted
        # SECOND in generation order — it must still be the one fetched.
        sess = _session("example.com")

        def fake_resolve(name, rdtype):
            host = str(name).rstrip(".")
            if rdtype == "A":
                return ["1.2.3.4"]
            # only inert.com gets no mail; staged.com carries MX+SPF
            if host == "staged.com" and rdtype == "MX":
                return ["10 mail.staged.com."]
            if host == "staged.com" and rdtype == "TXT":
                return ['"v=spf1 include:example.com -all"']
            raise dns.resolver.NoAnswer()

        fetched = []

        def fake_get(url, **kw):
            fetched.append(url)
            return type("R", (), {"text": "<html>hi</html>", "url": url})()

        with override_settings(), \
             patch("apps.tldsquatting.collector.CONTENT_MAX_FETCHES", 1), \
             patch("apps.tldsquatting.collector.generate_candidates",
                   return_value=[{"candidate": "inert.com", "technique": "typo"},
                                 {"candidate": "staged.com", "technique": "typo"}]), \
             patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve), \
             patch("apps.tldsquatting.collector._enrich_registration_age"), \
             patch("apps.tldsquatting.collector.requests.get", side_effect=fake_get):
            collect(sess)

        assert len(fetched) == 1
        assert fetched[0] == "https://staged.com/"   # exact URL, not substring


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestRdapAge:
    def test_rdap_created_parses_registration_date(self):
        from apps.tldsquatting.collector import _rdap_created
        payload = {"events": [
            {"eventAction": "registration", "eventDate": "1994-02-28T05:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2020-01-01T00:00:00Z"},
        ]}
        resp = Mock(status_code=200)
        resp.json.return_value = payload
        with patch("apps.tldsquatting.collector.requests.get", return_value=resp):
            assert _rdap_created("amnic.net") == "1994-02-28"

    def test_rdap_created_none_on_error(self):
        from apps.tldsquatting.collector import _rdap_created
        with patch("apps.tldsquatting.collector.requests.get", side_effect=Exception("boom")):
            assert _rdap_created("x.com") is None

    def test_rdap_created_none_on_non_200(self):
        from apps.tldsquatting.collector import _rdap_created
        resp = Mock(status_code=404)
        resp.json.return_value = {}
        with patch("apps.tldsquatting.collector.requests.get", return_value=resp):
            assert _rdap_created("x.com") is None

    def test_enrich_marks_predating(self):
        from apps.tldsquatting import collector as C
        sess = _session("amnic.com")
        results = [{"candidate": "amnic.net", "has_a": True, "has_mx": False,
                    "has_ns": False, "resolved_ips": ["1.2.3.4"]}]
        info = {
            "amnic.com": {"created": "1997-04-25", "registrant": "Amnic Inc", "registrar": "Reg A"},
            "amnic.net": {"created": "1994-02-28", "registrant": "Someone Else", "registrar": "Reg B"},
        }
        with patch("apps.tldsquatting.collector._rdap_info",
                   side_effect=lambda d, timeout=8: info[d]), \
             patch("apps.tldsquatting.collector._resolve_target_ns", return_value=["ns1.amnic.com"]):
            C._enrich_registration_age(sess, "amnic.com", results)
        assert results[0]["predates_target"] is True
        assert results[0]["created"] == "1994-02-28"
        assert results[0]["target_created"] == "1997-04-25"
        assert results[0]["registrant"] == "Someone Else"
        assert results[0]["target_registrant"] == "Amnic Inc"
        assert results[0]["target_registrar"] == "Reg A"
        assert results[0]["target_ns"] == ["ns1.amnic.com"]

    def test_rdap_info_parses_registrant_and_registrar(self):
        from apps.tldsquatting import collector
        payload = {
            "events": [{"eventAction": "registration", "eventDate": "2015-04-01T00:00:00Z"}],
            "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Zoho Corp"]]]}],
            "registrar": "MarkMonitor Inc.",
        }

        class _R:
            status_code = 200

            def json(self):
                return payload

        with patch("apps.tldsquatting.collector.requests.get", return_value=_R()):
            info = collector._rdap_info("zoho.com")
        assert info["created"] == "2015-04-01"
        assert info["registrant"] == "Zoho Corp"
        assert "MarkMonitor" in (info["registrar"] or "")

    def test_resolve_target_ns_returns_host_list(self):
        from apps.tldsquatting import collector
        from unittest.mock import MagicMock
        ans = [MagicMock(**{"to_text.return_value": "ns1.zoho.com."}),
               MagicMock(**{"to_text.return_value": "ns2.zoho.com."})]
        with patch("apps.tldsquatting.collector._thread_resolver") as mk:
            mk.return_value.resolve.return_value = ans
            ns = collector._resolve_target_ns("zoho.com")
        # exact membership (not `host in x`) so the URL-substring linter stays quiet
        assert sorted(ns) == ["ns1.zoho.com", "ns2.zoho.com"]

    def test_enrich_noop_when_disabled(self):
        from apps.tldsquatting import collector as C
        sess = _session("example.com")
        results = [{"candidate": "example.net", "has_a": True, "has_mx": False,
                    "has_ns": False, "resolved_ips": ["1.2.3.4"]}]
        with override_settings(TLDSQUATTING_RDAP_AGE=False), \
             patch("apps.tldsquatting.collector._rdap_created") as rdap:
            C._enrich_registration_age(sess, "example.com", results)
        rdap.assert_not_called()
        assert "predates_target" not in results[0]


@pytest.mark.django_db
class TestAnalyzer:
    """Severity now comes from the ported risk+threat scoring model
    (``scoring.py``), mapped threat-level → severity
    (PRE-EXISTING→info … CRITICAL→critical). These assert the bands, not an
    ad-hoc ladder."""

    def _find(self, sess, record):
        # These tests predate the classify.py grouping feature and assert
        # per-domain scoring/severity nuances (PRE-EXISTING, capping, parked
        # dampening, etc.) — that logic lives in `_individual_finding` and is
        # unaffected by classification/collapsing. Force the toggle off so
        # `_find` keeps returning exactly one individual Finding per record
        # regardless of which class.py bucket the record now falls into;
        # the collapse-into-rollup behavior itself is covered separately by
        # TestBenignRollup below.
        with override_settings(TLDSQUATTING_COLLAPSE_BENIGN=False):
            return analyze(sess, [record])[0]

    def test_finding_shape(self):
        sess = _session("example.com")
        f = self._find(sess, {"candidate": "examp1e.com", "technique": "typo",
                              "has_a": True, "resolved_ips": ["1.2.3.4"]})
        assert f.source == "tldsquatting"
        assert f.check_type == "lookalike_domain"
        assert f.target == "examp1e.com"
        assert f.extra["resolved_ips"] == ["1.2.3.4"]
        assert f.extra["technique"] == "typo"

    def test_predates_target_is_pre_existing_info(self):
        # amnic.net (1994) predates amnic.com (1997) → PRE-EXISTING, score 0, info,
        # even though it carries A+MX (which would otherwise raise the score).
        sess = _session("amnic.com")
        f = self._find(sess, {
            "candidate": "amnic.net", "technique": "tld_swap",
            "has_a": True, "has_mx": True, "resolved_ips": ["1.2.3.4"],
            "created": "1994-02-28", "target_created": "1997-04-25",
            "predates_target": True,
        })
        assert f.severity == "info"
        assert f.extra["risk_level"] == "PRE-EXISTING"
        assert f.extra["risk_score"] == 0.0
        assert f.extra["threat_level"] == "PRE-EXISTING"
        assert "predates" in f.description.lower()

    def test_apex_itself_is_pre_existing(self):
        sess = _session("example.com")
        f = self._find(sess, {"candidate": "example.com", "has_a": True,
                              "resolved_ips": ["1.2.3.4"]})
        assert f.severity == "info"
        assert f.extra["risk_level"] == "PRE-EXISTING"

    def test_weighted_email_infra_combo_is_critical(self):
        # MX + SPF + DMARC without an A record — the classic phishing-setup
        # fingerprint; the weighted suspicious-combo bonuses stack to CRITICAL.
        # This is email-only (no A/AAAA), so the no-weaponization cap does NOT
        # apply — it's the model's strongest phishing-prep signal and must
        # keep its full mapped severity.
        sess = _session("example.com")
        f = self._find(sess, {
            "candidate": "examp1e.com", "technique": "typo",
            "has_a": False, "has_mx": True, "has_spf": True, "has_dmarc": True,
            "resolved_ips": [],
        })
        assert f.extra["threat_level"] == "CRITICAL"
        assert f.severity == "critical"

    def test_email_only_phishing_prep_not_capped(self):
        # Email-only lookalike (MX, no A/AAAA) with no login_form/brand_mentioned
        # (there's no website to carry either signal) — must NOT be capped to
        # low; email-spoofing infrastructure is a real, live threat on its own.
        sess = _session("example.com")
        f = self._find(sess, {
            "candidate": "examp1e.com", "technique": "typo",
            "has_a": False, "has_mx": True, "resolved_ips": [],
            "login_form": False, "brand_mentioned": False,
        })
        assert f.extra["threat_level"] == "MEDIUM"
        assert f.severity == "medium"

    def test_login_form_with_infra_is_high(self):
        # A + MX + a live login form → HIGH threat (credential phishing).
        sess = _session("example.com")
        f = self._find(sess, {
            "candidate": "examp1e.com", "technique": "typo",
            "has_a": True, "has_mx": True, "resolved_ips": ["1.2.3.4"],
            "login_form": True, "content_checked": True,
        })
        assert f.severity == "high"
        assert f.extra["login_form"] is True
        assert f.extra["threat_score"] >= 8.0

    def test_fully_weaponized_recent_lookalike_is_critical(self):
        # Recent registration + full posture + login form + heavy brand mention.
        from datetime import datetime, timedelta, timezone
        recent = (datetime.now(timezone.utc) - timedelta(days=20)).strftime("%Y-%m-%d")
        sess = _session("example.com")
        f = self._find(sess, {
            "candidate": "examp1e.com", "technique": "typo",
            "has_a": True, "has_spf": True, "has_dmarc": True,
            "resolved_ips": ["1.2.3.4"], "created": recent,
            "target_created": "2000-01-01",
            "https_enabled": True, "ssl_valid": True,
            "login_form": True, "brand_mentioned": True, "brand_mention_count": 8,
            "content_checked": True,
        })
        assert f.severity == "critical"
        assert f.extra["risk_level"] == "CRITICAL"

    def test_enterprise_ns_lowers_score(self):
        # Enterprise NS (AWS) is a legitimacy signal (-1.0); unknown NS adds +1.0.
        sess = _session("example.com")
        base = {"candidate": "examp1e.com", "technique": "typo",
                "has_a": True, "resolved_ips": ["1.2.3.4"]}
        ent = self._find(sess, {**base, "ns_targets": ["ns-1.awsdns-01.org."]})
        unk = self._find(sess, {**base, "ns_targets": ["ns1.randomhost.io."]})
        assert ent.extra["risk_score"] < unk.extra["risk_score"]

    def test_parked_reduces_threat_to_low(self):
        # A parked A-only lookalike: the -1.0 parked nudge keeps it LOW.
        sess = _session("example.com")
        f = self._find(sess, {
            "candidate": "examp1e.com", "technique": "typo",
            "has_a": True, "resolved_ips": ["76.223.54.146"],
            "parked": True, "content_checked": True,
        })
        assert f.severity == "low"
        assert f.extra["parked"] is True

    def test_scores_stored_in_extra(self):
        sess = _session("example.com")
        f = self._find(sess, {"candidate": "examp1e.com", "has_a": True,
                              "resolved_ips": ["1.2.3.4"]})
        for key in ("risk_score", "risk_level", "threat_score", "threat_level"):
            assert key in f.extra

    def test_not_pre_existing_when_dates_missing(self):
        # No RDAP dates → not PRE-EXISTING; scored purely on DNS posture.
        sess = _session("example.com")
        f = self._find(sess, {"candidate": "examp1e.com", "has_a": True,
                              "has_mx": True, "resolved_ips": ["1.2.3.4"]})
        assert f.extra["risk_level"] != "PRE-EXISTING"
        assert f.severity in ("low", "medium", "high", "critical")

    def test_email_capable_lookalike_not_capped(self):
        # A lookalike with a website AND a configured mail-auth stack
        # (MX + SPF + DMARC) is staged to impersonate the brand over email —
        # impersonation infrastructure in its own right. Even with no live
        # login form / brand mention observed, it must KEEP its mapped severity
        # (not be demoted to low by the no-weaponization cap). The raw
        # scores/levels stay in extra unchanged.
        sess = _session("example.com")
        f = self._find(sess, {
            "candidate": "examp1e.com", "technique": "typo",
            "has_a": True, "has_mx": True, "has_spf": True, "has_dmarc": True,
            "resolved_ips": ["1.2.3.4"],
            "login_form": False, "brand_mentioned": False, "content_checked": True,
        })
        assert f.severity == "medium"           # NOT capped to low
        assert f.extra["risk_level"] == "HIGH"
        assert f.extra["threat_level"] == "MEDIUM"
        assert f.extra["threat_score"] == 7.0

    def test_plain_website_no_mail_still_capped_to_low(self):
        # The cap still fires for an ordinary website with NO mail-auth stack and
        # no live-impersonation evidence: infra (A + unknown-tier NS) bands it
        # MEDIUM, but with nothing observed live and no sender identity it's a
        # monitoring signal, not an incident → capped to low.
        sess = _session("example.com")
        f = self._find(sess, {
            "candidate": "examp1e.com", "technique": "typo",
            "has_a": True, "has_ns": True, "ns_targets": ["ns1.randomhost.io."],
            "resolved_ips": ["1.2.3.4"],
            "login_form": False, "brand_mentioned": False, "content_checked": True,
        })
        assert f.severity == "low"
        assert f.extra["threat_level"] in ("MEDIUM", "HIGH")  # raw band uncapped

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
# classify.py grouping — benign classes collapse into info rollups, threats
# always stay individual, and the collapse is toggleable.
# ---------------------------------------------------------------------------


def _analyze(session, recs):
    from apps.tldsquatting.analyzer import analyze
    return analyze(session, recs)


@pytest.mark.django_db
class TestBenignRollup:
    def test_owned_lookalikes_collapse_to_one_info_rollup(self, settings):
        settings.TLDSQUATTING_COLLAPSE_BENIGN = True
        from apps.core.engine.scans.models import ScanSession
        s = ScanSession.objects.create(domain="zoho.com", scan_type="full", status="completed")
        base = dict(has_a=True, content_checked=True, target_ns=["ns1.zoho.com"], target_created="2000-01-01")
        recs = [
            {**base, "candidate": "zoho.io", "ns_targets": ["ns1.zoho.com."], "technique": "tld_swap"},
            {**base, "candidate": "zoho.co", "ns_targets": ["ns2.zoho.com."], "technique": "tld_swap"},
        ]
        findings = _analyze(s, recs)
        owned = [f for f in findings if f.check_type == "lookalike_owned"]
        assert len(owned) == 1
        assert owned[0].severity == "info"
        assert len(owned[0].extra["domains"]) == 2
        assert not [f for f in findings if f.check_type == "lookalike_domain"]  # none individual

    def test_threat_stays_individual(self, settings):
        settings.TLDSQUATTING_COLLAPSE_BENIGN = True
        from apps.core.engine.scans.models import ScanSession
        s = ScanSession.objects.create(domain="zoho.com", scan_type="full", status="completed")
        rec = {"candidate": "zoho-login.com", "ns_targets": ["ns1.evil.com."], "has_a": True,
               "content_checked": True, "brand_mentioned": True, "login_form": True,
               "target_ns": ["ns1.zoho.com"], "target_created": "2000-01-01", "technique": "combo"}
        findings = _analyze(s, [rec])
        ind = [f for f in findings if f.check_type == "lookalike_domain"]
        assert len(ind) == 1 and ind[0].target == "zoho-login.com"
        assert not [f for f in findings if f.check_type.startswith("lookalike_") and f.check_type != "lookalike_domain"]

    def test_toggle_off_keeps_per_domain(self, settings):
        settings.TLDSQUATTING_COLLAPSE_BENIGN = False
        from apps.core.engine.scans.models import ScanSession
        s = ScanSession.objects.create(domain="zoho.com", scan_type="full", status="completed")
        rec = {"candidate": "zoho.io", "ns_targets": ["ns1.zoho.com."], "has_a": True,
               "content_checked": True, "target_ns": ["ns1.zoho.com"], "target_created": "2000-01-01", "technique": "x"}
        findings = _analyze(s, [rec])
        assert [f for f in findings if f.check_type == "lookalike_domain"]  # individual, not a rollup


# ---------------------------------------------------------------------------
# Scoring model (ported risk + threat functions)
# ---------------------------------------------------------------------------

class TestScoring:
    def test_pre_existing_when_predates(self):
        from apps.tldsquatting.scoring import calculate_risk_score
        score, level = calculate_risk_score(
            {"created": "1994-02-28", "has_a": True, "has_mx": True},
            target_created="1997-04-25",
        )
        assert (score, level) == (0.0, "PRE-EXISTING")

    def test_pre_existing_when_apex(self):
        from apps.tldsquatting.scoring import calculate_risk_score
        assert calculate_risk_score({"has_a": True}, is_apex=True) == (0.0, "PRE-EXISTING")

    def test_email_only_combo_scores_critical(self):
        from apps.tldsquatting.scoring import calculate_risk_score
        score, level = calculate_risk_score(
            {"has_mx": True, "has_spf": True, "has_dmarc": True}
        )
        assert level == "CRITICAL"
        assert score >= 8.0

    def test_ns_tier_classification(self):
        from apps.tldsquatting.scoring import ns_tier_from_targets
        assert ns_tier_from_targets(["ns-1.awsdns-01.org."]) == "enterprise"
        assert ns_tier_from_targets(["ns1.sedoparking.com."]) == "parking"
        assert ns_tier_from_targets(["dns1.registrar-servers.com."]) == "known"
        assert ns_tier_from_targets([]) == "unknown"
        assert ns_tier_from_targets(["ns1.randomhost.io."]) == "unknown"

    def test_threat_adds_content_signals(self):
        from apps.tldsquatting.scoring import calculate_threat_score
        base, _ = calculate_threat_score({}, 4.0)
        login, _ = calculate_threat_score({"login_form": True}, 4.0)
        assert login == base + 3.0

    def test_threat_bad_input_never_raises(self):
        from apps.tldsquatting.scoring import calculate_risk_score, calculate_threat_score
        # Garbage created date degrades to "unknown age", never raises.
        score, _ = calculate_risk_score({"created": "not-a-date", "has_a": True})
        assert score > 0.0
        assert calculate_threat_score({"brand_mention_count": None}, 1.0)[0] >= 1.0


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestScanner:
    def test_saves_findings(self):
        from apps.core.data.findings.models import Finding
        sess = _session("example.com")
        with patch("apps.tldsquatting.scanner.collect", return_value=[
            {"candidate": "examp1e.com", "technique": "typo", "has_a": True,
             "has_mx": False, "has_ns": False, "resolved_ips": ["1.2.3.4"]},
        ]):
            saved = run_tldsquatting(sess)
        assert len(saved) == 1
        assert Finding.objects.filter(session=sess, source="tldsquatting").count() == 1

    def test_empty_when_no_data(self):
        sess = _session("example.com")
        with patch("apps.tldsquatting.scanner.collect", return_value=[]):
            assert run_tldsquatting(sess) == []

    def test_never_raises_on_collect_error(self):
        sess = _session("example.com")
        with patch("apps.tldsquatting.scanner.collect", side_effect=RuntimeError("boom")):
            assert run_tldsquatting(sess) == []  # swallowed — must never fail a scan


@pytest.mark.django_db
class TestCollectorConcurrency:
    """The registration + homepage passes run concurrently (ThreadPoolExecutor)
    but must stay deterministic: results follow candidate order, and every
    registered candidate is still checked."""

    def test_results_preserve_candidate_order(self):
        from apps.tldsquatting import collector
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

        with patch("apps.tldsquatting.collector.generate_candidates", return_value=cands), \
             patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve), \
             patch("apps.tldsquatting.collector.requests.get") as get:
            get.return_value.text = "<html></html>"
            get.return_value.url = "https://x/"
            results = collector.collect(sess)

        assert [r["candidate"] for r in results] == ["aaa.com", "ccc.com"]

    def test_all_registered_candidates_checked_when_many(self):
        from apps.tldsquatting import collector
        sess = _session("example.com")
        cands = [{"candidate": f"c{i}.com", "technique": "typo"} for i in range(50)]

        def fake_resolve(name, rdtype):
            return ["1.2.3.4"] if rdtype == "A" else []  # all register

        with patch("apps.tldsquatting.collector.generate_candidates", return_value=cands), \
             patch("dns.resolver.Resolver.resolve", side_effect=fake_resolve), \
             patch("apps.tldsquatting.collector.requests.get") as get:
            get.return_value.text = "<html></html>"
            get.return_value.url = "https://x/"
            results = collector.collect(sess)

        assert len(results) == 50
        assert {r["candidate"] for r in results} == {f"c{i}.com" for i in range(50)}
        # homepage fetches capped at CONTENT_MAX_FETCHES
        assert sum(1 for r in results if r.get("content_checked")) == collector.CONTENT_MAX_FETCHES
