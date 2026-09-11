"""Fast, fully-mocked tests for domain_security's email-auth DEPTH checks
(SPF lookup limit / neutral / no-all, DMARC sp / pct / rua).

These live in their own file — separate from the network-touching
test_domain_security.py that fast CI excludes — because the spoofing/permerror
logic they cover is important enough to run on every CI run. Everything here is
mocked at _get_txt_record, so there is no real DNS.
"""

from unittest.mock import patch

import pytest


def _session():
    from apps.core.engine.scans.models import ScanSession
    return ScanSession.objects.create(domain="example.com", scan_type="full", status="pending")


def _spf(record):
    from apps.domain_security.scanner import _check_spf
    with patch("apps.domain_security.scanner._get_txt_record", return_value=[record]):
        return _check_spf(_session(), "example.com")


def _dmarc(record):
    from apps.domain_security.scanner import _check_dmarc
    with patch("apps.domain_security.scanner._get_txt_record", return_value=[record]):
        return _check_dmarc(_session(), "example.com")


# ---------------------------------------------------------------------------
# SPF
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestSPFDepth:
    def test_neutral_all_medium(self):
        titles = {(f.title, f.severity) for f in _spf("v=spf1 include:x.com ?all")}
        assert ("SPF policy is neutral (?all)", "medium") in titles

    def test_no_all_mechanism_medium(self):
        titles = {(f.title, f.severity) for f in _spf("v=spf1 include:x.com")}
        assert ("SPF record has no 'all' mechanism", "medium") in titles

    def test_hard_fail_single_lookup_clean(self):
        assert _spf("v=spf1 include:x.com -all") == []

    def test_soft_fail_still_medium(self):
        # Existing behaviour preserved.
        titles = {f.title for f in _spf("v=spf1 include:x.com ~all")}
        assert "SPF policy is soft fail (~all)" in titles

    def test_plus_all_critical(self):
        titles = {(f.title, f.severity) for f in _spf("v=spf1 +all")}
        assert ("SPF policy allows all senders (+all)", "critical") in titles

    def test_too_many_lookups_high(self):
        rec = "v=spf1 " + " ".join(f"include:s{i}.com" for i in range(11)) + " -all"
        hi = next(f for f in _spf(rec) if f.title == "SPF exceeds the 10 DNS-lookup limit")
        assert hi.severity == "high"
        assert hi.extra["lookups"] == 11

    def test_near_lookup_limit_medium(self):
        rec = "v=spf1 " + " ".join(f"include:s{i}.com" for i in range(8)) + " -all"
        titles = {f.title for f in _spf(rec)}
        assert "SPF is near the 10 DNS-lookup limit" in titles

    def test_lookup_counter_counts_a_mx_redirect(self):
        from apps.domain_security.scanner import _spf_lookup_count
        # include(1) + a(1) + mx(1) + a:host(1) + redirect(1) = 5; ip4 / -all cost 0.
        rec = "v=spf1 include:x.com a mx a:mail.x.com ip4:1.2.3.4 redirect=y.com"
        assert _spf_lookup_count(rec) == 5


# ---------------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestDMARCDepth:
    def test_none_policy_medium(self):
        titles = {(f.title, f.severity)
                  for f in _dmarc("v=DMARC1; p=none; rua=mailto:d@example.com")}
        assert ("DMARC policy is none (monitoring only)", "medium") in titles

    def test_quarantine_policy_low(self):
        titles = {f.title for f in _dmarc("v=DMARC1; p=quarantine; rua=mailto:d@example.com")}
        assert "DMARC policy is quarantine (not reject)" in titles

    def test_pct_partial_low(self):
        f = next(f for f in _dmarc("v=DMARC1; p=reject; rua=mailto:d@example.com; pct=50")
                 if f.title == "DMARC is only partially enforced (pct<100)")
        assert f.severity == "low" and f.extra["pct"] == 50

    def test_sp_none_not_misread_as_p_none(self):
        # Regression: "p=none" is a substring of "sp=none".
        found = _dmarc("v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com")
        titles = {f.title for f in found}
        assert "DMARC policy is none (monitoring only)" not in titles
        assert "DMARC subdomain policy is none (sp=none)" in titles

    def test_missing_rua_low(self):
        titles = {(f.title, f.severity) for f in _dmarc("v=DMARC1; p=reject")}
        assert ("DMARC has no aggregate reporting (rua)", "low") in titles

    def test_reject_with_rua_and_pct100_clean(self):
        assert _dmarc("v=DMARC1; p=reject; rua=mailto:d@example.com") == []

    def test_malformed_pct_ignored(self):
        # pct=abc must not crash and must not flag partial enforcement.
        titles = {f.title for f in _dmarc("v=DMARC1; p=reject; rua=mailto:d@x; pct=abc")}
        assert "DMARC is only partially enforced (pct<100)" not in titles
