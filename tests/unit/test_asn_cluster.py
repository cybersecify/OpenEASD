"""Tests for apps/asn_cluster — IP→ASN lookup + lookalike clustering.

Fully mocked at dns.resolver.Resolver.resolve — no real network.
"""

from unittest.mock import patch

import pytest


def _session():
    from apps.core.engine.scans.models import ScanSession
    return ScanSession.objects.create(domain="example.com", scan_type="full", status="pending")


def _lookalike(session, candidate, ips, weaponized=False):
    from apps.core.data.findings.models import Finding
    return Finding.objects.create(
        session=session, source="typosquat", check_type="lookalike_domain",
        severity="high" if weaponized else "medium",
        title=f"Registered lookalike domain {candidate}",
        description="d", remediation="r", target=candidate,
        extra={"candidate": candidate, "resolved_ips": ips, "has_a": True},
    )


# ---------------------------------------------------------------------------
# tool_meta / registration
# ---------------------------------------------------------------------------

class TestMeta:
    def test_passive(self):
        from apps.core.engine.workflows.registry import get_tool_active
        assert get_tool_active().get("asn_cluster") is False

    def test_phase_group(self):
        from apps.core.engine.workflows.registry import get_tool_phase_groups
        assert get_tool_phase_groups().get("asn_cluster") == "Brand Threat"


# ---------------------------------------------------------------------------
# collector — Team Cymru parsing
# ---------------------------------------------------------------------------

class TestLookupAsn:
    def _txt_mock(self, mapping):
        """Return a fake resolve() that yields TXT rdata whose .strings match mapping."""
        def fake(name, rdtype):
            for key, val in mapping.items():
                if name == key:
                    rd = type("R", (), {"strings": [val.encode()]})()
                    return [rd]
            raise Exception("NXDOMAIN")
        return fake

    def test_parses_asn_prefix_and_name(self):
        from apps.asn_cluster.collector import lookup_asn
        m = {
            "1.1.1.1.origin.asn.cymru.com": "13335 | 1.1.1.0/24 | US | arin | 2010-07-14",
            "AS13335.asn.cymru.com": "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US",
        }
        with patch("dns.resolver.Resolver.resolve", side_effect=self._txt_mock(m)):
            info = lookup_asn("1.1.1.1")
        assert info == {"asn": "13335", "as_name": "CLOUDFLARENET, US", "prefix": "1.1.1.0/24"}

    def test_first_asn_taken_from_space_list(self):
        from apps.asn_cluster.collector import lookup_asn
        m = {"4.3.2.1.origin.asn.cymru.com": "111 222 | 1.2.3.0/24 | US | arin |"}
        with patch("dns.resolver.Resolver.resolve", side_effect=self._txt_mock(m)):
            info = lookup_asn("1.2.3.4")
        assert info["asn"] == "111"

    def test_non_ipv4_returns_none(self):
        from apps.asn_cluster.collector import lookup_asn
        assert lookup_asn("2606:4700::1111") is None
        assert lookup_asn("not-an-ip") is None

    def test_dns_failure_returns_none(self):
        from apps.asn_cluster.collector import lookup_asn
        with patch("dns.resolver.Resolver.resolve", side_effect=Exception("timeout")):
            assert lookup_asn("8.8.8.8") is None


# ---------------------------------------------------------------------------
# analyzer — clustering
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestCluster:
    def test_two_lookalikes_same_asn_makes_cluster(self):
        from apps.asn_cluster.analyzer import cluster
        sess = _session()
        lookalikes = [
            {"candidate": "examp1e.com", "ips": ["1.1.1.1"], "weaponized": False},
            {"candidate": "exampl3.com", "ips": ["1.1.1.2"], "weaponized": False},
        ]
        asn_by_ip = {
            "1.1.1.1": {"asn": "13335", "as_name": "CLOUDFLARENET", "prefix": "1.1.1.0/24"},
            "1.1.1.2": {"asn": "13335", "as_name": "CLOUDFLARENET", "prefix": "1.1.1.0/24"},
        }
        out = cluster(sess, lookalikes, asn_by_ip)
        assert len(out) == 1
        assert out[0].check_type == "lookalike_cluster"
        assert out[0].severity == "medium"
        assert out[0].extra["member_count"] == 2
        assert set(out[0].extra["candidates"]) == {"examp1e.com", "exampl3.com"}

    def test_single_lookalike_per_asn_no_cluster(self):
        from apps.asn_cluster.analyzer import cluster
        sess = _session()
        lookalikes = [
            {"candidate": "a.com", "ips": ["1.1.1.1"], "weaponized": False},
            {"candidate": "b.com", "ips": ["2.2.2.2"], "weaponized": False},
        ]
        asn_by_ip = {
            "1.1.1.1": {"asn": "111", "as_name": "X", "prefix": ""},
            "2.2.2.2": {"asn": "222", "as_name": "Y", "prefix": ""},
        }
        assert cluster(sess, lookalikes, asn_by_ip) == []

    def test_weaponized_member_makes_cluster_high(self):
        from apps.asn_cluster.analyzer import cluster
        sess = _session()
        lookalikes = [
            {"candidate": "login-a.com", "ips": ["9.9.9.9"], "weaponized": True},
            {"candidate": "a-secure.com", "ips": ["9.9.9.9"], "weaponized": False},
        ]
        asn_by_ip = {"9.9.9.9": {"asn": "666", "as_name": "BadHost", "prefix": "9.9.9.0/24"}}
        out = cluster(sess, lookalikes, asn_by_ip)
        assert len(out) == 1
        assert out[0].severity == "high"
        assert out[0].extra["weaponized_count"] == 1

    def test_unresolved_ips_ignored(self):
        from apps.asn_cluster.analyzer import cluster
        sess = _session()
        lookalikes = [
            {"candidate": "a.com", "ips": ["1.1.1.1"], "weaponized": False},
            {"candidate": "b.com", "ips": ["1.1.1.1"], "weaponized": False},
        ]
        assert cluster(sess, lookalikes, {}) == []  # no ASN data → no clusters


# ---------------------------------------------------------------------------
# scanner — orchestration
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestScanner:
    def test_fewer_than_two_lookalikes_noop(self):
        from apps.asn_cluster.scanner import run_asn_cluster
        sess = _session()
        _lookalike(sess, "only-one.com", ["1.1.1.1"])
        with patch("apps.asn_cluster.scanner.lookup_asn") as lk:
            out = run_asn_cluster(sess)
        assert out == []
        lk.assert_not_called()  # short-circuits before any lookup

    def test_clusters_and_persists(self):
        from apps.asn_cluster.scanner import run_asn_cluster
        from apps.core.data.findings.models import Finding
        sess = _session()
        _lookalike(sess, "examp1e.com", ["1.1.1.1"])
        _lookalike(sess, "exampl3.com", ["1.1.1.2"])

        def fake_lookup(ip):
            return {"asn": "13335", "as_name": "CLOUDFLARENET", "prefix": "1.1.1.0/24"}

        with patch("apps.asn_cluster.scanner.lookup_asn", side_effect=fake_lookup):
            out = run_asn_cluster(sess)
        assert len(out) == 1
        assert Finding.objects.filter(session=sess, source="asn_cluster").count() == 1

    def test_skips_lookalikes_without_ips(self):
        from apps.asn_cluster.scanner import run_asn_cluster
        sess = _session()
        # Two lookalikes but neither has resolved_ips → nothing clusterable.
        from apps.core.data.findings.models import Finding
        for c in ("a.com", "b.com"):
            Finding.objects.create(
                session=sess, source="typosquat", check_type="lookalike_domain",
                severity="low", title=f"lookalike {c}", description="d", remediation="r",
                target=c, extra={"candidate": c, "resolved_ips": []},
            )
        with patch("apps.asn_cluster.scanner.lookup_asn") as lk:
            assert run_asn_cluster(sess) == []
        lk.assert_not_called()
