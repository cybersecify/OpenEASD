"""Unit tests for apps/domain_probe — the ACTIVE domain probes split out of
domain_security: AXFR zone transfer, MTA-STS policy fetch, SMTP open-relay.

All mocked — no real network. Mirrors the tests that previously lived in
test_domain_security.py, re-pointed at apps.domain_probe.scanner.
"""

import pytest
from unittest.mock import patch, MagicMock


# ---------------------------------------------------------------------------
# tool_meta / registration
# ---------------------------------------------------------------------------

class TestDomainProbeMeta:
    def test_is_active_tool(self):
        from apps.core.engine.workflows.registry import get_tool_active
        assert get_tool_active().get("domain_probe") is True

    def test_runner_registered(self):
        from apps.core.engine.workflows.registry import get_tool_runners
        assert get_tool_runners().get("domain_probe") == "apps.domain_probe.scanner.run_domain_probe"

    def test_phase_group(self):
        from apps.core.engine.workflows.registry import get_tool_phase_groups
        assert get_tool_phase_groups().get("domain_probe") == "Domain Intelligence"


# ---------------------------------------------------------------------------
# Zone Transfer (AXFR) checks
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestZoneTransferChecks:
    def _make_session(self, db):
        from apps.core.engine.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full", status="pending")

    def _mock_ns(self, ns_host="ns1.example.com"):
        ns = MagicMock()
        ns.target = MagicMock()
        ns.target.__str__ = lambda s: f"{ns_host}."
        return [ns]

    def test_zone_transfer_allowed_creates_critical_finding(self, db):
        from apps.domain_probe.scanner import _check_zone_transfer
        session = self._make_session(db)

        ns_records = self._mock_ns()
        mock_zone = MagicMock()
        mock_zone.nodes = {"node1": None, "node2": None}

        with patch("apps.domain_probe.scanner.dns") as mock_dns:
            mock_dns.resolver.resolve.return_value = [MagicMock(address="1.2.3.4")]
            with patch("apps.domain_probe.scanner.dns.zone.from_xfr", return_value=mock_zone):
                with patch("apps.domain_probe.scanner.dns.query.xfr"):
                    findings = _check_zone_transfer(session, "example.com", ns_records)

        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert findings[0].source == "domain_probe"
        assert "zone transfer allowed" in findings[0].title.lower()

    def test_zone_transfer_refused_no_finding(self, db):
        from apps.domain_probe.scanner import _check_zone_transfer
        session = self._make_session(db)

        ns_records = self._mock_ns()

        with patch("apps.domain_probe.scanner.dns") as mock_dns:
            mock_dns.resolver.resolve.return_value = [MagicMock(address="1.2.3.4")]
            with patch("apps.domain_probe.scanner.dns.zone.from_xfr",
                       side_effect=Exception("Transfer refused")):
                with patch("apps.domain_probe.scanner.dns.query.xfr"):
                    findings = _check_zone_transfer(session, "example.com", ns_records)

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# MTA-STS checks
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestMTASTSChecks:
    def _make_session(self, db):
        from apps.core.engine.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full", status="pending")

    def _mock_policy(self, mode):
        resp = MagicMock()
        resp.text = f"version: STSv1\nmode: {mode}\nmx: mail.example.com\nmax_age: 86400"
        resp.raise_for_status = MagicMock()
        return resp

    def test_missing_mta_sts_dns_creates_medium_finding(self, db):
        from apps.domain_probe.scanner import _check_mta_sts
        session = self._make_session(db)

        with patch("apps.domain_probe.scanner._get_txt_record", return_value=[]):
            findings = _check_mta_sts(session, "example.com")

        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert findings[0].source == "domain_probe"
        assert "MTA-STS not configured" in findings[0].title

    def test_dns_record_present_but_policy_file_unreachable_creates_high_finding(self, db):
        from apps.domain_probe.scanner import _check_mta_sts
        session = self._make_session(db)

        with patch("apps.domain_probe.scanner._get_txt_record", return_value=["v=STSv1; id=20240101"]), \
             patch("apps.domain_probe.scanner.requests.get", side_effect=Exception("connection refused")):
            findings = _check_mta_sts(session, "example.com")

        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert "not reachable" in findings[0].title

    def test_policy_mode_testing_creates_medium_finding(self, db):
        from apps.domain_probe.scanner import _check_mta_sts
        session = self._make_session(db)

        with patch("apps.domain_probe.scanner._get_txt_record", return_value=["v=STSv1; id=20240101"]), \
             patch("apps.domain_probe.scanner.requests.get", return_value=self._mock_policy("testing")):
            findings = _check_mta_sts(session, "example.com")

        assert len(findings) == 1
        assert findings[0].severity == "medium"
        assert "testing" in findings[0].title

    def test_policy_mode_none_creates_medium_finding(self, db):
        from apps.domain_probe.scanner import _check_mta_sts
        session = self._make_session(db)

        with patch("apps.domain_probe.scanner._get_txt_record", return_value=["v=STSv1; id=20240101"]), \
             patch("apps.domain_probe.scanner.requests.get", return_value=self._mock_policy("none")):
            findings = _check_mta_sts(session, "example.com")

        assert len(findings) == 1
        assert findings[0].severity == "medium"

    def test_policy_mode_enforce_no_finding(self, db):
        from apps.domain_probe.scanner import _check_mta_sts
        session = self._make_session(db)

        with patch("apps.domain_probe.scanner._get_txt_record", return_value=["v=STSv1; id=20240101"]), \
             patch("apps.domain_probe.scanner.requests.get", return_value=self._mock_policy("enforce")):
            findings = _check_mta_sts(session, "example.com")

        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Open relay checks
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestOpenRelayChecks:
    def _make_session(self, db):
        from apps.core.engine.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full", status="pending")

    def _mock_mx(self, hostname="mail.example.com", preference=10):
        mx = MagicMock()
        mx.preference = preference
        mx.exchange = MagicMock()
        mx.exchange.__str__ = lambda self: hostname
        return [mx]

    def test_no_mx_records_returns_empty(self, db):
        from apps.domain_probe.scanner import _check_open_relay
        session = self._make_session(db)

        with patch("apps.domain_probe.scanner._resolve", return_value=[]):
            findings = _check_open_relay(session, "example.com")

        assert findings == []

    def test_open_relay_confirmed_creates_critical_finding(self, db):
        from apps.domain_probe.scanner import _check_open_relay
        session = self._make_session(db)

        smtp_mock = MagicMock()
        smtp_mock.__enter__ = MagicMock(return_value=smtp_mock)
        smtp_mock.__exit__ = MagicMock(return_value=False)
        smtp_mock.ehlo.return_value = (250, b"ok")
        smtp_mock.mail.return_value = (250, b"ok")
        smtp_mock.rcpt.return_value = (250, b"ok")  # relay accepted

        with patch("apps.domain_probe.scanner._resolve", return_value=self._mock_mx()), \
             patch("apps.domain_probe.scanner.smtplib.SMTP", return_value=smtp_mock):
            findings = _check_open_relay(session, "example.com")

        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert findings[0].check_type == "open_relay"
        assert findings[0].source == "domain_probe"
        assert "Open mail relay" in findings[0].title

    def test_relay_rejected_returns_empty(self, db):
        from apps.domain_probe.scanner import _check_open_relay
        session = self._make_session(db)

        smtp_mock = MagicMock()
        smtp_mock.__enter__ = MagicMock(return_value=smtp_mock)
        smtp_mock.__exit__ = MagicMock(return_value=False)
        smtp_mock.ehlo.return_value = (250, b"ok")
        smtp_mock.mail.return_value = (250, b"ok")
        smtp_mock.rcpt.return_value = (554, b"relay denied")  # rejected

        with patch("apps.domain_probe.scanner._resolve", return_value=self._mock_mx()), \
             patch("apps.domain_probe.scanner.smtplib.SMTP", return_value=smtp_mock):
            findings = _check_open_relay(session, "example.com")

        assert findings == []

    def test_smtp_connection_refused_returns_empty(self, db):
        from apps.domain_probe.scanner import _check_open_relay
        session = self._make_session(db)

        with patch("apps.domain_probe.scanner._resolve", return_value=self._mock_mx()), \
             patch("apps.domain_probe.scanner.smtplib.SMTP", side_effect=ConnectionRefusedError):
            findings = _check_open_relay(session, "example.com")

        assert findings == []

    def test_mail_from_rejected_returns_empty(self, db):
        from apps.domain_probe.scanner import _check_open_relay
        session = self._make_session(db)

        smtp_mock = MagicMock()
        smtp_mock.__enter__ = MagicMock(return_value=smtp_mock)
        smtp_mock.__exit__ = MagicMock(return_value=False)
        smtp_mock.ehlo.return_value = (250, b"ok")
        smtp_mock.mail.return_value = (550, b"not allowed")  # MAIL FROM rejected

        with patch("apps.domain_probe.scanner._resolve", return_value=self._mock_mx()), \
             patch("apps.domain_probe.scanner.smtplib.SMTP", return_value=smtp_mock):
            findings = _check_open_relay(session, "example.com")

        assert findings == []


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestDomainProbeScanner:
    def _make_session(self, db):
        from apps.core.engine.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full", status="pending")

    def test_run_saves_findings_and_stamps_controls(self, db):
        from apps.domain_probe.scanner import run_domain_probe
        from apps.core.data.findings.models import Finding

        session = self._make_session(db)
        # AXFR none; MTA-STS missing (medium, control mta_sts); open-relay none.
        with patch("apps.domain_probe.scanner._resolve", return_value=[]), \
             patch("apps.domain_probe.scanner._get_txt_record", return_value=[]):
            findings = run_domain_probe(session)

        # The MTA-STS "not configured" finding is produced and stamped.
        assert Finding.objects.filter(session=session, source="domain_probe").count() == len(findings)
        mta = [f for f in findings if isinstance(f.extra, dict) and f.extra.get("control") == "mta_sts"]
        assert len(mta) == 1

    def test_run_never_raises_on_empty(self, db):
        from apps.domain_probe.scanner import run_domain_probe
        session = self._make_session(db)
        with patch("apps.domain_probe.scanner._resolve", return_value=[]), \
             patch("apps.domain_probe.scanner._get_txt_record", return_value=["v=STSv1; id=1"]), \
             patch("apps.domain_probe.scanner.requests.get", side_effect=Exception("down")):
            # MTA-STS DNS present but policy unreachable → one high finding; no raise.
            findings = run_domain_probe(session)
        assert isinstance(findings, list)
