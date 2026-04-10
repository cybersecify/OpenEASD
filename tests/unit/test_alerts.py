"""Unit tests for apps/alerts — dispatcher logic."""

import pytest
from unittest.mock import patch, MagicMock


@pytest.mark.django_db
class TestDispatchAlerts:
    def _make_session_with_findings(self, db, severity="high"):
        from apps.core.scans.models import ScanSession
        from apps.domain_security.models import DomainFinding
        session = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
        DomainFinding.objects.create(
            session=session, domain="example.com",
            check_type="dns", severity=severity,
            title="DNSSEC not enabled",
        )
        return session

    def test_no_alert_when_no_findings_above_threshold(self, db):
        from apps.core.notifications.dispatcher import dispatch_alerts
        from apps.core.scans.models import ScanSession
        from apps.core.notifications.models import Alert

        session = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
        dispatch_alerts(session.id, severity_threshold="high")
        assert Alert.objects.filter(session=session).count() == 0

    def test_slack_alert_sent_when_webhook_configured(self, db):
        from apps.core.notifications.dispatcher import dispatch_alerts
        from apps.core.notifications.models import Alert

        session = self._make_session_with_findings(db, severity="high")
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None

        with patch("apps.core.notifications.dispatcher.httpx.post", return_value=mock_resp) as mock_post:
            with patch("apps.core.notifications.dispatcher.settings") as mock_settings:
                mock_settings.SLACK_WEBHOOK_URL = "https://hooks.slack.com/test"
                mock_settings.MS_TEAMS_WEBHOOK_URL = ""
                dispatch_alerts(session.id, severity_threshold="high")

        assert Alert.objects.filter(session=session, alert_type="slack", status="sent").exists()
        assert mock_post.called

    def test_teams_alert_sent_when_webhook_configured(self, db):
        from apps.core.notifications.dispatcher import dispatch_alerts
        from apps.core.notifications.models import Alert

        session = self._make_session_with_findings(db, severity="high")
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None

        with patch("apps.core.notifications.dispatcher.httpx.post", return_value=mock_resp):
            with patch("apps.core.notifications.dispatcher.settings") as mock_settings:
                mock_settings.SLACK_WEBHOOK_URL = ""
                mock_settings.MS_TEAMS_WEBHOOK_URL = "https://outlook.office.com/webhook/test"
                dispatch_alerts(session.id, severity_threshold="high")

        assert Alert.objects.filter(session=session, alert_type="teams", status="sent").exists()

    def test_both_channels_fire_independently(self, db):
        from apps.core.notifications.dispatcher import dispatch_alerts
        from apps.core.notifications.models import Alert

        session = self._make_session_with_findings(db, severity="critical")
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None

        with patch("apps.core.notifications.dispatcher.httpx.post", return_value=mock_resp):
            with patch("apps.core.notifications.dispatcher.settings") as mock_settings:
                mock_settings.SLACK_WEBHOOK_URL = "https://hooks.slack.com/test"
                mock_settings.MS_TEAMS_WEBHOOK_URL = "https://outlook.office.com/webhook/test"
                dispatch_alerts(session.id, severity_threshold="high")

        assert Alert.objects.filter(session=session).count() == 2
        assert Alert.objects.filter(session=session, alert_type="slack").exists()
        assert Alert.objects.filter(session=session, alert_type="teams").exists()

    def test_slack_failure_does_not_block_teams(self, db):
        from apps.core.notifications.dispatcher import dispatch_alerts
        from apps.core.notifications.models import Alert

        session = self._make_session_with_findings(db, severity="high")

        call_count = 0
        def side_effect(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if "slack" in url:
                raise Exception("Slack timeout")
            mock_resp = MagicMock()
            mock_resp.raise_for_status.return_value = None
            return mock_resp

        with patch("apps.core.notifications.dispatcher.httpx.post", side_effect=side_effect):
            with patch("apps.core.notifications.dispatcher.settings") as mock_settings:
                mock_settings.SLACK_WEBHOOK_URL = "https://hooks.slack.com/test"
                mock_settings.MS_TEAMS_WEBHOOK_URL = "https://outlook.office.com/webhook/test"
                dispatch_alerts(session.id, severity_threshold="high")

        assert Alert.objects.filter(session=session, alert_type="slack", status="failed").exists()
        assert Alert.objects.filter(session=session, alert_type="teams", status="sent").exists()

    def test_low_severity_filtered_when_threshold_is_high(self, db):
        from apps.core.notifications.dispatcher import dispatch_alerts
        from apps.core.notifications.models import Alert
        from apps.core.scans.models import ScanSession
        from apps.domain_security.models import DomainFinding

        session = ScanSession.objects.create(domain="example.com", scan_type="full", status="completed")
        DomainFinding.objects.create(
            session=session, domain="example.com",
            check_type="email", severity="low", title="BIMI not configured",
        )
        with patch("apps.core.notifications.dispatcher.settings") as mock_settings:
            mock_settings.SLACK_WEBHOOK_URL = "https://hooks.slack.com/test"
            mock_settings.MS_TEAMS_WEBHOOK_URL = ""
            dispatch_alerts(session.id, severity_threshold="high")

        assert Alert.objects.filter(session=session).count() == 0

    def test_no_alert_record_when_no_webhook_configured(self, db):
        from apps.core.notifications.dispatcher import dispatch_alerts
        from apps.core.notifications.models import Alert

        session = self._make_session_with_findings(db, severity="critical")

        with patch("apps.core.notifications.dispatcher.settings") as mock_settings:
            mock_settings.SLACK_WEBHOOK_URL = ""
            mock_settings.MS_TEAMS_WEBHOOK_URL = ""
            dispatch_alerts(session.id, severity_threshold="high")

        assert Alert.objects.filter(session=session).count() == 0
