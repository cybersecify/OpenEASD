"""Unit tests for subscan — create_subscan_session and _copy_assets_from_parent."""

import pytest
from django.utils import timezone


@pytest.mark.django_db
class TestCreateSubscanSession:
    def _make_completed_session(self, domain="target.com"):
        from apps.core.scans.models import ScanSession
        from apps.core.workflows.models import Workflow, WorkflowStep
        workflow = Workflow.objects.filter(is_default=True).first()
        return ScanSession.objects.create(
            domain=domain,
            scan_type="full",
            status="completed",
            workflow=workflow,
            end_time=timezone.now(),
        )

    def test_creates_subscan_with_pending_status(self, db):
        from apps.core.scans.pipeline import create_subscan_session
        parent = self._make_completed_session()
        session = create_subscan_session(str(parent.uuid), ["tls_checker"])
        assert session is not None
        assert session.status == "pending"
        assert session.scan_type == "subscan"

    def test_links_parent_session(self, db):
        from apps.core.scans.pipeline import create_subscan_session
        parent = self._make_completed_session()
        session = create_subscan_session(str(parent.uuid), ["nuclei"])
        assert session.parent_session == parent

    def test_stores_subscan_tools(self, db):
        from apps.core.scans.pipeline import create_subscan_session
        parent = self._make_completed_session()
        tools = ["tls_checker", "web_checker"]
        session = create_subscan_session(str(parent.uuid), tools)
        assert session.subscan_tools == tools

    def test_inherits_domain_from_parent(self, db):
        from apps.core.scans.pipeline import create_subscan_session
        parent = self._make_completed_session("api.example.com")
        session = create_subscan_session(str(parent.uuid), ["nmap"])
        assert session.domain == "api.example.com"

    def test_returns_none_for_nonexistent_uuid(self, db):
        from apps.core.scans.pipeline import create_subscan_session
        import uuid
        result = create_subscan_session(str(uuid.uuid4()), ["tls_checker"])
        assert result is None

    def test_returns_none_for_non_completed_parent(self, db):
        from apps.core.scans.models import ScanSession
        from apps.core.scans.pipeline import create_subscan_session
        parent = ScanSession.objects.create(domain="running.com", scan_type="full", status="running")
        result = create_subscan_session(str(parent.uuid), ["tls_checker"])
        assert result is None

    def test_uses_default_workflow_when_parent_has_none(self, db):
        from apps.core.scans.models import ScanSession
        from apps.core.scans.pipeline import create_subscan_session
        from apps.core.workflows.models import Workflow
        parent = ScanSession.objects.create(
            domain="noworkflow.com", scan_type="full", status="completed",
            workflow=None, end_time=timezone.now(),
        )
        default = Workflow.objects.filter(is_default=True).first()
        session = create_subscan_session(str(parent.uuid), ["tls_checker"])
        if default:
            assert session is not None
            assert session.workflow == default
        else:
            assert session is None

    def test_triggered_by_stored(self, db):
        from apps.core.scans.pipeline import create_subscan_session
        parent = self._make_completed_session()
        session = create_subscan_session(str(parent.uuid), ["nmap"], triggered_by="monitoring")
        assert session.triggered_by == "monitoring"


@pytest.mark.django_db
class TestCopyAssetsFromParent:
    def _make_parent_with_assets(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import Subdomain, IPAddress, Port
        from apps.core.web_assets.models import URL
        from apps.core.workflows.models import Workflow

        workflow = Workflow.objects.filter(is_default=True).first()
        parent = ScanSession.objects.create(
            domain="copy.com", scan_type="full", status="completed",
            workflow=workflow, end_time=timezone.now(),
        )
        sub = Subdomain.objects.create(
            session=parent, domain="copy.com", subdomain="api.copy.com", source="subfinder",
        )
        ip = IPAddress.objects.create(
            session=parent, subdomain=sub, address="1.2.3.4", version=4, source="dnsx",
        )
        port = Port.objects.create(
            session=parent, ip_address=ip, address="1.2.3.4", port=443,
            protocol="tcp", state="open", service="https", is_web=True, source="naabu",
        )
        URL.objects.create(
            session=parent, port=port, subdomain=sub,
            url="https://api.copy.com", scheme="https", host="api.copy.com",
            port_number=443, status_code=200, source="httpx",
        )
        return parent

    def test_assets_copied_to_subscan_session(self, db):
        from apps.core.scans.pipeline import create_subscan_session, _copy_assets_from_parent
        from apps.core.assets.models import Subdomain, IPAddress, Port
        from apps.core.web_assets.models import URL

        parent = self._make_parent_with_assets()
        subscan = create_subscan_session(str(parent.uuid), ["tls_checker"])
        _copy_assets_from_parent(subscan)

        assert Subdomain.objects.filter(session=subscan).count() == 1
        assert IPAddress.objects.filter(session=subscan).count() == 1
        assert Port.objects.filter(session=subscan).count() == 1
        assert URL.objects.filter(session=subscan).count() == 1

    def test_parent_assets_unchanged_after_copy(self, db):
        from apps.core.scans.pipeline import create_subscan_session, _copy_assets_from_parent
        from apps.core.assets.models import Subdomain, IPAddress, Port

        parent = self._make_parent_with_assets()
        subscan = create_subscan_session(str(parent.uuid), ["tls_checker"])
        _copy_assets_from_parent(subscan)

        assert Subdomain.objects.filter(session=parent).count() == 1
        assert IPAddress.objects.filter(session=parent).count() == 1
        assert Port.objects.filter(session=parent).count() == 1

    def test_copied_subdomain_preserves_fields(self, db):
        from apps.core.scans.pipeline import create_subscan_session, _copy_assets_from_parent
        from apps.core.assets.models import Subdomain

        parent = self._make_parent_with_assets()
        subscan = create_subscan_session(str(parent.uuid), ["tls_checker"])
        _copy_assets_from_parent(subscan)

        new_sub = Subdomain.objects.get(session=subscan)
        assert new_sub.subdomain == "api.copy.com"
        assert new_sub.source == "subfinder"

    def test_copied_port_preserves_is_web(self, db):
        from apps.core.scans.pipeline import create_subscan_session, _copy_assets_from_parent
        from apps.core.assets.models import Port

        parent = self._make_parent_with_assets()
        subscan = create_subscan_session(str(parent.uuid), ["tls_checker"])
        _copy_assets_from_parent(subscan)

        new_port = Port.objects.get(session=subscan)
        assert new_port.is_web is True
        assert new_port.port == 443
