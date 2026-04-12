"""Unit tests for apps/core/assets — model constraints, FK relationships, cascade."""

import pytest
from django.db import IntegrityError


@pytest.mark.django_db
class TestSubdomainModel:
    def _session(self):
        from apps.core.scans.models import ScanSession
        return ScanSession.objects.create(domain="example.com", scan_type="full")

    def test_create_subdomain(self):
        from apps.core.assets.models import Subdomain
        sess = self._session()
        s = Subdomain.objects.create(
            session=sess, domain="example.com", subdomain="api.example.com", source="subfinder"
        )
        assert s.is_active is False  # default
        assert s.resolved_at is None

    def test_unique_subdomain_per_session(self):
        from apps.core.assets.models import Subdomain
        sess = self._session()
        Subdomain.objects.create(
            session=sess, domain="example.com", subdomain="api.example.com", source="subfinder"
        )
        with pytest.raises(IntegrityError):
            Subdomain.objects.create(
                session=sess, domain="example.com", subdomain="api.example.com", source="amass"
            )

    def test_same_subdomain_allowed_across_sessions(self):
        from apps.core.assets.models import Subdomain
        from apps.core.scans.models import ScanSession
        s1 = ScanSession.objects.create(domain="example.com", scan_type="full")
        s2 = ScanSession.objects.create(domain="example.com", scan_type="full")
        Subdomain.objects.create(session=s1, domain="example.com", subdomain="api.example.com", source="subfinder")
        # Different session — allowed
        Subdomain.objects.create(session=s2, domain="example.com", subdomain="api.example.com", source="subfinder")

    def test_session_related_name_returns_subdomains(self):
        from apps.core.assets.models import Subdomain
        sess = self._session()
        Subdomain.objects.create(session=sess, domain="example.com", subdomain="a.example.com", source="subfinder")
        Subdomain.objects.create(session=sess, domain="example.com", subdomain="b.example.com", source="subfinder")
        assert sess.subdomains.count() == 2


@pytest.mark.django_db
class TestIPAddressModel:
    def test_ip_linked_to_subdomain(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import Subdomain, IPAddress
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        sub = Subdomain.objects.create(session=sess, domain="example.com", subdomain="api.example.com", source="subfinder")
        ip = IPAddress.objects.create(session=sess, subdomain=sub, address="1.2.3.4", version=4, source="dnsx")
        assert sub.ips.count() == 1
        assert sub.ips.first().address == "1.2.3.4"

    def test_ipv4_and_ipv6_versions(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        IPAddress.objects.create(session=sess, address="2001:db8::1", version=6, source="dnsx")
        assert IPAddress.objects.filter(version=4).count() == 1
        assert IPAddress.objects.filter(version=6).count() == 1


@pytest.mark.django_db
class TestPortModel:
    def test_port_linked_to_ip(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import IPAddress, Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        ip = IPAddress.objects.create(session=sess, address="1.2.3.4", version=4, source="dnsx")
        port = Port.objects.create(
            session=sess, ip_address=ip, address="1.2.3.4", port=80,
            protocol="tcp", state="open", source="naabu",
        )
        assert ip.ports.count() == 1
        assert port.ip_address == ip

    def test_unique_port_per_address_per_session(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import Port
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        Port.objects.create(session=sess, address="1.2.3.4", port=80, protocol="tcp", state="open", source="naabu")
        with pytest.raises(IntegrityError):
            Port.objects.create(session=sess, address="1.2.3.4", port=80, protocol="tcp", state="open", source="nmap")


@pytest.mark.django_db
class TestURLModel:
    def test_url_linked_to_port_and_subdomain(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import Subdomain, IPAddress, Port
        from apps.core.web_assets.models import URL
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        sub = Subdomain.objects.create(session=sess, domain="example.com", subdomain="www.example.com", source="subfinder")
        ip = IPAddress.objects.create(session=sess, subdomain=sub, address="1.2.3.4", version=4, source="dnsx")
        port = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4", port=443, protocol="tcp", state="open", source="naabu")
        url = URL.objects.create(
            session=sess, port=port, subdomain=sub,
            url="https://www.example.com:443",
            host="www.example.com", port_number=443, source="httpx",
        )
        assert port.urls.count() == 1
        assert sub.urls.count() == 1
        assert url.host == "www.example.com"

    def test_url_unique_per_session(self):
        from apps.core.scans.models import ScanSession
        from apps.core.web_assets.models import URL
        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        URL.objects.create(session=sess, url="https://www.example.com:443", host="www.example.com", port_number=443, source="httpx")
        with pytest.raises(IntegrityError):
            URL.objects.create(session=sess, url="https://www.example.com:443", host="www.example.com", port_number=443, source="httpx")


@pytest.mark.django_db
class TestAssetCascadeDelete:
    """When a ScanSession is deleted, ALL related assets must cascade-delete."""

    def test_session_delete_cascades_all_assets(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import Subdomain, IPAddress, Port
        from apps.core.web_assets.models import URL

        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        sub = Subdomain.objects.create(session=sess, domain="example.com", subdomain="api.example.com", source="subfinder")
        ip = IPAddress.objects.create(session=sess, subdomain=sub, address="1.2.3.4", version=4, source="dnsx")
        port = Port.objects.create(session=sess, ip_address=ip, address="1.2.3.4", port=443, protocol="tcp", state="open", source="naabu")
        URL.objects.create(session=sess, port=port, subdomain=sub, url="https://api.example.com", host="api.example.com", port_number=443, source="httpx")

        sess_id = sess.id
        sess.delete()

        assert Subdomain.objects.filter(session_id=sess_id).count() == 0
        assert IPAddress.objects.filter(session_id=sess_id).count() == 0
        assert Port.objects.filter(session_id=sess_id).count() == 0
        assert URL.objects.filter(session_id=sess_id).count() == 0

    def test_subdomain_delete_cascades_to_ips(self):
        from apps.core.scans.models import ScanSession
        from apps.core.assets.models import Subdomain, IPAddress

        sess = ScanSession.objects.create(domain="example.com", scan_type="full")
        sub = Subdomain.objects.create(session=sess, domain="example.com", subdomain="api.example.com", source="subfinder")
        IPAddress.objects.create(session=sess, subdomain=sub, address="1.2.3.4", version=4, source="dnsx")

        sub.delete()
        assert IPAddress.objects.filter(session=sess).count() == 0
