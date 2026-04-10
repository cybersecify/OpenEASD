"""DNS security checks for domain_security app."""

import logging

import dns.resolver
import dns.query
import dns.zone
import dns.message
import dns.flags
import dns.rcode
import dns.dnssec
import dns.rdatatype
import dns.name
import dns.exception
from django.conf import settings

from apps.domain_security.models import DomainFinding

logger = logging.getLogger(__name__)

# Timeout defaults — override via settings.py
_DNS_TIMEOUT = getattr(settings, "SCANNER_DNS_TIMEOUT", 5)   # seconds


def _resolve(domain, record_type):
    """Resolve a DNS record, return answers or empty list."""
    try:
        return dns.resolver.resolve(domain, record_type)
    except Exception:
        return []


def _check_caa(session, domain) -> list:
    """Check for CAA records restricting certificate issuance."""
    findings = []
    caa_records = _resolve(domain, "CAA")

    if not caa_records:
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="dns",
            severity="medium",
            title="No CAA records found",
            description=(
                f"{domain} has no Certification Authority Authorization (CAA) records. "
                "Any Certificate Authority can issue SSL/TLS certificates for this domain."
            ),
            remediation=(
                'Add CAA records to restrict certificate issuance. Example: '
                '0 issue "letsencrypt.org" or 0 issue "digicert.com"'
            ),
        ))
    else:
        # Check for overly permissive CAA (0 issue ";")
        for record in caa_records:
            record_str = record.to_text()
            if '0 issue ";"' in record_str or "0 issue ;" in record_str:
                findings.append(DomainFinding(
                    session=session, domain=domain, check_type="dns",
                    severity="high",
                    title="CAA record blocks all certificate issuance",
                    description=(
                        f'{domain} has a CAA record "0 issue ;" which prevents any CA '
                        "from issuing certificates. This will break HTTPS renewals."
                    ),
                    remediation="Update CAA records to allow your CA to issue certificates.",
                    extra={"caa_records": [r.to_text() for r in caa_records]},
                ))
                break

    return findings


def _check_wildcard(session, domain) -> list:
    """Check if wildcard DNS is enabled (*.domain resolves)."""
    findings = []
    test_subdomain = f"openeasd-wildcard-probe.{domain}"

    try:
        answers = dns.resolver.resolve(test_subdomain, "A")
        if answers:
            findings.append(DomainFinding(
                session=session, domain=domain, check_type="dns",
                severity="medium",
                title="Wildcard DNS is enabled",
                description=(
                    f"*.{domain} resolves to an IP address. Any subdomain — including "
                    "non-existent or abandoned ones — will resolve, widening the attack "
                    "surface for subdomain takeover and phishing."
                ),
                remediation=(
                    "Disable wildcard DNS unless explicitly required. "
                    "Use explicit subdomain records instead."
                ),
                extra={"resolves_to": [r.address for r in answers]},
            ))
    except Exception:
        pass  # NXDOMAIN or timeout — wildcard not enabled

    return findings


def _check_zone_transfer(session, domain, ns_records) -> list:
    """Attempt AXFR zone transfer against each nameserver."""
    findings = []

    for ns in ns_records:
        try:
            ns_host = str(ns.target).rstrip(".")
        except AttributeError:
            ns_host = str(ns).rstrip(".")
        try:
            ns_ips = dns.resolver.resolve(ns_host, "A")
            ns_ip = str(ns_ips[0])
        except Exception:
            continue

        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, _DNS_TIMEOUT))
            if zone:
                record_count = sum(1 for _ in zone.nodes.keys())
                findings.append(DomainFinding(
                    session=session, domain=domain, check_type="dns",
                    severity="critical",
                    title=f"DNS zone transfer allowed on {ns_host}",
                    description=(
                        f"The nameserver {ns_host} allows unauthenticated AXFR zone transfers. "
                        f"An attacker can enumerate all {record_count} DNS records — subdomains, "
                        "mail servers, internal hostnames — in a single request."
                    ),
                    remediation=(
                        "Restrict zone transfers to authorized secondary nameservers only. "
                        "Configure allow-transfer ACLs on your DNS server."
                    ),
                    extra={"nameserver": ns_host, "record_count": record_count},
                ))
                break  # one confirmed AXFR is enough to report
        except Exception:
            pass  # transfer refused or timed out — expected

    return findings


def _check_lame_delegation(session, domain, ns_records) -> list:
    """
    Check for lame delegation — NS records that don't answer authoritatively.

    A nameserver is 'lame' if it is listed in the NS records but does not
    hold a copy of the zone (returns SERVFAIL/REFUSED or answers without
    the AA bit set). This causes intermittent resolution failures and can
    be exploited if the lame NS hostname itself becomes unregistered.
    """
    findings = []
    lame_servers = []

    for ns in ns_records:
        try:
            ns_host = str(ns.target).rstrip(".")
        except AttributeError:
            ns_host = str(ns).rstrip(".")

        try:
            ns_ips = dns.resolver.resolve(ns_host, "A")
            ns_ip = str(ns_ips[0])
        except Exception:
            # NS hostname doesn't resolve at all — definitely lame
            lame_servers.append(f"{ns_host} (no A record)")
            continue

        try:
            request = dns.message.make_query(domain, dns.rdatatype.SOA)
            response = dns.query.udp(request, ns_ip, _DNS_TIMEOUT)
            # AA (Authoritative Answer) bit must be set
            if not response.flags & dns.flags.AA:
                lame_servers.append(f"{ns_host} (non-authoritative response)")
            elif response.rcode() in (dns.rcode.SERVFAIL, dns.rcode.REFUSED, dns.rcode.NXDOMAIN):
                lame_servers.append(f"{ns_host} (rcode={dns.rcode.to_text(response.rcode())})")
        except Exception:
            lame_servers.append(f"{ns_host} (no response / timeout)")

    if lame_servers:
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="dns",
            severity="high",
            title=f"Lame delegation detected ({len(lame_servers)} nameserver(s))",
            description=(
                f"{domain} has nameservers that do not answer authoritatively for the zone: "
                f"{', '.join(lame_servers)}. "
                "This causes intermittent DNS resolution failures and, if the NS hostname is "
                "unregistered, can be hijacked by an attacker who registers it."
            ),
            remediation=(
                "Ensure all NS records listed for the domain are configured to host the zone. "
                "Remove any NS records pointing to servers not authoritative for this domain."
            ),
            extra={"lame_servers": lame_servers},
        ))

    return findings


def collect_and_analyze(session, domain) -> list:
    """Run all DNS checks and return list of DomainFinding objects (not yet saved)."""
    findings = []

    # A / AAAA
    a_records = _resolve(domain, "A")
    aaaa_records = _resolve(domain, "AAAA")
    if not a_records and not aaaa_records:
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="dns",
            severity="high",
            title="No A or AAAA record found",
            description=f"{domain} does not resolve to any IP address.",
            remediation="Add an A or AAAA record pointing to your server.",
        ))

    # NS records
    ns_records = _resolve(domain, "NS")
    if not ns_records:
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="dns",
            severity="high",
            title="No NS records found",
            description=f"{domain} has no nameserver records.",
            remediation="Configure NS records with your domain registrar.",
        ))

    # MX records
    mx_records = _resolve(domain, "MX")
    if not mx_records:
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="dns",
            severity="medium",
            title="No MX records found",
            description=f"{domain} has no mail exchange records.",
            remediation="Add MX records if you intend to receive email on this domain.",
        ))

    # DNSSEC
    try:
        response = dns.resolver.resolve(domain, "DNSKEY")
        has_dnssec = len(response) > 0
    except Exception:
        has_dnssec = False

    if not has_dnssec:
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="dns",
            severity="medium",
            title="DNSSEC not enabled",
            description=f"{domain} does not have DNSSEC configured.",
            remediation="Enable DNSSEC at your domain registrar to prevent DNS spoofing.",
        ))

    # CAA records
    findings += _check_caa(session, domain)

    # Wildcard DNS
    findings += _check_wildcard(session, domain)

    # Zone Transfer (AXFR)
    if ns_records:
        findings += _check_zone_transfer(session, domain, ns_records)

    # Lame delegation
    if ns_records:
        findings += _check_lame_delegation(session, domain, ns_records)

    return findings
