"""
Domain security scanner for OpenEASD.

Checks:
  - DNS: A/AAAA, NS, MX, DNSSEC, CAA, Wildcard, Zone Transfer (AXFR), Lame Delegation
  - Email: SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI
  - RDAP: domain expiry, transfer/delete/update locks, domain status

All private helpers live inline in this module so that test mocks targeting
``apps.domain_security.scanner.*`` patch the functions that are actually called.
The ``checks/`` subpackage contains the same logic split by concern and can be
used independently; it is NOT imported here.
"""

import datetime
import logging
import time
import urllib.parse

import dns.resolver
import dns.query
import dns.zone
import dns.message
import dns.flags
import dns.rcode
import dns.rdatatype
# Import DNS exception classes directly so they remain bound to real exception
# types even when tests patch the `dns` module-level reference.
from dns.resolver import NXDOMAIN as _DNS_NXDOMAIN, NoAnswer as _DNS_NoAnswer, NoNameservers as _DNS_NoNameservers
import requests
from django.conf import settings
from django.utils import timezone as django_tz

from apps.core.findings.models import Finding

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RDAP_URL = "https://rdap.org/domain/{}"
IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
DKIM_SELECTORS = ["default", "google", "mail", "dkim", "selector1", "selector2", "k1", "smtp"]

_DNS_TIMEOUT = getattr(settings, "SCANNER_DNS_TIMEOUT", 5)
_HTTP_TIMEOUT = getattr(settings, "SCANNER_HTTP_TIMEOUT", 10)


# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------

def _resolve(domain, record_type):
    """Resolve a DNS record, return answers or empty list."""
    try:
        return dns.resolver.resolve(domain, record_type)
    except (_DNS_NoAnswer, _DNS_NXDOMAIN, _DNS_NoNameservers):
        return []
    except Exception as e:
        logger.debug(f"[domain_security] DNS {record_type} lookup failed for {domain}: {e}")
        return []


def _check_caa(session, domain) -> list:
    """Check for CAA records restricting certificate issuance."""
    findings = []
    caa_records = _resolve(domain, "CAA")

    if not caa_records:
        findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="dns",
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
        for record in caa_records:
            record_str = record.to_text()
            if '0 issue ";"' in record_str or "0 issue ;" in record_str:
                findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="dns",
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
            findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="dns",
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
    except (_DNS_NoAnswer, _DNS_NXDOMAIN, _DNS_NoNameservers):
        pass  # No wildcard — expected
    except Exception as e:
        logger.debug(f"[domain_security] Wildcard probe failed for {domain}: {e}")

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
                findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="dns",
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
                break
        except Exception:
            pass

    return findings


def _check_lame_delegation(session, domain, ns_records) -> list:
    """Check for lame delegation — NS records that don't answer authoritatively."""
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
            lame_servers.append(f"{ns_host} (no A record)")
            continue

        try:
            request = dns.message.make_query(domain, dns.rdatatype.SOA)
            response = dns.query.udp(request, ns_ip, _DNS_TIMEOUT)
            if not response.flags & dns.flags.AA:
                lame_servers.append(f"{ns_host} (non-authoritative response)")
            elif response.rcode() in (dns.rcode.SERVFAIL, dns.rcode.REFUSED, dns.rcode.NXDOMAIN):
                lame_servers.append(f"{ns_host} (rcode={dns.rcode.to_text(response.rcode())})")
        except Exception:
            lame_servers.append(f"{ns_host} (no response / timeout)")

    if lame_servers:
        findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="dns",
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


def _check_dns(session, domain) -> list:
    """Run all DNS checks and return list of DomainFinding objects (not yet saved)."""
    findings = []

    # A / AAAA
    a_records = _resolve(domain, "A")
    aaaa_records = _resolve(domain, "AAAA")
    if not a_records and not aaaa_records:
        findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="dns",
            severity="high",
            title="No A or AAAA record found",
            description=f"{domain} does not resolve to any IP address.",
            remediation="Add an A or AAAA record pointing to your server.",
        ))

    # NS records
    ns_records = _resolve(domain, "NS")
    if not ns_records:
        findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="dns",
            severity="high",
            title="No NS records found",
            description=f"{domain} has no nameserver records.",
            remediation="Configure NS records with your domain registrar.",
        ))

    # MX records
    mx_records = _resolve(domain, "MX")
    if not mx_records:
        findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="dns",
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
        findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="dns",
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


# ---------------------------------------------------------------------------
# Email helpers
# ---------------------------------------------------------------------------

def _get_txt_record(domain) -> list:
    """Return all TXT record strings for a domain."""
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        return [b"".join(r.strings).decode("utf-8", errors="ignore") for r in answers]
    except Exception:
        return []


def _check_spf(session, domain) -> list:
    findings = []
    txt_records = _get_txt_record(domain)
    spf_records = [r for r in txt_records if r.startswith("v=spf1")]

    if not spf_records:
        findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="email",
            severity="high",
            title="SPF record missing",
            description=f"{domain} has no SPF record. Anyone can spoof email from this domain.",
            remediation="Add a TXT record: v=spf1 include:<your-mail-provider> -all",
        ))
    else:
        spf = spf_records[0]
        if "~all" in spf:
            findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="email",
                severity="medium",
                title="SPF policy is soft fail (~all)",
                description="SPF is set to ~all (soft fail). Spoofed emails may still be delivered.",
                remediation="Change ~all to -all for strict enforcement.",
                extra={"spf_record": spf},
            ))
        elif "+all" in spf:
            findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="email",
                severity="critical",
                title="SPF policy allows all senders (+all)",
                description="SPF +all means any server can send email as this domain.",
                remediation="Change +all to -all immediately.",
                extra={"spf_record": spf},
            ))

    return findings


def _check_dmarc(session, domain) -> list:
    findings = []
    dmarc_records = _get_txt_record(f"_dmarc.{domain}")
    dmarc = next((r for r in dmarc_records if r.startswith("v=DMARC1")), None)

    if not dmarc:
        findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="email",
            severity="high",
            title="DMARC record missing",
            description=f"{domain} has no DMARC record. Email spoofing is not prevented.",
            remediation=f"Add a TXT record at _dmarc.{domain}: v=DMARC1; p=reject; rua=mailto:dmarc@{domain}",
        ))
    else:
        if "p=none" in dmarc:
            findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="email",
                severity="medium",
                title="DMARC policy is none (monitoring only)",
                description="DMARC p=none means no action is taken on failing emails.",
                remediation="Change DMARC policy to p=quarantine or p=reject.",
                extra={"dmarc_record": dmarc},
            ))
        elif "p=quarantine" in dmarc:
            findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="email",
                severity="low",
                title="DMARC policy is quarantine (not reject)",
                description="DMARC p=quarantine sends failing emails to spam. p=reject is stronger.",
                remediation="Consider upgrading DMARC policy to p=reject.",
                extra={"dmarc_record": dmarc},
            ))

    return findings


def _check_dkim(session, domain) -> list:
    findings = []
    dkim_found = False
    for selector in DKIM_SELECTORS:
        records = _get_txt_record(f"{selector}._domainkey.{domain}")
        if any("v=DKIM1" in r for r in records):
            dkim_found = True
            break

    if not dkim_found:
        findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="email",
            severity="medium",
            title="DKIM record not found",
            description=f"No DKIM record found for common selectors on {domain}.",
            remediation="Configure DKIM signing with your email provider and publish the public key as a TXT record.",
        ))

    return findings


def _check_mta_sts(session, domain) -> list:
    """Check MTA-STS — enforces TLS for inbound email delivery."""
    findings = []
    mta_sts_records = _get_txt_record(f"_mta-sts.{domain}")
    mta_sts = next((r for r in mta_sts_records if r.startswith("v=STSv1")), None)

    if not mta_sts:
        findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="email",
            severity="medium",
            title="MTA-STS not configured",
            description=(
                f"{domain} has no MTA-STS policy. Inbound email delivery is not protected "
                "against TLS downgrade attacks — a MITM can force plaintext email delivery "
                "even when your mail server supports TLS."
            ),
            remediation=(
                f"1. Add TXT record at _mta-sts.{domain}: v=STSv1; id=<timestamp>\n"
                f"2. Publish policy at https://mta-sts.{domain}/.well-known/mta-sts.txt\n"
                "   Content: version: STSv1\\nmode: enforce\\nmx: mail.{domain}\\nmax_age: 86400"
            ),
        ))
    else:
        if "mode=testing" in mta_sts:
            findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="email",
                severity="low",
                title="MTA-STS is in testing mode",
                description="MTA-STS mode=testing reports failures but does not enforce TLS.",
                remediation="Change MTA-STS mode from testing to enforce once verified.",
                extra={"mta_sts_record": mta_sts},
            ))
        elif "mode=none" in mta_sts:
            findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="email",
                severity="medium",
                title="MTA-STS is in none mode (disabled)",
                description="MTA-STS mode=none disables enforcement.",
                remediation="Change MTA-STS mode to enforce.",
                extra={"mta_sts_record": mta_sts},
            ))

    return findings


def _check_tls_rpt(session, domain) -> list:
    """Check TLS-RPT — enables reporting of TLS failures on inbound email."""
    findings = []
    tls_rpt_records = _get_txt_record(f"_smtp._tls.{domain}")
    has_tls_rpt = any(r.startswith("v=TLSRPTv1") for r in tls_rpt_records)

    if not has_tls_rpt:
        findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="email",
            severity="low",
            title="TLS-RPT not configured",
            description=(
                f"{domain} has no SMTP TLS Reporting (TLS-RPT) record. "
                "You will not receive reports when TLS negotiation fails for inbound email."
            ),
            remediation=(
                f"Add TXT record at _smtp._tls.{domain}: "
                f"v=TLSRPTv1; rua=mailto:tls-report@{domain}"
            ),
        ))

    return findings


def _check_bimi(session, domain) -> list:
    """Check BIMI — brand logo in email, signals mature email security."""
    findings = []
    bimi_records = _get_txt_record(f"default._bimi.{domain}")
    has_bimi = any(r.startswith("v=BIMI1") for r in bimi_records)

    if not has_bimi:
        findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="email",
            severity="info",
            title="BIMI not configured",
            description=(
                f"{domain} has no BIMI record. BIMI displays your brand logo in email clients "
                "and requires DMARC p=reject, signalling maximum email security maturity."
            ),
            remediation=(
                "Implement BIMI after setting DMARC p=reject. "
                f"Add TXT record at default._bimi.{domain}: "
                "v=BIMI1; l=https://example.com/logo.svg; a=<vmc-url>"
            ),
        ))

    return findings


def _check_email(session, domain) -> list:
    """Run all email security checks and return list of DomainFinding objects (not yet saved)."""
    findings = []
    findings += _check_spf(session, domain)
    findings += _check_dmarc(session, domain)
    findings += _check_dkim(session, domain)
    findings += _check_mta_sts(session, domain)
    findings += _check_tls_rpt(session, domain)
    findings += _check_bimi(session, domain)
    return findings


# ---------------------------------------------------------------------------
# RDAP helpers
# ---------------------------------------------------------------------------

def _fetch_rdap(domain) -> dict:
    """
    Fetch RDAP data for a domain with retry + IANA bootstrap fallback.

    Strategy:
      1. Try rdap.org (aggregator) — up to 2 retries on transient errors.
      2. On failure, query the IANA bootstrap registry to find the
         authoritative RDAP server for the TLD, then query it directly.
      3. Raise if all attempts fail.
    """
    last_exc: Exception = RuntimeError(f"RDAP lookup failed for {domain}")

    # Step 1: rdap.org with retries
    for attempt in range(3):
        try:
            resp = requests.get(RDAP_URL.format(urllib.parse.quote(domain, safe="")), timeout=_HTTP_TIMEOUT)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            last_exc = e
            if attempt < 2:
                time.sleep(2 ** attempt)

    logger.warning(f"[domain_security] rdap.org failed for {domain} after 3 attempts: {last_exc}")

    # Step 2: IANA bootstrap fallback
    tld = domain.rsplit(".", 1)[-1].lower()
    try:
        bootstrap = requests.get(IANA_BOOTSTRAP_URL, timeout=_HTTP_TIMEOUT).json()
        rdap_base = None
        for tlds, urls in bootstrap.get("services", []):
            if tld in [t.lower() for t in tlds]:
                rdap_base = urls[0].rstrip("/")
                break

        if rdap_base:
            # Validate the bootstrap URL is an HTTPS URL before using it
            parsed = urllib.parse.urlparse(rdap_base)
            if parsed.scheme != "https" or not parsed.netloc:
                logger.warning(f"[domain_security] IANA bootstrap returned non-HTTPS URL for .{tld}: {rdap_base!r} — skipping")
                raise ValueError(f"Untrusted RDAP base URL: {rdap_base!r}")
            logger.info(f"[domain_security] Trying IANA RDAP bootstrap for .{tld}: {rdap_base}")
            resp = requests.get(f"{rdap_base}/domain/{urllib.parse.quote(domain, safe='')}", timeout=_HTTP_TIMEOUT)
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        last_exc = e
        logger.warning(f"[domain_security] IANA bootstrap fallback failed for {domain}: {e}")

    raise last_exc


def _check_rdap(session, domain) -> list:
    """Run RDAP checks and return list of DomainFinding objects (not yet saved)."""
    findings = []

    try:
        data = _fetch_rdap(domain)
    except Exception as e:
        logger.warning(f"[domain_security] All RDAP sources failed for {domain}: {e}")
        findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="rdap",
            severity="info",
            title="RDAP lookup failed",
            description=(
                f"Could not retrieve RDAP data for {domain} from rdap.org or the "
                "authoritative RDAP server (IANA bootstrap). "
                "Expiry, lock status, and registrar checks were skipped."
            ),
            remediation="Verify the domain is registered and RDAP is publicly available for its TLD.",
        ))
        return findings

    statuses = [s.lower() for s in data.get("status", [])]
    events = {e["eventAction"]: e["eventDate"] for e in data.get("events", []) if "eventDate" in e}

    # Domain expiry
    expiry_str = events.get("expiration")
    if expiry_str:
        try:
            expiry = datetime.datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
            days_left = (expiry - django_tz.now()).days
            extra = {"expiry_date": expiry_str, "days_left": days_left}

            if days_left <= 7:
                findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="rdap",
                    severity="critical",
                    title=f"Domain expires in {days_left} day(s)",
                    description=f"{domain} expires on {expiry.date()}. Immediate renewal required.",
                    remediation="Renew the domain immediately to avoid service disruption.",
                    extra=extra,
                ))
            elif days_left <= 30:
                findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="rdap",
                    severity="high",
                    title=f"Domain expires in {days_left} days",
                    description=f"{domain} expires on {expiry.date()}.",
                    remediation="Renew the domain soon to avoid disruption.",
                    extra=extra,
                ))
        except (ValueError, KeyError) as e:
            logger.debug(f"[domain_security] Could not parse RDAP expiry date {expiry_str!r} for {domain}: {e}")

    # Transfer lock
    has_transfer_lock = any(s in {"client transfer prohibited", "server transfer prohibited"} for s in statuses)
    if not has_transfer_lock:
        findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="rdap",
            severity="medium",
            title="Domain transfer lock not enabled",
            description=(
                f"{domain} does not have a transfer lock (clientTransferProhibited). "
                "An attacker with registrar account access could initiate an unauthorized domain transfer."
            ),
            remediation="Enable 'clientTransferProhibited' lock at your domain registrar.",
            extra={"statuses": statuses},
        ))

    # Delete lock
    has_delete_lock = any(s in {"client delete prohibited", "server delete prohibited"} for s in statuses)
    if not has_delete_lock:
        findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="rdap",
            severity="medium",
            title="Domain delete lock not enabled",
            description=(
                f"{domain} does not have a delete lock (clientDeleteProhibited). "
                "The domain could be accidentally or maliciously deleted, causing immediate service outage."
            ),
            remediation="Enable 'clientDeleteProhibited' lock at your domain registrar.",
            extra={"statuses": statuses},
        ))

    # Update lock
    has_update_lock = any(s in {"client update prohibited", "server update prohibited"} for s in statuses)
    if not has_update_lock:
        findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="rdap",
            severity="low",
            title="Domain update lock not enabled",
            description=(
                f"{domain} does not have an update lock (clientUpdateProhibited). "
                "Nameserver and contact records could be modified without an additional authorization step."
            ),
            remediation="Enable 'clientUpdateProhibited' lock at your domain registrar.",
            extra={"statuses": statuses},
        ))

    # Domain active status
    if "inactive" in statuses or "pending delete" in statuses:
        findings.append(Finding(
            session=session, source="domain_security", target=domain, check_type="rdap",
            severity="critical",
            title="Domain is inactive or pending deletion",
            description=f"{domain} status: {', '.join(statuses)}",
            remediation="Contact your registrar immediately.",
            extra={"statuses": statuses},
        ))

    return findings


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def run_domain_security(session) -> list:
    """Run all domain security checks and save findings."""
    domain = session.domain
    logger.info(f"[domain_security:{session.id}] Starting checks for {domain}")

    findings = []
    findings += _check_dns(session, domain)
    findings += _check_email(session, domain)
    findings += _check_rdap(session, domain)

    if findings:
        Finding.objects.bulk_create(findings)

    logger.info(f"[domain_security:{session.id}] {len(findings)} findings for {domain}")
    return findings
