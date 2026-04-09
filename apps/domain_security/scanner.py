"""
Domain security scanner for OpenEASD.

Checks:
  - DNS: A/AAAA, NS, MX, DNSSEC
  - Email: SPF, DMARC, DKIM
  - RDAP: domain expiry, registrar lock, domain status
"""

import logging
import datetime
import requests
import dns.resolver
import dns.dnssec
import dns.rdatatype

from .models import DomainFinding

logger = logging.getLogger(__name__)

RDAP_URL = "https://rdap.org/domain/{}"
DKIM_SELECTORS = ["default", "google", "mail", "dkim", "selector1", "selector2", "k1", "smtp"]


def run_domain_security(session) -> list:
    """Run all domain security checks and save findings."""
    domain = session.domain
    logger.info(f"[domain_security:{session.id}] Starting checks for {domain}")

    findings = []
    findings += _check_dns(session, domain)
    findings += _check_email(session, domain)
    findings += _check_rdap(session, domain)

    if findings:
        DomainFinding.objects.bulk_create(findings)

    logger.info(f"[domain_security:{session.id}] {len(findings)} findings for {domain}")
    return findings


# ---------------------------------------------------------------------------
# DNS checks
# ---------------------------------------------------------------------------

def _resolve(domain, record_type):
    """Resolve a DNS record, return answers or empty list."""
    try:
        return dns.resolver.resolve(domain, record_type)
    except Exception:
        return []


def _check_dns(session, domain) -> list:
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

    return findings


# ---------------------------------------------------------------------------
# Email security checks
# ---------------------------------------------------------------------------

def _get_txt_record(domain) -> list[str]:
    """Return all TXT record strings for a domain."""
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        return [b"".join(r.strings).decode("utf-8", errors="ignore") for r in answers]
    except Exception:
        return []


def _check_email(session, domain) -> list:
    findings = []

    # SPF
    txt_records = _get_txt_record(domain)
    spf_records = [r for r in txt_records if r.startswith("v=spf1")]

    if not spf_records:
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="email",
            severity="high",
            title="SPF record missing",
            description=f"{domain} has no SPF record. Anyone can spoof email from this domain.",
            remediation="Add a TXT record: v=spf1 include:<your-mail-provider> -all",
        ))
    else:
        spf = spf_records[0]
        if "~all" in spf:
            findings.append(DomainFinding(
                session=session, domain=domain, check_type="email",
                severity="medium",
                title="SPF policy is soft fail (~all)",
                description="SPF is set to ~all (soft fail). Spoofed emails may still be delivered.",
                remediation="Change ~all to -all for strict enforcement.",
                extra={"spf_record": spf},
            ))
        elif "+all" in spf:
            findings.append(DomainFinding(
                session=session, domain=domain, check_type="email",
                severity="critical",
                title="SPF policy allows all senders (+all)",
                description="SPF +all means any server can send email as this domain.",
                remediation="Change +all to -all immediately.",
                extra={"spf_record": spf},
            ))

    # DMARC
    dmarc_records = _get_txt_record(f"_dmarc.{domain}")
    dmarc = next((r for r in dmarc_records if r.startswith("v=DMARC1")), None)

    if not dmarc:
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="email",
            severity="high",
            title="DMARC record missing",
            description=f"{domain} has no DMARC record. Email spoofing is not prevented.",
            remediation="Add a TXT record at _dmarc.{domain}: v=DMARC1; p=reject; rua=mailto:dmarc@{domain}".format(domain=domain),
        ))
    else:
        if "p=none" in dmarc:
            findings.append(DomainFinding(
                session=session, domain=domain, check_type="email",
                severity="medium",
                title="DMARC policy is none (monitoring only)",
                description="DMARC p=none means no action is taken on failing emails.",
                remediation="Change DMARC policy to p=quarantine or p=reject.",
                extra={"dmarc_record": dmarc},
            ))
        elif "p=quarantine" in dmarc:
            findings.append(DomainFinding(
                session=session, domain=domain, check_type="email",
                severity="low",
                title="DMARC policy is quarantine (not reject)",
                description="DMARC p=quarantine sends failing emails to spam. p=reject is stronger.",
                remediation="Consider upgrading DMARC policy to p=reject.",
                extra={"dmarc_record": dmarc},
            ))

    # DKIM — check common selectors
    dkim_found = False
    for selector in DKIM_SELECTORS:
        records = _get_txt_record(f"{selector}._domainkey.{domain}")
        if any("v=DKIM1" in r for r in records):
            dkim_found = True
            break

    if not dkim_found:
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="email",
            severity="medium",
            title="DKIM record not found",
            description=f"No DKIM record found for common selectors on {domain}.",
            remediation="Configure DKIM signing with your email provider and publish the public key as a TXT record.",
        ))

    return findings


# ---------------------------------------------------------------------------
# RDAP checks
# ---------------------------------------------------------------------------

def _check_rdap(session, domain) -> list:
    findings = []

    try:
        resp = requests.get(RDAP_URL.format(domain), timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.warning(f"[domain_security] RDAP lookup failed for {domain}: {e}")
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="rdap",
            severity="info",
            title="RDAP lookup failed",
            description=f"Could not retrieve RDAP data for {domain}.",
            remediation="Verify the domain is registered and RDAP is available.",
        ))
        return findings

    statuses = [s.lower() for s in data.get("status", [])]
    events = {e["eventAction"]: e["eventDate"] for e in data.get("events", []) if "eventDate" in e}

    # Domain expiry
    expiry_str = events.get("expiration")
    if expiry_str:
        try:
            expiry = datetime.datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
            days_left = (expiry - datetime.datetime.now(datetime.timezone.utc)).days
            extra = {"expiry_date": expiry_str, "days_left": days_left}

            if days_left <= 7:
                findings.append(DomainFinding(
                    session=session, domain=domain, check_type="rdap",
                    severity="critical",
                    title=f"Domain expires in {days_left} day(s)",
                    description=f"{domain} expires on {expiry.date()}. Immediate renewal required.",
                    remediation="Renew the domain immediately to avoid service disruption.",
                    extra=extra,
                ))
            elif days_left <= 30:
                findings.append(DomainFinding(
                    session=session, domain=domain, check_type="rdap",
                    severity="high",
                    title=f"Domain expires in {days_left} days",
                    description=f"{domain} expires on {expiry.date()}.",
                    remediation="Renew the domain soon to avoid disruption.",
                    extra=extra,
                ))
        except Exception:
            pass

    # Registrar lock
    lock_statuses = {"client transfer prohibited", "server transfer prohibited"}
    has_lock = any(s in lock_statuses for s in statuses)
    if not has_lock:
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="rdap",
            severity="medium",
            title="Domain transfer lock not enabled",
            description=f"{domain} does not have a registrar transfer lock. It may be vulnerable to domain hijacking.",
            remediation="Enable 'clientTransferProhibited' lock at your domain registrar.",
            extra={"statuses": statuses},
        ))

    # Domain active status
    if "inactive" in statuses or "pending delete" in statuses:
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="rdap",
            severity="critical",
            title="Domain is inactive or pending deletion",
            description=f"{domain} status: {', '.join(statuses)}",
            remediation="Contact your registrar immediately.",
            extra={"statuses": statuses},
        ))

    return findings
