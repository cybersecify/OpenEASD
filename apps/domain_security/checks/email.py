"""Email security checks for domain_security app."""

import logging

import dns.resolver
from apps.domain_security.models import DomainFinding

logger = logging.getLogger(__name__)

DKIM_SELECTORS = ["default", "google", "mail", "dkim", "selector1", "selector2", "k1", "smtp"]


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

    return findings


def _check_dmarc(session, domain) -> list:
    findings = []
    dmarc_records = _get_txt_record(f"_dmarc.{domain}")
    dmarc = next((r for r in dmarc_records if r.startswith("v=DMARC1")), None)

    if not dmarc:
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="email",
            severity="high",
            title="DMARC record missing",
            description=f"{domain} has no DMARC record. Email spoofing is not prevented.",
            remediation=f"Add a TXT record at _dmarc.{domain}: v=DMARC1; p=reject; rua=mailto:dmarc@{domain}",
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
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="email",
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
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="email",
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
        # Check policy mode if record exists
        if "mode=testing" in mta_sts:
            findings.append(DomainFinding(
                session=session, domain=domain, check_type="email",
                severity="low",
                title="MTA-STS is in testing mode",
                description="MTA-STS mode=testing reports failures but does not enforce TLS.",
                remediation="Change MTA-STS mode from testing to enforce once verified.",
                extra={"mta_sts_record": mta_sts},
            ))
        elif "mode=none" in mta_sts:
            findings.append(DomainFinding(
                session=session, domain=domain, check_type="email",
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
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="email",
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
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="email",
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


def collect_and_analyze(session, domain) -> list:
    """Run all email security checks and return list of DomainFinding objects (not yet saved)."""
    findings = []
    findings += _check_spf(session, domain)
    findings += _check_dmarc(session, domain)
    findings += _check_dkim(session, domain)
    findings += _check_mta_sts(session, domain)
    findings += _check_tls_rpt(session, domain)
    findings += _check_bimi(session, domain)
    return findings
