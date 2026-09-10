"""Active domain probes for OpenEASD.

The checks here touch the target's own infrastructure directly (so the tool is
``active`` and requires DomainAuthorization), unlike the passive DNS/email/RDAP
intelligence in ``apps.domain_security``:

  - AXFR zone transfer  — connects to the target's nameservers
  - SMTP open relay      — connects to the target's MX on port 25
  - MTA-STS policy fetch — fetches https://mta-sts.<domain>/.well-known/mta-sts.txt

DNS/SMTP helpers are kept inline (a small copy of domain_security's), so tool
apps never import from one another and test mocks targeting
``apps.domain_probe.scanner.*`` patch the functions actually called.
"""

import logging
import smtplib

import dns.resolver
import dns.query
import dns.zone
from dns.resolver import NXDOMAIN as _DNS_NXDOMAIN, NoAnswer as _DNS_NoAnswer, NoNameservers as _DNS_NoNameservers
import requests
from django.conf import settings

from apps.core.data.findings.models import Finding

logger = logging.getLogger(__name__)

_DNS_TIMEOUT = getattr(settings, "SCANNER_DNS_TIMEOUT", 5)
_HTTP_TIMEOUT = getattr(settings, "SCANNER_HTTP_TIMEOUT", 10)


# ---------------------------------------------------------------------------
# DNS helpers (local copy — tools don't import from each other)
# ---------------------------------------------------------------------------

def _resolve(domain, record_type):
    """Resolve a DNS record, return answers or empty list."""
    try:
        return dns.resolver.resolve(domain, record_type)
    except (_DNS_NoAnswer, _DNS_NXDOMAIN, _DNS_NoNameservers):
        return []
    except Exception as e:
        logger.debug(f"[domain_probe] DNS {record_type} lookup failed for {domain}: {e}")
        return []


def _get_txt_record(domain) -> list:
    """Return all TXT record strings for a domain."""
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        return [b"".join(r.strings).decode("utf-8", errors="ignore") for r in answers]
    except Exception:
        return []


def _stamp_control(findings, control):
    """Tag email findings with the control they concern (mta_sts/open_relay).

    Email findings share check_type="email", so the report keys its per-control
    business-impact copy on extra["control"]. Mirrors domain_security's stamping."""
    for f in findings:
        f.extra = {**(f.extra or {}), "control": control}
    return findings


# ---------------------------------------------------------------------------
# Active probes
# ---------------------------------------------------------------------------

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
                    session=session, source="domain_probe", target=domain, check_type="dns",
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
            # A refused / timed-out AXFR is the normal, secure case — not an
            # error. Swallow it and move on to the next nameserver.
            pass

    return findings


def _check_mta_sts(session, domain) -> list:
    """Check MTA-STS — enforces TLS for inbound email delivery.

    Two-step check per RFC 8461:
    1. DNS TXT record at _mta-sts.domain must exist (signals policy presence)
    2. Policy file at https://mta-sts.domain/.well-known/mta-sts.txt must be
       reachable and have mode: enforce (mode is in the file, NOT the DNS record)
    """
    findings = []
    mta_sts_records = _get_txt_record(f"_mta-sts.{domain}")
    mta_sts_dns = next((r for r in mta_sts_records if r.startswith("v=STSv1")), None)

    if not mta_sts_dns:
        findings.append(Finding(
            session=session, source="domain_probe", target=domain, check_type="email",
            severity="medium",
            title="MTA-STS not configured",
            description=(
                f"{domain} has no MTA-STS policy. Email delivery to your mail server is not "
                "protected against TLS downgrade attacks — a network attacker between mail "
                "servers can force plaintext delivery and intercept email in transit."
            ),
            remediation=(
                f"1. Add DNS TXT record at _mta-sts.{domain}: v=STSv1; id=<timestamp>\n"
                f"2. Host policy file at https://mta-sts.{domain}/.well-known/mta-sts.txt\n"
                "   Content: version: STSv1\\nmode: enforce\\nmx: <your-mx-host>\\nmax_age: 86400"
            ),
        ))
        return findings

    # DNS record present — fetch and validate the policy file
    policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        resp = requests.get(policy_url, timeout=_HTTP_TIMEOUT)
        resp.raise_for_status()
        policy_text = resp.text
    except Exception:
        findings.append(Finding(
            session=session, source="domain_probe", target=domain, check_type="email",
            severity="high",
            title="MTA-STS policy file not reachable",
            description=(
                f"{domain} has an MTA-STS DNS record but the policy file at {policy_url} "
                "is not reachable. Sending mail servers cannot retrieve the policy and "
                "will not enforce TLS — the DNS record alone provides no protection."
            ),
            remediation=(
                f"Host the policy file at https://mta-sts.{domain}/.well-known/mta-sts.txt "
                "with a valid TLS certificate. The file must be publicly accessible over HTTPS."
            ),
            extra={"policy_url": policy_url},
        ))
        return findings

    # Parse mode field — this is what actually controls enforcement
    mode = None
    for line in policy_text.splitlines():
        if line.strip().lower().startswith("mode:"):
            mode = line.split(":", 1)[1].strip().lower()
            break

    if mode == "enforce":
        return []  # correctly configured

    title_map = {
        "testing": "MTA-STS is in testing mode — TLS not enforced",
        "none": "MTA-STS is disabled (mode: none)",
    }
    description_map = {
        "testing": (
            f"{domain} MTA-STS policy is set to mode: testing. Failures are reported "
            "but TLS is not enforced — email can still be downgraded to plaintext."
        ),
        "none": (
            f"{domain} MTA-STS policy is explicitly disabled (mode: none). "
            "No TLS is enforced on inbound email delivery."
        ),
    }
    findings.append(Finding(
        session=session, source="domain_probe", target=domain, check_type="email",
        severity="medium",
        title=title_map.get(mode, "MTA-STS policy mode is invalid or missing"),
        description=description_map.get(mode, (
            f"{domain} MTA-STS policy at {policy_url} has an unrecognised or missing "
            f"mode field (found: {mode!r}). Sending servers will not enforce TLS."
        )),
        remediation="Update the MTA-STS policy file: set mode: enforce",
        extra={"policy_url": policy_url, "mode": mode},
    ))
    return findings


def _check_open_relay(session, domain) -> list:
    """Attempt unauthenticated SMTP relay through the domain's MX server.

    Connects to port 25 and sends a relay probe using two external addresses.
    A 250 response to the RCPT TO confirms the server relays for anyone.
    """
    mx_records = _resolve(domain, "MX")
    if not mx_records:
        return []

    try:
        mx_host = str(sorted(mx_records, key=lambda r: r.preference)[0].exchange).rstrip(".")
    except Exception:
        return []

    try:
        with smtplib.SMTP(mx_host, 25, timeout=10) as smtp:
            smtp.ehlo("probe.openeasd.local")
            code, _ = smtp.mail("probe@relay-test.openeasd.local")
            if code != 250:
                return []
            code, _ = smtp.rcpt("probe@relay-check.openeasd.local")
            if code == 250:
                return [Finding(
                    session=session, source="domain_probe", target=mx_host,
                    check_type="open_relay", severity="critical",
                    title="Open mail relay detected",
                    description=(
                        f"The mail server {mx_host} (MX for {domain}) accepted a relay "
                        "attempt from an external address to an external address. "
                        "Anyone on the internet can send email through this server — "
                        "enabling spam campaigns and phishing attacks that appear to "
                        "originate from your infrastructure, and risking IP blacklisting."
                    ),
                    remediation=(
                        "Immediately restrict SMTP relay on your mail server:\n"
                        "1. Configure your MTA to only relay for authenticated users or trusted IPs\n"
                        "2. Postfix: set mynetworks and smtpd_relay_restrictions = permit_mynetworks, "
                        "permit_sasl_authenticated, reject\n"
                        "3. Exchange: disable anonymous relay in receive connectors\n"
                        "4. Verify: telnet <mx-host> 25 → EHLO → MAIL FROM external → "
                        "RCPT TO external → must receive 5xx rejection"
                    ),
                    extra={"mx_host": mx_host, "domain": domain},
                )]
    except Exception:
        # A closed port / refused connection / SMTP error means no open relay —
        # the expected, secure case. Not a finding, not an error.
        pass

    return []


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def run_domain_probe(session) -> list:
    """Run the active domain probes and save findings."""
    domain = session.domain
    logger.info(f"[domain_probe:{session.id}] Starting active probes for {domain}")

    findings = []
    findings += _check_zone_transfer(session, domain, _resolve(domain, "NS"))
    findings += _stamp_control(_check_mta_sts(session, domain), "mta_sts")
    findings += _stamp_control(_check_open_relay(session, domain), "open_relay")

    if findings:
        Finding.objects.bulk_create(findings)

    logger.info(f"[domain_probe:{session.id}] {len(findings)} findings for {domain}")
    return findings
