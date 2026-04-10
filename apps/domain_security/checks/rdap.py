"""RDAP checks for domain_security app."""

import datetime
import logging
import time

import requests
from django.conf import settings
from django.utils import timezone as django_tz

from apps.domain_security.models import DomainFinding

logger = logging.getLogger(__name__)

RDAP_URL = "https://rdap.org/domain/{}"
IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

# Timeout defaults — override via settings.py
_HTTP_TIMEOUT = getattr(settings, "SCANNER_HTTP_TIMEOUT", 10)  # seconds


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
            resp = requests.get(RDAP_URL.format(domain), timeout=_HTTP_TIMEOUT)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            last_exc = e
            if attempt < 2:
                time.sleep(2 ** attempt)  # 1s, 2s backoff

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
            logger.info(f"[domain_security] Trying IANA RDAP bootstrap for .{tld}: {rdap_base}")
            resp = requests.get(f"{rdap_base}/domain/{domain}", timeout=_HTTP_TIMEOUT)
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        last_exc = e
        logger.warning(f"[domain_security] IANA bootstrap fallback failed for {domain}: {e}")

    raise last_exc


def collect_and_analyze(session, domain) -> list:
    """Run RDAP checks and return list of DomainFinding objects (not yet saved)."""
    findings = []

    try:
        data = _fetch_rdap(domain)
    except Exception as e:
        logger.warning(f"[domain_security] All RDAP sources failed for {domain}: {e}")
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="rdap",
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

    # Transfer lock
    has_transfer_lock = any(s in {"client transfer prohibited", "server transfer prohibited"} for s in statuses)
    if not has_transfer_lock:
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="rdap",
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
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="rdap",
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
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="rdap",
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
        findings.append(DomainFinding(
            session=session, domain=domain, check_type="rdap",
            severity="critical",
            title="Domain is inactive or pending deletion",
            description=f"{domain} status: {', '.join(statuses)}",
            remediation="Contact your registrar immediately.",
            extra={"statuses": statuses},
        ))

    return findings
