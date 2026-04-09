import json
import logging
import subprocess

from .models import Subdomain

logger = logging.getLogger(__name__)

BINARY = "/opt/homebrew/bin/subfinder"


def run_subfinder(session) -> list:
    """Run subfinder against session.domain, save results, return Subdomain queryset."""
    domain = session.domain
    cmd = [BINARY, "-d", domain, "-json", "-silent"]
    logger.info(f"[subfinder:{session.id}] Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        logger.error(f"[subfinder:{session.id}] Binary not found: {BINARY}")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"[subfinder:{session.id}] Timed out")
        return []

    objs = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        try:
            data = json.loads(line)
            host = data.get("host", "").strip()
            if host:
                objs.append(Subdomain(
                    session=session,
                    subdomain=host,
                    ip_address=data.get("ip") or None,
                ))
        except json.JSONDecodeError:
            host = line.strip()
            if host:
                objs.append(Subdomain(session=session, subdomain=host))

    if objs:
        Subdomain.objects.bulk_create(objs, ignore_conflicts=True)

    saved = list(session.subdomains.all())
    logger.info(f"[subfinder:{session.id}] Found {len(saved)} subdomains")
    return saved
