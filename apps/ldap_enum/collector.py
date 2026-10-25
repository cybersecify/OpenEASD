"""Read-only LDAP root DSE collection from already classified LDAP ports.

Nmap's documented ldap-rootdse NSE script is in its `safe` category. No
LDAP credentials or search bases are supplied, and no directory search is run.
"""

import ipaddress
import logging
import subprocess
from collections import defaultdict

from django.conf import settings

from apps.core.data.assets.models import Port
from apps.core.engine.workflows.exceptions import ToolBinaryMissing, ToolTimeout

logger = logging.getLogger(__name__)


def _is_ldap_port(port: Port) -> bool:
    """Require the detected service, not just a suggestive port number."""
    service = (port.service or "").casefold().strip()
    return (
        port.protocol == "tcp"
        and port.state == "open"
        and not port.is_web
        and (service.startswith("ldap") or service in {"ssl/ldap", "ssl/ldaps"})
    )


def collect(session) -> dict[str, tuple[str, dict[int, Port]]]:
    """Return host XML together with exactly the Port objects that were probed.

    A probe failure is not proof of a secure service. When ALL probes fail the
    workflow step fails so the UI cannot report a misleading clean result.
    """
    ports = Port.objects.filter(session=session, state="open", protocol="tcp", is_web=False)
    by_host: dict[str, dict[int, Port]] = defaultdict(dict)
    for port in ports:
        if not _is_ldap_port(port):
            continue
        try:
            target = str(ipaddress.ip_address(port.address))
        except ValueError:
            logger.warning("[ldap_enum] Ignoring non-IP LDAP port: %r", port.address)
            continue
        if 0 < port.port <= 65535:
            by_host[target][port.port] = port

    if not by_host:
        return {}

    binary = getattr(settings, "TOOL_NMAP", "nmap")
    results: dict[str, tuple[str, dict[int, Port]]] = {}
    failed = 0
    timed_out = 0
    for host, matching_ports in sorted(by_host.items()):
        command = [
            binary, "-sT", "-Pn", "-n", "--max-retries", "1",
            "--script", "ldap-rootdse", "--script-timeout", "10s",
            "--host-timeout", "60s", "-p",
            ",".join(map(str, sorted(matching_ports))), "-oX", "-", host,
        ]
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True,
                timeout=75, stdin=subprocess.DEVNULL, check=False,
            )
        except FileNotFoundError as exc:
            raise ToolBinaryMissing(f"nmap binary not found: {binary}") from exc
        except subprocess.TimeoutExpired:
            timed_out += 1
            failed += 1
            logger.warning("[ldap_enum] Nmap timed out for %s", host)
            continue

        if completed.returncode != 0 or not completed.stdout.strip():
            failed += 1
            logger.warning("[ldap_enum] Nmap failed for %s (exit %d)", host, completed.returncode)
            continue
        results[host] = (completed.stdout, matching_ports)

    if failed == len(by_host):
        if timed_out == failed:
            raise ToolTimeout("LDAP RootDSE probes all timed out")
        raise RuntimeError("LDAP RootDSE probes all failed; no results are trustworthy")
    if failed:
        logger.warning("[ldap_enum] %d of %d host probes failed", failed, len(by_host))
    return results
