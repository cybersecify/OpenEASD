"""Turn safe, recognized LDAP RootDSE fields into informational findings."""

import logging

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from apps.core.data.findings.models import Finding

logger = logging.getLogger(__name__)

# These fields are standard RootDSE service capabilities and naming metadata.
# Do not extract user objects or arbitrary response text into findings.
_ALLOWED_KEYS = frozenset({
    "namingContexts", "defaultNamingContext", "supportedLDAPVersion",
    "supportedSASLMechanisms", "vendorName", "vendorVersion",
})
_MAX_XML_BYTES = 2 * 1024 * 1024
_MAX_VALUES = 8
_MAX_LENGTH = 180


def _safe_value(raw: str) -> str:
    """Bound stored metadata and remove control characters."""
    return "".join(c for c in raw if c.isprintable()).strip()[:_MAX_LENGTH]


def _metadata(script) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}

    def add(key: str | None, raw: str | None) -> None:
        if key not in _ALLOWED_KEYS or not raw:
            return
        value = _safe_value(raw)
        if value and value not in values.get(key, []) and len(values.get(key, [])) < _MAX_VALUES:
            values.setdefault(key, []).append(value)

    # Nmap XML normally contains a human-readable output attribute; some
    # installations also emit nested <elem key="..."> values.
    for line in script.get("output", "").splitlines():
        key, sep, value = line.strip(" |\t").partition(":")
        if sep:
            add(key.strip(), value.strip())
    for elem in script.iter("elem"):
        add(elem.get("key"), elem.text)

    return {key: sorted(items) for key, items in sorted(values.items())}


def analyze(session, responses: dict[str, tuple[str, dict]]) -> list[Finding]:
    findings: list[Finding] = []
    valid_documents = 0
    for host, (xml_output, known_ports) in sorted(responses.items()):
        if len(xml_output.encode("utf-8")) > _MAX_XML_BYTES:
            logger.warning("[ldap_enum] XML for %s exceeds safe size", host)
            continue
        try:
            root = ET.fromstring(xml_output)
        except (ET.ParseError, DefusedXmlException, ValueError) as exc:
            logger.warning("[ldap_enum] Invalid Nmap XML for %s: %s", host, exc)
            continue
        valid_documents += 1

        for port_element in root.findall(".//host/ports/port"):
            if port_element.get("protocol") != "tcp":
                continue
            try:
                port_number = int(port_element.get("portid", ""))
            except ValueError:
                continue
            port = known_ports.get(port_number)
            if port is None:
                continue  # Never trust XML to add an unrelated target/port.
            state = port_element.find("state")
            if state is None or state.get("state") != "open":
                continue
            script = port_element.find("./script[@id='ldap-rootdse']")
            if script is None:
                continue
            metadata = _metadata(script)
            if not metadata:
                continue
            findings.append(Finding(
                session=session,
                source="ldap_enum",
                check_type="ldap_rootdse_metadata",
                check_id="ldap_enum:ldap_rootdse_metadata",
                severity="info",
                title=f"LDAP RootDSE metadata available on {host}:{port_number}",
                description=(
                    "The LDAP service exposes standard root DSE metadata without "
                    "credentials. This is often normal behavior and does not, by "
                    "itself, confirm a vulnerability or anonymous directory access."
                ),
                remediation=(
                    "Review whether the directory metadata is appropriate for "
                    "external clients. Restrict exposure at the network boundary "
                    "if the service is not intended to be public."
                ),
                port=port,
                target=f"{host}:{port_number}",
                extra={"metadata": metadata, "method": "ldap-rootdse"},
            ))
    if responses and not valid_documents:
        raise ValueError("All LDAP RootDSE Nmap responses contained invalid XML")
    return findings
