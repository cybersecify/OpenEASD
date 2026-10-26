"""Re-probe verifier for nmap NSE-vulners CVE findings.

Real finding shape (confirmed by reading analyzer.py, not the design brief's
guess): the brief's guess was right about the storage key — every nmap CVE
Finding is ``check_type="cve"`` with ``extra["cve"]`` holding a single CVE id
(one Finding per CVE per host:port; see ``analyzer.analyze``'s
``key = (ip, port_num, v["id"])`` dedup) and ``target=f"{ip}:{port_num}"``. The
brief's collector/analyzer function names were wrong though:

  - There is no ``collector.run_vulners`` — the real entry point is
    ``collector.collect(session, ip_to_ports: dict[str, list[int]]) ->
    dict[str, str]`` (ip -> raw nmap XML), which runs ``nmap -sV
    --script=vulners`` per IP. It only needs ``session`` for log lines
    (``session.id``), so the finding's own session is passed through.
  - There is no ``analyzer.extract_cves`` — vulners XML parsing lives inline
    in ``analyzer.analyze()`` via the module-level ``_extract_vulns(script_el)``
    helper (already a small reusable function), which this module imports
    directly rather than duplicating.

Backport-aware CVE matching: ``analyzer.analyze()`` demotes (not drops) a CVE
to severity="info" when ``apps.nmap.backports.check_backport(product,
full_version_string, cve_id)`` reports the distro has backported a fix for it
— the Finding still gets created, just no longer treated as exploitable. A
re-probe must apply the exact same demotion, or a since-patched (backported)
CVE that still literally appears in vulners' version-based output would be
falsely re-VERIFIED. So ``_rescan_cves`` parses the fresh XML the same way
analyzer does (product/version/extrainfo -> ``full_version_string``) and
excludes any CVE that ``check_backport`` demotes, returning only the CVE ids
that are still genuinely reported as exploitable.

Active (touches the target) — gated upstream by DomainAuthorization in
verify_session, same as the tool itself.
"""
import defusedxml.ElementTree as ET

from apps.core.engine.verification.verdict import Verdict
from apps.nmap import collector
from apps.nmap.analyzer import _extract_vulns
from apps.nmap.backports import check_backport


def _split_target(target: str):
    host, _, port = (target or "").partition(":")
    try:
        port_num = int(port)
    except ValueError:
        port_num = 0
    return host, port_num


def _rescan_cves(session, host: str, port: int) -> set:
    """Re-run the nmap vulners NSE scan against a single host:port.

    Returns the set of CVE ids vulners still reports on ``host:port`` MINUS
    any CVE the backport-aware matcher (``apps.nmap.backports.check_backport``)
    demotes as already patched via distro backport — mirroring
    ``apps/nmap/analyzer.py``'s own severity-demotion rule so a backported CVE
    is never falsely re-VERIFIED. Reuses ``collector.collect`` (the tool's own
    scan invocation) and ``analyzer._extract_vulns`` (the tool's own vulners
    XML parse) rather than reimplementing either.
    """
    xml_outputs = collector.collect(session, {host: [port]})
    xml_str = xml_outputs.get(host, "")
    if not xml_str:
        return set()

    cves: set = set()
    root = ET.fromstring(xml_str)
    for host_el in root.findall("host"):
        for port_el in host_el.findall(".//port"):
            portid = port_el.get("portid", "")
            if not portid.isdigit() or int(portid) != port:
                continue
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            service_el = port_el.find("service")
            product = service_el.get("product", "") if service_el is not None else ""
            ver = service_el.get("version", "") if service_el is not None else ""
            extrainfo = service_el.get("extrainfo", "") if service_el is not None else ""
            version = f"{product} {ver}".strip()
            full_version_string = f"{version} {extrainfo}".strip()

            for script_el in port_el.findall("script"):
                if script_el.get("id") != "vulners":
                    continue
                for v in _extract_vulns(script_el):
                    cve_id = v["id"]
                    if not cve_id.startswith("CVE-"):
                        continue
                    if check_backport(product, full_version_string, cve_id):
                        continue  # patched via backport — don't re-verify
                    cves.add(cve_id.upper())

    return cves


def verify_finding(finding) -> Verdict:
    """Re-probe a single nmap CVE finding by re-scanning its one host:port.

    VERIFIED when the CVE still appears in fresh vulners output (post
    backport-demotion); INCONCLUSIVE when it's gone, the finding is missing a
    CVE/port to re-probe, or the rescan itself errors/times out — never raises.
    """
    cve = (finding.extra or {}).get("cve", "")
    cve = cve.upper() if cve else ""
    host, port = _split_target(finding.target)
    if not cve or not port:
        return Verdict(Verdict.INCONCLUSIVE, detail="missing cve or port on finding")

    try:
        cves = _rescan_cves(finding.session, host, port)
    except Exception as exc:  # noqa: BLE001 — any rescan failure -> inconclusive, never raise
        return Verdict(Verdict.INCONCLUSIVE, detail=f"rescan failed: {exc}")

    if cve in cves:
        return Verdict(Verdict.VERIFIED, evidence=f"{cve} still reported on {host}:{port}")
    return Verdict(Verdict.INCONCLUSIVE, detail=f"{cve} no longer reported on rescan")
