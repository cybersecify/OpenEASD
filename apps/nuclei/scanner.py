import json
import logging
import subprocess
import tempfile
import os

from .models import NucleiFinding

logger = logging.getLogger(__name__)

BINARY = "/opt/homebrew/bin/nuclei"

SEVERITY_MAP = {"info": "low", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}


def run_nuclei(session, targets: list) -> list:
    """Run nuclei vulnerability scan against targets, save results."""
    if not targets:
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        tmp = f.name

    cmd = [BINARY, "-list", tmp, "-json", "-silent"]
    logger.info(f"[nuclei:{session.id}] Scanning {len(targets)} targets")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except FileNotFoundError:
        logger.error(f"[nuclei:{session.id}] Binary not found: {BINARY}")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"[nuclei:{session.id}] Timed out")
        return []
    finally:
        os.unlink(tmp)

    objs = []
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        try:
            data = json.loads(line)
            info = data.get("info", {})
            raw_severity = info.get("severity", "info")
            severity = SEVERITY_MAP.get(raw_severity, "low")
            classification = info.get("classification", {})
            objs.append(NucleiFinding(
                session=session,
                host=data.get("host", ""),
                template_id=data.get("template-id", data.get("templateID", "")),
                template_name=info.get("name", ""),
                severity=severity,
                description=info.get("description", ""),
                matched_at=data.get("matched-at", ""),
                cvss_score=classification.get("cvss-score"),
                cve_id=", ".join(classification.get("cve-id", [])) if isinstance(classification.get("cve-id"), list) else "",
            ))
        except json.JSONDecodeError:
            continue

    if objs:
        NucleiFinding.objects.bulk_create(objs)

    saved = list(session.nuclei_findings.all())
    logger.info(f"[nuclei:{session.id}] Found {len(saved)} vulnerabilities")
    return saved
