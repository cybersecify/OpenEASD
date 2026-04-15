"""Amass binary execution — active + passive subdomain enumeration."""

import json
import logging
import os
import subprocess
import tempfile

import yaml
from django.conf import settings

logger = logging.getLogger(__name__)


def collect(session) -> list[dict]:
    """
    Run amass enum against session.domain.

    Respects AmassConfig.enabled — returns [] immediately if disabled.
    Writes a temp YAML config when API keys are set.
    Returns raw subdomain records: [{"host": "sub.example.com"}]
    """
    from .models import AmassConfig
    config = AmassConfig.get()

    if not config.enabled:
        logger.info(f"[amass:{session.id}] Disabled — skipping")
        return []

    binary = getattr(settings, "TOOL_AMASS", "amass")
    domain = session.domain

    cmd = [binary, "enum", "-d", domain, "-json", "-silent"]

    if config.wordlist_file:
        cmd += ["-brute", "-w", config.wordlist_file.path]

    cmd += ["-timeout", str(config.scan_timeout)]

    # Write temp config YAML if any API keys are set
    datasources = config.build_datasource_config()
    config_tmp = None
    if datasources:
        amass_cfg = {"datasources": datasources}
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(amass_cfg, f)
            config_tmp = f.name
        cmd += ["-config", config_tmp]
        provider_names = [s["name"] for s in datasources]
        logger.info(
            f"[amass:{session.id}] Using providers: {', '.join(provider_names)}"
        )

    brute = f" +brute({config.wordlist_file.name})" if config.wordlist_file else ""
    logger.info(
        f"[amass:{session.id}] Scanning {domain} "
        f"(mode=active{brute}, timeout={config.scan_timeout}m)"
    )

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.scan_timeout * 60 + 30,  # seconds, with 30s grace
        )
    except FileNotFoundError:
        logger.error(f"[amass:{session.id}] Binary not found: {binary}")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"[amass:{session.id}] Timed out after {config.scan_timeout}m")
        return []
    finally:
        if config_tmp:
            os.unlink(config_tmp)

    if result.returncode != 0:
        logger.warning(f"[amass:{session.id}] Exited with code {result.returncode}")
        if result.stderr:
            logger.warning(f"[amass:{session.id}] stderr: {result.stderr[:500]}")

    records = []
    seen = set()
    for line in result.stdout.strip().splitlines():
        if not line:
            continue
        try:
            data = json.loads(line)
            # amass JSONL: {"name": "sub.example.com", "domain": "example.com", ...}
            host = (data.get("name") or data.get("host") or "").strip().lower()
        except json.JSONDecodeError:
            host = line.strip().lower()

        if host and host not in seen:
            seen.add(host)
            records.append({"host": host})

    logger.info(f"[amass:{session.id}] Found {len(records)} subdomains")
    return records
