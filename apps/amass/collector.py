"""Amass binary execution — active + passive subdomain enumeration."""

import json
import logging
import os
import subprocess
import tempfile

import yaml
from django.conf import settings

from apps.core.workflows.exceptions import ToolBinaryMissing, ToolTimeout

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

    # amass v4 dropped the `-json` flag; output is line-by-line plain text on
    # stdout by default. The parser below handles both plain text and JSONL.
    cmd = [binary, "enum", "-d", domain, "-silent"]

    low_memory = getattr(settings, "LOW_MEMORY", False)

    # Brute-force wordlist expansion is amass's biggest memory driver — it's what
    # OOM-kills it on a ~1 GB host. In low-memory mode skip -brute (and cap DNS
    # query concurrency) so amass still enumerates from passive sources + normal
    # resolution and actually completes, instead of thrashing to death.
    if config.wordlist_file and not low_memory:
        cmd += ["-brute", "-w", config.wordlist_file.path]
    if low_memory:
        cmd += ["-max-dns-queries", "1000"]

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

    brute = f" +brute({config.wordlist_file.name})" if (config.wordlist_file and not low_memory) else (" (low-memory: no brute)" if low_memory else "")
    logger.info(
        f"[amass:{session.id}] Scanning {domain} "
        f"(mode=active{brute}, timeout={config.scan_timeout}m)"
    )

    stdout = ""
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            stdin=subprocess.DEVNULL,
        )
        try:
            stdout, stderr = proc.communicate(timeout=config.scan_timeout * 60 + 30)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            # This fires 30s PAST amass's own scan_timeout — i.e. amass ignored
            # its internal budget and hung, not a clean time-boxed finish. Raise
            # so the step is marked failed and the scan reports "partial" instead
            # of silently presenting a truncated surface as a complete scan.
            logger.warning(
                f"[amass:{session.id}] Hung past {config.scan_timeout}m budget "
                f"— marking step failed (scan will report partial)"
            )
            raise ToolTimeout(
                f"amass hung past its {config.scan_timeout}m scan_timeout"
            )
        else:
            if proc.returncode != 0:
                logger.warning(f"[amass:{session.id}] Exited with code {proc.returncode}")
                if stderr:
                    logger.warning(f"[amass:{session.id}] stderr: {stderr[:500]}")
    except FileNotFoundError:
        logger.error(f"[amass:{session.id}] Binary not found: {binary}")
        raise ToolBinaryMissing(f"amass binary not found: {binary}")
    finally:
        if config_tmp:
            os.unlink(config_tmp)

    records = []
    seen = set()
    for line in stdout.strip().splitlines():
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
