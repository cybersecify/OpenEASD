"""Subzy collector — runs subzy against a list of subdomains and returns parsed records.

subzy CLI surface (PentestPad/subzy v1.2.1, verified via source):
    subzy run --targets <file> --output <file.json> --hide_fails [--timeout <s>] [--concurrency <n>]

Notes:
- --output writes JSON-encoded results to a file (no `--json` flag exists).
- --hide_fails suppresses non-vulnerable rows in the printed text output;
  the JSON file still contains all probed rows, with vulnerability state on each.
- subzy needs to download its fingerprint database on first run. The tool stores
  fingerprints under $HOME/.config/subzy by default; in the container we set
  HOME so this lands somewhere writable.
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile

from django.conf import settings

from apps.core.workflows.exceptions import ToolBinaryMissing, ToolTimeout

logger = logging.getLogger(__name__)


def collect(subdomains: list[str]) -> list[dict]:
    """Run subzy against a list of subdomains; return parsed JSON records.

    Returns an empty list on:
    - empty input
    - missing binary
    - subprocess error or timeout
    - unparseable output

    Each returned record is a dict from the subzy JSON output; vulnerability
    state lives on the record (typically a boolean key the analyzer keys off).
    """
    if not subdomains:
        return []

    binary = getattr(settings, "TOOL_SUBZY", "subzy")
    if not shutil.which(binary):
        logger.error("subzy binary not found at %r", binary)
        raise ToolBinaryMissing(f"subzy binary not found: {binary}")

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False
    ) as targets_file:
        targets_file.write("\n".join(subdomains))
        targets_path = targets_file.name

    output_path = targets_path + ".json"

    try:
        cmd = [
            binary,
            "run",
            "--targets", targets_path,
            "--output", output_path,
            "--hide_fails",
            "--timeout", "20",
            "--concurrency", "10",
        ]

        # Bound total runtime: subzy probes each target with --timeout per probe;
        # cap overall at 30 min so a runaway input list can't hang a scan.
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            logger.warning("subzy timed out after 1800s")
            raise ToolTimeout("subzy timed out after 1800s")

        if result.returncode != 0:
            logger.warning(
                "subzy exited %s: %s",
                result.returncode,
                (result.stderr or "")[:300],
            )
            return []

        if not os.path.exists(output_path):
            logger.warning("subzy ran but produced no output file at %s", output_path)
            return []

        with open(output_path, "r") as f:
            raw = f.read()

        if not raw.strip():
            return []

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            logger.warning("subzy output not valid JSON: %s", e)
            return []

        records = data if isinstance(data, list) else [data]
        logger.info("subzy returned %d records", len(records))
        return records

    finally:
        # Best-effort temp-file cleanup. OSError here means the file is already
        # gone (subzy never produced output) or unwritable — neither is
        # recoverable nor worth surfacing, so swallow it.
        for path in (targets_path, output_path):
            try:
                os.unlink(path)
            except OSError:
                continue
