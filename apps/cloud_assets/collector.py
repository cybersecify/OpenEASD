import logging
import os
import shutil
import subprocess
import tempfile

from django.conf import settings

from apps.core.workflows.exceptions import ToolBinaryMissing, ToolTimeout

logger = logging.getLogger(__name__)

_TIMEOUT = 1800  # 30 minutes — cloud_enum probes many permutations


def collect(keywords: list[str]) -> list[str]:
    if not keywords:
        return []

    binary = getattr(settings, "TOOL_CLOUD_ENUM", "cloud_enum")
    if not shutil.which(binary):
        logger.debug("cloud_enum binary not found at %r — skipping", binary)
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as kf:
        kf.write("\n".join(keywords))
        keywords_path = kf.name

    output_path = keywords_path + ".out"

    try:
        cmd = [binary, "-kf", keywords_path, "-l", output_path, "-t", "10"]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_TIMEOUT,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            logger.warning("cloud_enum timed out after %ss", _TIMEOUT)
            raise ToolTimeout(f"cloud_enum timed out after {_TIMEOUT}s")
        except FileNotFoundError:
            raise ToolBinaryMissing(f"cloud_enum binary not found: {binary}")

        if result.returncode != 0:
            logger.warning(
                "cloud_enum exited %s: %s",
                result.returncode,
                (result.stderr or "")[:300],
            )
            return []

        if not os.path.exists(output_path):
            logger.info("[cloud_assets] cloud_enum found no open buckets")
            return []

        with open(output_path) as f:
            raw = f.read()

        if not raw.strip():
            return []

        return [line.strip() for line in raw.splitlines() if line.strip()]

    finally:
        for path in (keywords_path, output_path):
            try:
                os.unlink(path)
            except OSError:
                continue
