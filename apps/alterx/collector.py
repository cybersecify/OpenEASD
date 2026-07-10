import logging
import shutil
import subprocess

from django.conf import settings

from apps.core.workflows.exceptions import ToolBinaryMissing, ToolTimeout

logger = logging.getLogger(__name__)

_TIMEOUT = 300


def collect(subdomains: list[str]) -> list[str]:
    """Pipe subdomains to alterx and return generated permutation strings."""
    if not subdomains:
        return []

    binary = getattr(settings, "TOOL_ALTERX", "alterx")
    if not shutil.which(binary):
        logger.debug("alterx binary not found at %r — skipping", binary)
        return []

    stdin_data = "\n".join(subdomains)

    try:
        result = subprocess.run(
            [binary],
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        logger.warning("alterx timed out after %ss", _TIMEOUT)
        raise ToolTimeout(f"alterx timed out after {_TIMEOUT}s")
    except FileNotFoundError:
        raise ToolBinaryMissing("alterx binary not found")

    if result.returncode != 0:
        logger.warning(
            "alterx exited %s: %s",
            result.returncode, (result.stderr or "")[:200],
        )
        return []

    return [line for line in result.stdout.splitlines() if line.strip()]
