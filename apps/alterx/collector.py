import logging
import shutil
import subprocess

from django.conf import settings

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
        return []
    except FileNotFoundError:
        return []

    if result.returncode != 0:
        logger.warning(
            "alterx exited %s: %s",
            result.returncode, (result.stderr or "")[:200],
        )
        return []

    return [line for line in result.stdout.splitlines() if line.strip()]
