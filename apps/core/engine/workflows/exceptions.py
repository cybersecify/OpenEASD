"""Typed tool-execution failures.

Collectors historically swallowed a missing binary or a wall-clock timeout into
`return []`, which the workflow runner could not tell apart from a genuine
"ran fine, found nothing" result — so a broken tool reported `completed` with no
error. Raising these instead lets the runner (which already marks any raising
step `failed` → run `partial`) surface the failure honestly.

Use:
    except FileNotFoundError:
        raise ToolBinaryMissing(f"{binary} not found")
    except subprocess.TimeoutExpired:
        raise ToolTimeout(f"{binary} timed out after {timeout}s")
"""


class ToolExecutionError(Exception):
    """Base for a tool that failed to run to completion (vs. found nothing)."""


class ToolTimeout(ToolExecutionError):
    """The tool's external process exceeded its wall-clock cap and was killed."""


class ToolBinaryMissing(ToolExecutionError):
    """The tool's external binary is not installed / not on PATH."""
