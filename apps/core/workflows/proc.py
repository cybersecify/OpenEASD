"""Shared subprocess runner for tools that spawn escape-prone helper processes.

nuclei (and nuclei_network — the same binary) spawn helpers (interactsh poller,
resolvers, headless) that can escape the process group and inherit the stdout
pipe. With subprocess.run/communicate() that means: even after we SIGKILL the
group on timeout, the pipe never reaches EOF and communicate() blocks forever —
the timeout fires but the call never returns, wedging the worker thread until the
session watchdog reaps it.

The fix (originally in apps/nuclei/collector.py, extracted here so nuclei_network
gets it too): redirect stdout/stderr to temp FILES (no pipe) and wait() on the
direct child. wait() returns the moment the child exits regardless of inherited
FDs, so a SIGKILL always unblocks us. An escaped grandchild can leak but can no
longer hang the scan.
"""

import os
import signal
import subprocess
import tempfile

_DRAIN_GRACE = 30  # seconds to let a SIGKILL'd process die before we give up


def run_capped(cmd: list[str], timeout: int, env: dict | None = None) -> subprocess.CompletedProcess:
    """Run an external tool with a timeout that child processes cannot defeat.

    Mirrors subprocess.run's contract: returns CompletedProcess, raises
    FileNotFoundError if the binary is missing, re-raises TimeoutExpired after the
    process group is killed. On timeout the raised TimeoutExpired carries whatever
    the tool had already written to stdout in `.output` (so callers can recover
    partial results instead of discarding them).
    """
    out_fd, out_path = tempfile.mkstemp(suffix=".tool.out")
    err_fd, err_path = tempfile.mkstemp(suffix=".tool.err")
    try:
        with os.fdopen(out_fd, "wb") as out_f, os.fdopen(err_fd, "wb") as err_f:
            proc = subprocess.Popen(
                cmd,
                stdout=out_f,
                stderr=err_f,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
                env=env,
            )
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    proc.kill()
                try:
                    proc.wait(timeout=_DRAIN_GRACE)
                except subprocess.TimeoutExpired:
                    pass
                # Attach whatever was written before the wall so callers can save
                # partial findings rather than report a misleading 0.
                try:
                    with open(out_path, "r", errors="replace") as f:
                        exc.output = f.read()
                except OSError:
                    pass
                raise
        with open(out_path, "r", errors="replace") as f:
            stdout = f.read()
        with open(err_path, "r", errors="replace") as f:
            stderr = f.read()
        return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)
    finally:
        for p in (out_path, err_path):
            try:
                os.unlink(p)
            except OSError:
                pass
