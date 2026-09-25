"""Second entry point, called from the stub's EXIT trap. Best effort
throughout: failing here would turn a successful run into a failed one."""

import os
import shutil
import signal
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from launcher.lib.constants import (
    CLEANUP,
    CLEANUP_IF_EMPTY,
    LAUNCH_LOG,
    PRIVOXY_CONF,
    PRIVOXY_PID,
    PROXY_PID,
)
from launcher.lib.launch_log import write_sandbox_exit
from launcher.lib.session_state import SANDBOX_TMPDIR_NAME


def _read_nul(path: Path) -> list[Path]:
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    return [Path(entry.decode()) for entry in raw.split(b"\0") if entry]


def _read_pid(path: Path) -> int | None:
    try:
        pid = int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    # Zero and negative pids address process groups rather than a process.
    return pid if pid > 0 else None


def _kill_proxy(session_dir: Path) -> None:
    # The whole group: sockd forks its workers into it.
    pid = _read_pid(session_dir / PROXY_PID)
    if pid is None:
        return
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        pass


def _kill_privoxy(session_dir: Path) -> None:
    """macOS only: on Linux Privoxy dies with bubblewrap's PID namespace, and
    its pid file never leaves the sandbox's own /tmp.

    The pid file sits in the sandbox TMPDIR, which the agent can write, so a
    pid is only trusted if that process is Privoxy running this session's
    config. Otherwise the agent could aim a SIGKILL at any host process.
    """
    pid = _read_pid(session_dir / SANDBOX_TMPDIR_NAME / PRIVOXY_PID)
    if pid is None:
        return
    try:
        command = subprocess.run(
            ["/bin/ps", "-o", "command=", "-p", str(pid)],
            capture_output=True,
            text=True,
            check=False,
        ).stdout
    except OSError:
        return
    if f"--no-daemon {session_dir / PRIVOXY_CONF}" not in command:
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def cleanup_launch(session_dir: Path, exit_status: int | None, now: datetime) -> None:
    if exit_status is not None:
        write_sandbox_exit(session_dir / LAUNCH_LOG, exit_status, now)

    _kill_proxy(session_dir)
    if sys.platform == "darwin":
        _kill_privoxy(session_dir)

    for path in _read_nul(session_dir / CLEANUP):
        shutil.rmtree(path, ignore_errors=True)
        try:
            path.unlink()
        except OSError:
            pass

    # Mount points bubblewrap materialised on the host. If something wrote
    # real content there in the meantime, it is not ours to delete.
    for path in _read_nul(session_dir / CLEANUP_IF_EMPTY):
        try:
            if path.stat().st_size == 0:
                path.unlink()
        except OSError:
            pass


def main() -> None:
    # Raising from an EXIT trap would replace the sandbox's own exit status
    # with a traceback, so a malformed status is treated as absent.
    exit_status = None
    if len(sys.argv) > 2:
        try:
            exit_status = int(sys.argv[2])
        except ValueError:
            exit_status = None
    cleanup_launch(Path(sys.argv[1]), exit_status, datetime.now())


if __name__ == "__main__":
    main()
