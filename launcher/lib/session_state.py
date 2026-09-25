import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from launcher.lib.build_spec import ProxySpec, SandboxBuildSpec, SandboxBuildSpecLinux
from launcher.lib.constants import (
    ERROR_PREFIX,
    PASTA_GATEWAY_IP,
    PRIVOXY_CONF,
    PRIVOXY_LINUX_PORT,
    PROXY_LISTEN_HOST,
    PROXY_LOG,
    PROXY_STARTUP_TIMEOUT_SECONDS,
    SESSION_RETENTION,
    SOCKD_CONF,
    SOCKD_PID,
    STUB_PID,
    WARN_PREFIX,
)

# Deliberately undocumented; used by the test suite. XDG_STATE_HOME is the
# supported knob.
SESSIONS_ROOT_OVERRIDE = "AGENT_SANDBOX_SESSIONS_ROOT"
SESSIONS_ROOT_NAME = "agent-sandbox"
DEFAULT_STATE_HOME = ".local/state"
SESSION_DIR_TIMESTAMP = "%Y%m%d-%H%M%S"
# Must stay in step with the name create_session_dir builds: it is what stops
# the prune from touching anything else in a shared root.
SESSION_DIR_NAME = re.compile(r"\d{8}-\d{6}-\d+-.+")
# Inside the session directory, and 0700: under a shared temp root one
# session could write into a concurrent session's HOME, which the seatbelt
# profile grants process-exec on.
SANDBOX_HOME_NAME = "home"
SANDBOX_TMPDIR_NAME = "tmp"


@dataclass(frozen=True, kw_only=True)
class ProxyState:
    # Where the sandbox reaches sockd: the pasta gateway on Linux, loopback
    # on macOS. Both land on the host's 127.0.0.1:sockd_port.
    sockd_host: str
    sockd_port: int
    # A process group leader: sockd forks its workers into the same group.
    sockd_pid: int
    # Privoxy's port on the sandbox's loopback.
    privoxy_port: int


@dataclass(frozen=True, kw_only=True)
class SessionState:
    session_dir: Path
    proxy: ProxyState | None


@dataclass(frozen=True, kw_only=True)
class SessionStateDarwin(SessionState):
    sandbox_home: Path
    sandbox_tmpdir: Path


def _get_sessions_root() -> Path:
    override = os.environ.get(SESSIONS_ROOT_OVERRIDE)
    if override:
        return Path(override)

    state_home = os.environ.get("XDG_STATE_HOME")
    if state_home:
        return Path(state_home) / SESSIONS_ROOT_NAME

    home = os.environ.get("HOME")
    if not home:
        raise SystemExit(f"{ERROR_PREFIX} HOME is not set")
    return Path(home) / DEFAULT_STATE_HOME / SESSIONS_ROOT_NAME


def _is_session_live(session_dir: Path) -> bool:
    # Both error directions fall towards live: a finished session surviving
    # until the next launch is harmless, deleting a running one is not.
    try:
        pid = int((session_dir / STUB_PID).read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return False
    # Zero and negative pids address process groups rather than a process.
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _prune_sessions_root(root: Path) -> None:
    """Keep the newest SESSION_RETENTION sessions, and every running one:
    a running session is still reading its own directory."""
    try:
        sessions = [
            entry
            for entry in root.iterdir()
            if SESSION_DIR_NAME.fullmatch(entry.name) and entry.is_dir()
        ]
    except OSError:
        return

    sessions.sort(key=lambda session: session.name, reverse=True)
    for session in sessions[SESSION_RETENTION:]:
        if _is_session_live(session):
            continue
        shutil.rmtree(session, ignore_errors=True)


def create_session_dir(spec: SandboxBuildSpec, now: datetime) -> Path:
    timestamp = now.strftime(SESSION_DIR_TIMESTAMP)
    name = f"{timestamp}-{os.getpid()}-{spec.out_name}"
    root = _get_sessions_root()
    _prune_sessions_root(root)
    session_dir = root / name
    try:
        session_dir.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise SystemExit(
            f"{ERROR_PREFIX} could not create the session directory "
            f"{session_dir}: {error}"
        ) from error
    return Path(os.path.realpath(session_dir))


def _create_sandbox_dir(session_dir: Path, name: str) -> Path:
    directory = session_dir / name
    try:
        directory.mkdir(mode=0o700)
    except OSError as error:
        raise SystemExit(
            f"{ERROR_PREFIX} could not create {directory}: {error}"
        ) from error
    return Path(os.path.realpath(directory))


def create_darwin_sandbox_home(session_dir: Path) -> Path:
    return _create_sandbox_dir(session_dir, SANDBOX_HOME_NAME)


def create_darwin_sandbox_tmpdir(session_dir: Path) -> Path:
    return _create_sandbox_dir(session_dir, SANDBOX_TMPDIR_NAME)


def remove_darwin_sandbox_dir(directory: Path) -> None:
    shutil.rmtree(directory, ignore_errors=True)


def _pick_free_port() -> int:
    # Racy by nature: the port is free now, not necessarily when sockd or
    # Privoxy binds it. A lost race fails the launch loudly, never silently.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((PROXY_LISTEN_HOST, 0))
        return int(probe.getsockname()[1])


def _get_default_interface_linux() -> str | None:
    try:
        lines = Path("/proc/net/route").read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines[1:]:
        fields = line.split()
        if len(fields) > 1 and fields[1] == "00000000":
            return fields[0]
    return None


def _get_default_interface_darwin() -> str | None:
    try:
        result = subprocess.run(
            ["/sbin/route", "-n", "get", "default"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    for line in result.stdout.splitlines():
        key, _, value = line.strip().partition(":")
        if key == "interface" and value.strip():
            return value.strip()
    return None


def _get_external_interface(is_linux: bool) -> str:
    """The interface sockd connects out from. sockd refuses a wildcard
    address, and refuses outright any listed interface that has no address,
    so it gets the default route's."""
    if is_linux:
        interface = _get_default_interface_linux()
        loopback = "lo"
    else:
        interface = _get_default_interface_darwin()
        loopback = "lo0"
    if interface is not None:
        return interface
    # Offline: sockd still has to start, so every allowed CONNECT fails
    # instead of the launch.
    print(
        f"{WARN_PREFIX} no default route; allowed domains will be unreachable "
        f"until the next launch",
        file=sys.stderr,
    )
    return loopback


def _write_sockd_conf(
    proxy: ProxySpec, session_dir: Path, port: int, external: str
) -> Path:
    # resolveprotocol: fake is load-bearing. Without it, a request carrying
    # an IP address (ATYP 0x01) is matched against the domain rules by
    # reverse-resolving it, which trusts whoever controls the PTR record.
    header = [
        f"logoutput: {session_dir / PROXY_LOG}",
        f"internal: {PROXY_LISTEN_HOST} port = {port}",
        f"external: {external}",
        "resolveprotocol: fake",
        "clientmethod: none",
        "socksmethod: none",
        # Loopback-only listener, so every client is already local. Not
        # logged: the launcher's readiness probe would read as a block.
        "client pass {",
        "  from: 0/0 to: 0/0",
        "}",
    ]
    rules = proxy.dante_rules_file.read_text(encoding="utf-8")
    path = session_dir / SOCKD_CONF
    path.write_text("\n".join(header) + "\n" + rules, encoding="utf-8")
    return path


def _write_privoxy_conf(
    session_dir: Path, listen_port: int, sockd_host: str, sockd_port: int
) -> None:
    # No actions or filters: Privoxy only translates. forward-socks5 (not 4a
    # or 5t) with "." sends sockd the name, never a local resolution.
    lines = [
        f"listen-address 127.0.0.1:{listen_port}",
        f"forward-socks5 / {sockd_host}:{sockd_port} .",
        "toggle 0",
        "enable-remote-toggle 0",
        "enable-remote-http-toggle 0",
        "enable-edit-actions 0",
    ]
    (session_dir / PRIVOXY_CONF).write_text("\n".join(lines) + "\n", encoding="utf-8")


def _start_sockd(
    proxy: ProxySpec, session_dir: Path, conf: Path
) -> subprocess.Popen[bytes]:
    # A session of its own, so the forked workers share a process group that
    # one killpg takes down.
    log = (session_dir / PROXY_LOG).open("ab")
    argv = [str(proxy.sockd), "-f", str(conf), "-p", str(session_dir / SOCKD_PID)]
    return subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=log,
        start_new_session=True,
    )


def _wait_for_sockd(
    process: subprocess.Popen[bytes], port: int, session_dir: Path
) -> None:
    log = session_dir / PROXY_LOG
    deadline = time.monotonic() + PROXY_STARTUP_TIMEOUT_SECONDS
    while True:
        if process.poll() is not None:
            raise SystemExit(
                f"{ERROR_PREFIX} sockd exited with status {process.returncode} "
                f"before accepting connections (see {log})"
            )
        try:
            with socket.create_connection((PROXY_LISTEN_HOST, port), timeout=0.2):
                return
        except OSError:
            pass
        if time.monotonic() >= deadline:
            raise SystemExit(
                f"{ERROR_PREFIX} sockd did not accept connections on port {port} "
                f"within {PROXY_STARTUP_TIMEOUT_SECONDS:g}s (see {log})"
            )
        time.sleep(0.05)


def _kill_process_group(pid: int) -> None:
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        pass


def kill_proxy(proxy: ProxyState | None) -> None:
    if proxy is None:
        return
    _kill_process_group(proxy.sockd_pid)


def create_proxy_state(spec: SandboxBuildSpec, session_dir: Path) -> ProxyState | None:
    if spec.proxy is None:
        return None

    is_linux = isinstance(spec, SandboxBuildSpecLinux)
    sockd_port = _pick_free_port()
    if is_linux:
        sockd_host = PASTA_GATEWAY_IP
        privoxy_port = PRIVOXY_LINUX_PORT
    else:
        sockd_host = PROXY_LISTEN_HOST
        privoxy_port = _pick_free_port()

    external = _get_external_interface(is_linux)
    conf = _write_sockd_conf(spec.proxy, session_dir, sockd_port, external)
    _write_privoxy_conf(session_dir, privoxy_port, sockd_host, sockd_port)

    process = _start_sockd(spec.proxy, session_dir, conf)
    try:
        _wait_for_sockd(process, sockd_port, session_dir)
    except BaseException:
        _kill_process_group(process.pid)
        raise
    return ProxyState(
        sockd_host=sockd_host,
        sockd_port=sockd_port,
        sockd_pid=process.pid,
        privoxy_port=privoxy_port,
    )
