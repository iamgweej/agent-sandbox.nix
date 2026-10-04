#!/usr/bin/env bash
# Test: an allowed domain that resolves to host loopback does not reach host
# services. sockd runs on the host, so without the dante patch it would dial
# 127.0.0.1 for the sandbox and bypass the local-port policy.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_CWD="$(cd "$SCRIPT_DIR/../../.." && pwd)"

source "$SCRIPT_DIR/../lib.sh"

echo "=== Loopback-resolving domain denied (shared) ==="
echo

PORT=18950
HOST_PYTHON3=$(build_host_pkg python3Minimal)/bin/python3

# localtest.me is public DNS with a single A record, 127.0.0.1. Not
# *.localhost: that resolves to ::1 first on macOS, which sockd refuses
# earlier, for want of an IPv6 external address, without reaching the patch.
if ! "$HOST_PYTHON3" -c '
import socket, sys
addrs = {a[4][0] for a in socket.getaddrinfo("localtest.me", 80)}
sys.exit(0 if addrs == {"127.0.0.1"} else 1)
' 2>/dev/null; then
	echo "SKIP: the host does not resolve localtest.me to 127.0.0.1 alone"
	exit 0
fi

# SO_REUSEADDR like the server, so a previous run's TIME_WAIT is not a
# conflict; a live listener still is.
if ! "$HOST_PYTHON3" -c '
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen()
' "$PORT" 2>/dev/null; then
	echo "FAIL: test setup — 127.0.0.1:$PORT already in use" >&2
	exit 1
fi

SANDBOXED=$(build_fixture loopback-domain.nix --argstr port "$PORT")
SHELL_BIN="$SANDBOXED/bin/sandboxed-bash-loopback-domain"

TESTDIR_ROOT="$TEST_CWD/.tmp-test"
mkdir -p "$TESTDIR_ROOT"
TESTDIR=$(mktemp -d "$TESTDIR_ROOT/loopback-domain.XXXXXX")

SERVER_PID=""
cleanup() {
	if [ -n "$SERVER_PID" ]; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	rm -rf "$TESTDIR"
}
trap cleanup EXIT

"$HOST_PYTHON3" "$SCRIPT_DIR/../helpers/host-http-loopback.py" "$PORT" \
	>"$TESTDIR/server.log" 2>&1 &
SERVER_PID=$!

_ready=0
for _ in $(seq 1 50); do
	if grep -q '^READY$' "$TESTDIR/server.log" 2>/dev/null; then
		_ready=1
		break
	fi
	sleep 0.1
done
if [ "$_ready" -ne 1 ]; then
	echo "ERROR: host HTTP server never came up" >&2
	cat "$TESTDIR/server.log" >&2 || true
	exit 1
fi

# One session root per run, so each proxy.log is the only one under it.
run_in() {
	local subdir="$1" command="$2"
	(cd "$TEST_CWD" && AGENT_SANDBOX_SESSIONS_ROOT="$AGENT_SANDBOX_SESSIONS_ROOT/$subdir" \
		"$SHELL_BIN" --norc --noprofile -c "$command") >/dev/null 2>&1
}
run() { run_in env "$1"; }
run_http() { run_in http "$1"; }
run_socks() { run_in socks "$1"; }

# The control: the name and the server both work from the host.
if "$HOST_PYTHON3" -c '
import sys, urllib.request
urllib.request.urlopen("http://localtest.me:%s/" % sys.argv[1], timeout=3).read()
' "$PORT" 2>/dev/null; then
	echo "PASS: the host reaches localtest.me:$PORT directly"
	PASS=$((PASS + 1))
else
	echo "FAIL: the host cannot reach localtest.me:$PORT, so the denials below prove nothing"
	FAIL=$((FAIL + 1))
fi

expect_ok run "NO_PROXY is unset, so the request goes to the proxy" \
	'test -z "${NO_PROXY:-}" && test -n "$HTTP_PROXY" && test -n "$ALL_PROXY"'

expect_fail run_http "loopback-resolving domain denied through Privoxy" \
	"curl -sf --max-time 10 -o /dev/null http://localtest.me:$PORT/"

expect_fail run_socks "loopback-resolving domain denied through sockd directly" \
	"curl -sf --max-time 10 -o /dev/null --proxy \"\$ALL_PROXY\" http://localtest.me:$PORT/"

for subdir in http socks; do
	log=$(find "$AGENT_SANDBOX_SESSIONS_ROOT/$subdir" -mindepth 2 -maxdepth 2 -name proxy.log 2>/dev/null | head -1)
	desc="proxy.log records the $subdir refusal as a loopback block"
	if [ -z "$log" ]; then
		echo "FAIL: $desc (no proxy.log under $subdir)"
		FAIL=$((FAIL + 1))
	elif grep -qF -- "loopback and link-local destinations are blocked" "$log"; then
		echo "PASS: $desc"
		PASS=$((PASS + 1))
	else
		echo "FAIL: $desc"
		sed 's/^/    /' "$log"
		FAIL=$((FAIL + 1))
	fi
done

print_results
exit_status
