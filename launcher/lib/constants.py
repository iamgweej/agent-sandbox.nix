# The artifact filenames are a contract with stub.sh, which finds what it
# needs by name.

ARGV_BEFORE_ENV = "argv-before-env"
ARGV_AFTER_ENV = "argv-after-env"
BWRAP_ARGS = "bwrap.args"
NETWORK = "network.json"
SEATBELT_PROFILE = "seatbelt.sb"
SECCOMP_FILTER = "seccomp.bpf"
# Where apply_network_rules leaves the filter open, and the number compute.py
# writes after --seccomp; the two sides never meet in one process.
SECCOMP_FD = 9
PASSWD = "passwd"
PROXY_PID = "proxy.pid"
PROXY_LOG = "proxy.log"
SOCKD_CONF = "sockd.conf"
# sockd's own pid file; without -p it tries /var/run, which an unprivileged
# user cannot write. proxy.pid, the process group cleanup kills, is ours.
SOCKD_PID = "sockd.pid"
PRIVOXY_CONF = "privoxy.conf"
# Written by the pre-entry script into the sandbox TMPDIR. Only macOS reads
# it back: there Privoxy outlives the agent.
PRIVOXY_PID = "privoxy.pid"
LAUNCH_LOG = "launch.log"
CLEANUP = "cleanup"
CLEANUP_IF_EMPTY = "cleanup-if-empty"
STUB_PID = "stub.pid"

PROXY_LISTEN_HOST = "127.0.0.1"
# pasta forwards <gateway>:<port> to 127.0.0.1:<port> on the host, which is
# both how the Linux sandbox reaches sockd and why the gateway has to be
# firewalled in open mode.
PASTA_GATEWAY_IP = "10.0.2.2"
# Privoxy's port inside the Linux sandbox, which has its own loopback. On
# macOS loopback is shared with the host, so the launcher picks a free one.
PRIVOXY_LINUX_PORT = 8118
# sockd matches names only, so it refuses every loopback address: those are
# host services the localhost: entries exist to gate. A client that obeys
# HTTP_PROXY would hand it those requests anyway and be refused, never taking
# the direct path a localhost: entry opened. These send it there instead.
NO_PROXY_HOSTS = "localhost,127.0.0.1,::1"
PROXY_STARTUP_TIMEOUT_SECONDS = 5.0
SESSION_RETENTION = 25

WARN_PREFIX = "[WARN][agent-sandbox.nix]"
ERROR_PREFIX = "[ERROR][agent-sandbox.nix]"
