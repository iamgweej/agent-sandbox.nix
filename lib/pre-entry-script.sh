# shellcheck shell=bash
# First process inside the sandbox. Warns at launch when no git identity
# resolves; with user.useConfigOnly set, `git commit` fails closed rather
# than fabricating one.
if command -v git >/dev/null 2>&1; then
  if ! { git var GIT_AUTHOR_IDENT && git var GIT_COMMITTER_IDENT; } >/dev/null 2>&1; then
    printf "[WARN][agent-sandbox.nix] no git identity declared; git commit will fail. Set GIT_AUTHOR_*/GIT_COMMITTER_* in env, or bind a gitconfig (see README).\n" >&2
  fi
fi

# Restricted mode: Privoxy turns the agent's HTTP proxy requests into SOCKS5
# domain CONNECTs to sockd on the host. It runs in here, under the sandbox's
# own restrictions, so it can reach nothing the agent could not. On Linux it
# dies with bubblewrap's PID namespace; on macOS it outlives the agent, and
# cleanup kills it from the pid file.
if [[ -n ${SANDBOX_HTTP_FORWARDER:-} ]]; then
  forwarder=$SANDBOX_HTTP_FORWARDER
  forwarder_conf=$SANDBOX_HTTP_FORWARDER_CONF
  forwarder_port=$SANDBOX_HTTP_FORWARDER_PORT
  forwarder_pidfile=$SANDBOX_HTTP_FORWARDER_PIDFILE
  unset SANDBOX_HTTP_FORWARDER SANDBOX_HTTP_FORWARDER_CONF \
    SANDBOX_HTTP_FORWARDER_PORT SANDBOX_HTTP_FORWARDER_PIDFILE

  # Privoxy logs to stderr, which is the agent's terminal.
  forwarder_log="${forwarder_pidfile%/*}/privoxy.log"
  "$forwarder" --no-daemon "$forwarder_conf" >"$forwarder_log" 2>&1 &
  forwarder_pid=$!
  echo "$forwarder_pid" >"$forwarder_pidfile"

  # Up to 5s, the same budget the launcher gives sockd.
  for ((attempt = 0; attempt < 100; attempt++)); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$forwarder_port") 2>/dev/null; then
      break
    fi
    if ! kill -0 "$forwarder_pid" 2>/dev/null; then
      break
    fi
    "@sleep@" 0.05
  done
  if ! (exec 3<>"/dev/tcp/127.0.0.1/$forwarder_port") 2>/dev/null; then
    printf "[ERROR][agent-sandbox.nix] the HTTP proxy (Privoxy) did not start listening on 127.0.0.1:%s:\n" "$forwarder_port" >&2
    cat "$forwarder_log" >&2 2>/dev/null
    kill "$forwarder_pid" 2>/dev/null
    exit 1
  fi
fi

exec "$@"
