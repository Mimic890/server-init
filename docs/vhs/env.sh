# Sourced (hidden) by the tapes: server-init runs inside a systemd container
# named si-demo (see test/integration/Dockerfile), so the recording shows a
# real Ubuntu 24.04 host without touching the machine that records it.
server-init() {
  docker exec -it -e TERM=xterm-256color -e SSH_CLIENT="203.0.113.7 51234 22" \
    -e SSH_CONNECTION="203.0.113.7 51234 198.51.100.10 22" si-demo server-init "$@"
}
PS1='$ '
clear
