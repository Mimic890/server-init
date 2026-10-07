#!/usr/bin/env bash
# Integration test: run server-init in a systemd container.
#   test/integration/run.sh <image> <server-init binary>
# Checks: --dry-run changes nothing, --config apply works, SSH login with the
# generated key works on the new port and passwords are refused, a rerun
# changes nothing, rollback restores port 22.
set -euo pipefail

img=$1
bin=$2
here=$(cd "$(dirname "$0")" && pwd)
name="si-it-$$"
fail() { echo "FAIL: $*" >&2; docker exec "$name" tail -n 40 /var/log/server-init.log >&2 || true; exit 1; }
step() { echo "--- $*"; }
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$name" --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock "$img" >/dev/null
for _ in $(seq 60); do
  state=$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)
  [[ $state == running || $state == degraded ]] && break
  sleep 1
done
docker cp "$bin" "$name:/usr/local/bin/server-init"
docker cp "$here/answers.yaml" "$name:/root/answers.yaml"
ip=$(docker inspect "$name" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
sx() { docker exec "$name" "$@"; }
etc_sum() { sx sh -c 'find /etc -type f -print0 | sort -z | xargs -0 sha256sum' | sha256sum; }

step "dry run changes nothing"
before=$(etc_sum)
sx server-init --config /root/answers.yaml --dry-run >/tmp/dry.out || { cat /tmp/dry.out; fail "dry run"; }
grep -q "Dry run: nothing was changed" /tmp/dry.out || fail "dry run output"
[[ $(etc_sum) == "$before" ]] || fail "dry run modified /etc"

step "apply"
sx server-init --config /root/answers.yaml --yes >/tmp/apply.out || { cat /tmp/apply.out; fail "apply"; }
sx ss -ltn | grep -q ':40022 ' || fail "not listening on 40022"
sx ss -ltn | grep -q ':22 ' && fail "port 22 still open"
sx sshd -T | grep -qx 'passwordauthentication no' || fail "password auth on"

step "firewall"
sx ufw status | grep -q "Status: active" || fail "ufw not active"
sx ufw status | grep -q "40022/tcp *LIMIT" || fail "SSH rule missing"
sx ufw status | grep -q "443/tcp *ALLOW" || fail "HTTPS rule missing"
sx grep -q "BEGIN UFW AND DOCKER" /etc/ufw/after.rules || fail "docker fix missing"

step "login from a client"
docker cp "$name:/root/.ssh/server-init_ed25519" /tmp/si-key-$$
chmod 600 /tmp/si-key-$$
opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5)
docker run --rm -v /tmp/si-key-$$:/k:ro "$img" sh -c \
  "cp /k /tmp/k && chmod 600 /tmp/k && ssh ${opts[*]} -i /tmp/k -p 40022 root@$ip true" || fail "key login"
docker run --rm "$img" ssh "${opts[@]}" -o PubkeyAuthentication=no -p 40022 "root@$ip" true 2>/dev/null \
  && fail "password login must be refused"
rm -f /tmp/si-key-$$

step "rerun is a no-op"
sx server-init --config /root/answers.yaml --yes >/tmp/rerun.out || { cat /tmp/rerun.out; fail "rerun"; }
grep -q "Everything is already applied" /tmp/rerun.out || { cat /tmp/rerun.out; fail "rerun changed something"; }

step "rollback"
sx server-init --rollback ssh || fail "rollback"
sleep 1
sx ss -ltn | grep -q ':22 ' || fail "port 22 not back after rollback"
sx test ! -e /etc/ssh/sshd_config.d/00-server-init.conf || fail "drop-in left behind"
sx ufw status | grep -q "^22/tcp " || fail "rollback must open port 22 in the active ufw"

step "rollback ufw"
sx server-init --rollback ufw || fail "ufw rollback"
sx ufw status | grep -q "Status: inactive" || fail "ufw still active after rollback"
sx grep -q "BEGIN UFW AND DOCKER" /etc/ufw/after.rules && fail "docker block left behind"

echo "PASS: $img"
