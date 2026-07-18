#!/usr/bin/env bash
set -Eeuo pipefail

# Live Fail2Ban state-machine smoke test. It uses an isolated daemon, private
# socket, polling log, and the stock dummy action, so it never changes the
# host firewall or the system Fail2Ban service.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FILTER_SOURCE="${REPO_ROOT}/config/fail2ban/filter.d/security-recipes-caddy-404.conf"
JAIL_NAME="security-recipes-caddy-404"

for command in fail2ban-client fail2ban-server; do
  command -v "${command}" >/dev/null 2>&1 || {
    printf 'ERROR: %s is required.\n' "${command}" >&2
    exit 1
  }
done
[[ -d /etc/fail2ban ]] || {
  printf 'ERROR: /etc/fail2ban is required.\n' >&2
  exit 1
}

workdir="$(mktemp -d)"
config_dir="${workdir}/fail2ban"
access_log="${workdir}/access.log"
action_log="${workdir}/dummy-action.log"
socket_path="${workdir}/fail2ban.sock"
pid_path="${workdir}/fail2ban.pid"
server_started="false"

cleanup() {
  if [[ "${server_started}" == "true" ]]; then
    fail2ban-client -c "${config_dir}" stop >/dev/null 2>&1 || true
  fi
  rm -rf -- "${workdir}"
}
trap cleanup EXIT

cp -a /etc/fail2ban "${config_dir}"
cp "${FILTER_SOURCE}" "${config_dir}/filter.d/security-recipes-caddy-404.conf"
touch "${access_log}"

cat >"${config_dir}/fail2ban.local" <<EOF
[Definition]
allowipv6 = auto
loglevel = INFO
logtarget = ${workdir}/fail2ban.log
socket = ${socket_path}
pidfile = ${pid_path}
dbfile = ${workdir}/fail2ban.sqlite3
dbpurgeage = 1d
EOF

cat >"${config_dir}/jail.local" <<EOF
[DEFAULT]
backend = polling

[sshd]
enabled = false

[${JAIL_NAME}]
enabled = true
filter = security-recipes-caddy-404
logpath = ${access_log}
backend = polling
usedns = no
ignoreip = 127.0.0.0/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7 fe80::/10
maxretry = 5
findtime = 5s
bantime = 2s
bantime.increment = false
action = dummy[name=sr404-smoke,target=${action_log}]
EOF

fail2ban-client -c "${config_dir}" -t >/dev/null
fail2ban-client -c "${config_dir}" -x start >/dev/null
server_started="true"

client() {
  fail2ban-client -c "${config_dir}" "$@"
}

emit() {
  local ip="$1"
  local status="$2"
  local timestamp="${3:-$(date +%s)}"
  printf '{"level":"info","ts":%s.001,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.8","remote_port":"55000","client_ip":"%s","proto":"HTTP/2.0","method":"GET","host":"security-recipes.ai","uri":"/missing","headers":{}},"bytes_read":0,"duration":0.001,"size":0,"status":%s,"resp_headers":{}}\n' \
    "${timestamp}" "${ip}" "${status}" >>"${access_log}"
}

is_banned() {
  local ip="$1"
  client get "${JAIL_NAME}" banip 2>/dev/null | grep -Fq -- "${ip}"
}

wait_for_ban_state() {
  local ip="$1"
  local expected="$2"
  local attempt
  for attempt in $(seq 1 60); do
    if is_banned "${ip}"; then
      [[ "${expected}" == "banned" ]] && return 0
    else
      [[ "${expected}" == "clear" ]] && return 0
    fi
    sleep 0.1
  done
  printf 'ERROR: %s did not become %s.\n' "${ip}" "${expected}" >&2
  return 1
}

four_ip="203.0.113.40"
for _ in 1 2 3 4; do
  emit "${four_ip}" 404
done
sleep 1.2
if is_banned "${four_ip}"; then
  printf 'ERROR: four 404 responses triggered a ban.\n' >&2
  exit 1
fi

stale_ip="203.0.113.41"
stale_timestamp="$(( $(date +%s) - 10 ))"
for _ in 1 2 3 4; do
  emit "${stale_ip}" 404 "${stale_timestamp}"
done
emit "${stale_ip}" 404
sleep 1.2
if is_banned "${stale_ip}"; then
  printf 'ERROR: 404 responses outside the five-second window triggered a ban.\n' >&2
  exit 1
fi

ban_ip="203.0.113.42"
for _ in 1 2 3 4 5; do
  emit "${ban_ip}" 404
done
wait_for_ban_state "${ban_ip}" banned
grep -Fq -- "+${ban_ip}" "${action_log}"

wait_for_ban_state "${ban_ip}" clear
grep -Fq -- "-${ban_ip}" "${action_log}"

printf 'Caddy 404 Fail2Ban state-machine smoke test passed.\n'
