#!/usr/bin/env bash
set -Eeuo pipefail

# Installs the managed Fail2Ban filter and jail used by the Caddy edge.
# The operation is idempotent and validates the complete Fail2Ban
# configuration before the running daemon is reloaded.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SOURCE_ROOT="${REPO_ROOT}/config/fail2ban"
FAIL2BAN_CONFIG_DIR="${FAIL2BAN_CONFIG_DIR:-/etc/fail2ban}"
CADDY_ACCESS_LOG="${SECURITY_RECIPES_CADDY_ACCESS_LOG:-/var/log/caddy/access.log}"
FILTER_NAME="security-recipes-caddy-404.conf"
JAIL_NAME="security-recipes-caddy-404.local"
FILTER_SOURCE="${SOURCE_ROOT}/filter.d/${FILTER_NAME}"
JAIL_SOURCE="${SOURCE_ROOT}/jail.d/${JAIL_NAME}"
FILTER_TEST_LOG="${SOURCE_ROOT}/testdata/caddy-404-sample.jsonl"
FILTER_DEST="${FAIL2BAN_CONFIG_DIR}/filter.d/${FILTER_NAME}"
JAIL_DEST="${FAIL2BAN_CONFIG_DIR}/jail.d/${JAIL_NAME}"
CHANGED="false"
TEMP_FILES=()

log() {
  printf '[%s] caddy-404-ban: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

die() {
  log "ERROR: $*"
  exit 1
}

cleanup() {
  local file
  for file in "${TEMP_FILES[@]}"; do
    [[ ! -e "${file}" ]] || rm -rf -- "${file}"
  done
}
trap cleanup EXIT

atomic_install() {
  local source="$1"
  local destination="$2"
  local temp

  if [[ -f "${destination}" ]] && cmp -s -- "${source}" "${destination}"; then
    return 0
  fi

  temp="$(mktemp "${destination}.tmp.XXXXXXXX")"
  TEMP_FILES+=("${temp}")
  install -o root -g root -m 0644 "${source}" "${temp}"
  mv -f -- "${temp}" "${destination}"
  CHANGED="true"
}

verify_bundled_caddy_log_mount() {
  local container_id mounted_source expected_source
  command -v docker >/dev/null 2>&1 || return 0
  docker compose version >/dev/null 2>&1 || return 0

  container_id="$(
    docker compose --project-directory "${REPO_ROOT}" ps -q caddy 2>/dev/null ||
      true
  )"
  [[ -n "${container_id}" ]] || return 0

  mounted_source="$(
    docker inspect --format \
      '{{range .Mounts}}{{if eq .Destination "/var/log/caddy"}}{{.Source}}{{end}}{{end}}' \
      "${container_id}" 2>/dev/null || true
  )"
  expected_source="$(readlink -f "$(dirname "${CADDY_ACCESS_LOG}")")"
  if [[ -z "${mounted_source}" ||
        "$(readlink -f "${mounted_source}")" != "${expected_source}" ]]; then
    die "Bundled Caddy is not writing to ${expected_source}. Set SECURITY_RECIPES_TRAFFIC_LOGS_SOURCE=${expected_source} in .env, then recreate only Caddy once during a maintenance window before enabling this jail."
  fi
}

[[ "${EUID}" -eq 0 ]] || die "Run as root so Fail2Ban and nftables can be configured."
[[ "${CADDY_ACCESS_LOG}" == /* ]] || die "SECURITY_RECIPES_CADDY_ACCESS_LOG must be an absolute path."
[[ "${CADDY_ACCESS_LOG}" != *$'\n'* && "${CADDY_ACCESS_LOG}" != *$'\r'* ]] ||
  die "SECURITY_RECIPES_CADDY_ACCESS_LOG cannot contain line breaks."

for source in "${FILTER_SOURCE}" "${JAIL_SOURCE}" "${FILTER_TEST_LOG}"; do
  [[ -f "${source}" ]] || die "Required source file is missing: ${source}"
done
command -v fail2ban-client >/dev/null 2>&1 || die "fail2ban is not installed."
command -v fail2ban-regex >/dev/null 2>&1 || die "fail2ban-regex is not installed."
command -v nft >/dev/null 2>&1 || die "nftables is not installed."
command -v systemctl >/dev/null 2>&1 || die "systemd is required to manage fail2ban."

verify_bundled_caddy_log_mount

install -d -o root -g root -m 0755 \
  "${FAIL2BAN_CONFIG_DIR}/filter.d" \
  "${FAIL2BAN_CONFIG_DIR}/jail.d"

log_dir="$(dirname "${CADDY_ACCESS_LOG}")"
if getent passwd caddy >/dev/null 2>&1; then
  install -d -o caddy -g caddy -m 0750 "${log_dir}"
  if [[ ! -e "${CADDY_ACCESS_LOG}" ]]; then
    install -o caddy -g caddy -m 0640 /dev/null "${CADDY_ACCESS_LOG}"
  fi
else
  install -d -o root -g root -m 0750 "${log_dir}"
  if [[ ! -e "${CADDY_ACCESS_LOG}" ]]; then
    install -o root -g root -m 0640 /dev/null "${CADDY_ACCESS_LOG}"
  fi
fi

jail_rendered="$(mktemp)"
TEMP_FILES+=("${jail_rendered}")
awk -v logpath="${CADDY_ACCESS_LOG}" '
  /^logpath[[:space:]]*=/ {
    print "logpath = " logpath
    next
  }
  { print }
' "${JAIL_SOURCE}" >"${jail_rendered}"

regex_output="$(LC_ALL=C fail2ban-regex "${FILTER_TEST_LOG}" "${FILTER_SOURCE}")" ||
  die "The Caddy 404 filter failed its fixture validation."
grep -Eq 'Lines:.*1 matched, 1 missed' <<<"${regex_output}" ||
  die "The Caddy 404 filter did not match exactly the expected fixture record."

validation_dir="$(mktemp -d)"
TEMP_FILES+=("${validation_dir}")
cp -a -- "${FAIL2BAN_CONFIG_DIR}/." "${validation_dir}/"
install -o root -g root -m 0644 \
  "${FILTER_SOURCE}" "${validation_dir}/filter.d/${FILTER_NAME}"
install -o root -g root -m 0644 \
  "${jail_rendered}" "${validation_dir}/jail.d/${JAIL_NAME}"

log "Validating the staged Fail2Ban configuration before installation."
fail2ban-client -c "${validation_dir}" -t >/dev/null ||
  die "Fail2Ban rejected the managed Caddy 404 jail; the daemon was not reloaded."

atomic_install "${FILTER_SOURCE}" "${FILTER_DEST}"
atomic_install "${jail_rendered}" "${JAIL_DEST}"

if systemctl is-active --quiet fail2ban; then
  if [[ "${CHANGED}" == "true" ]] ||
     ! fail2ban-client status security-recipes-caddy-404 >/dev/null 2>&1; then
    fail2ban-client reload
  fi
else
  systemctl enable --now fail2ban
fi

fail2ban-client status security-recipes-caddy-404 >/dev/null ||
  die "The security-recipes-caddy-404 jail is not running."
log "Active: 5 final 404 responses in 5 seconds trigger a 1-hour web ban."
