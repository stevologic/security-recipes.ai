#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Creates a small recovery bundle for the configuration that cannot be rebuilt
# from Git. The generated site and Docker images are intentionally excluded:
# deploy.sh recreates those from a CI-verified main commit.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${SECURITY_RECIPES_APP_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
BACKUP_DIR="${SECURITY_RECIPES_BACKUP_DIR:-/var/backups/security-recipes}"
RETENTION_DAYS="${SECURITY_RECIPES_BACKUP_RETENTION_DAYS:-14}"
RCLONE_DESTINATION="${SECURITY_RECIPES_BACKUP_RCLONE_DESTINATION:-}"
AGE_RECIPIENT="${SECURITY_RECIPES_BACKUP_AGE_RECIPIENT:-}"
HEARTBEAT_URL="${SECURITY_RECIPES_BACKUP_HEARTBEAT_URL:-}"
HEARTBEAT_TIMEOUT="${SECURITY_RECIPES_BACKUP_HEARTBEAT_TIMEOUT:-10}"

log() {
  printf '[%s] backup: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

die() {
  log "ERROR: $*"
  exit 1
}

[[ "${EUID}" -eq 0 ]] || die "Run as root so private deployment configuration can be read safely."
[[ "${APP_DIR}" == /* && -d "${APP_DIR}/.git" ]] || die "SECURITY_RECIPES_APP_DIR must be an absolute Git checkout."
[[ "${BACKUP_DIR}" == /* && "${BACKUP_DIR}" != "/" ]] || die "SECURITY_RECIPES_BACKUP_DIR must be a non-root absolute path."
[[ "${RETENTION_DAYS}" =~ ^[1-9][0-9]*$ ]] || die "SECURITY_RECIPES_BACKUP_RETENTION_DAYS must be a positive integer."
[[ "${HEARTBEAT_TIMEOUT}" =~ ^[1-9][0-9]*$ ]] || die "SECURITY_RECIPES_BACKUP_HEARTBEAT_TIMEOUT must be a positive integer."
if [[ -n "${HEARTBEAT_URL}" && ! "${HEARTBEAT_URL}" =~ ^https?:// ]]; then
  die "SECURITY_RECIPES_BACKUP_HEARTBEAT_URL must use http:// or https://."
fi
if [[ "${HEARTBEAT_URL}" == *$'\n'* || "${HEARTBEAT_URL}" == *$'\r'* ]]; then
  die "SECURITY_RECIPES_BACKUP_HEARTBEAT_URL cannot contain line breaks."
fi

install -d -o root -g root -m 0700 "${BACKUP_DIR}"
staging="$(mktemp -d "${BACKUP_DIR}/.staging.XXXXXXXX")"
partial=""
encrypted=""
cleanup() {
  rm -rf -- "${staging}"
  [[ -z "${partial}" || ! -e "${partial}" ]] || rm -f -- "${partial}"
}
trap cleanup EXIT

copy_path() {
  local source="$1"
  local relative_destination="$2"
  local destination="${staging}/${relative_destination}"
  [[ -e "${source}" ]] || return 0
  install -d -m 0700 "$(dirname "${destination}")"
  if [[ -d "${source}" ]]; then
    install -d -m 0700 "${destination}"
    cp -a -- "${source}/." "${destination}/"
  else
    cp -a -- "${source}" "${destination}"
  fi
}

# Server-owned values and runtime evidence. Runtime state is diagnostic during
# a restore; deploy.sh should reconcile or reinitialize it instead of trusting
# it blindly on a replacement host.
copy_path "${APP_DIR}/.env" "app/.env"
copy_path "${APP_DIR}/mcp-server.toml" "app/mcp-server.toml"
copy_path "${APP_DIR}/.git/deploy-state" "app/deploy-state"
copy_path "${APP_DIR}/.git/deploy-failed-sha" "app/deploy-failed-sha"
copy_path "/etc/security-recipes" "etc/security-recipes"
copy_path "/etc/caddy/Caddyfile" "etc/caddy/Caddyfile"
copy_path "/etc/caddy/Caddyfile.security-recipes-preinstall.bak" \
  "etc/caddy/Caddyfile.security-recipes-preinstall.bak"
copy_path "/etc/systemd/system/caddy.service.d/20-security-recipes-resume.conf" \
  "etc/systemd/system/caddy.service.d/20-security-recipes-resume.conf"

for unit in \
  security-recipes-deploy.service \
  security-recipes-deploy.timer \
  security-recipes-backup.service \
  security-recipes-backup.timer; do
  copy_path "/etc/systemd/system/${unit}" "etc/systemd/system/${unit}"
done

install -d -m 0700 "${staging}/metadata"
date -u +%Y-%m-%dT%H:%M:%SZ >"${staging}/metadata/created-at"
git -C "${APP_DIR}" rev-parse HEAD >"${staging}/metadata/checkout-head"
if command -v docker >/dev/null 2>&1 &&
   docker compose version >/dev/null 2>&1; then
  (
    cd "${APP_DIR}"
    docker compose ps --format json
  ) >"${staging}/metadata/compose-containers.json" 2>/dev/null || true
fi

host="$(hostname -s 2>/dev/null | tr -cd 'A-Za-z0-9._-' || true)"
host="${host:-droplet}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
archive="${BACKUP_DIR}/security-recipes-config-${host}-${timestamp}.tar.gz"
partial="${archive}.partial"

tar --numeric-owner -C "${staging}" -czf "${partial}" .
chmod 0600 "${partial}"
mv -f -- "${partial}" "${archive}"
partial=""
log "Created root-only recovery bundle ${archive}."

if [[ -n "${RCLONE_DESTINATION}" ]]; then
  [[ -n "${AGE_RECIPIENT}" ]] ||
    die "Set SECURITY_RECIPES_BACKUP_AGE_RECIPIENT before enabling off-host upload."
  command -v age >/dev/null 2>&1 ||
    die "age is required for encrypted off-host backup upload."
  command -v rclone >/dev/null 2>&1 ||
    die "rclone is required for off-host backup upload."

  encrypted="${archive}.age"
  age --recipient "${AGE_RECIPIENT}" --output "${encrypted}" "${archive}"
  chmod 0600 "${encrypted}"
  rclone copyto \
    "${encrypted}" \
    "${RCLONE_DESTINATION%/}/$(basename "${encrypted}")"
  log "Uploaded an age-encrypted recovery bundle off-host."
fi

# This directory is fixed above and files are selected by a narrow prefix, so
# retention cannot cross into other backups or Docker volumes.
find "${BACKUP_DIR}" -maxdepth 1 -type f \
  \( -name 'security-recipes-config-*.tar.gz' -o \
     -name 'security-recipes-config-*.tar.gz.age' \) \
  -mtime "+${RETENTION_DAYS}" -delete

if [[ -n "${HEARTBEAT_URL}" ]]; then
  escaped_heartbeat_url="${HEARTBEAT_URL//\\/\\\\}"
  escaped_heartbeat_url="${escaped_heartbeat_url//\"/\\\"}"
  if printf 'url = "%s"\n' "${escaped_heartbeat_url}" |
    curl --config - --fail --silent --show-error \
      --retry 2 --retry-delay 1 --retry-all-errors \
      --connect-timeout 5 --max-time "${HEARTBEAT_TIMEOUT}" >/dev/null; then
    log "Backup success heartbeat delivered."
  else
    log "WARNING: Backup success heartbeat delivery failed."
  fi
fi
