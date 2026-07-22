#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR=""
APP_USER="security-recipes"
APP_GROUP="security-recipes"
SSH_PORT="22"
REMOVE_REPO="false"
REMOVE_IMAGES="false"
REMOVE_VOLUMES="false"
REMOVE_PACKAGES="false"
REMOVE_FIREWALL_RULES="true"
REMOVE_APP_USER="false"
DISABLE_CADDY="false"

CADDYFILE="/etc/caddy/Caddyfile"
CADDY_BACKUP="/etc/caddy/Caddyfile.security-recipes-preinstall.bak"
SSH_CONFIG="/etc/ssh/sshd_config.d/99-security-recipes.conf"
FAIL2BAN_JAIL="/etc/fail2ban/jail.d/sshd-security-recipes.local"
CADDY_404_FAIL2BAN_FILTER="/etc/fail2ban/filter.d/security-recipes-caddy-404.conf"
CADDY_404_FAIL2BAN_JAIL="/etc/fail2ban/jail.d/security-recipes-caddy-404.local"
CADDY_404_GOOGLEBOT_VERIFIER="/usr/local/bin/security-recipes-verify-googlebot.py"

usage() {
  cat <<'EOF'
Usage:
  sudo bash scripts/uninstall_digitalocean_droplet.sh [options]

Remove the security-recipes.ai droplet deployment created by
setup_digitalocean_droplet.sh. The default teardown is conservative:
it stops the Docker Compose stack and removes only managed host config.

Options:
  --app-dir PATH             Deploy path. Default: current repo, or /opt/security-recipes.ai
  --app-user USER            Managed app user. Default: security-recipes
  --ssh-port PORT            SSH firewall port to preserve. Default: 22
  --remove-repo              Delete the application checkout after stopping containers.
  --remove-app-user          Delete the managed app user and group after teardown.
  --remove-images            Remove project images after compose down.
  --remove-volumes           Remove compose volumes too.
  --remove-packages          Purge Caddy, fail2ban, UFW, Docker, and Compose packages.
  --keep-firewall-rules      Do not remove managed HTTP/HTTPS firewall allow rules.
  --disable-caddy            Stop/disable Caddy after removing this site's config.
  -h, --help                 Show this help.

Examples:
  sudo bash scripts/uninstall_digitalocean_droplet.sh
  sudo bash scripts/uninstall_digitalocean_droplet.sh --remove-repo --remove-images --remove-app-user
EOF
}

log() {
  printf '\n[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --app-dir)
      APP_DIR="${2:?Missing value for --app-dir}"
      shift 2
      ;;
    --app-user)
      APP_USER="${2:?Missing value for --app-user}"
      APP_GROUP="${APP_USER}"
      shift 2
      ;;
    --ssh-port)
      SSH_PORT="${2:?Missing value for --ssh-port}"
      shift 2
      ;;
    --remove-repo)
      REMOVE_REPO="true"
      shift
      ;;
    --remove-app-user)
      REMOVE_APP_USER="true"
      shift
      ;;
    --remove-images)
      REMOVE_IMAGES="true"
      shift
      ;;
    --remove-volumes)
      REMOVE_VOLUMES="true"
      shift
      ;;
    --remove-packages)
      REMOVE_PACKAGES="true"
      shift
      ;;
    --keep-firewall-rules)
      REMOVE_FIREWALL_RULES="false"
      shift
      ;;
    --disable-caddy)
      DISABLE_CADDY="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown option: $1"
      ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  die "Run as root, for example: sudo bash scripts/uninstall_digitalocean_droplet.sh"
fi

if [[ -z "${APP_DIR}" ]]; then
  if [[ -f "docker-compose.yml" && -d ".git" ]]; then
    APP_DIR="$(pwd)"
  else
    APP_DIR="/opt/security-recipes.ai"
  fi
fi

compose_cmd() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    return 127
  fi
}

stop_stack() {
  if [[ ! -f "${APP_DIR}/docker-compose.yml" ]]; then
    log "No docker-compose.yml found at ${APP_DIR}; skipping compose teardown."
    return 0
  fi

  log "Stopping security-recipes Docker Compose stack in ${APP_DIR}."
  cd "${APP_DIR}"

  local args=(down --remove-orphans)
  if [[ "${REMOVE_VOLUMES}" == "true" ]]; then
    args+=(--volumes)
  fi
  if [[ "${REMOVE_IMAGES}" == "true" ]]; then
    args+=(--rmi local)
  fi

  if ! compose_cmd "${args[@]}"; then
    log "Docker Compose is unavailable or teardown failed; continuing host cleanup."
  fi
}

restore_caddy() {
  local removed_managed_caddyfile="false"

  if [[ -f "${CADDYFILE}" ]] && grep -q "Managed by security-recipes.ai setup script" "${CADDYFILE}"; then
    if [[ -f "${CADDY_BACKUP}" ]]; then
      log "Restoring preinstall Caddyfile backup."
      cp "${CADDY_BACKUP}" "${CADDYFILE}"
      chmod 644 "${CADDYFILE}"
    else
      log "Removing managed Caddyfile; no preinstall backup was present."
      rm -f "${CADDYFILE}"
      removed_managed_caddyfile="true"
    fi
  else
    log "Caddyfile is not managed by security-recipes; leaving it unchanged."
  fi

  if command -v caddy >/dev/null 2>&1 && systemctl list-unit-files caddy.service >/dev/null 2>&1; then
    if [[ -f "${CADDYFILE}" ]]; then
      caddy validate --config "${CADDYFILE}" && (systemctl reload caddy || systemctl restart caddy) || true
    elif [[ "${removed_managed_caddyfile}" == "true" ]]; then
      log "Stopping Caddy because the managed Caddyfile was removed and no backup exists."
      systemctl stop caddy || true
    fi
    if [[ "${DISABLE_CADDY}" == "true" ]]; then
      log "Disabling Caddy service."
      systemctl disable --now caddy || true
    fi
  fi
}

remove_managed_security_config() {
  local fail2ban_changed="false"

  if [[ -f "${SSH_CONFIG}" ]]; then
    log "Removing managed SSH hardening snippet."
    rm -f "${SSH_CONFIG}"
    sshd -t && (systemctl reload ssh || systemctl reload sshd) || true
  fi

  if [[ -f "${FAIL2BAN_JAIL}" ]]; then
    log "Removing managed SSH fail2ban jail."
    rm -f "${FAIL2BAN_JAIL}"
    fail2ban_changed="true"
  fi

  if [[ -f "${CADDY_404_FAIL2BAN_FILTER}" ||
        -f "${CADDY_404_FAIL2BAN_JAIL}" ||
        -f "${CADDY_404_GOOGLEBOT_VERIFIER}" ]]; then
    log "Removing managed Caddy 404 fail2ban filter and jail."
    rm -f \
      "${CADDY_404_FAIL2BAN_FILTER}" \
      "${CADDY_404_FAIL2BAN_JAIL}" \
      "${CADDY_404_GOOGLEBOT_VERIFIER}"
    fail2ban_changed="true"
  fi

  if [[ "${fail2ban_changed}" == "true" ]] &&
     systemctl list-unit-files fail2ban.service >/dev/null 2>&1; then
    systemctl restart fail2ban || true
  fi
}

remove_firewall_rules() {
  if [[ "${REMOVE_FIREWALL_RULES}" != "true" ]] || ! command -v ufw >/dev/null 2>&1; then
    return 0
  fi

  log "Removing managed HTTP/HTTPS UFW allow rules. SSH rule on ${SSH_PORT}/tcp is preserved."
  ufw --force delete allow 80/tcp || true
  ufw --force delete allow 443/tcp || true
  ufw status verbose || true
}

remove_repo() {
  if [[ "${REMOVE_REPO}" != "true" ]]; then
    return 0
  fi

  if [[ "${APP_DIR}" == "/" || "${APP_DIR}" == "/root" || "${APP_DIR}" == "/home" || "${APP_DIR}" == "/opt" ]]; then
    die "Refusing to remove broad directory: ${APP_DIR}"
  fi

  if [[ -d "${APP_DIR}" ]]; then
    log "Removing application directory ${APP_DIR}."
    rm -rf --one-file-system "${APP_DIR}"
  fi
}

remove_app_user() {
  if [[ "${REMOVE_APP_USER}" != "true" ]]; then
    return 0
  fi

  if [[ "${APP_USER}" == "root" || "${APP_USER}" == "ubuntu" || "${APP_USER}" == "admin" ]]; then
    die "Refusing to remove privileged or common login user: ${APP_USER}"
  fi

  if id -u "${APP_USER}" >/dev/null 2>&1; then
    log "Removing managed application user ${APP_USER}."
    pkill -u "${APP_USER}" || true
    userdel -r "${APP_USER}" || userdel "${APP_USER}" || true
  fi

  if getent group "${APP_GROUP}" >/dev/null 2>&1; then
    if ! getent passwd | awk -F: -v gid="$(getent group "${APP_GROUP}" | cut -d: -f3)" '$4 == gid { found=1 } END { exit found ? 0 : 1 }'; then
      log "Removing managed application group ${APP_GROUP}."
      groupdel "${APP_GROUP}" || true
    fi
  fi
}

purge_packages() {
  if [[ "${REMOVE_PACKAGES}" != "true" ]]; then
    return 0
  fi

  log "Purging packages installed by setup script. This may affect other services on this droplet."
  apt-get purge -y caddy fail2ban docker.io docker-compose docker-compose-plugin ufw || true
  apt-get autoremove -y || true
}

stop_stack
restore_caddy
remove_managed_security_config
remove_firewall_rules
remove_repo
remove_app_user
purge_packages

cat <<EOF

Uninstall complete.

Conservative defaults used:
  repo removed: ${REMOVE_REPO}
  app user: ${APP_USER}
  app user removed: ${REMOVE_APP_USER}
  images removed: ${REMOVE_IMAGES}
  volumes removed: ${REMOVE_VOLUMES}
  packages purged: ${REMOVE_PACKAGES}
  Caddy disabled: ${DISABLE_CADDY}

If DNS still points at this droplet, HTTPS may stop serving once Caddy is
disabled or the managed Caddyfile is removed.
EOF
