#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="security-recipes"
APP_USER="security-recipes"
APP_GROUP="security-recipes"
DOMAIN="security-recipes.ai"
REPO_URL="https://github.com/stevologic/security-recipes.ai.git"
APP_DIR=""
EMAIL=""
SSH_PORT="22"
APP_BIND="127.0.0.1:8080"
APP_GREEN_BIND=""
ENABLE_CADDY="true"
ENABLE_UPGRADE="true"
HARDEN_SSH="auto"
SKIP_FIREWALL="false"
ENABLE_DEPLOY_TIMER="true"
ENABLE_BACKUP_TIMER="true"
DEPLOY_INTERVAL_MINUTES="15"
AUTOMATION_ONLY="false"
CADDYFILE="/etc/caddy/Caddyfile"
CADDY_BACKUP="/etc/caddy/Caddyfile.security-recipes-preinstall.bak"
CADDY_SYSTEMD_OVERRIDE="/etc/systemd/system/caddy.service.d/20-security-recipes-resume.conf"
SSH_CONFIG="/etc/ssh/sshd_config.d/99-security-recipes.conf"
FAIL2BAN_JAIL="/etc/fail2ban/jail.d/sshd-security-recipes.local"
RUNTIME_CONFIG_DIR="/etc/security-recipes"
DEPLOY_ENV_FILE="${RUNTIME_CONFIG_DIR}/deploy.env"
BACKUP_ENV_FILE="${RUNTIME_CONFIG_DIR}/backup.env"
DEPLOY_SERVICE="/etc/systemd/system/security-recipes-deploy.service"
DEPLOY_TIMER="/etc/systemd/system/security-recipes-deploy.timer"
BACKUP_SERVICE="/etc/systemd/system/security-recipes-backup.service"
BACKUP_TIMER="/etc/systemd/system/security-recipes-backup.timer"

usage() {
  cat <<'EOF'
Usage:
  sudo bash scripts/setup_digitalocean_droplet.sh [options]

Securely configure an Ubuntu DigitalOcean droplet to host security-recipes.ai
with Docker Compose, the site container, and the MCP server behind one HTTPS
origin.

Options:
  --domain DOMAIN          Public hostname. Default: security-recipes.ai
  --repo-url URL           Git repository URL. Default: upstream repo
  --app-dir PATH           Checkout/deploy path. Default: current repo, or /opt/security-recipes.ai
  --app-user USER          Locked host account with no Docker access. Default: security-recipes
  --email EMAIL            Email for Caddy ACME registration.
  --ssh-port PORT          SSH port to keep open in UFW. Default: 22
  --app-bind HOST:PORT     Local Docker bind for nginx site. Default: 127.0.0.1:8080
  --app-green-bind HOST:PORT
                           Warm-standby bind. Default: APP_BIND host and next port
  --no-caddy               Do not install/configure Caddy HTTPS reverse proxy.
  --no-upgrade             Skip apt upgrade.
  --no-firewall            Do not enable/configure UFW.
  --deploy-interval-minutes MINUTES
                           Delay between completed deploy checks. Default: 15
  --no-deploy-timer        Do not install the managed deploy systemd timer.
  --no-backup-timer        Do not install the daily local config-backup timer.
  --automation-only        Only install timers/environment files in an existing checkout.
  --harden-ssh             Disable SSH password auth and root password login.
  --no-harden-ssh          Leave SSH config unchanged.
  -h, --help               Show this help.

Examples:
  sudo bash scripts/setup_digitalocean_droplet.sh \
    --domain security-recipes.ai \
    --email admin@security-recipes.ai
EOF
}

log() {
  printf '\n[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

run() {
  log "$*"
  "$@"
}

service_reload() {
  local service_name="$1"
  if systemctl list-unit-files "${service_name}.service" >/dev/null 2>&1; then
    systemctl reload "${service_name}" || systemctl restart "${service_name}"
    return $?
  fi
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)
      DOMAIN="${2:?Missing value for --domain}"
      shift 2
      ;;
    --repo-url)
      REPO_URL="${2:?Missing value for --repo-url}"
      shift 2
      ;;
    --app-dir)
      APP_DIR="${2:?Missing value for --app-dir}"
      shift 2
      ;;
    --app-user)
      APP_USER="${2:?Missing value for --app-user}"
      APP_GROUP="${APP_USER}"
      shift 2
      ;;
    --email)
      EMAIL="${2:?Missing value for --email}"
      shift 2
      ;;
    --ssh-port)
      SSH_PORT="${2:?Missing value for --ssh-port}"
      shift 2
      ;;
    --app-bind)
      APP_BIND="${2:?Missing value for --app-bind}"
      shift 2
      ;;
    --app-green-bind)
      APP_GREEN_BIND="${2:?Missing value for --app-green-bind}"
      shift 2
      ;;
    --no-caddy)
      ENABLE_CADDY="false"
      shift
      ;;
    --no-upgrade)
      ENABLE_UPGRADE="false"
      shift
      ;;
    --no-firewall)
      SKIP_FIREWALL="true"
      shift
      ;;
    --deploy-interval-minutes)
      DEPLOY_INTERVAL_MINUTES="${2:?Missing value for --deploy-interval-minutes}"
      shift 2
      ;;
    --no-deploy-timer)
      ENABLE_DEPLOY_TIMER="false"
      shift
      ;;
    --no-backup-timer)
      ENABLE_BACKUP_TIMER="false"
      shift
      ;;
    --automation-only)
      AUTOMATION_ONLY="true"
      shift
      ;;
    --harden-ssh)
      HARDEN_SSH="true"
      shift
      ;;
    --no-harden-ssh)
      HARDEN_SSH="false"
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
  die "Run as root, for example: sudo bash scripts/setup_digitalocean_droplet.sh"
fi

if [[ -z "${APP_DIR}" ]]; then
  if [[ -f "docker-compose.yml" && -d ".git" ]]; then
    APP_DIR="$(pwd)"
  else
    APP_DIR="/opt/security-recipes.ai"
  fi
fi

[[ "${APP_DIR}" =~ ^/[A-Za-z0-9._/-]+$ ]] ||
  die "--app-dir must be an absolute path containing only letters, numbers, dot, underscore, slash, or hyphen."
[[ "${DEPLOY_INTERVAL_MINUTES}" =~ ^[1-9][0-9]*$ ]] ||
  die "--deploy-interval-minutes must be a positive integer."

if [[ -z "${APP_GREEN_BIND}" ]]; then
  app_bind_host="${APP_BIND%:*}"
  app_bind_port="${APP_BIND##*:}"
  [[ "${app_bind_port}" =~ ^[0-9]+$ ]] ||
    die "--app-bind must end in a numeric TCP port."
  (( app_bind_port >= 1 && app_bind_port < 65535 )) ||
    die "--app-bind port must be between 1 and 65534."
  APP_GREEN_BIND="${app_bind_host}:$((app_bind_port + 1))"
fi

if ! grep -qiE 'ubuntu|debian' /etc/os-release; then
  die "This bootstrap script is intended for Ubuntu/Debian droplets."
fi

export DEBIAN_FRONTEND=noninteractive

create_app_user() {
  log "Ensuring locked application user exists: ${APP_USER}"

  if ! getent group "${APP_GROUP}" >/dev/null 2>&1; then
    groupadd --system "${APP_GROUP}"
  fi

  if ! id -u "${APP_USER}" >/dev/null 2>&1; then
    useradd \
      --system \
      --gid "${APP_GROUP}" \
      --create-home \
      --home-dir "/var/lib/${APP_USER}" \
      --shell /usr/sbin/nologin \
      --comment "security-recipes.ai application owner" \
      "${APP_USER}"
  else
    usermod --gid "${APP_GROUP}" --home "/var/lib/${APP_USER}" "${APP_USER}" || true
  fi

  passwd -l "${APP_USER}" >/dev/null 2>&1 || true

  if id -nG "${APP_USER}" | tr ' ' '\n' | grep -qx docker; then
    log "Removing ${APP_USER} from docker group to avoid Docker-root-equivalent access."
    gpasswd -d "${APP_USER}" docker >/dev/null 2>&1 || true
  fi

  install -d -o "${APP_USER}" -g "${APP_GROUP}" -m 750 "/var/lib/${APP_USER}"
}

configure_docker_apt_repo() {
  local os_id os_codename arch

  . /etc/os-release
  os_id="${ID}"
  os_codename="${VERSION_CODENAME:-}"
  arch="$(dpkg --print-architecture)"

  if [[ -z "${os_codename}" ]]; then
    log "Could not determine Debian/Ubuntu codename; skipping Docker upstream apt repository."
    return 1
  fi

  log "Configuring Docker upstream apt repository for Compose v2."
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/${os_id}/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc

  cat >/etc/apt/sources.list.d/docker.list <<EOF
deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${os_id} ${os_codename} stable
EOF

  apt-get update
}

install_docker_stack() {
  if docker compose version >/dev/null 2>&1; then
    log "Docker Compose v2 is already available."
    install_compose_legacy_alias
    return 0
  fi

  if configure_docker_apt_repo; then
    if apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
      if docker compose version >/dev/null 2>&1; then
        log "Installed Docker Engine and Compose v2 plugin from Docker upstream packages."
        install_compose_legacy_alias
        return 0
      fi
    fi
    log "Docker upstream packages did not provide a working Compose v2 install; falling back to distro packages."
  fi

  if apt-get install -y docker.io docker-compose-plugin; then
    if docker compose version >/dev/null 2>&1; then
      log "Installed Docker and Compose v2 plugin from distro packages."
      install_compose_legacy_alias
      return 0
    fi
  fi

  die "Docker Compose v2 is unavailable. Install docker-compose-plugin and rerun this script."
}

install_compose_legacy_alias() {
  cat >/usr/local/bin/docker-compose <<'EOF'
#!/usr/bin/env sh
exec docker compose "$@"
EOF
  chmod 755 /usr/local/bin/docker-compose
  log "Installed docker-compose compatibility shim at /usr/local/bin/docker-compose."
}

install_packages() {
  run apt-get update
  if [[ "${ENABLE_UPGRADE}" == "true" ]]; then
    run apt-get -y upgrade
  fi

  run apt-get install -y \
    ca-certificates \
    curl \
    git \
    gnupg \
    jq \
    logrotate \
    lsb-release \
    ufw \
    fail2ban \
    unattended-upgrades

  install_docker_stack

  if ! apt-get install -y age rclone; then
    log "age/rclone are unavailable; local backups still work, but encrypted off-host upload will remain disabled."
  fi

  if [[ "${ENABLE_CADDY}" == "true" ]]; then
    if ! apt-get install -y caddy; then
      die "Could not install caddy from apt. Re-run with --no-caddy or install Caddy before retrying."
    fi
  fi
}

configure_unattended_upgrades() {
  log "Configuring unattended security upgrades."
  cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
}

configure_fail2ban() {
  log "Configuring fail2ban for sshd."
  mkdir -p "$(dirname "${FAIL2BAN_JAIL}")"
  cat >"${FAIL2BAN_JAIL}" <<EOF
[sshd]
enabled = true
port = ${SSH_PORT}
maxretry = 5
findtime = 10m
bantime = 1h
EOF
  systemctl enable --now fail2ban
  systemctl restart fail2ban
}

has_authorized_key() {
  [[ -s /root/.ssh/authorized_keys ]] && return 0
  find /home -maxdepth 3 -path '*/.ssh/authorized_keys' -type f -size +0c 2>/dev/null | grep -q .
}

configure_ssh() {
  local should_harden="${HARDEN_SSH}"
  if [[ "${should_harden}" == "auto" ]]; then
    if has_authorized_key; then
      should_harden="true"
    else
      should_harden="false"
      log "No SSH authorized_keys file found; leaving SSH password settings unchanged."
    fi
  fi

  if [[ "${should_harden}" != "true" ]]; then
    return 0
  fi

  log "Hardening SSH password access while preserving key-based root login."
  mkdir -p /etc/ssh/sshd_config.d
  cat >"${SSH_CONFIG}" <<EOF
# Managed by security-recipes.ai setup script.
Port ${SSH_PORT}
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
MaxAuthTries 3
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

  sshd -t
  service_reload ssh || service_reload sshd
}

configure_firewall() {
  if [[ "${SKIP_FIREWALL}" == "true" ]]; then
    log "Skipping firewall configuration."
    return 0
  fi

  log "Configuring UFW without resetting existing rules."
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow "${SSH_PORT}/tcp"

  if [[ "${ENABLE_CADDY}" == "true" ]]; then
    ufw allow 80/tcp
    ufw allow 443/tcp
  else
    local public_port="${APP_BIND##*:}"
    ufw allow "${public_port}/tcp"
  fi

  ufw --force enable
  ufw status verbose
}

prepare_repo() {
  log "Preparing application directory: ${APP_DIR}"
  mkdir -p "$(dirname "${APP_DIR}")"

  if [[ -d "${APP_DIR}/.git" ]]; then
    # Migrate older installations where the locked application account owned
    # the checkout before invoking Git as root.
    chown -R root:root "${APP_DIR}"
    chmod -R go-w "${APP_DIR}"
    git -C "${APP_DIR}" fetch --all --prune
    git -C "${APP_DIR}" pull --ff-only || log "Git pull could not fast-forward; leaving existing checkout unchanged."
  else
    git clone "${REPO_URL}" "${APP_DIR}"
  fi

  # The root deployment service executes deploy.sh and Git hooks with
  # host-level privileges.
  # Keep the entire checkout, including .git, outside the write control of the
  # locked application account.
  chown -R root:root "${APP_DIR}"
  chmod -R go-w "${APP_DIR}"
  chmod 750 "${APP_DIR}"
}

write_env_file() {
  log "Writing ${APP_DIR}/.env with localhost container bind and public URLs."
  local env_file="${APP_DIR}/.env"

  if [[ -f "${env_file}" ]]; then
    log "Updating existing .env in place. Provider API keys are intentionally not written server-side."
  fi

  cat >"${env_file}" <<EOF
# Managed by security-recipes.ai setup script.
SECURITY_RECIPES_BASE_URL=https://${DOMAIN}/
SECURITY_RECIPES_REPO_URL=${REPO_URL%.git}
SECURITY_RECIPES_HTTP_PORT=${APP_BIND}
SECURITY_RECIPES_GREEN_HTTP_PORT=${APP_GREEN_BIND}
SECURITY_RECIPES_LOG_MAX_SIZE=10m
SECURITY_RECIPES_LOG_MAX_FILES=5

RECIPES_MCP_SOURCE_INDEX_URL=https://${DOMAIN}/api/recipes-index.json
RECIPES_MCP_ALLOWED_SOURCE_HOSTS=security-recipes,security-recipes-green,${DOMAIN}
RECIPES_MCP_PUBLIC_BASE_URL=https://${DOMAIN}/mcp
RECIPES_MCP_LOG_LEVEL=info
RECIPES_MCP_EAGER_REFRESH=false
EOF
  chown root:root "${env_file}"
  chmod 600 "${env_file}"
}

configure_caddy() {
  if [[ "${ENABLE_CADDY}" != "true" ]]; then
    log "Skipping Caddy configuration."
    return 0
  fi

  local host="${APP_BIND%:*}"
  local port="${APP_BIND##*:}"
  local green_host="${APP_GREEN_BIND%:*}"
  local green_port="${APP_GREEN_BIND##*:}"
  local upstream="http://${host}:${port}"
  local green_upstream="http://${green_host}:${green_port}"

  log "Configuring Caddy blue/green proxy for ${DOMAIN} -> ${upstream}, fallback ${green_upstream}."
  mkdir -p /etc/caddy

  if [[ -f "${CADDYFILE}" ]] && ! grep -q "Managed by security-recipes.ai setup script" "${CADDYFILE}"; then
    if [[ ! -f "${CADDY_BACKUP}" ]]; then
      cp "${CADDYFILE}" "${CADDY_BACKUP}"
      chmod 600 "${CADDY_BACKUP}"
      log "Existing Caddyfile backed up to ${CADDY_BACKUP}."
    else
      log "Existing preinstall Caddyfile backup already present at ${CADDY_BACKUP}."
    fi
  fi

  {
    if [[ -n "${EMAIL}" ]]; then
      cat <<EOF
# Managed by security-recipes.ai setup script.
{
	email ${EMAIL}
}

EOF
    fi
    cat <<EOF
# Managed by security-recipes.ai setup script.
${DOMAIN} {
	encode zstd gzip

	header {
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		X-Content-Type-Options "nosniff"
		Referrer-Policy "strict-origin-when-cross-origin"
		X-Frame-Options "DENY"
		Permissions-Policy "camera=(), microphone=(), geolocation=()"
	}

	# deploy.sh overrides these values while gracefully switching slots.
	reverse_proxy {\$SECURITY_RECIPES_PRIMARY_UPSTREAM:${upstream}} {\$SECURITY_RECIPES_FALLBACK_UPSTREAM:${green_upstream}} {
		lb_policy first
		health_uri /
		health_interval 5s
		health_timeout 2s
		health_status 200
		health_fails 1
		health_passes 2
		fail_duration 30s
		max_fails 1
		unhealthy_status 5xx
		lb_try_duration 5s
		lb_try_interval 100ms
		stream_close_delay 5m
	}
}
EOF
  } >"${CADDYFILE}"

  caddy validate --config "${CADDYFILE}"
  systemctl enable --now caddy
  caddy reload --force --config "${CADDYFILE}" --adapter caddyfile

  # deploy.sh changes route order through Caddy's admin API. Resume the
  # autosaved config after process or machine restarts so a stale default slot
  # can never silently become primary again.
  mkdir -p "$(dirname "${CADDY_SYSTEMD_OVERRIDE}")"
  cat >"${CADDY_SYSTEMD_OVERRIDE}" <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/caddy run --environ --resume --config /etc/caddy/Caddyfile
ExecReload=
EOF
  systemctl daemon-reload
  systemctl restart caddy
  systemctl is-active --quiet caddy
}

compose_cmd() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  else
    die "Docker Compose v2 is not installed. Run scripts/install_docker_compose_v2.sh."
  fi
}

start_stack() {
  log "Enabling Docker and starting the compose stack."
  systemctl enable --now docker
  cd "${APP_DIR}"
  compose_cmd up -d --build
  compose_cmd ps
}

write_automation_environment() {
  install -d -o root -g root -m 0700 "${RUNTIME_CONFIG_DIR}"

  if [[ ! -f "${DEPLOY_ENV_FILE}" ]]; then
    cat >"${DEPLOY_ENV_FILE}" <<'EOF'
# Root-only environment loaded by security-recipes-deploy.service.
# Set a dead-man URL from Healthchecks.io, Uptime Kuma, or an equivalent
# monitor. It is contacted only after the public revision and catalog pass.
DEPLOY_SUCCESS_HEARTBEAT_URL=
DEPLOY_CATALOG_MAX_AGE_HOURS=36
DEPLOY_MIN_FREE_MB=2048
# Optional when Docker storage is on a non-default filesystem.
DEPLOY_DISK_PATH=
DEPLOY_BUILD_CACHE_MAX_AGE=168h
DEPLOY_BUILD_CACHE_KEEP_STORAGE=5GB
EOF
  fi
  chown root:root "${DEPLOY_ENV_FILE}"
  chmod 0600 "${DEPLOY_ENV_FILE}"

  if [[ ! -f "${BACKUP_ENV_FILE}" ]]; then
    cat >"${BACKUP_ENV_FILE}" <<'EOF'
# Root-only environment loaded by security-recipes-backup.service.
SECURITY_RECIPES_BACKUP_DIR=/var/backups/security-recipes
SECURITY_RECIPES_BACKUP_RETENTION_DAYS=14
# Configure both values to upload age-encrypted bundles with rclone.
SECURITY_RECIPES_BACKUP_RCLONE_DESTINATION=
SECURITY_RECIPES_BACKUP_AGE_RECIPIENT=
SECURITY_RECIPES_BACKUP_HEARTBEAT_URL=
EOF
  fi
  chown root:root "${BACKUP_ENV_FILE}"
  chmod 0600 "${BACKUP_ENV_FILE}"
}

remove_legacy_deploy_cron() {
  local current filtered
  if ! command -v crontab >/dev/null 2>&1; then
    return 0
  fi
  current="$(mktemp)"
  filtered="$(mktemp)"

  if crontab -l >"${current}" 2>/dev/null; then
    awk \
      -v deploy="${APP_DIR}/deploy.sh" \
      -v legacy="${APP_DIR}/scripts/redeploy_from_github.sh" \
      'index($0, deploy) == 0 && index($0, legacy) == 0' \
      "${current}" >"${filtered}"
    if ! cmp -s "${current}" "${filtered}"; then
      if [[ -s "${filtered}" ]]; then
        crontab "${filtered}"
      else
        crontab -r || true
      fi
      log "Removed legacy root cron deploy entries; the managed timer is now the sole scheduler."
    fi
  fi
  rm -f -- "${current}" "${filtered}"
}

configure_deploy_timer() {
  if [[ "${ENABLE_DEPLOY_TIMER}" != "true" ]]; then
    systemctl disable --now security-recipes-deploy.timer >/dev/null 2>&1 || true
    rm -f -- "${DEPLOY_SERVICE}" "${DEPLOY_TIMER}"
    log "Managed deploy timer disabled by request."
    return 0
  fi

  chmod 0750 "${APP_DIR}/deploy.sh"
  cat >"${DEPLOY_SERVICE}" <<EOF
[Unit]
Description=CI-gated blue/green deployment for security-recipes.ai
Wants=network-online.target
After=network-online.target docker.service
ConditionPathIsExecutable=${APP_DIR}/deploy.sh

[Service]
Type=oneshot
WorkingDirectory=${APP_DIR}
EnvironmentFile=-${DEPLOY_ENV_FILE}
ExecStart=${APP_DIR}/deploy.sh
TimeoutStartSec=45min
UMask=0027
StandardOutput=journal
StandardError=journal
SyslogIdentifier=security-recipes-deploy
EOF

  cat >"${DEPLOY_TIMER}" <<EOF
[Unit]
Description=Check for a CI-verified security-recipes.ai release

[Timer]
OnBootSec=5min
OnUnitInactiveSec=${DEPLOY_INTERVAL_MINUTES}min
RandomizedDelaySec=60s
AccuracySec=30s
Unit=security-recipes-deploy.service

[Install]
WantedBy=timers.target
EOF

  remove_legacy_deploy_cron
}

configure_backup_timer() {
  if [[ "${ENABLE_BACKUP_TIMER}" != "true" ]]; then
    systemctl disable --now security-recipes-backup.timer >/dev/null 2>&1 || true
    rm -f -- "${BACKUP_SERVICE}" "${BACKUP_TIMER}"
    log "Managed backup timer disabled by request."
    return 0
  fi

  chmod 0750 "${APP_DIR}/scripts/backup_droplet_config.sh"
  cat >"${BACKUP_SERVICE}" <<EOF
[Unit]
Description=Back up private security-recipes.ai droplet configuration
After=local-fs.target docker.service
ConditionPathIsExecutable=${APP_DIR}/scripts/backup_droplet_config.sh

[Service]
Type=oneshot
Environment=SECURITY_RECIPES_APP_DIR=${APP_DIR}
EnvironmentFile=-${BACKUP_ENV_FILE}
ExecStart=${APP_DIR}/scripts/backup_droplet_config.sh
TimeoutStartSec=30min
UMask=0077
StandardOutput=journal
StandardError=journal
SyslogIdentifier=security-recipes-backup
EOF

  cat >"${BACKUP_TIMER}" <<'EOF'
[Unit]
Description=Daily security-recipes.ai configuration backup

[Timer]
OnCalendar=*-*-* 03:15:00
RandomizedDelaySec=30min
Persistent=true
Unit=security-recipes-backup.service

[Install]
WantedBy=timers.target
EOF
}

configure_automation() {
  log "Installing managed deploy and backup scheduling."
  write_automation_environment
  configure_deploy_timer
  configure_backup_timer
  systemctl daemon-reload

  if [[ "${ENABLE_DEPLOY_TIMER}" == "true" ]]; then
    systemctl enable --now security-recipes-deploy.timer
  fi
  if [[ "${ENABLE_BACKUP_TIMER}" == "true" ]]; then
    systemctl enable --now security-recipes-backup.timer
  fi
}

print_summary() {
  cat <<EOF

Done.

Public site:
  https://${DOMAIN}/

MCP endpoint:
  https://${DOMAIN}/mcp

Application directory:
  ${APP_DIR}

Deployment checkout owner:
  root:root

Locked application account (no Docker access):
  ${APP_USER}:${APP_GROUP}

Container bind:
  ${APP_BIND}

Warm-standby bind:
  ${APP_GREEN_BIND}

Useful commands:
  cd ${APP_DIR}
  docker compose ps
  docker compose logs -f security-recipes
  bash ${APP_DIR}/deploy.sh --force
  systemctl list-timers 'security-recipes-*'
  journalctl -u security-recipes-deploy.service -n 100
  systemctl start security-recipes-backup.service
  systemctl status caddy
  ufw status verbose

Before expecting HTTPS to work, make sure the ${DOMAIN} A record points
to this droplet's public IPv4 address. Caddy will obtain and renew the
certificate automatically once DNS is correct.
EOF
}

print_automation_summary() {
  cat <<EOF

Automation installed without restarting the site or proxy.

Deploy interval:
  ${DEPLOY_INTERVAL_MINUTES} minutes after the previous check finishes

Configuration:
  ${DEPLOY_ENV_FILE}
  ${BACKUP_ENV_FILE}

Useful commands:
  systemctl list-timers 'security-recipes-*'
  systemctl start security-recipes-deploy.service
  journalctl -u security-recipes-deploy.service -n 100
  systemctl start security-recipes-backup.service
  journalctl -u security-recipes-backup.service -n 100
EOF
}

if [[ "${AUTOMATION_ONLY}" == "true" ]]; then
  [[ -d "${APP_DIR}/.git" ]] ||
    die "--automation-only requires an existing checkout at ${APP_DIR}."
  [[ -x "${APP_DIR}/deploy.sh" || -f "${APP_DIR}/deploy.sh" ]] ||
    die "${APP_DIR}/deploy.sh is missing."
  [[ -f "${APP_DIR}/scripts/backup_droplet_config.sh" ]] ||
    die "${APP_DIR}/scripts/backup_droplet_config.sh is missing."
  [[ "$(stat -c '%u' "${APP_DIR}")" == "0" ]] ||
    die "--automation-only requires a root-owned checkout: chown -R root:root ${APP_DIR}"
  configure_automation
  print_automation_summary
  exit 0
fi

install_packages
configure_unattended_upgrades
configure_fail2ban
configure_ssh
configure_firewall
create_app_user
prepare_repo
write_env_file
start_stack
configure_caddy
configure_automation
print_summary
