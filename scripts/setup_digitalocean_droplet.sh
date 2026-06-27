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
ENABLE_CADDY="true"
ENABLE_UPGRADE="true"
HARDEN_SSH="auto"
SKIP_FIREWALL="false"
CADDYFILE="/etc/caddy/Caddyfile"
CADDY_BACKUP="/etc/caddy/Caddyfile.security-recipes-preinstall.bak"
SSH_CONFIG="/etc/ssh/sshd_config.d/99-security-recipes.conf"
FAIL2BAN_JAIL="/etc/fail2ban/jail.d/sshd-security-recipes.local"

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
  --app-user USER          Locked host user that owns the checkout. Default: security-recipes
  --email EMAIL            Email for Caddy ACME registration.
  --ssh-port PORT          SSH port to keep open in UFW. Default: 22
  --app-bind HOST:PORT     Local Docker bind for nginx site. Default: 127.0.0.1:8080
  --no-caddy               Do not install/configure Caddy HTTPS reverse proxy.
  --no-upgrade             Skip apt upgrade.
  --no-firewall            Do not enable/configure UFW.
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
    lsb-release \
    ufw \
    fail2ban \
    unattended-upgrades

  install_docker_stack

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
    git -C "${APP_DIR}" fetch --all --prune
    git -C "${APP_DIR}" pull --ff-only || log "Git pull could not fast-forward; leaving existing checkout unchanged."
  else
    git clone "${REPO_URL}" "${APP_DIR}"
  fi

  chown -R "${APP_USER}:${APP_GROUP}" "${APP_DIR}"
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
SECURITY_RECIPES_HUGO_MINIFY=false
SECURITY_RECIPES_HUGO_GOMAXPROCS=1

RECIPES_MCP_SOURCE_INDEX_URL=http://security-recipes/api/recipes.json
RECIPES_MCP_ALLOWED_SOURCE_HOSTS=security-recipes,${DOMAIN}
RECIPES_MCP_PUBLIC_BASE_URL=https://${DOMAIN}/mcp
RECIPES_MCP_LOG_LEVEL=info
RECIPES_MCP_EAGER_REFRESH=false
EOF
  chown "${APP_USER}:${APP_GROUP}" "${env_file}"
  chmod 600 "${env_file}"
}

configure_caddy() {
  if [[ "${ENABLE_CADDY}" != "true" ]]; then
    log "Skipping Caddy configuration."
    return 0
  fi

  local host="${APP_BIND%:*}"
  local port="${APP_BIND##*:}"
  local upstream="http://${host}:${port}"

  log "Configuring Caddy HTTPS reverse proxy for ${DOMAIN} -> ${upstream}."
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

	reverse_proxy ${upstream}
}
EOF
  } >"${CADDYFILE}"

  caddy validate --config "${CADDYFILE}"
  systemctl enable --now caddy
  systemctl reload caddy || systemctl restart caddy
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

print_summary() {
  cat <<EOF

Done.

Public site:
  https://${DOMAIN}/

MCP endpoint:
  https://${DOMAIN}/mcp

Application directory:
  ${APP_DIR}

Application owner:
  ${APP_USER}:${APP_GROUP}

Container bind:
  ${APP_BIND}

Useful commands:
  cd ${APP_DIR}
  docker compose ps
  docker compose logs -f security-recipes
  bash ${APP_DIR}/scripts/redeploy_from_github.sh
  systemctl status caddy
  ufw status verbose

Before expecting HTTPS to work, make sure the ${DOMAIN} A record points
to this droplet's public IPv4 address. Caddy will obtain and renew the
certificate automatically once DNS is correct.
EOF
}

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
print_summary
