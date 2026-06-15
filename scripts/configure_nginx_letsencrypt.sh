#!/usr/bin/env bash
set -Eeuo pipefail

DOMAIN=""
EMAIL=""
UPSTREAM="127.0.0.1:8080"
SITE_NAME="security-recipes"
WEBROOT="/var/www/letsencrypt"
SITE_CONF_DIR="/etc/nginx/sites-available"
SITE_LINK_DIR="/etc/nginx/sites-enabled"
INSTALL_PACKAGES="true"
STAGING="false"

usage() {
  cat <<'EOF'
Usage:
  sudo bash scripts/configure_nginx_letsencrypt.sh [options]

Configure a host nginx reverse proxy for security-recipes.ai and obtain a
Let's Encrypt certificate with Certbot.

Options:
  --domain DOMAIN             Public hostname to serve over HTTPS. Required.
  --email EMAIL               Email used for Let's Encrypt registration. Required.
  --upstream HOST:PORT        Loopback app upstream. Default: 127.0.0.1:8080
  --site-name NAME            nginx site filename prefix. Default: security-recipes
  --webroot PATH              ACME challenge webroot. Default: /var/www/letsencrypt
  --skip-package-install      Do not install nginx/certbot packages.
  --staging                   Use Let's Encrypt staging endpoints for testing.
  -h, --help                  Show this help.

Example:
  sudo bash scripts/configure_nginx_letsencrypt.sh \
    --domain docs.example.com \
    --email admin@example.com
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

reload_nginx() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl reload nginx || systemctl restart nginx
  else
    nginx -s reload
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)
      DOMAIN="${2:?Missing value for --domain}"
      shift 2
      ;;
    --email)
      EMAIL="${2:?Missing value for --email}"
      shift 2
      ;;
    --upstream)
      UPSTREAM="${2:?Missing value for --upstream}"
      shift 2
      ;;
    --site-name)
      SITE_NAME="${2:?Missing value for --site-name}"
      shift 2
      ;;
    --webroot)
      WEBROOT="${2:?Missing value for --webroot}"
      shift 2
      ;;
    --skip-package-install)
      INSTALL_PACKAGES="false"
      shift
      ;;
    --staging)
      STAGING="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown argument: $1"
      ;;
  esac
done

[[ "${EUID}" -eq 0 ]] || die "Run this script as root."
[[ -n "${DOMAIN}" ]] || die "--domain is required."
[[ -n "${EMAIL}" ]] || die "--email is required."

SITE_CONF_PATH="${SITE_CONF_DIR}/${SITE_NAME}.conf"
SITE_LINK_PATH="${SITE_LINK_DIR}/${SITE_NAME}.conf"
DEFAULT_SITE_LINK="${SITE_LINK_DIR}/default"
RENEW_HOOK_DIR="/etc/letsencrypt/renewal-hooks/deploy"
RENEW_HOOK_PATH="${RENEW_HOOK_DIR}/${SITE_NAME}-reload-nginx.sh"

install_packages() {
  if [[ "${INSTALL_PACKAGES}" != "true" ]]; then
    log "Skipping package installation as requested."
    return
  fi

  export DEBIAN_FRONTEND=noninteractive
  run apt-get update
  run apt-get install -y --no-install-recommends nginx certbot python3-certbot-nginx
  if command -v systemctl >/dev/null 2>&1; then
    run systemctl enable nginx
    run systemctl start nginx
  fi
}

write_http_proxy_config() {
  mkdir -p "${WEBROOT}/.well-known/acme-challenge"

  cat > "${SITE_CONF_PATH}" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    client_max_body_size 20m;

    location ^~ /.well-known/acme-challenge/ {
        root ${WEBROOT};
        default_type text/plain;
        try_files \$uri =404;
    }

    location / {
        proxy_pass http://${UPSTREAM};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
        proxy_read_timeout 300s;
    }
}
EOF

  ln -sfn "${SITE_CONF_PATH}" "${SITE_LINK_PATH}"

  if [[ -L "${DEFAULT_SITE_LINK}" ]] && [[ "$(readlink -f "${DEFAULT_SITE_LINK}")" == "/etc/nginx/sites-available/default" ]]; then
    rm -f "${DEFAULT_SITE_LINK}"
  fi
}

install_renew_hook() {
  mkdir -p "${RENEW_HOOK_DIR}"
  cat > "${RENEW_HOOK_PATH}" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

if command -v systemctl >/dev/null 2>&1; then
  systemctl reload nginx || systemctl restart nginx
else
  nginx -s reload
fi
EOF
  chmod 755 "${RENEW_HOOK_PATH}"
}

obtain_certificate() {
  local certbot_args=(
    certbot
    --nginx
    --non-interactive
    --agree-tos
    --redirect
    --keep-until-expiring
    -m "${EMAIL}"
    -d "${DOMAIN}"
  )

  if [[ "${STAGING}" == "true" ]]; then
    certbot_args+=(--staging)
  fi

  run "${certbot_args[@]}"
}

main() {
  install_packages
  write_http_proxy_config
  run nginx -t
  reload_nginx
  obtain_certificate
  install_renew_hook
  run nginx -t
  reload_nginx

  cat <<EOF

HTTPS proxy is configured for ${DOMAIN}.

Upstream application: http://${UPSTREAM}
nginx site config: ${SITE_CONF_PATH}
Renewal hook: ${RENEW_HOOK_PATH}

Next checks:
  curl -I http://${UPSTREAM}/
  curl -I https://${DOMAIN}/
  sudo certbot renew --dry-run
EOF
}

main "$@"
