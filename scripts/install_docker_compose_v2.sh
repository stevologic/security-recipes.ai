#!/usr/bin/env bash
set -Eeuo pipefail

CREATE_LEGACY_SHIM="true"

usage() {
  cat <<'EOF'
Usage:
  sudo bash scripts/install_docker_compose_v2.sh [options]

Install Docker Compose v2 on an Ubuntu/Debian host and optionally add a
docker-compose compatibility shim that forwards old commands to `docker compose`.

Options:
  --no-legacy-shim       Do not create /usr/local/bin/docker-compose.
  -h, --help             Show this help.

Why this exists:
  The legacy Python docker-compose v1 package can fail on newer Docker images
  with KeyError: 'ContainerConfig'. Compose v2 is the supported path.
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

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-legacy-shim)
      CREATE_LEGACY_SHIM="false"
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

configure_docker_apt_repo() {
  local os_id os_codename arch

  . /etc/os-release
  os_id="${ID}"
  os_codename="${VERSION_CODENAME:-}"
  arch="$(dpkg --print-architecture)"

  [[ -n "${os_codename}" ]] || return 1

  log "Configuring Docker upstream apt repository."
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/${os_id}/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc

  cat >/etc/apt/sources.list.d/docker.list <<EOF
deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${os_id} ${os_codename} stable
EOF

  apt-get update
}

install_compose_v2() {
  export DEBIAN_FRONTEND=noninteractive

  if docker compose version >/dev/null 2>&1; then
    log "Docker Compose v2 is already available: $(docker compose version)"
    return 0
  fi

  run apt-get update
  run apt-get install -y ca-certificates curl gnupg lsb-release

  if configure_docker_apt_repo; then
    if apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
      docker compose version >/dev/null 2>&1 && return 0
    fi
    log "Docker upstream packages did not provide a working Compose v2 install; trying distro packages."
  fi

  run apt-get install -y docker.io docker-compose-plugin
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is still unavailable after installation."
}

install_legacy_shim() {
  [[ "${CREATE_LEGACY_SHIM}" == "true" ]] || return 0

  local shim_path
  local target_paths=("/usr/local/bin/docker-compose")

  if [[ -e "/usr/bin/docker-compose" ]] || [[ -L "/usr/bin/docker-compose" ]]; then
    target_paths+=("/usr/bin/docker-compose")
  fi

  for shim_path in "${target_paths[@]}"; do
    if [[ -e "${shim_path}" ]] || [[ -L "${shim_path}" ]]; then
      if ! grep -qs "exec docker compose" "${shim_path}"; then
        mv "${shim_path}" "${shim_path}.v1-disabled"
        log "Moved legacy docker-compose aside: ${shim_path}.v1-disabled"
      fi
    fi

    cat >"${shim_path}" <<'EOF'
#!/usr/bin/env sh
exec docker compose "$@"
EOF
    chmod 755 "${shim_path}"
    log "Installed ${shim_path} shim -> docker compose."
  done

  hash -r 2>/dev/null || true
}

install_compose_v2
install_legacy_shim

cat <<EOF

Docker Compose is ready:
  $(docker compose version)

Use:
  docker compose up -d --build --remove-orphans

If you type docker-compose, /usr/local/bin/docker-compose will forward it to
Compose v2 on standard Ubuntu/Debian PATHs.
EOF
