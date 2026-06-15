#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${APP_DIR:-$(pwd)}"
PROJECT_NAME="${COMPOSE_PROJECT_NAME:-}"
SKIP_RESTART="false"

usage() {
  cat <<'EOF'
Usage:
  sudo bash scripts/repair_docker_compose_containerconfig.sh [options]

Repair a deployment that failed under legacy docker-compose v1 with:
  KeyError: 'ContainerConfig'

The script installs Docker Compose v2, removes stale Compose-managed project
containers, and restarts the stack with `docker compose`.

Options:
  --app-dir PATH        Directory containing docker-compose.yml. Default: current directory.
  --project-name NAME   Compose project name to clean. Default: inferred.
  --skip-restart        Install/clean only; do not run docker compose up.
  -h, --help            Show this help.
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
    --project-name)
      PROJECT_NAME="${2:?Missing value for --project-name}"
      shift 2
      ;;
    --skip-restart)
      SKIP_RESTART="true"
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
[[ -f "${APP_DIR}/docker-compose.yml" ]] || die "No docker-compose.yml found in ${APP_DIR}."

cd "${APP_DIR}"

if [[ -z "${PROJECT_NAME}" ]]; then
  PROJECT_NAME="$(basename "${APP_DIR}" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')"
fi

install_compose_v2() {
  if [[ -x "${APP_DIR}/scripts/install_docker_compose_v2.sh" ]]; then
    bash "${APP_DIR}/scripts/install_docker_compose_v2.sh"
  elif docker compose version >/dev/null 2>&1; then
    log "Docker Compose v2 is available: $(docker compose version)"
  else
    die "Docker Compose v2 is missing and scripts/install_docker_compose_v2.sh is not available."
  fi

  if command -v docker-compose >/dev/null 2>&1; then
    log "docker-compose now resolves to: $(command -v docker-compose)"
    docker-compose version || true
  fi
}

remove_containers_for_project() {
  local project="$1"
  [[ -n "${project}" ]] || return 0

  local ids
  ids="$(docker ps -aq --filter "label=com.docker.compose.project=${project}")"
  if [[ -z "${ids}" ]]; then
    log "No stale containers found for Compose project: ${project}"
    return 0
  fi

  log "Removing stale containers for Compose project: ${project}"
  # shellcheck disable=SC2086
  docker rm -f ${ids}
}

cleanup_stale_stack() {
  log "Stopping current Compose stack if v2 can identify it."
  docker compose down --remove-orphans || true

  remove_containers_for_project "${PROJECT_NAME}"
  remove_containers_for_project "security-recipesai"
}

restart_stack() {
  [[ "${SKIP_RESTART}" != "true" ]] || return 0

  log "Rebuilding and starting stack with Docker Compose v2."
  docker compose up -d --build --remove-orphans
  docker compose ps
}

install_compose_v2
cleanup_stale_stack
restart_stack

cat <<EOF

Repair complete.

Use these commands going forward:
  docker compose up -d --build --remove-orphans
  docker compose ps
  docker compose logs -f security-recipes
EOF
