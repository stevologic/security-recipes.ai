#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${APP_DIR:-/opt/security-recipes.ai}"
APP_USER="${APP_USER:-security-recipes}"
BRANCH="${BRANCH:-main}"
REMOTE="${REMOTE:-origin}"
LOCK_FILE="${LOCK_FILE:-/var/lock/security-recipes-redeploy.lock}"
LOG_PREFIX="${LOG_PREFIX:-security-recipes-redeploy}"
FORCE_REBUILD="${FORCE_REBUILD:-false}"
PRUNE_IMAGES="${PRUNE_IMAGES:-false}"

usage() {
  cat <<'EOF'
Usage:
  sudo bash scripts/redeploy_from_github.sh [options]

Pull the latest security-recipes.ai checkout from GitHub and rebuild/restart the
Docker Compose stack when the deployed branch changed. Safe for cron.

Options:
  --app-dir PATH       Repo checkout path. Default: /opt/security-recipes.ai
  --app-user USER      Managed app owner. Default: security-recipes
  --branch BRANCH      Branch to deploy. Default: main
  --remote NAME        Git remote to fetch. Default: origin
  --force              Rebuild even when HEAD did not change.
  --prune-images       Run docker image prune -f after a successful deploy.
  -h, --help           Show this help.

Environment variables with the same names are also supported:
  APP_DIR, APP_USER, BRANCH, REMOTE, LOCK_FILE, FORCE_REBUILD, PRUNE_IMAGES
EOF
}

log() {
  printf '[%s] %s: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${LOG_PREFIX}" "$*"
}

die() {
  log "ERROR: $*"
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
      shift 2
      ;;
    --branch)
      BRANCH="${2:?Missing value for --branch}"
      shift 2
      ;;
    --remote)
      REMOTE="${2:?Missing value for --remote}"
      shift 2
      ;;
    --force)
      FORCE_REBUILD="true"
      shift
      ;;
    --prune-images)
      PRUNE_IMAGES="true"
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
  die "Run as root so the script can rebuild Docker images and repair ownership."
fi

if [[ ! -d "${APP_DIR}/.git" ]]; then
  die "No git checkout found at ${APP_DIR}"
fi

if [[ ! -f "${APP_DIR}/docker-compose.yml" ]]; then
  die "No docker-compose.yml found at ${APP_DIR}"
fi

compose_cmd() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  else
    die "Docker Compose v2 is not installed. Run scripts/install_docker_compose_v2.sh."
  fi
}

repair_ownership() {
  if id -u "${APP_USER}" >/dev/null 2>&1; then
    chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}"
    chmod 750 "${APP_DIR}"
    [[ ! -f "${APP_DIR}/.env" ]] || chmod 600 "${APP_DIR}/.env"
  fi
}

deploy() {
  cd "${APP_DIR}"

  local before after
  before="$(git rev-parse HEAD)"

  log "Fetching ${REMOTE}/${BRANCH} in ${APP_DIR}"
  git fetch --prune "${REMOTE}" "${BRANCH}"

  after="$(git rev-parse "${REMOTE}/${BRANCH}")"
  if [[ "${before}" == "${after}" && "${FORCE_REBUILD}" != "true" ]]; then
    log "Already up to date at ${before}; skipping rebuild."
    repair_ownership
    return 0
  fi

  log "Deploying ${after} (previous ${before})"
  git reset --hard "${REMOTE}/${BRANCH}"
  git clean -fd -e .env -e mcp-server.toml
  repair_ownership

  log "Rebuilding and restarting Docker Compose stack."
  compose_cmd up -d --build --remove-orphans
  compose_cmd ps

  if [[ "${PRUNE_IMAGES}" == "true" ]]; then
    docker image prune -f
  fi

  log "Deploy complete at $(git rev-parse HEAD)."
}

mkdir -p "$(dirname "${LOCK_FILE}")"
exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
  log "Another redeploy is already running; exiting."
  exit 0
fi

deploy
