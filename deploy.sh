#!/usr/bin/env bash
set -Eeuo pipefail

# ============================================================================
# deploy.sh — keep the droplet in sync with the main branch, without downtime.
#
# Designed to run from cron on the deployment host. It:
#   1. Fetches the deploy branch and exits quietly when nothing changed.
#   2. Hard-resets the checkout to origin/main (local edits are discarded;
#      .env and mcp-server.toml are preserved).
#   3. Builds images BEFORE touching the running stack, so the only service
#      interruption is the container swap itself (~1-2s) — which the bundled
#      Caddy proxy absorbs by holding and retrying requests (lb_try_duration
#      in docker/caddy/Caddyfile), so clients never see an error.
#   4. Waits for the site to answer on its loopback bind, and rolls back to
#      the previous commit automatically if the new build never turns healthy.
#   5. Prunes dangling images so the disk doesn't fill up over time.
#
# Cron example (every 15 minutes, logging to a file):
#   */15 * * * * root /opt/security-recipes.ai/deploy.sh >> /var/log/security-recipes-deploy.log 2>&1
#
# Options / environment overrides:
#   --force            Rebuild and redeploy even when HEAD did not change.
#   DEPLOY_BRANCH      Branch to track.               Default: main
#   DEPLOY_REMOTE      Git remote to fetch.           Default: origin
#   DEPLOY_HEALTH_URL  URL that must return HTTP 200. Default: http://<SECURITY_RECIPES_HTTP_PORT>/
#   DEPLOY_HEALTH_TIMEOUT  Seconds to wait for health. Default: 90
# ============================================================================

# DEPLOY_REPO_DIR overrides the checkout to operate on (useful for testing or
# for running the script from outside the deployment checkout). Default: the
# directory this script lives in.
REPO_DIR="${DEPLOY_REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
BRANCH="${DEPLOY_BRANCH:-main}"
REMOTE="${DEPLOY_REMOTE:-origin}"
HEALTH_TIMEOUT="${DEPLOY_HEALTH_TIMEOUT:-90}"
LOCK_FILE="${DEPLOY_LOCK_FILE:-/var/lock/security-recipes-deploy.lock}"
FORCE="false"

[[ "${1:-}" == "--force" ]] && FORCE="true"

log() {
  printf '[%s] deploy: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

die() {
  log "ERROR: $*"
  exit 1
}

# --- single-instance guard (flock on Linux, mkdir fallback elsewhere) -------
if command -v flock >/dev/null 2>&1; then
  mkdir -p "$(dirname "${LOCK_FILE}")"
  exec 9>"${LOCK_FILE}"
  if ! flock -n 9; then
    log "Another deploy is already running; exiting."
    exit 0
  fi
else
  if ! mkdir "${LOCK_FILE}.d" 2>/dev/null; then
    log "Another deploy is already running (${LOCK_FILE}.d exists); exiting."
    exit 0
  fi
  trap 'rmdir "${LOCK_FILE}.d"' EXIT
fi

cd "${REPO_DIR}"
[[ -d .git ]] || die "${REPO_DIR} is not a git checkout."
[[ -f docker-compose.yml ]] || die "No docker-compose.yml in ${REPO_DIR}."
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required (scripts/install_docker_compose_v2.sh)."

# Root cron + non-root checkout owner would otherwise trip git's dubious
# ownership check.
if ! git config --global --get-all safe.directory 2>/dev/null | grep -qxF "${REPO_DIR}"; then
  git config --global --add safe.directory "${REPO_DIR}" || true
fi

# Loopback bind of the site container, e.g. 127.0.0.1:8080 (see .env).
health_url() {
  if [[ -n "${DEPLOY_HEALTH_URL:-}" ]]; then
    printf '%s' "${DEPLOY_HEALTH_URL}"
    return
  fi
  local bind="127.0.0.1:8080"
  if [[ -f .env ]]; then
    local from_env
    from_env="$(grep -E '^SECURITY_RECIPES_HTTP_PORT=' .env | tail -1 | cut -d= -f2- || true)"
    [[ -n "${from_env}" ]] && bind="${from_env}"
  fi
  printf 'http://%s/' "${bind}"
}

wait_for_health() {
  local url deadline
  url="$(health_url)"
  deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
  log "Waiting for ${url} to answer (timeout ${HEALTH_TIMEOUT}s)."
  while (( $(date +%s) < deadline )); do
    if curl -fsS -o /dev/null --max-time 5 "${url}"; then
      log "Healthy: ${url}"
      return 0
    fi
    sleep 3
  done
  return 1
}

build_and_swap() {
  # Build first: the running stack keeps serving while images bake.
  log "Building images."
  docker compose build --pull
  # Swap: compose only recreates services whose image/config changed. Caddy
  # keeps running (certificates untouched) and bridges the site swap.
  log "Swapping containers."
  docker compose up -d --remove-orphans
}

# All work happens inside main(): when this script targets its own checkout,
# the git reset below can rewrite deploy.sh itself mid-run, and bash reads
# scripts lazily — a function body is fully parsed before it executes, so the
# running process is immune to the file changing under it.
main() {
  # --- fetch and compare -----------------------------------------------------
  git fetch --prune "${REMOTE}" "${BRANCH}" || die "git fetch failed."
  local CURRENT TARGET
  CURRENT="$(git rev-parse HEAD)"
  TARGET="$(git rev-parse "${REMOTE}/${BRANCH}")"

  if [[ "${CURRENT}" == "${TARGET}" && "${FORCE}" != "true" ]]; then
    log "Already up to date at ${CURRENT:0:12}; nothing to do."
    exit 0
  fi

  # A commit that already failed health checks and was rolled back is not
  # retried on every cron tick — push a fix (or run --force) to clear it.
  local FAILED_MARKER=".git/deploy-failed-sha"
  if [[ "${FORCE}" != "true" && -f "${FAILED_MARKER}" && "$(cat "${FAILED_MARKER}")" == "${TARGET}" ]]; then
    log "Skipping ${TARGET:0:12}: it failed health checks on a previous run. Push a fix or run deploy.sh --force."
    exit 0
  fi

  log "Deploying ${TARGET:0:12} (currently ${CURRENT:0:12}) from ${REMOTE}/${BRANCH}."
  git checkout -q "${BRANCH}" 2>/dev/null || git checkout -qb "${BRANCH}" "${REMOTE}/${BRANCH}"
  git reset --hard "${TARGET}"
  git clean -fd -e .env -e mcp-server.toml

  build_and_swap

  if wait_for_health; then
    rm -f "${FAILED_MARKER}"
    docker image prune -f >/dev/null
    log "Deploy complete at $(git rev-parse --short=12 HEAD)."
    exit 0
  fi

  # --- rollback --------------------------------------------------------------
  log "New build never turned healthy; rolling back to ${CURRENT:0:12}."
  printf '%s' "${TARGET}" > "${FAILED_MARKER}"
  git reset --hard "${CURRENT}"
  build_and_swap
  if wait_for_health; then
    log "Rollback to ${CURRENT:0:12} is healthy. ${TARGET:0:12} is marked failed and will be skipped until a new commit lands or deploy.sh --force runs."
  else
    log "Rollback did not turn healthy either — manual intervention required (docker compose ps / logs)."
  fi
  exit 1
}

main "$@"
