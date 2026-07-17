#!/usr/bin/env bash
set -Eeuo pipefail
umask 027

# Schedulers start with a deliberately small environment. Keep caller-provided
# PATH first (integration tests and custom installations may rely on it), then
# append the standard Ubuntu locations. DEPLOY_PATH can replace it explicitly.
DEPLOY_DEFAULT_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export PATH="${DEPLOY_PATH:-${PATH:+${PATH}:}${DEPLOY_DEFAULT_PATH}}"

# A scheduled deploy must fail rather than wait forever for an interactive Git
# credential prompt. Public HTTPS remotes require no credentials; private
# remotes must have non-interactive credentials configured for the service user.
export GIT_TERMINAL_PROMPT=0
export GIT_SSH_COMMAND="${GIT_SSH_COMMAND:-ssh -o BatchMode=yes}"

# ============================================================================
# deploy.sh — keep the droplet in sync with the main branch, without downtime.
#
# Designed to run from the managed systemd timer (or cron) on the deployment
# host. It:
#   1. Fetches the deploy branch and exits quietly when nothing changed.
#   2. Waits for every GitHub Actions run on the exact target commit to finish
#      without a failure, including the required Build workflow.
#   3. Hard-resets the checkout to origin/main (local edits are discarded;
#      .env and mcp-server.toml are preserved).
#   4. Builds a commit-tagged image for the inactive blue/green site slot while
#      the active slot keeps serving every request.
#   5. Withdraws that slot from Caddy, replaces it, and admits it again only
#      after its exact commit marker is verified directly.
#   6. Gracefully switches Caddy and retains only a revision-verified previous
#      release as the warm fallback.
#   7. Verifies the exact commit marker through the local HTTPS proxy before
#      recording success; routing rolls back immediately on failure.
#   8. Prunes unused images and old build cache without touching either
#      running slot, so the disk does not fill up over time.
#   9. Verifies catalog freshness and sends an optional success heartbeat.
#
# Root crontab example (`sudo crontab -e`; no username column):
#   */15 * * * * /opt/security-recipes.ai/deploy.sh >> /var/log/security-recipes-deploy.log 2>&1
#
# Options / environment overrides:
#   --force            Rebuild and redeploy even when HEAD did not change.
#   DEPLOY_PATH        Complete executable search path. Default: current PATH + Ubuntu paths
#   DEPLOY_BRANCH      Branch to track.               Default: main
#   DEPLOY_REMOTE      Git remote to fetch.           Default: origin
#   DEPLOY_GIT_TIMEOUT Seconds allowed for git fetch. Default: 120
#   DEPLOY_HEALTH_TIMEOUT  Seconds to wait for health. Default: 90
#   DEPLOY_PROXY_HEALTH_URL Base URL for local post-switch verification.
#                           Default: SECURITY_RECIPES_BASE_URL resolved to loopback
#   DEPLOY_HEALTH_URL       Legacy alias for DEPLOY_PROXY_HEALTH_URL.
#   DEPLOY_PROXY_MODE       auto, bundled, or host.    Default: auto
#   DEPLOY_HOST_CADDYFILE   Host Caddy config path.    Default: /etc/caddy/Caddyfile
#   DEPLOY_SITE_IMAGE_REPOSITORY Commit-tagged image repository.
#                                                   Default: security-recipes-ai-site
#   DEPLOY_GITHUB_REPOSITORY  owner/repo override; normally derived from the remote.
#   DEPLOY_GITHUB_API_URL     GitHub REST API base.    Default: https://api.github.com
#   DEPLOY_GITHUB_REQUEST_TIMEOUT  Seconds per GitHub API request. Default: 30
#   DEPLOY_REQUIRED_WORKFLOWS Comma-separated workflow names. Default: Build
#   DEPLOY_CI_TIMEOUT         Seconds to wait for CI.  Default: 1800
#   DEPLOY_CI_POLL_SECONDS    Seconds between polls.   Default: 60
#   DEPLOY_CI_SETTLE_SECONDS  Stable-green window.     Default: 30
#   DEPLOY_MIN_FREE_MB        Required free disk before a build. Default: 2048
#   DEPLOY_DISK_PATH          Filesystem to check. Default: Docker root directory
#   DEPLOY_MIN_AVAILABLE_MEMORY_MB
#                           Required MemAvailable + SwapFree before a build.
#                           Default: 1536
#   DEPLOY_BUILD_CACHE_MAX_AGE  Age eligible for cache pruning. Default: 168h
#   DEPLOY_BUILD_CACHE_KEEP_STORAGE  Minimum cache to retain. Default: 5GB
#   DEPLOY_CATALOG_MAX_AGE_HOURS  Maximum live catalog age. Default: 36
#   DEPLOY_SUCCESS_HEARTBEAT_URL  Optional dead-man success ping URL.
#   DEPLOY_HEARTBEAT_TIMEOUT  Heartbeat request timeout. Default: 10
#   GH_TOKEN or GITHUB_TOKEN  Optional for public repos; recommended for API rate limits.
# ============================================================================

# DEPLOY_REPO_DIR overrides the checkout to operate on (useful for testing or
# for running the script from outside the deployment checkout). Default: the
# directory this script lives in.
REPO_DIR="${DEPLOY_REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
BRANCH="${DEPLOY_BRANCH:-main}"
REMOTE="${DEPLOY_REMOTE:-origin}"
GIT_TIMEOUT="${DEPLOY_GIT_TIMEOUT:-120}"
HEALTH_TIMEOUT="${DEPLOY_HEALTH_TIMEOUT:-90}"
LOCK_FILE="${DEPLOY_LOCK_FILE:-/var/lock/security-recipes-deploy.lock}"
PROXY_HEALTH_URL="${DEPLOY_PROXY_HEALTH_URL:-${DEPLOY_HEALTH_URL:-}}"
PROXY_MODE="${DEPLOY_PROXY_MODE:-auto}"
HOST_CADDYFILE="${DEPLOY_HOST_CADDYFILE:-/etc/caddy/Caddyfile}"
SITE_IMAGE_REPOSITORY="${DEPLOY_SITE_IMAGE_REPOSITORY:-security-recipes-ai-site}"
BLUE_SERVICE="security-recipes"
GREEN_SERVICE="security-recipes-green"
STATE_FILE="${DEPLOY_STATE_FILE:-${REPO_DIR}/.git/deploy-state}"
GITHUB_API_URL="${DEPLOY_GITHUB_API_URL:-https://api.github.com}"
GITHUB_REPOSITORY="${DEPLOY_GITHUB_REPOSITORY:-}"
GITHUB_REQUEST_TIMEOUT="${DEPLOY_GITHUB_REQUEST_TIMEOUT:-30}"
REQUIRED_WORKFLOWS="${DEPLOY_REQUIRED_WORKFLOWS:-Build}"
CI_TIMEOUT="${DEPLOY_CI_TIMEOUT:-1800}"
CI_POLL_SECONDS="${DEPLOY_CI_POLL_SECONDS:-60}"
CI_SETTLE_SECONDS="${DEPLOY_CI_SETTLE_SECONDS:-30}"
MIN_FREE_MB="${DEPLOY_MIN_FREE_MB:-2048}"
DISK_PATH="${DEPLOY_DISK_PATH:-}"
MIN_AVAILABLE_MEMORY_MB="${DEPLOY_MIN_AVAILABLE_MEMORY_MB:-1536}"
BUILD_CACHE_MAX_AGE="${DEPLOY_BUILD_CACHE_MAX_AGE:-168h}"
BUILD_CACHE_KEEP_STORAGE="${DEPLOY_BUILD_CACHE_KEEP_STORAGE:-5GB}"
CATALOG_MAX_AGE_HOURS="${DEPLOY_CATALOG_MAX_AGE_HOURS:-36}"
SUCCESS_HEARTBEAT_URL="${DEPLOY_SUCCESS_HEARTBEAT_URL:-}"
HEARTBEAT_TIMEOUT="${DEPLOY_HEARTBEAT_TIMEOUT:-10}"
FORCE="false"

[[ "${1:-}" == "--force" ]] && FORCE="true"

log() {
  printf '[%s] deploy: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

die() {
  log "ERROR: $*"
  exit 1
}

[[ "${HEALTH_TIMEOUT}" =~ ^[1-9][0-9]*$ ]] || die "DEPLOY_HEALTH_TIMEOUT must be a positive integer."
[[ "${GIT_TIMEOUT}" =~ ^[1-9][0-9]*$ ]] || die "DEPLOY_GIT_TIMEOUT must be a positive integer."
[[ "${GITHUB_REQUEST_TIMEOUT}" =~ ^[1-9][0-9]*$ ]] || die "DEPLOY_GITHUB_REQUEST_TIMEOUT must be a positive integer."
[[ "${CI_TIMEOUT}" =~ ^[1-9][0-9]*$ ]] || die "DEPLOY_CI_TIMEOUT must be a positive integer."
[[ "${CI_POLL_SECONDS}" =~ ^[1-9][0-9]*$ ]] || die "DEPLOY_CI_POLL_SECONDS must be a positive integer."
[[ "${CI_SETTLE_SECONDS}" =~ ^[0-9]+$ ]] || die "DEPLOY_CI_SETTLE_SECONDS must be a non-negative integer."
[[ "${MIN_FREE_MB}" =~ ^[1-9][0-9]*$ ]] || die "DEPLOY_MIN_FREE_MB must be a positive integer."
[[ "${MIN_AVAILABLE_MEMORY_MB}" =~ ^[1-9][0-9]*$ ]] ||
  die "DEPLOY_MIN_AVAILABLE_MEMORY_MB must be a positive integer."
if [[ -n "${DISK_PATH}" && "${DISK_PATH}" != /* ]]; then
  die "DEPLOY_DISK_PATH must be an absolute path."
fi
[[ "${CATALOG_MAX_AGE_HOURS}" =~ ^[0-9]+$ ]] || die "DEPLOY_CATALOG_MAX_AGE_HOURS must be a non-negative integer."
[[ "${HEARTBEAT_TIMEOUT}" =~ ^[1-9][0-9]*$ ]] || die "DEPLOY_HEARTBEAT_TIMEOUT must be a positive integer."
[[ -n "${BUILD_CACHE_MAX_AGE}" ]] || die "DEPLOY_BUILD_CACHE_MAX_AGE cannot be empty."
[[ -n "${BUILD_CACHE_KEEP_STORAGE}" ]] || die "DEPLOY_BUILD_CACHE_KEEP_STORAGE cannot be empty."
if [[ -n "${SUCCESS_HEARTBEAT_URL}" &&
      ! "${SUCCESS_HEARTBEAT_URL}" =~ ^https?:// ]]; then
  die "DEPLOY_SUCCESS_HEARTBEAT_URL must use http:// or https://."
fi
if [[ "${SUCCESS_HEARTBEAT_URL}" == *$'\n'* ||
      "${SUCCESS_HEARTBEAT_URL}" == *$'\r'* ]]; then
  die "DEPLOY_SUCCESS_HEARTBEAT_URL cannot contain line breaks."
fi
[[ -n "${REQUIRED_WORKFLOWS//[[:space:],]/}" ]] || die "DEPLOY_REQUIRED_WORKFLOWS must name at least one workflow."
[[ "${PROXY_MODE}" =~ ^(auto|bundled|host)$ ]] || die "DEPLOY_PROXY_MODE must be auto, bundled, or host."
[[ "${SITE_IMAGE_REPOSITORY}" =~ ^[A-Za-z0-9][A-Za-z0-9._:/-]*$ ]] ||
  die "DEPLOY_SITE_IMAGE_REPOSITORY contains unsupported characters."

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

# The root scheduler executes deploy.sh with full host privileges. Refuse a checkout
# that another account can replace or alter through its Git metadata.
if (( EUID == 0 )); then
  for protected_path in "${REPO_DIR}" "${REPO_DIR}/.git" "${REPO_DIR}/deploy.sh"; do
    protected_owner="$(stat -c '%u' "${protected_path}")" ||
      die "Could not inspect ownership of ${protected_path}."
    protected_mode="$(stat -c '%a' "${protected_path}")" ||
      die "Could not inspect permissions of ${protected_path}."
    [[ "${protected_owner}" == "0" ]] ||
      die "The root deployment service requires a root-owned checkout. Run: chown -R root:root ${REPO_DIR}"
    (( (8#${protected_mode} & 022) == 0 )) ||
      die "${protected_path} is group/world writable. Run: chmod -R go-w ${REPO_DIR}"
  done
fi

command -v timeout >/dev/null 2>&1 || die "GNU timeout is required (provided by Ubuntu coreutils)."
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required (scripts/install_docker_compose_v2.sh)."

fetch_branch() {
  timeout --kill-after=10s "${GIT_TIMEOUT}s" \
    git fetch --prune "${REMOTE}" "${BRANCH}"
}

github_repository() {
  local repository="${GITHUB_REPOSITORY}"
  local remote_url

  if [[ -z "${repository}" ]]; then
    if ! remote_url="$(git remote get-url "${REMOTE}")"; then
      log "ERROR: Cannot read the ${REMOTE} remote URL." >&2
      return 1
    fi
    remote_url="${remote_url%.git}"
    case "${remote_url}" in
      https://github.com/*|http://github.com/*|git://github.com/*)
        repository="${remote_url#*github.com/}"
        ;;
      git@github.com:*)
        repository="${remote_url#git@github.com:}"
        ;;
      ssh://git@github.com/*)
        repository="${remote_url#ssh://git@github.com/}"
        ;;
      *)
        log "ERROR: Cannot derive a GitHub owner/repo from ${remote_url}; set DEPLOY_GITHUB_REPOSITORY." >&2
        return 1
        ;;
    esac
  fi

  if [[ ! "${repository}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    log "ERROR: Invalid GitHub repository ${repository}; expected owner/repo." >&2
    return 1
  fi
  printf '%s' "${repository}"
}

github_workflow_runs() {
  local repository="$1"
  local sha="$2"
  local token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
  local -a curl_args=(
    --fail
    --silent
    --show-error
    --retry 2
    --retry-delay 2
    --retry-all-errors
    --connect-timeout 10
    --max-time "${GITHUB_REQUEST_TIMEOUT}"
    -H "Accept: application/vnd.github+json"
    -H "X-GitHub-Api-Version: 2022-11-28"
    --get "${GITHUB_API_URL%/}/repos/${repository}/actions/runs"
    --data-urlencode "branch=${BRANCH}"
    --data-urlencode "head_sha=${sha}"
    --data-urlencode "per_page=100"
  )

  if [[ -n "${token}" ]]; then
    # Keep the token out of the process argument list.
    printf 'Authorization: Bearer %s\n' "${token}" |
      curl "${curl_args[@]}" --header @-
  else
    curl "${curl_args[@]}"
  fi
}

wait_for_ci() {
  local repository="$1"
  local sha="$2"
  local deadline=$(( $(date +%s) + CI_TIMEOUT ))
  local response failures pending pending_names count reported_total mismatched missing signature now
  local stable_since=0
  local last_signature=""
  local workflow workflow_count required_bad_count
  local -a required_workflows

  command -v curl >/dev/null 2>&1 || {
    log "ERROR: curl is required to check GitHub Actions."
    return 1
  }
  command -v jq >/dev/null 2>&1 || {
    log "ERROR: jq is required to check GitHub Actions. Install it with: sudo apt-get install jq"
    return 1
  }

  IFS=',' read -r -a required_workflows <<< "${REQUIRED_WORKFLOWS}"
  log "Waiting for GitHub Actions on ${repository}@${sha:0:12} (timeout ${CI_TIMEOUT}s)."

  while true; do
    if ! response="$(github_workflow_runs "${repository}" "${sha}")"; then
      log "ERROR: GitHub Actions query failed. Set GH_TOKEN for private repositories or higher API limits."
      return 1
    fi
    if ! jq -e '(.workflow_runs | type) == "array"' >/dev/null 2>&1 <<< "${response}"; then
      log "ERROR: GitHub returned an unexpected workflow-runs response."
      return 1
    fi
    if ! jq -e '(.total_count | type) == "number"' >/dev/null 2>&1 <<< "${response}"; then
      log "ERROR: GitHub omitted the workflow-runs total count."
      return 1
    fi

    count="$(jq -r '.workflow_runs | length' <<< "${response}")"
    reported_total="$(jq -r '.total_count' <<< "${response}")"
    if (( reported_total != count )); then
      log "ERROR: GitHub reported ${reported_total} workflow runs but returned ${count}; refusing an incomplete CI view."
      return 1
    fi
    mismatched="$(
      jq -r --arg sha "${sha}" --arg branch "${BRANCH}" '
        [
          .workflow_runs[]
          | select(.head_sha != $sha or .head_branch != $branch)
        ]
        | length
      ' <<< "${response}"
    )"
    if (( mismatched > 0 )); then
      log "ERROR: GitHub returned workflow runs outside ${BRANCH}@${sha}; refusing to deploy."
      return 1
    fi

    failures="$(
      jq -r '
        .workflow_runs[]
        | select(
            .status == "completed"
            and .conclusion != "success"
            and .conclusion != "neutral"
            and .conclusion != "skipped"
          )
        | "\(.name): \(.conclusion // "unknown") \(.html_url)"
      ' <<< "${response}"
    )"
    if [[ -n "${failures}" ]]; then
      log "GitHub Actions rejected ${sha:0:12}:"
      while IFS= read -r failure; do
        log "  ${failure}"
      done <<< "${failures}"
      return 1
    fi

    pending="$(jq -r '[.workflow_runs[] | select(.status != "completed")] | length' <<< "${response}")"
    pending_names="$(
      jq -r '
        [.workflow_runs[] | select(.status != "completed") | "\(.name)=\(.status)"]
        | join(", ")
      ' <<< "${response}"
    )"
    missing=""
    for workflow in "${required_workflows[@]}"; do
      workflow="${workflow#"${workflow%%[![:space:]]*}"}"
      workflow="${workflow%"${workflow##*[![:space:]]}"}"
      [[ -n "${workflow}" ]] || continue
      workflow_count="$(
        jq -r --arg workflow "${workflow}" \
          '[.workflow_runs[] | select(.name == $workflow)] | length' \
          <<< "${response}"
      )"
      if (( workflow_count == 0 )); then
        missing="${missing}${missing:+, }${workflow}"
        continue
      fi
      required_bad_count="$(
        jq -r --arg workflow "${workflow}" '
          [
            .workflow_runs[]
            | select(
                .name == $workflow
                and .status == "completed"
                and .conclusion != "success"
              )
          ]
          | length
        ' <<< "${response}"
      )"
      if (( required_bad_count > 0 )); then
        log "Required workflow ${workflow} did not conclude successfully."
        return 1
      fi
    done

    now="$(date +%s)"
    if (( count == 0 )); then
      log "No workflow runs are registered yet for ${sha:0:12}; waiting."
      stable_since=0
      last_signature=""
    elif [[ -n "${missing}" ]]; then
      log "Waiting for required workflow(s): ${missing}."
      stable_since=0
      last_signature=""
    elif (( pending > 0 )); then
      log "CI still running (${pending_names})."
      stable_since=0
      last_signature=""
    else
      signature="$(
        jq -c '
          [.workflow_runs[] | {id, run_attempt, status, conclusion}]
          | sort_by(.id)
        ' <<< "${response}"
      )"
      if [[ "${signature}" != "${last_signature}" ]]; then
        last_signature="${signature}"
        stable_since="${now}"
        log "All discovered workflows passed; holding for ${CI_SETTLE_SECONDS}s to catch late runs."
      fi
      if (( now - stable_since >= CI_SETTLE_SECONDS )); then
        log "GitHub Actions passed for ${sha:0:12}:"
        jq -r '
          .workflow_runs[]
          | "  \(.name): \(.conclusion) \(.html_url)"
        ' <<< "${response}" | while IFS= read -r run; do
          log "${run}"
        done
        return 0
      fi
    fi

    if (( now >= deadline )); then
      log "ERROR: Timed out waiting for CI on ${sha:0:12}."
      jq -r '
        .workflow_runs[]
        | "  \(.name): \(.status)/\(.conclusion // "pending") \(.html_url)"
      ' <<< "${response}" | while IFS= read -r run; do
        log "${run}"
      done
      return 1
    fi
    sleep "${CI_POLL_SECONDS}"
  done
}

other_slot() {
  case "$1" in
    "${BLUE_SERVICE}") printf '%s' "${GREEN_SERVICE}" ;;
    "${GREEN_SERVICE}") printf '%s' "${BLUE_SERVICE}" ;;
    *) return 1 ;;
  esac
}

state_value() {
  local key="$1"
  [[ -f "${STATE_FILE}" ]] || return 1
  sed -n "s/^${key}=//p" "${STATE_FILE}" | tail -1
}

write_deploy_state() {
  local active_service="$1"
  local deployed_sha="$2"
  local fallback_service="${3:-}"
  local fallback_sha="${4:-}"
  local temporary="${STATE_FILE}.tmp.$$"

  [[ "${active_service}" == "${BLUE_SERVICE}" || "${active_service}" == "${GREEN_SERVICE}" ]] ||
    return 1
  [[ -z "${deployed_sha}" || "${deployed_sha}" =~ ^[0-9a-f]{40}$ ]] || return 1
  if [[ -n "${fallback_service}" || -n "${fallback_sha}" ]]; then
    [[ "${fallback_service}" == "${BLUE_SERVICE}" || "${fallback_service}" == "${GREEN_SERVICE}" ]] ||
      return 1
    [[ "${fallback_service}" != "${active_service}" ]] || return 1
    [[ "${fallback_sha}" =~ ^[0-9a-f]{40}$ ]] || return 1
  fi

  {
    printf 'version=2\n'
    printf 'active_service=%s\n' "${active_service}"
    printf 'deployed_sha=%s\n' "${deployed_sha}"
    printf 'fallback_service=%s\n' "${fallback_service}"
    printf 'fallback_sha=%s\n' "${fallback_sha}"
  } > "${temporary}"
  chmod 600 "${temporary}"
  mv -f "${temporary}" "${STATE_FILE}"
}

load_deploy_state() {
  local version active_service deployed_sha fallback_service fallback_sha

  if [[ ! -f "${STATE_FILE}" ]]; then
    STATE_VERSION="0"
    ACTIVE_SERVICE="${BLUE_SERVICE}"
    # An existing pre-blue/green container has no trustworthy revision
    # marker. Leave the deployed commit unknown so the first run initializes
    # a verified SHA-tagged standby instead of assuming checkout HEAD is live.
    DEPLOYED_SHA=""
    FALLBACK_SERVICE=""
    FALLBACK_SHA=""
    return
  fi

  version="$(state_value version 2>/dev/null || true)"
  active_service="$(state_value active_service 2>/dev/null || true)"
  deployed_sha="$(state_value deployed_sha 2>/dev/null || true)"
  fallback_service="$(state_value fallback_service 2>/dev/null || true)"
  fallback_sha="$(state_value fallback_sha 2>/dev/null || true)"

  if [[ "${active_service}" != "${BLUE_SERVICE}" && "${active_service}" != "${GREEN_SERVICE}" ]]; then
    active_service="${BLUE_SERVICE}"
  fi
  if [[ -n "${deployed_sha}" && ! "${deployed_sha}" =~ ^[0-9a-f]{40}$ ]]; then
    deployed_sha=""
  fi
  if [[ "${version}" != "2" ||
        ( "${fallback_service}" != "${BLUE_SERVICE}" &&
          "${fallback_service}" != "${GREEN_SERVICE}" ) ||
        "${fallback_service}" == "${active_service}" ||
        ! "${fallback_sha}" =~ ^[0-9a-f]{40}$ ]]; then
    fallback_service=""
    fallback_sha=""
  fi

  STATE_VERSION="${version}"
  ACTIVE_SERVICE="${active_service}"
  DEPLOYED_SHA="${deployed_sha}"
  FALLBACK_SERVICE="${fallback_service}"
  FALLBACK_SHA="${fallback_sha}"
}

env_file_value() {
  local key="$1"
  local value
  [[ -f .env ]] || return 1
  value="$(grep -E "^${key}=" .env | tail -1 | cut -d= -f2- || true)"
  value="${value%$'\r'}"
  if [[ "${value}" == \"*\" && "${value}" == *\" ]]; then
    value="${value:1:${#value}-2}"
  elif [[ "${value}" == \'*\' && "${value}" == *\' ]]; then
    value="${value:1:${#value}-2}"
  fi
  [[ -n "${value}" ]] || return 1
  printf '%s' "${value}"
}

configured_slot_bind() {
  local service="$1"
  local bind
  case "${service}" in
    "${BLUE_SERVICE}")
      bind="$(env_file_value SECURITY_RECIPES_HTTP_PORT 2>/dev/null || printf '127.0.0.1:8080')"
      ;;
    "${GREEN_SERVICE}")
      bind="$(env_file_value SECURITY_RECIPES_GREEN_HTTP_PORT 2>/dev/null || printf '127.0.0.1:8081')"
      ;;
    *)
      return 1
      ;;
  esac
  [[ "${bind}" == *:* ]] || bind="127.0.0.1:${bind}"
  bind="${bind/#0.0.0.0:/127.0.0.1:}"
  printf '%s' "${bind}"
}

slot_endpoint() {
  local service="$1"
  local endpoint
  endpoint="$(docker compose port "${service}" 80 2>/dev/null | head -1)" || return 1
  [[ -n "${endpoint}" ]] || return 1
  endpoint="${endpoint/#0.0.0.0:/127.0.0.1:}"
  printf '%s' "${endpoint}"
}

slot_is_healthy() {
  local service="$1"
  local endpoint
  endpoint="$(slot_endpoint "${service}")" || return 1
  curl --fail --silent --show-error --max-time 5 \
    "http://${endpoint}/" >/dev/null 2>&1
}

slot_revision() {
  local service="$1"
  local endpoint revision
  endpoint="$(slot_endpoint "${service}")" || return 1
  revision="$(
    curl --fail --silent --show-error --max-time 5 \
      "http://${endpoint}/.well-known/deploy-revision" 2>/dev/null ||
      true
  )"
  revision="${revision//$'\r'/}"
  revision="${revision//$'\n'/}"
  printf '%s' "${revision}"
}

slot_serves_revision() {
  local service="$1"
  local expected_sha="$2"
  [[ "$(slot_revision "${service}")" == "${expected_sha}" ]]
}

wait_for_slot_revision() {
  local service="$1"
  local expected_sha="$2"
  local deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
  local revision

  log "Verifying ${service} directly at its loopback port (timeout ${HEALTH_TIMEOUT}s)."
  while (( $(date +%s) < deadline )); do
    revision="$(slot_revision "${service}")"
    if [[ "${revision}" == "${expected_sha}" ]]; then
      log "${service} is healthy at ${expected_sha:0:12}."
      return 0
    fi
    sleep 3
  done

  log "ERROR: ${service} never served the expected revision ${expected_sha:0:12}."
  return 1
}

detect_proxy() {
  local bundled_id="" host_exec_reload=""

  if [[ "${PROXY_MODE}" == "auto" || "${PROXY_MODE}" == "bundled" ]]; then
    bundled_id="$(docker compose ps --status running -q caddy 2>/dev/null || true)"
    if [[ -n "${bundled_id}" ]]; then
      if ! docker inspect --format '{{json .Config.Cmd}}' "${bundled_id}" 2>/dev/null |
           grep -q -- '--resume'; then
        log "ERROR: Bundled Caddy is not restart-durable yet. Recreate only the Caddy service once with the new Compose command during a maintenance window."
        return 1
      fi
      PROXY_KIND="bundled"
      return 0
    fi
    [[ "${PROXY_MODE}" != "bundled" ]] ||
      { log "ERROR: Bundled Caddy is not running."; return 1; }
  fi

  if [[ "${PROXY_MODE}" == "auto" || "${PROXY_MODE}" == "host" ]]; then
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet caddy; then
      if ! systemctl show --property=ExecStart --value caddy 2>/dev/null |
           grep -q -- '--resume'; then
        log "ERROR: Host Caddy is not restart-durable yet. Install the managed --resume systemd override before enabling scheduled deploys."
        return 1
      fi
      host_exec_reload="$(systemctl show --property=ExecReload --value caddy 2>/dev/null || true)"
      if [[ -n "${host_exec_reload}" ]]; then
        log "ERROR: Host Caddy still has a file-based ExecReload that can overwrite blue/green state. Install the managed API-only systemd override."
        return 1
      fi
      PROXY_KIND="host"
      return 0
    fi
    [[ "${PROXY_MODE}" != "host" ]] ||
      { log "ERROR: Host Caddy is not running."; return 1; }
  fi

  log "ERROR: Zero-downtime deployment requires either bundled Caddy or the managed host Caddy service."
  return 1
}

slot_upstream() {
  local service="$1"
  case "${PROXY_KIND}" in
    bundled)
      printf '%s:80' "${service}"
      ;;
    host)
      printf 'http://%s' "$(configured_slot_bind "${service}")"
      ;;
    *)
      return 1
      ;;
  esac
}

switch_proxy() {
  local primary_service="$1"
  local fallback_service="${2:-}"
  local primary_upstream fallback_upstream

  primary_upstream="$(slot_upstream "${primary_service}")" || return 1
  fallback_upstream=""
  if [[ -n "${fallback_service}" ]]; then
    fallback_upstream="$(slot_upstream "${fallback_service}")" || return 1
    log "Gracefully routing Caddy to ${primary_service}; ${fallback_service} remains the verified fallback."
  else
    log "Gracefully routing Caddy only to ${primary_service}; the inactive slot is withdrawn."
  fi

  case "${PROXY_KIND}" in
    bundled)
      [[ -f docker/caddy/Caddyfile ]] || {
        log "ERROR: docker/caddy/Caddyfile is missing."
        return 1
      }
      docker compose exec -T \
        -e "SECURITY_RECIPES_PRIMARY_UPSTREAM=${primary_upstream}" \
        -e "SECURITY_RECIPES_FALLBACK_UPSTREAM=${fallback_upstream}" \
        caddy sh -eu -c '
          config=/tmp/security-recipes-deploy.Caddyfile
          trap "rm -f ${config}" EXIT
          cat > "${config}"
          caddy validate --config "${config}" --adapter caddyfile
          caddy reload --force --config "${config}" --adapter caddyfile
        ' < docker/caddy/Caddyfile
      ;;
    host)
      [[ -r "${HOST_CADDYFILE}" ]] || {
        log "ERROR: Cannot read host Caddy config ${HOST_CADDYFILE}."
        return 1
      }
      grep -q 'SECURITY_RECIPES_PRIMARY_UPSTREAM' "${HOST_CADDYFILE}" || {
        log "ERROR: Host Caddy is not blue/green-ready. Re-run scripts/setup_digitalocean_droplet.sh before enabling scheduled deploys."
        return 1
      }
      SECURITY_RECIPES_PRIMARY_UPSTREAM="${primary_upstream}" \
      SECURITY_RECIPES_FALLBACK_UPSTREAM="${fallback_upstream}" \
        caddy validate --config "${HOST_CADDYFILE}" --adapter caddyfile &&
      SECURITY_RECIPES_PRIMARY_UPSTREAM="${primary_upstream}" \
      SECURITY_RECIPES_FALLBACK_UPSTREAM="${fallback_upstream}" \
        caddy reload --force --config "${HOST_CADDYFILE}" --adapter caddyfile
      ;;
    *)
      return 1
      ;;
  esac
}

proxy_base_url() {
  local base_url domain
  if [[ -n "${PROXY_HEALTH_URL}" ]]; then
    printf '%s' "${PROXY_HEALTH_URL%/}"
    return
  fi
  if base_url="$(env_file_value SECURITY_RECIPES_BASE_URL 2>/dev/null)"; then
    printf '%s' "${base_url%/}"
    return
  fi
  domain="$(env_file_value SECURITY_RECIPES_DOMAIN 2>/dev/null || printf 'security-recipes.ai')"
  printf 'https://%s' "${domain}"
}

proxy_curl() {
  local path="$1"
  local base_url url authority host port
  base_url="$(proxy_base_url)"
  url="${base_url%/}${path}"

  if [[ -n "${PROXY_HEALTH_URL}" || "${url}" != https://* ]]; then
    curl --fail --silent --show-error --max-time 8 "${url}"
    return
  fi

  authority="${url#https://}"
  authority="${authority%%/*}"
  host="${authority%%:*}"
  port="443"
  if [[ "${authority}" == *:* ]]; then
    port="${authority##*:}"
  fi
  curl --fail --silent --show-error --max-time 8 \
      --resolve "${host}:${port}:127.0.0.1" "${url}"
}

validate_catalog_freshness() {
  local manifest updated_at updated_epoch now_epoch age_seconds max_age_seconds

  if (( CATALOG_MAX_AGE_HOURS == 0 )); then
    log "Live catalog freshness check is disabled."
    return 0
  fi

  command -v jq >/dev/null 2>&1 || {
    log "ERROR: jq is required to validate the live CVE catalog."
    return 1
  }
  manifest="$(proxy_curl "/api/cve-catalog/manifest.json?health=$(date +%s)")" || {
    log "ERROR: The live CVE catalog manifest is unavailable."
    return 1
  }
  updated_at="$(
    jq -er '
      .catalog_updated_at
      | select(type == "string" and length > 0)
    ' <<<"${manifest}" 2>/dev/null
  )" || {
    log "ERROR: The live CVE catalog manifest has no valid catalog_updated_at value."
    return 1
  }
  updated_epoch="$(date -u -d "${updated_at}" +%s 2>/dev/null)" || {
    log "ERROR: The live CVE catalog timestamp cannot be parsed: ${updated_at}."
    return 1
  }
  now_epoch="$(date -u +%s)"
  age_seconds=$(( now_epoch - updated_epoch ))
  max_age_seconds=$(( CATALOG_MAX_AGE_HOURS * 3600 ))

  if (( age_seconds < -3600 )); then
    log "ERROR: The live CVE catalog timestamp is more than one hour in the future: ${updated_at}."
    return 1
  fi
  if (( age_seconds > max_age_seconds )); then
    log "ERROR: The live CVE catalog is stale (${updated_at}; limit ${CATALOG_MAX_AGE_HOURS}h)."
    return 1
  fi

  log "Live CVE catalog freshness passed (${updated_at})."
}

send_success_heartbeat() {
  local escaped_url
  if [[ -z "${SUCCESS_HEARTBEAT_URL}" ]]; then
    return 0
  fi

  # Keep the private heartbeat URL out of the process argument list.
  escaped_url="${SUCCESS_HEARTBEAT_URL//\\/\\\\}"
  escaped_url="${escaped_url//\"/\\\"}"
  if printf 'url = "%s"\n' "${escaped_url}" |
    curl --config - --fail --silent --show-error \
      --retry 2 --retry-delay 1 --retry-all-errors \
      --connect-timeout 5 --max-time "${HEARTBEAT_TIMEOUT}" >/dev/null; then
    log "Success heartbeat delivered."
  else
    # The deployment and its local checks succeeded. Do not turn a monitoring
    # provider outage into a rollback; a dead-man monitor will alert because it
    # did not receive this ping.
    log "WARNING: Success heartbeat delivery failed."
  fi
}

proxy_revision() {
  local expected_sha="$1"
  local revision
  revision="$(
    proxy_curl "/.well-known/deploy-revision?deploy=${expected_sha}" 2>/dev/null ||
      true
  )"
  revision="${revision//$'\r'/}"
  revision="${revision//$'\n'/}"
  printf '%s' "${revision}"
}

proxy_serves_revision() {
  local expected_sha="$1"
  [[ "$(proxy_revision "${expected_sha}")" == "${expected_sha}" ]]
}

wait_for_proxy_revision() {
  local expected_sha="$1"
  local deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
  local revision

  log "Verifying revision ${expected_sha:0:12} through the local Caddy listener."
  while (( $(date +%s) < deadline )); do
    revision="$(proxy_revision "${expected_sha}")"
    if [[ "${revision}" == "${expected_sha}" ]]; then
      log "Caddy is serving ${expected_sha:0:12}."
      return 0
    fi
    sleep 3
  done
  log "ERROR: Caddy never served the expected revision ${expected_sha:0:12}."
  return 1
}

wait_for_proxy_root() {
  local deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
  while (( $(date +%s) < deadline )); do
    if proxy_curl "/" >/dev/null 2>&1; then
      return 0
    fi
    sleep 3
  done
  return 1
}

run_slot_compose() {
  local service="$1"
  local image="$2"
  local revision="$3"
  shift 3

  case "${service}" in
    "${BLUE_SERVICE}")
      SECURITY_RECIPES_BLUE_IMAGE="${image}" \
      SECURITY_RECIPES_IMAGE_REVISION="${revision}" \
        docker compose "$@"
      ;;
    "${GREEN_SERVICE}")
      SECURITY_RECIPES_GREEN_IMAGE="${image}" \
      SECURITY_RECIPES_IMAGE_REVISION="${revision}" \
        docker compose "$@"
      ;;
    *)
      return 1
      ;;
  esac
}

build_candidate() {
  local service="$1"
  local image="$2"
  local revision="$3"

  log "Building ${image} for inactive slot ${service}; the active site remains untouched."
  run_slot_compose "${service}" "${image}" "${revision}" \
    build --pull "${service}"
}

start_candidate() {
  local service="$1"
  local image="$2"
  local revision="$3"

  log "Starting only withdrawn inactive slot ${service}."
  SWAP_ATTEMPTED="true"
  run_slot_compose "${service}" "${image}" "${revision}" \
    up -d --no-deps --force-recreate --pull never \
      --wait --wait-timeout "${HEALTH_TIMEOUT}" "${service}" || return 1

  wait_for_slot_revision "${service}" "${revision}"
}

refresh_non_site_images() {
  log "Pulling ancillary image updates without recreating the public Caddy edge."
  docker compose pull --policy always caddy traffic-report || return 1

  log "Rebuilding and refreshing the MCP service before site cutover."
  docker compose build --pull mcp-server || return 1
  docker compose up -d --no-deps --force-recreate --pull never \
    --wait --wait-timeout "${HEALTH_TIMEOUT}" mcp-server || return 1
}

cleanup_site_images() {
  local blue_id green_id blue_ref green_ref ref
  blue_id="$(docker compose ps -q "${BLUE_SERVICE}" 2>/dev/null || true)"
  green_id="$(docker compose ps -q "${GREEN_SERVICE}" 2>/dev/null || true)"
  blue_ref=""
  green_ref=""
  [[ -z "${blue_id}" ]] ||
    blue_ref="$(docker inspect --format '{{.Config.Image}}' "${blue_id}" 2>/dev/null || true)"
  [[ -z "${green_id}" ]] ||
    green_ref="$(docker inspect --format '{{.Config.Image}}' "${green_id}" 2>/dev/null || true)"

  while IFS= read -r ref; do
    [[ -n "${ref}" ]] || continue
    if [[ "${ref}" != "${blue_ref}" && "${ref}" != "${green_ref}" ]]; then
      docker image rm "${ref}" >/dev/null 2>&1 || true
    fi
  done < <(
    docker image ls "${SITE_IMAGE_REPOSITORY}" \
      --format '{{.Repository}}:{{.Tag}}' 2>/dev/null || true
  )
  docker image prune -f >/dev/null
}

prune_build_cache() {
  local help
  local -a prune_args=(
    builder prune --force
    --filter "until=${BUILD_CACHE_MAX_AGE}"
  )

  log "Pruning build cache older than ${BUILD_CACHE_MAX_AGE}, retaining ${BUILD_CACHE_KEEP_STORAGE} of reusable cache when possible."
  help="$(docker builder prune --help 2>/dev/null || true)"
  if grep -q -- '--reserved-space' <<<"${help}"; then
    prune_args+=(--reserved-space "${BUILD_CACHE_KEEP_STORAGE}")
  elif grep -q -- '--keep-storage' <<<"${help}"; then
    prune_args+=(--keep-storage "${BUILD_CACHE_KEEP_STORAGE}")
  else
    log "WARNING: This Docker version cannot reserve a configured cache floor; applying the age filter only."
  fi

  if ! docker "${prune_args[@]}" >/dev/null; then
    log "WARNING: Docker build-cache cleanup failed; active and fallback images were not removed."
  fi
}

available_disk_mb() {
  local path="${DISK_PATH}"
  if [[ -z "${path}" ]]; then
    path="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
  fi
  path="${path:-${REPO_DIR}}"
  [[ -e "${path}" ]] || path="${REPO_DIR}"
  df -Pk "${path}" | awk 'NR == 2 { print int($4 / 1024) }'
}

ensure_disk_headroom() {
  local available_mb
  available_mb="$(available_disk_mb)" || {
    log "ERROR: Could not determine free disk space for Docker storage."
    return 1
  }
  [[ "${available_mb}" =~ ^[0-9]+$ ]] || {
    log "ERROR: Unexpected free-space value: ${available_mb}."
    return 1
  }

  if (( available_mb < MIN_FREE_MB )); then
    log "Free disk is ${available_mb}MB; safely pruning unused site images and old build cache before the build."
    cleanup_site_images
    prune_build_cache
    available_mb="$(available_disk_mb)" || return 1
  fi

  if [[ ! "${available_mb}" =~ ^[0-9]+$ ]] ||
     (( available_mb < MIN_FREE_MB )); then
    log "ERROR: Only ${available_mb:-unknown}MB is free; ${MIN_FREE_MB}MB is required before building."
    return 1
  fi
  log "Disk headroom passed: ${available_mb}MB free (minimum ${MIN_FREE_MB}MB)."
}

available_memory_mb() {
  awk '
    /^MemAvailable:/ { memory_kb = $2 }
    /^SwapFree:/ { swap_kb = $2 }
    END {
      if (memory_kb == "" || swap_kb == "") {
        exit 1
      }
      print int((memory_kb + swap_kb) / 1024)
    }
  ' /proc/meminfo
}

ensure_memory_headroom() {
  local available_mb
  available_mb="$(available_memory_mb)" || {
    log "ERROR: Could not determine available memory and swap from /proc/meminfo."
    return 1
  }
  [[ "${available_mb}" =~ ^[0-9]+$ ]] || {
    log "ERROR: Unexpected available-memory value: ${available_mb}."
    return 1
  }

  if (( available_mb < MIN_AVAILABLE_MEMORY_MB )); then
    log "ERROR: Only ${available_mb}MB of memory plus free swap is available; ${MIN_AVAILABLE_MEMORY_MB}MB is required before building."
    log "The active site was not changed. Add swap, resize the Droplet, or lower DEPLOY_MIN_AVAILABLE_MEMORY_MB only after measuring a safe build."
    return 1
  fi
  log "Memory headroom passed: ${available_mb}MB available including free swap (minimum ${MIN_AVAILABLE_MEMORY_MB}MB)."
}

revision_is_marked_failed() {
  local revision="$1"
  [[ -f .git/deploy-failed-sha ]] &&
    [[ "$(cat .git/deploy-failed-sha 2>/dev/null || true)" == "${revision}" ]]
}

reconcile_active_slot() {
  local other_service active_revision other_revision proxy_active_revision candidate_service
  local recovery_matched="false"
  local original_deployed_sha="${DEPLOYED_SHA}"
  local original_fallback_service="${FALLBACK_SERVICE}"
  local original_fallback_sha="${FALLBACK_SHA}"
  local needs_reload="false"

  # If runtime state was deleted or predates v2, prefer the exact revision
  # Caddy is already serving. This preserves the current release across state
  # recovery instead of blindly reverting to the blue default.
  if [[ "${STATE_VERSION}" != "2" ||
        ! "${DEPLOYED_SHA}" =~ ^[0-9a-f]{40}$ ]]; then
    proxy_active_revision="$(proxy_revision recovery)"
    if [[ "${proxy_active_revision}" =~ ^[0-9a-f]{40}$ ]]; then
      if revision_is_marked_failed "${proxy_active_revision}"; then
        log "ERROR: Caddy is serving revision ${proxy_active_revision:0:12}, which is marked as failed."
        return 1
      fi
      for candidate_service in "${BLUE_SERVICE}" "${GREEN_SERVICE}"; do
        if slot_serves_revision "${candidate_service}" "${proxy_active_revision}"; then
          ACTIVE_SERVICE="${candidate_service}"
          DEPLOYED_SHA="${proxy_active_revision}"
          recovery_matched="true"
          log "Recovered active state from Caddy: ${candidate_service}@${proxy_active_revision:0:12}."
          break
        fi
      done
      if [[ "${recovery_matched}" != "true" ]]; then
        log "ERROR: Caddy serves ${proxy_active_revision:0:12}, but neither blue/green slot serves that exact revision; refusing to change routing."
        return 1
      fi

      candidate_service="$(other_slot "${ACTIVE_SERVICE}")" || return 1
      if slot_is_healthy "${candidate_service}"; then
        other_revision="$(slot_revision "${candidate_service}")"
        if [[ "${other_revision}" =~ ^[0-9a-f]{40}$ ]] &&
           ! revision_is_marked_failed "${other_revision}"; then
          FALLBACK_SERVICE="${candidate_service}"
          FALLBACK_SHA="${other_revision}"
          log "Recovered verified fallback state: ${candidate_service}@${other_revision:0:12}."
        fi
      fi
    fi
  fi

  other_service="$(other_slot "${ACTIVE_SERVICE}")" || return 1

  if slot_is_healthy "${ACTIVE_SERVICE}"; then
    active_revision="$(slot_revision "${ACTIVE_SERVICE}")"
    if [[ "${active_revision}" =~ ^[0-9a-f]{40}$ ]] &&
       ! revision_is_marked_failed "${active_revision}"; then
      if [[ "${DEPLOYED_SHA}" != "${active_revision}" ]]; then
        log "Recorded revision does not match ${ACTIVE_SERVICE}; adopting its verified marker ${active_revision:0:12}."
        DEPLOYED_SHA="${active_revision}"
      fi
    else
      [[ -z "${DEPLOYED_SHA}" ]] ||
        log "${ACTIVE_SERVICE} is root-healthy but does not serve its recorded revision; treating it as an unverified legacy slot."
      DEPLOYED_SHA=""
    fi

    if [[ "${FALLBACK_SERVICE}" != "${other_service}" ||
          ! "${FALLBACK_SHA}" =~ ^[0-9a-f]{40}$ ]] ||
       ! slot_is_healthy "${other_service}" ||
       ! slot_serves_revision "${other_service}" "${FALLBACK_SHA}" ||
       revision_is_marked_failed "${FALLBACK_SHA}"; then
      FALLBACK_SERVICE=""
      FALLBACK_SHA=""
    fi

    [[ "${STATE_VERSION}" == "2" ]] || needs_reload="true"
    [[ "${original_deployed_sha}" == "${DEPLOYED_SHA}" ]] || needs_reload="true"
    [[ "${original_fallback_service}" == "${FALLBACK_SERVICE}" ]] || needs_reload="true"
    [[ "${original_fallback_sha}" == "${FALLBACK_SHA}" ]] || needs_reload="true"
    if [[ "${DEPLOYED_SHA}" =~ ^[0-9a-f]{40}$ ]]; then
      proxy_serves_revision "${DEPLOYED_SHA}" || needs_reload="true"
    else
      needs_reload="true"
      FALLBACK_SERVICE=""
      FALLBACK_SHA=""
    fi

    if [[ "${needs_reload}" == "true" ]]; then
      switch_proxy "${ACTIVE_SERVICE}" "${FALLBACK_SERVICE}" || return 1
      if [[ "${DEPLOYED_SHA}" =~ ^[0-9a-f]{40}$ ]]; then
        wait_for_proxy_revision "${DEPLOYED_SHA}" || return 1
      else
        wait_for_proxy_root || return 1
      fi
      write_deploy_state \
        "${ACTIVE_SERVICE}" "${DEPLOYED_SHA}" \
        "${FALLBACK_SERVICE}" "${FALLBACK_SHA}" || return 1
      STATE_VERSION="2"
    else
      log "Caddy already serves the recorded active revision ${DEPLOYED_SHA:0:12}."
    fi
    return 0
  fi

  if ! slot_is_healthy "${other_service}"; then
    log "ERROR: Neither blue/green site slot is healthy."
    return 1
  fi

  other_revision="$(slot_revision "${other_service}")"
  if [[ ! "${other_revision}" =~ ^[0-9a-f]{40}$ ]] ||
     revision_is_marked_failed "${other_revision}"; then
    log "ERROR: The only root-healthy standby does not have a trusted revision marker."
    return 1
  fi

  log "Active slot ${ACTIVE_SERVICE} is unhealthy; failing over to verified ${other_service}@${other_revision:0:12}."
  switch_proxy "${other_service}" "" || return 1
  wait_for_proxy_revision "${other_revision}" || return 1
  ACTIVE_SERVICE="${other_service}"
  DEPLOYED_SHA="${other_revision}"
  FALLBACK_SERVICE=""
  FALLBACK_SHA=""
  STATE_VERSION="2"
  write_deploy_state "${ACTIVE_SERVICE}" "${DEPLOYED_SHA}" || return 1
}

fail_deployment() {
  local reason="$1"
  local target_sha="$2"
  local rollback_sha="$3"
  local previous_active="$4"
  local previous_deployed_sha="$5"
  local previous_fallback_service="$6"
  local previous_fallback_sha="$7"
  local candidate_service="$8"
  local failed_marker="$9"
  local rollback_fallback_service=""
  local rollback_fallback_sha=""

  if [[ "${ROUTING_WITHDRAWN}" != "true" &&
          "${previous_fallback_service}" == "${candidate_service}" &&
          "${previous_fallback_sha}" =~ ^[0-9a-f]{40}$ ]] &&
       slot_serves_revision "${previous_fallback_service}" "${previous_fallback_sha}"; then
    rollback_fallback_service="${previous_fallback_service}"
    rollback_fallback_sha="${previous_fallback_sha}"
  fi

  log "ERROR: ${reason}"
  if [[ "${PROXY_SWITCH_ATTEMPTED}" == "true" ]]; then
    log "Restoring Caddy routing to the previous slot ${previous_active}."
    if switch_proxy "${previous_active}" "${rollback_fallback_service}" &&
       {
         if [[ "${previous_deployed_sha}" =~ ^[0-9a-f]{40}$ ]]; then
           wait_for_proxy_revision "${previous_deployed_sha}"
         else
           wait_for_proxy_root
         fi
       }; then
      log "Previous slot ${previous_active} is serving again."
    else
      log "CRITICAL: Caddy routing rollback failed; manual inspection is required."
    fi
  fi

  if [[ "${SWAP_ATTEMPTED}" == "true" ]]; then
    printf '%s' "${target_sha}" > "${failed_marker}"
  fi
  git reset --hard "${rollback_sha}" ||
    die "Could not restore checkout ${rollback_sha:0:12}; manual intervention required."
  write_deploy_state \
    "${previous_active}" "${previous_deployed_sha}" \
    "${rollback_fallback_service}" "${rollback_fallback_sha}" ||
    die "Could not restore deployment state."
  exit 1
}

# All work happens inside main(): when this script targets its own checkout,
# the git reset below can rewrite deploy.sh itself mid-run, and bash reads
# scripts lazily — a function body is fully parsed before it executes, so the
# running process is immune to the file changing under it.
main() {
  # --- fetch, compare, and gate on exact-commit CI ---------------------------
  local CURRENT_HEAD TARGET CONFIRMED REPOSITORY
  local ROLLBACK_SHA PREVIOUS_ACTIVE PREVIOUS_DEPLOYED_SHA
  local PREVIOUS_FALLBACK_SERVICE PREVIOUS_FALLBACK_SHA
  local CANDIDATE_SERVICE CANDIDATE_IMAGE
  local CUTOVER_FALLBACK_SERVICE CUTOVER_FALLBACK_SHA
  local FAILED_MARKER=".git/deploy-failed-sha"
  CURRENT_HEAD="$(git rev-parse HEAD)"
  REPOSITORY=""
  PROXY_KIND=""
  PROXY_SWITCH_ATTEMPTED="false"
  SWAP_ATTEMPTED="false"
  ROUTING_WITHDRAWN="false"

  load_deploy_state
  detect_proxy || die "No zero-downtime Caddy proxy is available."
  reconcile_active_slot || die "Could not reconcile the active blue/green slot."
  if [[ ! -f "${STATE_FILE}" ]]; then
    write_deploy_state \
      "${ACTIVE_SERVICE}" "${DEPLOYED_SHA}" \
      "${FALLBACK_SERVICE}" "${FALLBACK_SHA}" ||
      die "Could not initialize deployment state."
  fi

  while true; do
    fetch_branch || die "git fetch failed or exceeded ${GIT_TIMEOUT}s."
    TARGET="$(git rev-parse "${REMOTE}/${BRANCH}")"

    if [[ "${DEPLOYED_SHA}" == "${TARGET}" &&
          "${FORCE}" != "true" ]] &&
       slot_serves_revision "${ACTIVE_SERVICE}" "${TARGET}" &&
       proxy_serves_revision "${TARGET}"; then
      log "Already serving ${TARGET:0:12} from ${ACTIVE_SERVICE}; nothing to do."
      validate_catalog_freshness ||
        die "The deployed revision is healthy, but its live CVE catalog freshness check failed."
      send_success_heartbeat
      exit 0
    fi

    # A commit that already failed health checks and was rolled back is not
    # retried on every timer tick — push a fix (or run --force) to clear it.
    if [[ "${FORCE}" != "true" &&
          -f "${FAILED_MARKER}" &&
          "$(cat "${FAILED_MARKER}")" == "${TARGET}" ]]; then
      if slot_serves_revision "${ACTIVE_SERVICE}" "${TARGET}" &&
         proxy_serves_revision "${TARGET}"; then
        log "The previously failed target ${TARGET:0:12} is unexpectedly active; rebuilding it instead of suppressing recovery."
      else
        die "Target ${TARGET:0:12} failed health checks on a previous run and remains undeployed. Push a fix or run deploy.sh --force."
      fi
    fi

    if [[ -z "${REPOSITORY}" ]]; then
      REPOSITORY="$(github_repository)" || die "Could not determine the GitHub repository."
    fi
    if ! wait_for_ci "${REPOSITORY}" "${TARGET}"; then
      # Build workflow concurrency cancels an older run when main advances.
      # Follow the newer target instead of treating that expected cancellation
      # as a permanent deployment failure.
      fetch_branch || die "post-CI-failure git fetch failed or exceeded ${GIT_TIMEOUT}s."
      CONFIRMED="$(git rev-parse "${REMOTE}/${BRANCH}")"
      if [[ "${CONFIRMED}" != "${TARGET}" ]]; then
        log "CI did not pass for superseded commit ${TARGET:0:12}; checking newer ${CONFIRMED:0:12}."
        continue
      fi
      die "CI did not pass for ${TARGET:0:12}; deployment stopped."
    fi

    # CI can take several minutes. Refetch before deploying so a newer main
    # commit cannot be silently skipped while this process was waiting.
    fetch_branch || die "post-CI git fetch failed or exceeded ${GIT_TIMEOUT}s."
    CONFIRMED="$(git rev-parse "${REMOTE}/${BRANCH}")"
    if [[ "${CONFIRMED}" != "${TARGET}" ]]; then
      log "${REMOTE}/${BRANCH} advanced from ${TARGET:0:12} to ${CONFIRMED:0:12} while CI ran; checking the newer commit."
      continue
    fi
    break
  done

  ensure_disk_headroom ||
    die "Insufficient safe disk headroom; the active site was not changed."
  ensure_memory_headroom ||
    die "Insufficient safe memory/swap headroom; the active site was not changed."

  PREVIOUS_ACTIVE="${ACTIVE_SERVICE}"
  PREVIOUS_DEPLOYED_SHA="${DEPLOYED_SHA}"
  PREVIOUS_FALLBACK_SERVICE="${FALLBACK_SERVICE}"
  PREVIOUS_FALLBACK_SHA="${FALLBACK_SHA}"
  CANDIDATE_SERVICE="$(other_slot "${PREVIOUS_ACTIVE}")" ||
    die "Could not select the inactive deployment slot."
  CANDIDATE_IMAGE="${SITE_IMAGE_REPOSITORY}:${TARGET}"
  ROLLBACK_SHA="${CURRENT_HEAD}"
  if [[ "${PREVIOUS_DEPLOYED_SHA}" =~ ^[0-9a-f]{40}$ ]] &&
     git cat-file -e "${PREVIOUS_DEPLOYED_SHA}^{commit}" 2>/dev/null; then
    ROLLBACK_SHA="${PREVIOUS_DEPLOYED_SHA}"
  fi

  log "Deploying ${TARGET:0:12} into inactive slot ${CANDIDATE_SERVICE}; ${PREVIOUS_ACTIVE} remains live."
  git checkout -q "${BRANCH}" 2>/dev/null || git checkout -qb "${BRANCH}" "${REMOTE}/${BRANCH}"
  git reset --hard "${TARGET}"
  git clean -fd -e .env -e mcp-server.toml

  docker compose config --quiet ||
    fail_deployment "Docker Compose configuration is invalid." \
      "${TARGET}" "${ROLLBACK_SHA}" "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" \
      "${PREVIOUS_FALLBACK_SERVICE}" "${PREVIOUS_FALLBACK_SHA}" \
      "${CANDIDATE_SERVICE}" "${FAILED_MARKER}"

  # Pulling/building does not touch either site slot or the public edge.
  refresh_non_site_images ||
    fail_deployment "Ancillary image preparation failed; the active site was not changed." \
      "${TARGET}" "${ROLLBACK_SHA}" "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" \
      "${PREVIOUS_FALLBACK_SERVICE}" "${PREVIOUS_FALLBACK_SHA}" \
      "${CANDIDATE_SERVICE}" "${FAILED_MARKER}"

  # Image construction cannot affect the running fallback, so keep both known-
  # good slots eligible until the candidate image is ready.
  build_candidate "${CANDIDATE_SERVICE}" "${CANDIDATE_IMAGE}" "${TARGET}" ||
    fail_deployment "The inactive candidate image could not be built; the active site was not changed." \
      "${TARGET}" "${ROLLBACK_SHA}" "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" \
      "${PREVIOUS_FALLBACK_SERVICE}" "${PREVIOUS_FALLBACK_SHA}" \
      "${CANDIDATE_SERVICE}" "${FAILED_MARKER}"

  # A reload can theoretically be applied server-side even if the client
  # loses the response. Treat every switch attempt as potentially effective
  # so the failure path always restores the known-good ordering.
  # Write the active-only intent first: a crash before the reload leaves an
  # extra *verified* fallback, while a crash after it leaves state and Caddy
  # in agreement. Neither window can expose the slot while it is replaced.
  write_deploy_state "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" ||
    fail_deployment "Could not durably record standby withdrawal intent." \
      "${TARGET}" "${ROLLBACK_SHA}" "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" \
      "${PREVIOUS_FALLBACK_SERVICE}" "${PREVIOUS_FALLBACK_SHA}" \
      "${CANDIDATE_SERVICE}" "${FAILED_MARKER}"
  PROXY_SWITCH_ATTEMPTED="true"
  switch_proxy "${PREVIOUS_ACTIVE}" "" ||
    fail_deployment "Caddy could not withdraw the inactive slot before it was replaced." \
      "${TARGET}" "${ROLLBACK_SHA}" "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" \
      "${PREVIOUS_FALLBACK_SERVICE}" "${PREVIOUS_FALLBACK_SHA}" \
      "${CANDIDATE_SERVICE}" "${FAILED_MARKER}"
  if [[ "${PREVIOUS_DEPLOYED_SHA}" =~ ^[0-9a-f]{40}$ ]]; then
    wait_for_proxy_revision "${PREVIOUS_DEPLOYED_SHA}" ||
      fail_deployment "Caddy did not keep serving the active revision after standby withdrawal." \
        "${TARGET}" "${ROLLBACK_SHA}" "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" \
        "${PREVIOUS_FALLBACK_SERVICE}" "${PREVIOUS_FALLBACK_SHA}" \
        "${CANDIDATE_SERVICE}" "${FAILED_MARKER}"
  else
    wait_for_proxy_root ||
      fail_deployment "Caddy did not keep serving the active legacy slot after standby withdrawal." \
        "${TARGET}" "${ROLLBACK_SHA}" "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" \
        "${PREVIOUS_FALLBACK_SERVICE}" "${PREVIOUS_FALLBACK_SHA}" \
        "${CANDIDATE_SERVICE}" "${FAILED_MARKER}"
  fi
  ROUTING_WITHDRAWN="true"
  FALLBACK_SERVICE=""
  FALLBACK_SHA=""

  start_candidate "${CANDIDATE_SERVICE}" "${CANDIDATE_IMAGE}" "${TARGET}" ||
    fail_deployment "The withdrawn candidate did not become healthy; it remains ineligible for traffic." \
      "${TARGET}" "${ROLLBACK_SHA}" "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" \
      "${PREVIOUS_FALLBACK_SERVICE}" "${PREVIOUS_FALLBACK_SHA}" \
      "${CANDIDATE_SERVICE}" "${FAILED_MARKER}"

  CUTOVER_FALLBACK_SERVICE=""
  CUTOVER_FALLBACK_SHA=""
  if [[ "${PREVIOUS_DEPLOYED_SHA}" =~ ^[0-9a-f]{40}$ ]] &&
     slot_serves_revision "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}"; then
    CUTOVER_FALLBACK_SERVICE="${PREVIOUS_ACTIVE}"
    CUTOVER_FALLBACK_SHA="${PREVIOUS_DEPLOYED_SHA}"
  fi
  switch_proxy "${CANDIDATE_SERVICE}" "${CUTOVER_FALLBACK_SERVICE}" ||
    fail_deployment "Caddy rejected the candidate routing configuration; the previous route remains active." \
      "${TARGET}" "${ROLLBACK_SHA}" "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" \
      "${PREVIOUS_FALLBACK_SERVICE}" "${PREVIOUS_FALLBACK_SHA}" \
      "${CANDIDATE_SERVICE}" "${FAILED_MARKER}"

  wait_for_proxy_revision "${TARGET}" ||
    fail_deployment "The local HTTPS proxy did not serve the candidate revision." \
      "${TARGET}" "${ROLLBACK_SHA}" "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" \
      "${PREVIOUS_FALLBACK_SERVICE}" "${PREVIOUS_FALLBACK_SHA}" \
      "${CANDIDATE_SERVICE}" "${FAILED_MARKER}"

  write_deploy_state \
    "${CANDIDATE_SERVICE}" "${TARGET}" \
    "${CUTOVER_FALLBACK_SERVICE}" "${CUTOVER_FALLBACK_SHA}" ||
    fail_deployment "Could not atomically record the active deployment state." \
      "${TARGET}" "${ROLLBACK_SHA}" "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" \
      "${PREVIOUS_FALLBACK_SERVICE}" "${PREVIOUS_FALLBACK_SHA}" \
      "${CANDIDATE_SERVICE}" "${FAILED_MARKER}"

  ACTIVE_SERVICE="${CANDIDATE_SERVICE}"
  DEPLOYED_SHA="${TARGET}"
  FALLBACK_SERVICE="${CUTOVER_FALLBACK_SERVICE}"
  if [[ -n "${CUTOVER_FALLBACK_SERVICE}" ]]; then
    FALLBACK_SHA="${PREVIOUS_DEPLOYED_SHA}"
  else
    FALLBACK_SHA=""
  fi
  rm -f "${FAILED_MARKER}"
  cleanup_site_images
  prune_build_cache
  if [[ -n "${FALLBACK_SERVICE}" ]]; then
    log "Deploy complete: ${TARGET:0:12} is active on ${ACTIVE_SERVICE}; ${FALLBACK_SERVICE}@${FALLBACK_SHA:0:12} remains the verified warm fallback."
  else
    log "Deploy complete: ${TARGET:0:12} is active on ${ACTIVE_SERVICE}; no unverified fallback was admitted."
  fi
  validate_catalog_freshness ||
    die "Deployment completed, but the live CVE catalog freshness check failed."
  send_success_heartbeat
}

main "$@"
