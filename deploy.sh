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
#   2. Waits for push-triggered, GitHub default-CodeQL, and trusted dispatched
#      Build runs on the exact target commit to finish without a failure.
#      Scheduled production monitors are deliberately excluded.
#   3. Hard-resets the checkout to origin/main (local edits are discarded;
#      .env and mcp-server.toml are preserved).
#   4. Pulls CI-built, commit-tagged site and MCP images and verifies their
#      revision labels while the active site keeps serving every request.
#   5. Withdraws that slot from Caddy, replaces its paired MCP and site, and
#      admits them again only after the exact revision and CVE contract pass.
#   6. Gracefully switches Caddy and retains only a revision-verified previous
#      release as the warm fallback.
#   7. Verifies the exact commit marker through the local HTTPS proxy before
#      recording success; routing rolls back immediately on failure.
#   8. Prunes unused images without touching either running slot, so the disk
#      does not fill up over time.
#   9. Verifies catalog freshness and sends an optional success heartbeat.
#
# Root crontab example (`sudo crontab -e`; no username column):
#   */15 * * * * /opt/security-recipes.ai/deploy.sh >> /var/log/security-recipes-deploy.log 2>&1
#
# Options / environment overrides:
#   --force            Pull and redeploy even when HEAD did not change. Run
#                      interactively, this also takes over a deploy already
#                      holding the lock (see DEPLOY_ALLOW_TAKEOVER).
#   DEPLOY_PATH        Complete executable search path. Default: current PATH + Ubuntu paths
#   DEPLOY_BRANCH      Branch to track.               Default: main
#   DEPLOY_DEVELOPMENT_BRANCH
#                      Staging branch for
#                      https://dev.<apex-domain>/.    Default: development
#                      Set empty to disable the track.
#   DEPLOY_DEVELOPMENT_IMAGE_SUFFIX
#                      Immutable GHCR tag suffix for
#                      development images.            Default: -development
#   DEPLOY_REMOTE      Git remote to fetch.           Default: origin
#   DEPLOY_GIT_TIMEOUT Seconds allowed for git fetch. Default: 120
#   DEPLOY_HEALTH_TIMEOUT  Seconds to wait for health. Default: 90
#   DEPLOY_PROXY_HEALTH_URL Base URL for local post-switch verification.
#                           Default: SECURITY_RECIPES_BASE_URL resolved to loopback
#   DEPLOY_HEALTH_URL       Legacy alias for DEPLOY_PROXY_HEALTH_URL.
#   DEPLOY_PROXY_MODE       auto, bundled, or host.    Default: auto
#   DEPLOY_COMPOSE_FAIL2BAN Run the Caddy abuse jail in Compose. Default: false
#   DEPLOY_HOST_CADDYFILE   Host Caddy config path.    Default: /etc/caddy/Caddyfile
#   DEPLOY_HOST_CADDY_LOG_DIR Host Caddy access-log directory. Default: /var/log/caddy
#   DEPLOY_SITE_IMAGE_REPOSITORY CI-published, commit-tagged site repository.
#                           Default: ghcr.io/stevologic/security-recipes.ai-site
#   DEPLOY_MCP_IMAGE_REPOSITORY CI-published, commit-tagged MCP repository.
#                           Default: ghcr.io/stevologic/security-recipes.ai-mcp
#   DEPLOY_GITHUB_REPOSITORY  owner/repo override; normally derived from the remote.
#   DEPLOY_GITHUB_API_URL     GitHub REST API base.    Default: https://api.github.com
#   DEPLOY_GITHUB_REQUEST_TIMEOUT  Seconds per GitHub API request. Default: 30
#   DEPLOY_REQUIRED_WORKFLOWS Comma-separated workflow names. Default: Build
#   DEPLOY_ALLOW_TAKEOVER     Force taking over the lock on/off. Default: auto,
#                           meaning --force from a terminal outside systemd.
#   DEPLOY_TAKEOVER_GRACE     Seconds to wait after SIGTERM before SIGKILL when
#                           taking over a running deploy. Default: 30
#   DEPLOY_CI_TIMEOUT         Seconds to wait for CI.  Default: 1800
#   DEPLOY_CI_POLL_SECONDS    Seconds between polls.   Default: 60
#   DEPLOY_CI_SETTLE_SECONDS  Stable-green window.     Default: 30
#   DEPLOY_MIN_FREE_MB        Required free disk before deployment. Default: 2048
#   DEPLOY_DISK_PATH          Filesystem to check. Default: Docker root directory
#   DEPLOY_MIN_AVAILABLE_MEMORY_MB
#                           Required MemAvailable + SwapFree before pulling and
#                           replacing an inactive container. Default: 256
#   DEPLOY_BUILD_CACHE_MAX_AGE  Age eligible for cache pruning. Default: 168h
#   DEPLOY_BUILD_CACHE_KEEP_STORAGE  Minimum cache to retain. Default: 5GB
#   DEPLOY_CATALOG_MAX_AGE_HOURS  Maximum live catalog age. Default: 36
#   DEPLOY_SUCCESS_HEARTBEAT_URL  Optional dead-man success ping URL.
#   DEPLOY_HEARTBEAT_TIMEOUT  Heartbeat request timeout. Default: 10
#   GH_TOKEN or GITHUB_TOKEN  Optional for public repos; recommended for API rate limits.
#   DIGITALOCEAN_ACCESS_TOKEN Optional. When present (or found in
#                           /etc/security-recipes/deploy.env or doctl
#                           config), deploy.sh creates or repairs the
#                           DigitalOcean A record for the staging hostname.
# ============================================================================

# DEPLOY_REPO_DIR overrides the checkout to operate on (useful for testing or
# for running the script from outside the deployment checkout). Default: the
# directory this script lives in.
REPO_DIR="${DEPLOY_REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
BRANCH="${DEPLOY_BRANCH:-main}"
DEVELOPMENT_BRANCH="${DEPLOY_DEVELOPMENT_BRANCH-development}"
DEVELOPMENT_IMAGE_SUFFIX="${DEPLOY_DEVELOPMENT_IMAGE_SUFFIX--development}"
REMOTE="${DEPLOY_REMOTE:-origin}"
GIT_TIMEOUT="${DEPLOY_GIT_TIMEOUT:-120}"
HEALTH_TIMEOUT="${DEPLOY_HEALTH_TIMEOUT:-90}"
LOCK_FILE="${DEPLOY_LOCK_FILE:-/var/lock/security-recipes-deploy.lock}"
TAKEOVER_GRACE="${DEPLOY_TAKEOVER_GRACE:-30}"
PROXY_HEALTH_URL="${DEPLOY_PROXY_HEALTH_URL:-${DEPLOY_HEALTH_URL:-}}"
PROXY_MODE="${DEPLOY_PROXY_MODE:-auto}"
COMPOSE_FAIL2BAN="${DEPLOY_COMPOSE_FAIL2BAN:-}"
HOST_CADDYFILE="${DEPLOY_HOST_CADDYFILE:-/etc/caddy/Caddyfile}"
HOST_CADDY_LOG_DIR="${DEPLOY_HOST_CADDY_LOG_DIR:-/var/log/caddy}"
SITE_IMAGE_REPOSITORY="${DEPLOY_SITE_IMAGE_REPOSITORY:-ghcr.io/stevologic/security-recipes.ai-site}"
MCP_IMAGE_REPOSITORY="${DEPLOY_MCP_IMAGE_REPOSITORY:-ghcr.io/stevologic/security-recipes.ai-mcp}"
BLUE_SERVICE="security-recipes"
GREEN_SERVICE="security-recipes-green"
DEV_SERVICE="security-recipes-dev"
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
MIN_AVAILABLE_MEMORY_MB="${DEPLOY_MIN_AVAILABLE_MEMORY_MB:-256}"
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
[[ "${TAKEOVER_GRACE}" =~ ^[1-9][0-9]*$ ]] || die "DEPLOY_TAKEOVER_GRACE must be a positive integer."
[[ -n "${REQUIRED_WORKFLOWS//[[:space:],]/}" ]] || die "DEPLOY_REQUIRED_WORKFLOWS must name at least one workflow."
[[ "${PROXY_MODE}" =~ ^(auto|bundled|host)$ ]] || die "DEPLOY_PROXY_MODE must be auto, bundled, or host."
[[ "${HOST_CADDY_LOG_DIR}" =~ ^/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+$ &&
   "${HOST_CADDY_LOG_DIR}" != *"/../"* &&
   "${HOST_CADDY_LOG_DIR}" != */.. &&
   "${HOST_CADDY_LOG_DIR}" != *"/./"* &&
   "${HOST_CADDY_LOG_DIR}" != */. &&
   "${HOST_CADDY_LOG_DIR}" != *"//"* ]] ||
  die "DEPLOY_HOST_CADDY_LOG_DIR must be a safe absolute child path."
[[ "${SITE_IMAGE_REPOSITORY}" =~ ^[A-Za-z0-9][A-Za-z0-9._:/-]*$ ]] ||
  die "DEPLOY_SITE_IMAGE_REPOSITORY contains unsupported characters."
[[ "${MCP_IMAGE_REPOSITORY}" =~ ^[A-Za-z0-9][A-Za-z0-9._:/-]*$ ]] ||
  die "DEPLOY_MCP_IMAGE_REPOSITORY contains unsupported characters."
if [[ -n "${DEVELOPMENT_BRANCH}" ]]; then
  [[ "${DEVELOPMENT_BRANCH}" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] ||
    die "DEPLOY_DEVELOPMENT_BRANCH contains unsupported characters."
fi
if [[ -n "${DEVELOPMENT_IMAGE_SUFFIX}" ]]; then
  [[ "${DEVELOPMENT_IMAGE_SUFFIX}" =~ ^-[A-Za-z0-9][A-Za-z0-9._-]*$ ]] ||
    die "DEPLOY_DEVELOPMENT_IMAGE_SUFFIX must start with a hyphen."
fi

# --- single-instance guard (flock on Linux, mkdir fallback elsewhere) -------
LOCK_PID_FILE="${LOCK_FILE}.pid"

# An operator running --force at a terminal is asking to take control of the
# host, so a deploy left running by the timer (it can sit in wait_for_ci for
# DEPLOY_CI_TIMEOUT) must not turn that into a no-op. The scheduler itself must
# never take over: overlapping unattended deploys are what the lock exists for.
deploy_takeover_allowed() {
  case "${DEPLOY_ALLOW_TAKEOVER:-auto}" in
    1 | true | yes) return 0 ;;
    0 | false | no) return 1 ;;
  esac
  [[ "${FORCE}" == "true" && -t 0 && -z "${INVOCATION_ID:-}" ]]
}

# Print the PID recorded by the lock holder, but only when it is still a live
# deploy.sh. A stale or recycled PID therefore fails closed rather than
# signalling an unrelated process.
lock_holder_pid() {
  local pid
  [[ -r "${LOCK_PID_FILE}" ]] || return 1
  read -r pid <"${LOCK_PID_FILE}" 2>/dev/null || return 1
  [[ "${pid}" =~ ^[1-9][0-9]*$ ]] || return 1
  (( pid == $$ || pid == 1 )) && return 1
  grep -qa 'deploy\.sh' "/proc/${pid}/cmdline" 2>/dev/null || return 1
  printf '%s' "${pid}"
}

terminate_lock_holder() {
  local pid="$1"
  local waited=0
  log "Taking over from running deploy process ${pid}."
  kill -TERM "${pid}" 2>/dev/null || true
  while (( waited < TAKEOVER_GRACE )) && kill -0 "${pid}" 2>/dev/null; do
    sleep 1
    (( waited += 1 ))
  done
  if kill -0 "${pid}" 2>/dev/null; then
    log "Deploy process ${pid} ignored SIGTERM after ${TAKEOVER_GRACE}s; sending SIGKILL."
    kill -KILL "${pid}" 2>/dev/null || true
    sleep 1
  fi
}

if command -v flock >/dev/null 2>&1; then
  mkdir -p "$(dirname "${LOCK_FILE}")"
  # Append rather than truncate: opening the lock must not destroy the holder's
  # recorded PID before we have had a chance to read it.
  exec 9>>"${LOCK_FILE}"
  if ! flock -n 9; then
    lock_holder=""
    if deploy_takeover_allowed; then
      lock_holder="$(lock_holder_pid || true)"
    fi
    if [[ -n "${lock_holder}" ]]; then
      terminate_lock_holder "${lock_holder}"
      flock -w "${TAKEOVER_GRACE}" 9 ||
        die "Could not acquire the deploy lock after taking over ${lock_holder}."
    else
      log "Another deploy is already running; exiting."
      exit 0
    fi
  fi
  printf '%s\n' "$$" >"${LOCK_PID_FILE}"
  trap 'rm -f "${LOCK_PID_FILE}"' EXIT
else
  if ! mkdir "${LOCK_FILE}.d" 2>/dev/null; then
    lock_holder=""
    if deploy_takeover_allowed; then
      lock_holder="$(lock_holder_pid || true)"
    fi
    if [[ -n "${lock_holder}" ]]; then
      terminate_lock_holder "${lock_holder}"
      rm -rf "${LOCK_FILE}.d"
      mkdir "${LOCK_FILE}.d" 2>/dev/null ||
        die "Could not acquire the deploy lock after taking over ${lock_holder}."
    else
      log "Another deploy is already running (${LOCK_FILE}.d exists); exiting."
      exit 0
    fi
  fi
  printf '%s\n' "$$" >"${LOCK_PID_FILE}"
  trap 'rm -f "${LOCK_PID_FILE}"; rmdir "${LOCK_FILE}.d"' EXIT
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
  local branch="${1:-${BRANCH}}"
  timeout --kill-after=10s "${GIT_TIMEOUT}s" \
    git fetch --prune "${REMOTE}" "${branch}"
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
  local event="$3"
  local workflow_file="${4:-}"
  local branch="${5:-${BRANCH}}"
  local token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
  local runs_url="${GITHUB_API_URL%/}/repos/${repository}/actions/runs"
  if [[ -n "${workflow_file}" ]]; then
    runs_url="${GITHUB_API_URL%/}/repos/${repository}/actions/workflows/${workflow_file}/runs"
  fi
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
    --get "${runs_url}"
    --data-urlencode "branch=${branch}"
    --data-urlencode "head_sha=${sha}"
    --data-urlencode "event=${event}"
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
  local branch="${3:-${BRANCH}}"
  local deadline=$(( $(date +%s) + CI_TIMEOUT ))
  local response event_response failures pending pending_names count missing signature now
  local stable_since=0
  local last_signature=""
  local event workflow_file expected_workflow expected_title_prefix expected_path
  local event_count event_reported_total event_mismatched
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
  log "Waiting for push/default-CodeQL/dispatched-Build GitHub Actions on ${repository}@${sha:0:12} (${branch}, timeout ${CI_TIMEOUT}s)."

  while true; do
    response='{"total_count":0,"workflow_runs":[]}'
    for event in push dynamic workflow_dispatch; do
      workflow_file=""
      expected_workflow=""
      expected_title_prefix=""
      expected_path=""
      if [[ "${event}" == "workflow_dispatch" ]]; then
        workflow_file="build.yml"
        expected_workflow="Build"
        expected_title_prefix="CVE catalog Build ${sha} "
        expected_path=".github/workflows/build.yml"
      fi
      if ! event_response="$(github_workflow_runs "${repository}" "${sha}" "${event}" "${workflow_file}" "${branch}")"; then
        log "ERROR: GitHub Actions ${event} query failed. Set GH_TOKEN for private repositories or higher API limits."
        return 1
      fi
      if ! jq -e '(.workflow_runs | type) == "array"' >/dev/null 2>&1 <<< "${event_response}"; then
        log "ERROR: GitHub returned an unexpected ${event} workflow-runs response."
        return 1
      fi
      if ! jq -e '(.total_count | type) == "number"' >/dev/null 2>&1 <<< "${event_response}"; then
        log "ERROR: GitHub omitted the ${event} workflow-runs total count."
        return 1
      fi

      event_count="$(jq -r '.workflow_runs | length' <<< "${event_response}")"
      event_reported_total="$(jq -r '.total_count' <<< "${event_response}")"
      if (( event_reported_total != event_count )); then
        log "ERROR: GitHub reported ${event_reported_total} ${event} workflow runs but returned ${event_count}; refusing an incomplete CI view."
        return 1
      fi
      # Identity is checked against .path, never .name: a workflow's run-name
      # overrides .name, so build.yml's dispatched runs report "CVE catalog
      # Build <sha> <request>" rather than "Build".
      event_mismatched="$(
        jq -r \
          --arg sha "${sha}" \
          --arg branch "${branch}" \
          --arg event "${event}" \
          --arg path "${expected_path}" '
          [
            .workflow_runs[]
            | select(
                .head_sha != $sha
                or .head_branch != $branch
                or .event != $event
                or ($path != "" and .path != $path)
              )
          ]
          | length
        ' <<< "${event_response}"
      )"
      if (( event_mismatched > 0 )); then
        log "ERROR: GitHub returned workflow runs outside ${event}:${branch}@${sha}; refusing to deploy."
        return 1
      fi
      if [[ "${event}" == "dynamic" ]]; then
        # Default-setup CodeQL reports its trigger in .name ("Push on main",
        # "PR #12", "Scheduled"). Only the run for this push gates the release:
        # a scheduled scan merely shares the SHA of whatever main points at, and
        # GitHub refuses to retry it, so letting it gate would strand every
        # deployment on that commit until an unrelated commit landed.
        event_response="$(
          jq '
            .workflow_runs = [
              .workflow_runs[]
              | select(.path == "dynamic/github-code-scanning/codeql")
              | select(.name != "Scheduled")
            ]
            | .total_count = (.workflow_runs | length)
          ' <<< "${event_response}"
        )"
      elif [[ "${event}" == "workflow_dispatch" ]]; then
        # Restore the workflow name that run-name masked, so the required-workflow
        # checks below still recognize this as the Build run they are waiting for.
        event_response="$(
          jq \
            --arg title_prefix "${expected_title_prefix}" \
            --arg workflow "${expected_workflow}" '
            .workflow_runs = (
              [
                .workflow_runs[]
                | select((.display_title // "") | startswith($title_prefix))
                | .name = $workflow
              ]
              | sort_by(.id)
              | reverse
              | .[:1]
            )
            | .total_count = (.workflow_runs | length)
          ' <<< "${event_response}"
        )"
      fi
      # An invalid workflow file produces a completed failure whose .name is the
      # file path, with no jobs. GitHub records that on every push even when
      # the file is not a push workflow. Those runs are not real CI.
      invalid_workflow_runs="$(
        jq -r '
          [
            .workflow_runs[]
            | select(.name == .path)
            | "\(.path): \(.conclusion // "unknown") \(.html_url)"
          ]
          | join("\n")
        ' <<< "${event_response}"
      )"
      if [[ -n "${invalid_workflow_runs}" ]]; then
        log "Ignoring invalid workflow-file run(s) that never started jobs:"
        while IFS= read -r invalid_run; do
          log "  ${invalid_run}"
        done <<< "${invalid_workflow_runs}"
        event_response="$(
          jq '
            .workflow_runs = [.workflow_runs[] | select(.name != .path)]
            | .total_count = (.workflow_runs | length)
          ' <<< "${event_response}"
        )"
      fi
      response="$(
        jq -cn \
          --argjson accumulated "${response}" \
          --argjson current "${event_response}" '
            ($accumulated.workflow_runs + $current.workflow_runs | unique_by(.id)) as $runs
            | {total_count: ($runs | length), workflow_runs: $runs}
          '
      )"
    done

    count="$(jq -r '.workflow_runs | length' <<< "${response}")"

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
        log "All discovered push/default-CodeQL/dispatched-Build workflows passed; holding for ${CI_SETTLE_SECONDS}s to catch late runs."
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

load_compose_fail2ban_setting() {
  if [[ -z "${COMPOSE_FAIL2BAN}" ]]; then
    COMPOSE_FAIL2BAN="$(
      env_file_value DEPLOY_COMPOSE_FAIL2BAN 2>/dev/null || printf 'false'
    )"
  fi
  [[ "${COMPOSE_FAIL2BAN}" =~ ^(true|false)$ ]] || {
    log "ERROR: DEPLOY_COMPOSE_FAIL2BAN must be true or false."
    return 1
  }
}

prepare_traffic_report_source() {
  [[ "${PROXY_KIND}" == "host" ]] || return 0

  local configured_source="" log_path temp_file
  log_path="${HOST_CADDY_LOG_DIR}/access.log"

  if configured_source="$(env_file_value SECURITY_RECIPES_TRAFFIC_LOGS_SOURCE 2>/dev/null)"; then
    if [[ "${configured_source}" != "${HOST_CADDY_LOG_DIR}" ]]; then
      log "ERROR: SECURITY_RECIPES_TRAFFIC_LOGS_SOURCE must match ${HOST_CADDY_LOG_DIR} for managed host Caddy."
      return 1
    fi
  else
    [[ -f .env ]] || {
      log "ERROR: Host Caddy traffic reporting requires the deployment .env file."
      return 1
    }
    printf '\nSECURITY_RECIPES_TRAFFIC_LOGS_SOURCE=%s\n' "${HOST_CADDY_LOG_DIR}" >> .env || return 1
    chmod 600 .env || return 1
    log "Configured the traffic report to read host Caddy logs from ${HOST_CADDY_LOG_DIR}."
  fi

  command -v caddy >/dev/null 2>&1 || {
    log "ERROR: The host Caddy binary is required to validate traffic logging."
    return 1
  }
  getent passwd caddy >/dev/null 2>&1 || {
    log "ERROR: The host Caddy account is missing."
    return 1
  }
  install -d -o caddy -g caddy -m 0750 "${HOST_CADDY_LOG_DIR}" || return 1

  if grep -Fq "output file ${log_path}" "${HOST_CADDYFILE}"; then
    return 0
  fi
  grep -q "Managed by security-recipes.ai setup script" "${HOST_CADDYFILE}" || {
    log "ERROR: Refusing to edit an unmanaged host Caddyfile; re-run the droplet setup script to enable traffic reporting."
    return 1
  }

  temp_file="$(mktemp "${HOST_CADDYFILE}.traffic.XXXXXX")" || return 1
  if ! awk -v log_path="${log_path}" '
      BEGIN { inserted = 0 }
      {
        print
        if (!inserted && $0 ~ /^[[:space:]]*encode[[:space:]]+zstd[[:space:]]+gzip[[:space:]]*$/) {
          print ""
          print "\t# Structured access logs feed the privacy-preserving aggregate report."
          print "\tlog {"
          print "\t\toutput file " log_path " {"
          print "\t\t\troll_size 50MiB"
          print "\t\t\troll_keep 10"
          print "\t\t\troll_keep_for 720h"
          print "\t\t}"
          print "\t\tformat json"
          print "\t}"
          inserted = 1
        }
      }
      END { if (!inserted) exit 42 }
    ' "${HOST_CADDYFILE}" > "${temp_file}"; then
    rm -f "${temp_file}"
    log "ERROR: Could not place managed traffic logging in ${HOST_CADDYFILE}."
    return 1
  fi

  if ! caddy validate --config "${temp_file}" --adapter caddyfile; then
    rm -f "${temp_file}"
    log "ERROR: Caddy rejected the managed traffic logging configuration."
    return 1
  fi
  install -o root -g root -m 0644 "${temp_file}" "${HOST_CADDYFILE}" || {
    rm -f "${temp_file}"
    return 1
  }
  rm -f "${temp_file}"
  log "Prepared host Caddy traffic logging; the next graceful route reload will activate it."
  TRAFFIC_CADDY_CONFIG_CHANGED="true"
}

prepare_host_caddy_www_redirect() {
  [[ "${PROXY_KIND}" == "host" ]] || return 0

  local base_url domain temp_file
  domain="$(env_file_value SECURITY_RECIPES_DOMAIN 2>/dev/null || true)"
  if [[ -z "${domain}" ]]; then
    base_url="$(env_file_value SECURITY_RECIPES_BASE_URL 2>/dev/null || true)"
    domain="${base_url#http://}"
    domain="${domain#https://}"
    domain="${domain%%/*}"
    domain="${domain%%:*}"
  fi
  if [[ ! "${domain}" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ ]] ||
     [[ "${domain}" != *.* ]] || [[ "${domain}" == www.* ]]; then
    log "ERROR: Cannot derive a safe apex domain for the managed host Caddy www redirect."
    return 1
  fi
  if grep -Fq "www.${domain} {" "${HOST_CADDYFILE}"; then
    return 0
  fi
  grep -q "Managed by security-recipes.ai setup script" "${HOST_CADDYFILE}" || {
    log "ERROR: Refusing to add the canonical www redirect to an unmanaged host Caddyfile."
    return 1
  }

  temp_file="$(mktemp "${HOST_CADDYFILE}.www.XXXXXX")" || return 1
  cp "${HOST_CADDYFILE}" "${temp_file}" || {
    rm -f "${temp_file}"
    return 1
  }
  printf '\n%s\n%s\n\t%s\n%s\n' \
    '# Acquire a certificate for www before consolidating it to the canonical apex host.' \
    "www.${domain} {" "redir https://${domain}{uri} permanent" '}' >> "${temp_file}" || {
      rm -f "${temp_file}"
      return 1
    }
  if ! caddy validate --config "${temp_file}" --adapter caddyfile; then
    rm -f "${temp_file}"
    log "ERROR: Caddy rejected the managed canonical www redirect."
    return 1
  fi
  install -o root -g root -m 0644 "${temp_file}" "${HOST_CADDYFILE}" || {
    rm -f "${temp_file}"
    return 1
  }
  rm -f "${temp_file}"
  log "Prepared host Caddy to obtain a www certificate and redirect to ${domain}."
  TRAFFIC_CADDY_CONFIG_CHANGED="true"
}

ensure_staging_dns_record() {
  local helper updater output status
  helper="${REPO_DIR}/scripts/upsert_dev_dns_from_host.py"
  updater="${REPO_DIR}/scripts/upsert_dev_dns_record.py"
  if [[ ! -f "${helper}" || ! -f "${updater}" ]]; then
    log "Staging DNS helper is not in this checkout; skipping A-record repair."
    return 0
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    log "python3 is not available; skipping staging A-record repair."
    return 0
  fi

  set +e
  output="$(python3 "${helper}" 2>&1)"
  status="$?"
  set -e
  if [[ "${status}" -eq 0 ]]; then
    log "Staging DNS: ${output}"
    return 0
  fi
  if [[ "${status}" -eq 2 ]]; then
    log "Staging DNS skipped: no DigitalOcean API token is present on this host."
    return 0
  fi
  log "Staging DNS repair failed (exit ${status}); production deploy continues. ${output}"
  return 0
}

prepare_host_caddy_dev_site() {
  [[ "${PROXY_KIND}" == "host" ]] || return 0

  local base_url domain temp_file bind host port
  domain="$(env_file_value SECURITY_RECIPES_DOMAIN 2>/dev/null || true)"
  if [[ -z "${domain}" ]]; then
    base_url="$(env_file_value SECURITY_RECIPES_BASE_URL 2>/dev/null || true)"
    domain="${base_url#http://}"
    domain="${domain#https://}"
    domain="${domain%%/*}"
    domain="${domain%%:*}"
  fi
  if [[ ! "${domain}" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ ]] ||
     [[ "${domain}" != *.* ]] || [[ "${domain}" == www.* ]]; then
    log "ERROR: Cannot derive a safe apex domain for the managed host Caddy development site."
    return 1
  fi
  if grep -Fq "dev.${domain} {" "${HOST_CADDYFILE}"; then
    return 0
  fi
  grep -q "Managed by security-recipes.ai setup script" "${HOST_CADDYFILE}" || {
    log "ERROR: Refusing to add the development site to an unmanaged host Caddyfile."
    return 1
  }
  bind="$(configured_slot_bind "${DEV_SERVICE}")" || bind="127.0.0.1:8082"
  host="${bind%:*}"
  port="${bind##*:}"

  temp_file="$(mktemp "${HOST_CADDYFILE}.dev.XXXXXX")" || return 1
  cp "${HOST_CADDYFILE}" "${temp_file}" || {
    rm -f "${temp_file}"
    return 1
  }
  cat >> "${temp_file}" <<EOF

# Staging hostname served from origin/development.
dev.${domain} {
	encode zstd gzip
	header X-Robots-Tag "noindex, nofollow, noarchive"
	reverse_proxy {\$SECURITY_RECIPES_DEV_UPSTREAM:${host}:${port}} {
		health_uri /
		health_interval 5s
		health_timeout 2s
		health_status 200
	}
}
EOF
  if ! caddy validate --config "${temp_file}" --adapter caddyfile; then
    rm -f "${temp_file}"
    log "ERROR: Caddy rejected the managed development hostname."
    return 1
  fi
  install -o root -g root -m 0644 "${temp_file}" "${HOST_CADDYFILE}" || {
    rm -f "${temp_file}"
    return 1
  }
  rm -f "${temp_file}"
  log "Prepared host Caddy to serve https://dev.${domain}/ from ${host}:${port}."
  TRAFFIC_CADDY_CONFIG_CHANGED="true"
}

ensure_caddy_404_ban() {
  # Host Fail2Ban remains owned by the droplet setup/installer. deploy.sh only
  # manages the explicitly opted-in Compose service, so a host without the
  # fail2ban package can deploy normally when the option is off.
  [[ "${COMPOSE_FAIL2BAN}" == "true" ]] || return 0

  [[ "${PROXY_KIND}" == "bundled" ]] || {
    log "ERROR: DEPLOY_COMPOSE_FAIL2BAN=true requires bundled Caddy. Use host Fail2Ban with host Caddy."
    return 1
  }
  if [[ -e /etc/fail2ban/jail.d/security-recipes-caddy-404.local ]] ||
     { command -v fail2ban-client >/dev/null 2>&1 &&
       fail2ban-client status security-recipes-caddy-404 >/dev/null 2>&1; }; then
    log "ERROR: The host security-recipes-caddy-404 jail is installed or active. Disable and remove that host jail before enabling Compose Fail2Ban."
    return 1
  fi
}

compose_fail2ban_is_healthy() {
  local container_id health
  container_id="$(docker compose ps --status running -q fail2ban 2>/dev/null || true)"
  [[ -n "${container_id}" ]] || return 1
  health="$(
    docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' \
      "${container_id}" 2>/dev/null || true
  )"
  [[ "${health}" == "healthy" ]]
}

ensure_compose_fail2ban_log() {
  [[ "${COMPOSE_FAIL2BAN}" == "true" ]] || return 0

  # Fail2Ban rejects an enabled file-backed jail when its log does not exist.
  # Caddy may not create access.log until its first request, so initialize the
  # shared named volume or host bind through the already-running edge.
  log "Ensuring the Caddy access log exists before starting Compose Fail2Ban."
  docker compose exec -T caddy sh -c \
    'mkdir -p /var/log/caddy && touch /var/log/caddy/access.log' || return 1
  docker compose exec -T caddy test -f /var/log/caddy/access.log
}

refresh_compose_fail2ban() {
  [[ "${COMPOSE_FAIL2BAN}" == "true" ]] || return 0
  ensure_caddy_404_ban || return 1
  ensure_compose_fail2ban_log || return 1

  log "Pulling and refreshing the opt-in Compose Fail2Ban service."
  docker compose pull --policy always fail2ban || return 1
  docker compose up -d --no-deps --force-recreate --pull never \
    --wait --wait-timeout "${HEALTH_TIMEOUT}" fail2ban
}

ensure_compose_fail2ban_runtime() {
  [[ "${COMPOSE_FAIL2BAN}" == "true" ]] || return 0
  ensure_caddy_404_ban || return 1
  if ! docker compose config --services 2>/dev/null | grep -Fxq fail2ban; then
    log "Compose Fail2Ban is enabled but absent from the current checkout; deferring startup until the target revision is checked out."
    return 0
  fi
  compose_fail2ban_is_healthy && return 0

  log "Repairing the missing or unhealthy opt-in Compose Fail2Ban service."
  docker compose config --quiet || return 1
  refresh_compose_fail2ban
}

traffic_report_is_healthy() {
  local container_id health
  container_id="$(docker compose ps --status running -q traffic-report 2>/dev/null || true)"
  [[ -n "${container_id}" ]] || return 1
  health="$(
    docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' \
      "${container_id}" 2>/dev/null || true
  )"
  [[ "${health}" == "healthy" ]]
}

ensure_traffic_report_runtime() {
  prepare_traffic_report_source || return 1
  prepare_host_caddy_www_redirect || return 1
  ensure_staging_dns_record
  prepare_host_caddy_dev_site || return 1

  if [[ "${TRAFFIC_CADDY_CONFIG_CHANGED}" == "true" ]]; then
    log "Activating the managed host Caddy configuration without changing the active route."
    switch_proxy "${ACTIVE_SERVICE}" "${FALLBACK_SERVICE}" || return 1
    if [[ "${DEPLOYED_SHA}" =~ ^[0-9a-f]{40}$ ]]; then
      wait_for_proxy_revision "${DEPLOYED_SHA}" || return 1
      validate_public_www_redirect "${DEPLOYED_SHA}" || return 1
    else
      wait_for_proxy_root || return 1
    fi
    TRAFFIC_CADDY_CONFIG_CHANGED="false"
  fi

  if traffic_report_is_healthy; then
    return 0
  fi

  log "Repairing the missing or unhealthy aggregate traffic report service."
  docker compose config --quiet || return 1
  docker compose pull --policy always traffic-report || return 1
  docker compose up -d --no-deps --force-recreate --pull never \
    --wait --wait-timeout "${HEALTH_TIMEOUT}" traffic-report
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
    "${DEV_SERVICE}")
      bind="$(env_file_value SECURITY_RECIPES_DEV_HTTP_PORT 2>/dev/null || printf '127.0.0.1:8082')"
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

wait_for_slot_cve_landing() {
  local service="$1"
  local endpoint page expected_canonical
  local deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
  endpoint="$(slot_endpoint "${service}")" || return 1
  expected_canonical="$(public_site_base_url)/cve/CVE-2024-3400/"

  log "Verifying the canonical CVE contract through ${service} (timeout ${HEALTH_TIMEOUT}s)."
  while (( $(date +%s) < deadline )); do
    page="$(
      curl --fail --silent --show-error --max-time 8 \
        "http://${endpoint}/cve/CVE-2024-3400/" 2>/dev/null || true
    )"
    if grep -Fq 'data-cve-initial-id="CVE-2024-3400"' <<<"${page}" &&
       grep -Fq '"@type":"Article"' <<<"${page}" &&
       grep -Fq '"additionalType":"https://schema.org/TechArticle"' <<<"${page}" &&
       grep -Fq "<link rel=\"canonical\" href=\"${expected_canonical}\">" <<<"${page}" &&
       grep -Fq '<meta name="robots" content="index,follow,max-image-preview:large,max-snippet:-1,max-video-preview:-1">' <<<"${page}" &&
       ! grep -Fq '<meta name="robots" content="noindex' <<<"${page}"; then
      log "${service} renders the indexable canonical CVE contract."
      return 0
    fi
    sleep 3
  done

  log "ERROR: ${service} never rendered the indexable canonical CVE contract."
  return 1
}

mcp_service_for_slot() {
  local service="$1"
  case "${service}" in
    "${BLUE_SERVICE}") printf '%s' 'mcp-server-blue' ;;
    "${GREEN_SERVICE}") printf '%s' 'mcp-server-green' ;;
    *) return 1 ;;
  esac
}

run_mcp_compose() {
  local service="$1"
  local image="$2"
  local revision="$3"
  shift 3

  case "${service}" in
    "${BLUE_SERVICE}")
      RECIPES_MCP_BLUE_IMAGE="${image}" \
      SECURITY_RECIPES_IMAGE_REVISION="${revision}" \
        docker compose "$@"
      ;;
    "${GREEN_SERVICE}")
      RECIPES_MCP_GREEN_IMAGE="${image}" \
      SECURITY_RECIPES_IMAGE_REVISION="${revision}" \
        docker compose "$@"
      ;;
    *)
      return 1
      ;;
  esac
}

mcp_service_container_id() {
  local service="$1"
  docker compose ps --status running -q "${service}" 2>/dev/null | head -1
}

mcp_service_any_container_id() {
  local service="$1"
  docker compose ps --all -q "${service}" 2>/dev/null | head -1
}

slot_mcp_upstream() {
  local service="$1"
  local container_id
  container_id="$(
    docker compose ps --status running -q "${service}" 2>/dev/null | head -1
  )" || return 1
  [[ -n "${container_id}" ]] || return 1
  docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' \
      "${container_id}" 2>/dev/null |
    awk -F= '$1 == "MCP_UPSTREAM" { sub(/^[^=]*=/, ""); print; exit }'
}

mcp_service_revision() {
  local service="$1"
  local container_id
  container_id="$(mcp_service_container_id "${service}")" || return 1
  [[ -n "${container_id}" ]] || return 1
  docker inspect \
    --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' \
    "${container_id}" 2>/dev/null
}

mcp_service_is_healthy() {
  local service="$1"
  local container_id health
  container_id="$(mcp_service_container_id "${service}")" || return 1
  [[ -n "${container_id}" ]] || return 1
  health="$(
    docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' \
      "${container_id}" 2>/dev/null || true
  )"
  [[ "${health}" == "healthy" ]]
}

validate_mcp_pair() {
  local service="$1"
  local expected_revision="$2"
  local mcp_service actual_revision
  mcp_service="$(mcp_service_for_slot "${service}")" || return 1
  actual_revision="$(mcp_service_revision "${mcp_service}" || true)"
  if [[ "${actual_revision}" != "${expected_revision}" ]]; then
    log "ERROR: ${mcp_service} declares revision ${actual_revision:-missing}; expected ${expected_revision}."
    return 1
  fi
  if ! mcp_service_is_healthy "${mcp_service}"; then
    log "ERROR: ${mcp_service} is not healthy."
    return 1
  fi
}

pull_mcp_candidate() {
  local revision="$1"
  local image="${MCP_IMAGE_REPOSITORY}:${revision}"
  log "Pulling CI-built MCP image ${image}; the running MCP service is unchanged."
  docker pull "${image}" || return 1
  verify_image_revision "${image}" "${revision}"
}

start_candidate_mcp() {
  local service="$1"
  local revision="$2"
  local image="${MCP_IMAGE_REPOSITORY}:${revision}"
  local mcp_service
  mcp_service="$(mcp_service_for_slot "${service}")" || return 1

  log "Starting inactive paired MCP ${mcp_service} at ${revision:0:12}; the active pair remains untouched."
  SWAP_ATTEMPTED="true"
  run_mcp_compose "${service}" "${image}" "${revision}" \
    up -d --no-deps --force-recreate --no-build --pull never \
      --wait --wait-timeout "${HEALTH_TIMEOUT}" "${mcp_service}" || return 1
  validate_mcp_pair "${service}" "${revision}"
}

validate_slot_mcp_contract() {
  local service="$1"
  local expected_revision="$2"
  local mcp_service upstream container_id legacy_revision
  [[ "${expected_revision}" =~ ^[0-9a-f]{40}$ ]] || return 0
  mcp_service="$(mcp_service_for_slot "${service}")" || return 1
  if ! upstream="$(slot_mcp_upstream "${service}")"; then
    log "ERROR: Could not inspect MCP_UPSTREAM for running slot ${service}."
    return 1
  fi

  case "${upstream}" in
    "${mcp_service}")
      container_id="$(mcp_service_any_container_id "${mcp_service}" || true)"
      if [[ -z "${container_id}" ]]; then
        log "ERROR: ${service} is configured for ${mcp_service}, but that paired MCP container is missing."
        return 1
      fi
      validate_mcp_pair "${service}" "${expected_revision}" || return 1
      ;;
    ""|mcp-server)
      # Pre-pair site images did not declare MCP_UPSTREAM; their nginx config
      # still targets the singleton. Allow that state only while the singleton
      # is running, healthy, and directly renders the expected CVE contract.
      legacy_revision="$(mcp_service_revision mcp-server || true)"
      if [[ -n "${legacy_revision}" && "${legacy_revision}" != "${expected_revision}" ]]; then
        log "ERROR: Transitional mcp-server declares revision ${legacy_revision}; expected ${expected_revision}."
        return 1
      fi
      if ! mcp_service_is_healthy mcp-server; then
        log "ERROR: Transitional mcp-server is not healthy."
        return 1
      fi
      log "Slot ${service} still uses the transitional singleton MCP; paired migration will occur on its next candidate cutover."
      ;;
    *)
      log "ERROR: ${service} declares unsupported MCP_UPSTREAM=${upstream}."
      return 1
      ;;
  esac

  wait_for_slot_cve_landing "${service}"
}

validate_active_mcp_pair() {
  validate_slot_mcp_contract "$1" "$2"
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

public_site_base_url() {
  local base_url domain
  if base_url="$(env_file_value SECURITY_RECIPES_BASE_URL 2>/dev/null)"; then
    printf '%s' "${base_url%/}"
    return
  fi
  domain="$(env_file_value SECURITY_RECIPES_DOMAIN 2>/dev/null || printf 'security-recipes.ai')"
  printf 'https://%s' "${domain}"
}

proxy_base_url() {
  if [[ -n "${PROXY_HEALTH_URL}" ]]; then
    printf '%s' "${PROXY_HEALTH_URL%/}"
    return
  fi
  public_site_base_url
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

validate_public_www_redirect() {
  local expected_revision="$1"
  local base_url domain port port_suffix www_url expected_url
  local deadline temp_file effective_url revision

  base_url="$(public_site_base_url)"
  if [[ "${base_url}" != https://* ]]; then
    log "Skipping the www TLS redirect probe because the public site URL is not HTTPS."
    return 0
  fi
  if [[ ! "${base_url}" =~ ^https://([A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9])(:([0-9]+))?/?$ ]]; then
    log "ERROR: Cannot derive a safe HTTPS apex URL for the www redirect probe."
    return 1
  fi
  domain="${BASH_REMATCH[1]}"
  port="${BASH_REMATCH[3]:-443}"
  if [[ "${domain}" == www.* || "${domain}" != *.* ]] ||
     [[ ! "${port}" =~ ^[1-9][0-9]{0,4}$ ]] || (( 10#${port} > 65535 )); then
    log "ERROR: Cannot derive a safe apex host and port for the www redirect probe."
    return 1
  fi
  port_suffix=""
  [[ "${port}" == "443" ]] || port_suffix=":${port}"
  www_url="https://www.${domain}${port_suffix}/.well-known/deploy-revision"
  expected_url="https://${domain}${port_suffix}/.well-known/deploy-revision"
  deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))

  log "Verifying the local www HTTPS redirect and certificate (timeout ${HEALTH_TIMEOUT}s)."
  while (( $(date +%s) < deadline )); do
    temp_file="$(mktemp)" || return 1
    effective_url="$(
      curl --fail --silent --show-error \
        --connect-timeout 3 --max-time 8 \
        --proto '=https' --proto-redir '=https' \
        --location --max-redirs 1 \
        --resolve "www.${domain}:${port}:127.0.0.1" \
        --resolve "${domain}:${port}:127.0.0.1" \
        --output "${temp_file}" --write-out '%{url_effective}' \
        "${www_url}" 2>/dev/null || true
    )"
    revision="$(tr -d '\r\n' < "${temp_file}")"
    rm -f "${temp_file}"
    if [[ "${effective_url}" == "${expected_url}" &&
          "${revision}" == "${expected_revision}" ]]; then
      log "The www HTTPS endpoint redirects to the canonical apex revision."
      return 0
    fi
    sleep 3
  done

  log "ERROR: The www HTTPS endpoint did not redirect safely to ${expected_url}."
  return 1
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

validate_proxy_cve_landing() {
  local page expected_canonical
  expected_canonical="$(public_site_base_url)/cve/CVE-2024-3400/"
  page="$(proxy_curl "/cve/CVE-2024-3400/")" || {
    log "ERROR: The canonical CVE landing route is unavailable through the active proxy."
    return 1
  }
  grep -Fq 'data-cve-initial-id="CVE-2024-3400"' <<<"${page}" &&
    grep -Fq '"@type":"Article"' <<<"${page}" &&
    grep -Fq '"additionalType":"https://schema.org/TechArticle"' <<<"${page}" &&
    grep -Fq "<link rel=\"canonical\" href=\"${expected_canonical}\">" <<<"${page}" &&
    grep -Fq '<meta name="robots" content="index,follow,max-image-preview:large,max-snippet:-1,max-video-preview:-1">' <<<"${page}" &&
    ! grep -Fq '<meta name="robots" content="noindex' <<<"${page}" || {
      log "ERROR: The canonical CVE landing route is missing its server-rendered SEO contract."
      return 1
    }
  log "Canonical CVE landing route passed through the active proxy."
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
      SECURITY_RECIPES_BLUE_MCP_UPSTREAM="mcp-server-blue" \
      SECURITY_RECIPES_IMAGE_REVISION="${revision}" \
        docker compose "$@"
      ;;
    "${GREEN_SERVICE}")
      SECURITY_RECIPES_GREEN_IMAGE="${image}" \
      SECURITY_RECIPES_GREEN_MCP_UPSTREAM="mcp-server-green" \
      SECURITY_RECIPES_IMAGE_REVISION="${revision}" \
        docker compose "$@"
      ;;
    "${DEV_SERVICE}")
      SECURITY_RECIPES_DEV_IMAGE="${image}" \
      SECURITY_RECIPES_DEV_MCP_UPSTREAM="mcp-server" \
      SECURITY_RECIPES_IMAGE_REVISION="${revision}" \
        docker compose "$@"
      ;;
    *)
      return 1
      ;;
  esac
}

verify_image_revision() {
  local image="$1"
  local expected_revision="$2"
  local actual_revision

  actual_revision="$(
    docker inspect \
      --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' \
      "${image}" 2>/dev/null || true
  )"
  if [[ "${actual_revision}" != "${expected_revision}" ]]; then
    log "ERROR: ${image} declares revision ${actual_revision:-missing}; expected ${expected_revision}."
    return 1
  fi
}

pull_candidate() {
  local service="$1"
  local image="$2"
  local revision="$3"

  log "Pulling CI-built ${image} for inactive slot ${service}; the active site remains untouched."
  docker pull "${image}" || return 1
  verify_image_revision "${image}" "${revision}"
}

start_candidate() {
  local service="$1"
  local image="$2"
  local revision="$3"

  log "Starting only withdrawn inactive slot ${service}."
  SWAP_ATTEMPTED="true"
  run_slot_compose "${service}" "${image}" "${revision}" \
    up -d --no-deps --force-recreate --no-build --pull never \
      --wait --wait-timeout "${HEALTH_TIMEOUT}" "${service}" || return 1

  wait_for_slot_revision "${service}" "${revision}"
}

refresh_non_site_images() {
  local revision="$1"

  log "Pulling ancillary image updates without recreating the public Caddy edge."
  docker compose pull --policy always caddy traffic-report || return 1

  log "Refreshing the aggregate traffic report service."
  docker compose up -d --no-deps --force-recreate --pull never \
    --wait --wait-timeout "${HEALTH_TIMEOUT}" traffic-report || return 1

  refresh_compose_fail2ban || return 1
  pull_mcp_candidate "${revision}"
}

cleanup_site_images() {
  local blue_id green_id dev_id blue_ref green_ref dev_ref ref
  blue_id="$(docker compose ps -q "${BLUE_SERVICE}" 2>/dev/null || true)"
  green_id="$(docker compose ps -q "${GREEN_SERVICE}" 2>/dev/null || true)"
  dev_id="$(docker compose ps -q "${DEV_SERVICE}" 2>/dev/null || true)"
  blue_ref=""
  green_ref=""
  dev_ref=""
  [[ -z "${blue_id}" ]] ||
    blue_ref="$(docker inspect --format '{{.Config.Image}}' "${blue_id}" 2>/dev/null || true)"
  [[ -z "${green_id}" ]] ||
    green_ref="$(docker inspect --format '{{.Config.Image}}' "${green_id}" 2>/dev/null || true)"
  [[ -z "${dev_id}" ]] ||
    dev_ref="$(docker inspect --format '{{.Config.Image}}' "${dev_id}" 2>/dev/null || true)"

  while IFS= read -r ref; do
    [[ -n "${ref}" ]] || continue
    if [[ "${ref}" != "${blue_ref}" && "${ref}" != "${green_ref}" && "${ref}" != "${dev_ref}" ]]; then
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
    log "ERROR: Only ${available_mb:-unknown}MB is free; ${MIN_FREE_MB}MB is required before deploying."
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
    log "ERROR: Only ${available_mb}MB of memory plus free swap is available; ${MIN_AVAILABLE_MEMORY_MB}MB is required for a safe pull-only deployment."
    log "The active site was not changed. Stop nonessential workloads or resize the Droplet before deploying."
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
    if [[ -n "${FALLBACK_SERVICE}" ]] &&
       ! validate_slot_mcp_contract "${FALLBACK_SERVICE}" "${FALLBACK_SHA}"; then
      log "Standby ${FALLBACK_SERVICE} failed its MCP/CVE contract and will be removed from fallback routing."
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
  if ! validate_slot_mcp_contract "${other_service}" "${other_revision}"; then
    log "ERROR: The only root-healthy standby failed its MCP/CVE contract; refusing failover."
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
  if [[ "${SWAP_ATTEMPTED}" == "true" ]]; then
    if ! printf '%s' "${target_sha}" > "${failed_marker}"; then
      log "WARNING: Could not record failed revision ${target_sha:0:12}; rollback will continue."
    fi
  fi
  git reset --hard "${rollback_sha}" ||
    die "Could not restore checkout ${rollback_sha:0:12}; manual intervention required."
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
  write_deploy_state \
    "${previous_active}" "${previous_deployed_sha}" \
    "${rollback_fallback_service}" "${rollback_fallback_sha}" ||
    die "Could not restore deployment state."
  exit 1
}

# All work happens inside main(): when this script targets its own checkout,
start_development_slot() {
  local service="$1"
  local image="$2"
  local revision="$3"

  log "Starting staging slot ${service} from ${image}."
  run_slot_compose "${service}" "${image}" "${revision}" \
    up -d --no-deps --force-recreate --no-build --pull never \
      --wait --wait-timeout "${HEALTH_TIMEOUT}" "${service}" || return 1
  wait_for_slot_revision "${service}" "${revision}"
}

deploy_development_track() {
  local branch="${DEVELOPMENT_BRANCH}"
  local target confirmed image repository

  [[ -n "${branch}" ]] || return 0
  [[ "${branch}" != "${BRANCH}" ]] || {
    log "Development track skipped: DEPLOY_DEVELOPMENT_BRANCH matches DEPLOY_BRANCH."
    return 0
  }

  ensure_staging_dns_record

  if ! fetch_branch "${branch}"; then
    log "Development track skipped: ${REMOTE}/${branch} could not be fetched."
    return 0
  fi
  if ! git rev-parse --verify --quiet "${REMOTE}/${branch}^{commit}" >/dev/null; then
    log "Development track skipped: ${REMOTE}/${branch} does not exist."
    return 0
  fi

  target="$(git rev-parse "${REMOTE}/${branch}")"
  if [[ ! "${target}" =~ ^[0-9a-f]{40}$ ]]; then
    log "ERROR: ${REMOTE}/${branch} did not resolve to a commit."
    return 1
  fi
  if [[ "${FORCE}" != "true" ]] && slot_serves_revision "${DEV_SERVICE}" "${target}"; then
    log "Development site already serving ${target:0:12}."
    return 0
  fi

  if [[ -z "${REPOSITORY}" ]]; then
    repository="$(github_repository)" || {
      log "Development track skipped: GitHub repository could not be determined."
      return 0
    }
  else
    repository="${REPOSITORY}"
  fi
  if ! wait_for_ci "${repository}" "${target}" "${branch}"; then
    log "Development track skipped: CI for ${branch}@${target:0:12} is not green yet."
    return 0
  fi
  if ! fetch_branch "${branch}"; then
    log "Development track skipped: post-CI fetch of ${REMOTE}/${branch} failed."
    return 0
  fi
  confirmed="$(git rev-parse "${REMOTE}/${branch}")"
  if [[ "${confirmed}" != "${target}" ]]; then
    log "Development track skipped: ${REMOTE}/${branch} advanced to ${confirmed:0:12} while CI ran."
    return 0
  fi

  image="${SITE_IMAGE_REPOSITORY}:${target}${DEVELOPMENT_IMAGE_SUFFIX}"
  if ! pull_candidate "${DEV_SERVICE}" "${image}" "${target}"; then
    log "Development track skipped: ${image} is not available yet."
    return 0
  fi
  prepare_host_caddy_dev_site || return 1
  if [[ "${TRAFFIC_CADDY_CONFIG_CHANGED}" == "true" ]]; then
    switch_proxy "${ACTIVE_SERVICE}" "${FALLBACK_SERVICE}" || return 1
    TRAFFIC_CADDY_CONFIG_CHANGED="false"
  fi
  start_development_slot "${DEV_SERVICE}" "${image}" "${target}" || {
    log "ERROR: The development slot did not become revision-verified."
    return 1
  }
  log "Development site is serving ${target:0:12} at the staging hostname."
}

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
  TRAFFIC_CADDY_CONFIG_CHANGED="false"

  load_compose_fail2ban_setting || die "Invalid Compose Fail2Ban deployment setting."
  load_deploy_state
  detect_proxy || die "No zero-downtime Caddy proxy is available."
  reconcile_active_slot || die "Could not reconcile the active blue/green slot."
  validate_active_mcp_pair "${ACTIVE_SERVICE}" "${DEPLOYED_SHA}" ||
    die "The active paired MCP does not match the active site revision."
  if [[ ! -f "${STATE_FILE}" ]]; then
    write_deploy_state \
      "${ACTIVE_SERVICE}" "${DEPLOYED_SHA}" \
      "${FALLBACK_SERVICE}" "${FALLBACK_SHA}" ||
      die "Could not initialize deployment state."
  fi
  ensure_traffic_report_runtime ||
    die "The aggregate traffic report service could not be prepared safely."
  ensure_compose_fail2ban_runtime ||
    die "The opt-in Compose Fail2Ban service could not be prepared safely."

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
      deploy_development_track ||
        die "Production is healthy, but the development track failed after image pull."
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

  prepare_traffic_report_source ||
    fail_deployment "Traffic report source preparation failed; the active site was not changed." \
      "${TARGET}" "${ROLLBACK_SHA}" "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" \
      "${PREVIOUS_FALLBACK_SERVICE}" "${PREVIOUS_FALLBACK_SHA}" \
      "${CANDIDATE_SERVICE}" "${FAILED_MARKER}"

  ensure_caddy_404_ban ||
    fail_deployment "The Caddy 404 abuse jail could not be activated safely; the active site was not changed." \
      "${TARGET}" "${ROLLBACK_SHA}" "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" \
      "${PREVIOUS_FALLBACK_SERVICE}" "${PREVIOUS_FALLBACK_SHA}" \
      "${CANDIDATE_SERVICE}" "${FAILED_MARKER}"

  docker compose config --quiet ||
    fail_deployment "Docker Compose configuration is invalid." \
      "${TARGET}" "${ROLLBACK_SHA}" "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" \
      "${PREVIOUS_FALLBACK_SERVICE}" "${PREVIOUS_FALLBACK_SHA}" \
      "${CANDIDATE_SERVICE}" "${FAILED_MARKER}"

  # Pulling does not touch either site slot or the public edge.
  refresh_non_site_images "${TARGET}" ||
    fail_deployment "Ancillary image preparation failed; the active site was not changed." \
      "${TARGET}" "${ROLLBACK_SHA}" "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" \
      "${PREVIOUS_FALLBACK_SERVICE}" "${PREVIOUS_FALLBACK_SHA}" \
      "${CANDIDATE_SERVICE}" "${FAILED_MARKER}"

  # Pulling the candidate cannot affect the running fallback, so keep both
  # known-good slots eligible until the revision-labelled image is ready.
  pull_candidate "${CANDIDATE_SERVICE}" "${CANDIDATE_IMAGE}" "${TARGET}" ||
    fail_deployment "The CI-built inactive candidate image could not be pulled and verified; the active site was not changed." \
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

  start_candidate_mcp "${CANDIDATE_SERVICE}" "${TARGET}" ||
    fail_deployment "The inactive paired MCP did not become revision-verified and healthy." \
      "${TARGET}" "${ROLLBACK_SHA}" "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" \
      "${PREVIOUS_FALLBACK_SERVICE}" "${PREVIOUS_FALLBACK_SHA}" \
      "${CANDIDATE_SERVICE}" "${FAILED_MARKER}"

  start_candidate "${CANDIDATE_SERVICE}" "${CANDIDATE_IMAGE}" "${TARGET}" ||
    fail_deployment "The withdrawn candidate did not become healthy; it remains ineligible for traffic." \
      "${TARGET}" "${ROLLBACK_SHA}" "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" \
      "${PREVIOUS_FALLBACK_SERVICE}" "${PREVIOUS_FALLBACK_SHA}" \
      "${CANDIDATE_SERVICE}" "${FAILED_MARKER}"
  wait_for_slot_cve_landing "${CANDIDATE_SERVICE}" ||
    fail_deployment "The inactive candidate and target MCP did not render the canonical CVE contract." \
      "${TARGET}" "${ROLLBACK_SHA}" "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" \
      "${PREVIOUS_FALLBACK_SERVICE}" "${PREVIOUS_FALLBACK_SHA}" \
      "${CANDIDATE_SERVICE}" "${FAILED_MARKER}"

  CUTOVER_FALLBACK_SERVICE=""
  CUTOVER_FALLBACK_SHA=""
  if [[ "${PREVIOUS_DEPLOYED_SHA}" =~ ^[0-9a-f]{40}$ ]] &&
     slot_serves_revision "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" &&
     validate_slot_mcp_contract "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}"; then
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

  validate_public_www_redirect "${TARGET}" ||
    fail_deployment "The www HTTPS endpoint did not consolidate safely after the Caddy reload." \
      "${TARGET}" "${ROLLBACK_SHA}" "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" \
      "${PREVIOUS_FALLBACK_SERVICE}" "${PREVIOUS_FALLBACK_SHA}" \
      "${CANDIDATE_SERVICE}" "${FAILED_MARKER}"

  validate_proxy_cve_landing ||
    fail_deployment "The switched site failed its canonical CVE landing verification." \
      "${TARGET}" "${ROLLBACK_SHA}" "${PREVIOUS_ACTIVE}" "${PREVIOUS_DEPLOYED_SHA}" \
      "${PREVIOUS_FALLBACK_SERVICE}" "${PREVIOUS_FALLBACK_SHA}" \
      "${CANDIDATE_SERVICE}" "${FAILED_MARKER}"
  validate_catalog_freshness ||
    fail_deployment "The switched site failed its live catalog freshness verification." \
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
  deploy_development_track ||
    die "Production is live, but the development track failed after image pull."
  send_success_heartbeat
}

main "$@"
