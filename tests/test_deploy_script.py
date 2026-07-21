from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SCRIPT = ROOT / "deploy.sh"
COMPOSE_FILE = ROOT / "docker-compose.yml"
CADDYFILE = ROOT / "docker" / "caddy" / "Caddyfile"
NGINX_CONFIG = ROOT / "docker" / "nginx" / "default.conf"
TRAFFIC_REPORT_SCRIPT = ROOT / "docker" / "goaccess" / "generate-traffic-report.sh"
TRAFFIC_REPORT_PLACEHOLDER = ROOT / "docker" / "goaccess" / "traffic-initializing.html"
TRAFFIC_REPORT_THEME = ROOT / "docker" / "goaccess" / "traffic-theme.css"
DOCS_LAYOUT = ROOT / "_includes" / "layouts" / "docs.njk"
ELEVENTY_CONFIG = ROOT / "eleventy.config.js"
DOCKERFILE = ROOT / "Dockerfile"
SETUP_SCRIPT = ROOT / "scripts" / "setup_digitalocean_droplet.sh"
BACKUP_SCRIPT = ROOT / "scripts" / "backup_droplet_config.sh"
UNINSTALL_SCRIPT = ROOT / "scripts" / "uninstall_digitalocean_droplet.sh"
CADDY_404_BAN_INSTALLER = ROOT / "scripts" / "configure_caddy_404_ban.sh"


def bash_binary() -> str | None:
    if os.name != "nt":
        return shutil.which("bash")
    for candidate in (
        Path(r"C:\Program Files\Git\bin\bash.exe"),
        Path(r"C:\Program Files\Git\usr\bin\bash.exe"),
    ):
        if candidate.exists():
            return str(candidate)
    return None


BASH = bash_binary()


class DeployScriptStaticTests(unittest.TestCase):
    def test_scripts_have_valid_bash_syntax(self) -> None:
        if not BASH:
            self.skipTest("bash is not installed")
        subprocess.run(
            [
                BASH,
                "-n",
                str(DEPLOY_SCRIPT),
                str(SETUP_SCRIPT),
                str(BACKUP_SCRIPT),
                str(UNINSTALL_SCRIPT),
                str(CADDY_404_BAN_INSTALLER),
                str(TRAFFIC_REPORT_SCRIPT),
                str(ROOT / "tests" / "smoke_caddy_404_ban.sh"),
            ],
            check=True,
        )

    def test_ci_gate_precedes_checkout_and_candidate_pull(self) -> None:
        source = DEPLOY_SCRIPT.read_text(encoding="utf-8")
        main = source[source.index("main() {") :]

        self.assertIn("export GIT_TERMINAL_PROMPT=0", source)
        self.assertIn('GIT_SSH_COMMAND="${GIT_SSH_COMMAND:-ssh -o BatchMode=yes}"', source)
        self.assertIn('DEPLOY_DEFAULT_PATH="/usr/local/sbin:', source)
        self.assertNotIn("*/15 * * * * root ", source)
        self.assertIn('timeout --kill-after=10s "${GIT_TIMEOUT}s"', source)
        self.assertIn('"${REPO_DIR}/.git" "${REPO_DIR}/deploy.sh"', source)
        self.assertIn("curl \"${curl_args[@]}\" --header @-", source)
        self.assertIn('--data-urlencode "head_sha=${sha}"', source)
        self.assertIn('REQUIRED_WORKFLOWS="${DEPLOY_REQUIRED_WORKFLOWS:-Build}"', source)
        self.assertLess(
            main.index('wait_for_ci "${REPOSITORY}" "${TARGET}"'),
            main.index('git reset --hard "${TARGET}"'),
        )
        self.assertLess(
            main.index('git reset --hard "${TARGET}"'),
            main.index('pull_candidate "${CANDIDATE_SERVICE}" "${CANDIDATE_IMAGE}" "${TARGET}"'),
        )

    def test_compose_defines_two_isolated_site_slots(self) -> None:
        compose = COMPOSE_FILE.read_text(encoding="utf-8")

        self.assertIn("security-recipes:", compose)
        self.assertIn("security-recipes-green:", compose)
        self.assertIn("SECURITY_RECIPES_BLUE_IMAGE", compose)
        self.assertIn("SECURITY_RECIPES_GREEN_IMAGE", compose)
        self.assertIn("SECURITY_RECIPES_HTTP_PORT:-127.0.0.1:8080", compose)
        self.assertIn("SECURITY_RECIPES_GREEN_HTTP_PORT:-127.0.0.1:8081", compose)
        self.assertIn('"80:80"', compose)
        self.assertIn('"443:443"', compose)
        self.assertIn(
            'command: ["caddy", "run", "--resume", "--config", '
            '"/etc/caddy/Caddyfile", "--adapter", "caddyfile"]',
            compose,
        )
        self.assertNotIn("condition: service_healthy", compose)

    def test_compose_bounds_logs_and_health_checks_the_edge(self) -> None:
        compose = COMPOSE_FILE.read_text(encoding="utf-8")

        self.assertIn("driver: local", compose)
        self.assertIn("SECURITY_RECIPES_LOG_MAX_SIZE:-10m", compose)
        self.assertIn("SECURITY_RECIPES_LOG_MAX_FILES:-5", compose)
        self.assertGreaterEqual(compose.count("logging: *security-recipes-logging"), 4)
        self.assertIn("http://127.0.0.1:2019/config/", compose)
        self.assertIn(
            '"${SECURITY_RECIPES_TRAFFIC_LOGS_SOURCE:-caddy_logs}:/var/log/caddy"',
            compose,
        )

    def test_compose_fail2ban_can_enforce_the_caddy_404_jail(self) -> None:
        compose = COMPOSE_FILE.read_text(encoding="utf-8")

        self.assertIn("fail2ban:", compose)
        self.assertIn('profiles: ["fail2ban"]', compose)
        self.assertIn("network_mode: host", compose)
        self.assertIn("- NET_ADMIN", compose)
        self.assertIn("- NET_RAW", compose)
        self.assertIn("fail2ban_data:/data", compose)
        self.assertIn(
            "./config/fail2ban/filter.d/security-recipes-caddy-404.conf:"
            "/data/filter.d/security-recipes-caddy-404.conf:ro",
            compose,
        )
        self.assertIn(
            "./config/fail2ban/jail.d/security-recipes-caddy-404.local:"
            "/data/jail.d/security-recipes-caddy-404.local:ro",
            compose,
        )
        self.assertIn(
            '"${SECURITY_RECIPES_TRAFFIC_LOGS_SOURCE:-caddy_logs}:'
            '/var/log/caddy:ro"',
            compose,
        )

    def test_traffic_report_has_a_stable_entrypoint_and_atomic_publication(self) -> None:
        compose = COMPOSE_FILE.read_text(encoding="utf-8")
        generator = TRAFFIC_REPORT_SCRIPT.read_text(encoding="utf-8")
        theme = TRAFFIC_REPORT_THEME.read_text(encoding="utf-8")
        placeholder = TRAFFIC_REPORT_PLACEHOLDER.read_text(encoding="utf-8")
        docs_layout = DOCS_LAYOUT.read_text(encoding="utf-8")
        robots = ELEVENTY_CONFIG.read_text(encoding="utf-8")
        nginx = NGINX_CONFIG.read_text(encoding="utf-8")
        deploy = DEPLOY_SCRIPT.read_text(encoding="utf-8")
        refresh = deploy[
            deploy.index("refresh_non_site_images() {") : deploy.index(
                "cleanup_site_images() {"
            )
        ]

        self.assertIn(
            'entrypoint: ["/bin/sh", "/opt/security-recipes/generate-traffic-report.sh"]',
            compose,
        )
        self.assertNotIn('entrypoint: ["/bin/sh", "-c"]', compose)
        self.assertIn(
            "test -s /report/index.html && test -s /report/traffic-theme.css "
            "&& test -s /report/.generator-healthy",
            compose,
        )
        self.assertIn("./docker/goaccess:/opt/security-recipes:ro", compose)
        self.assertIn("SECURITY_RECIPES_TRAFFIC_LOGS_SOURCE:-caddy_logs", compose)
        self.assertIn("publish_placeholder", generator)
        self.assertIn('.index.next.$$.html\"', generator)
        self.assertIn('mv -f "${next_report}" "${REPORT_FILE}"', generator)
        self.assertIn("--no-query-string", generator)
        self.assertIn("--anonymize-level=3", generator)
        self.assertIn("--ignore-panel=HOSTS", generator)
        self.assertIn("--ignore-panel=REFERRERS", generator)
        self.assertIn("publish_theme", generator)
        self.assertIn('--html-custom-css="${THEME_NAME}"', generator)
        self.assertIn('"theme":"darkGray"', generator)
        self.assertIn("security-recipes.ai traffic dashboard theme", theme)
        self.assertIn("--sr-teal: #2dd4bf", theme)
        self.assertIn("font-size: 16px !important", theme)
        self.assertIn("font-size: 0.95rem !important", theme)
        self.assertIn("font-size: 17px !important", theme)
        self.assertIn("Privacy-preserving analytics", placeholder)
        self.assertIn("prefers-reduced-motion", placeholder)
        self.assertIn('name="robots" content="noindex, nofollow, noarchive"', placeholder)
        self.assertIn('name="robots" content="noindex, nofollow, noarchive"', generator)
        self.assertNotIn('href="/traffic/', docs_layout)
        self.assertIn("Disallow: /traffic/", robots)
        self.assertIn('Sitemap: ${feeds.absURL("/sitemap.xml")}', robots)
        self.assertIn("location = /traffic/", nginx)
        self.assertIn("try_files /traffic/index.html =404", nginx)
        self.assertIn('X-Robots-Tag "noindex, nofollow, noarchive" always', nginx)
        self.assertNotIn('[[ "${PROXY_KIND}" == "bundled" ]]', refresh)
        self.assertIn("--wait --wait-timeout", refresh)
        self.assertIn("traffic-report || return 1", refresh)
        self.assertIn("prepare_traffic_report_source", deploy)
        self.assertIn("SECURITY_RECIPES_TRAFFIC_LOGS_SOURCE", deploy)
        self.assertIn("output file ${log_path}", deploy)
        self.assertIn("ensure_caddy_404_ban", deploy)
        self.assertIn("scripts/configure_caddy_404_ban.sh", deploy)

    def test_compose_preserves_the_traffic_report_entrypoint(self) -> None:
        docker = shutil.which("docker")
        if not docker:
            self.skipTest("Docker Compose is not installed")

        result = subprocess.run(
            [docker, "compose", "--profile", "caddy", "config", "--format", "json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        service = json.loads(result.stdout)["services"]["traffic-report"]
        self.assertEqual(
            service["entrypoint"],
            ["/bin/sh", "/opt/security-recipes/generate-traffic-report.sh"],
        )
        self.assertIsNone(service.get("command"))
        self.assertEqual(
            service["healthcheck"]["test"],
            [
                "CMD-SHELL",
                "test -s /report/index.html && test -s /report/traffic-theme.css "
                "&& test -s /report/.generator-healthy",
            ],
        )

    @unittest.skipIf(os.name == "nt", "POSIX path behavior is covered on Linux CI")
    def test_traffic_report_publishes_an_immediate_placeholder(self) -> None:
        if not BASH:
            self.skipTest("bash is not installed")

        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            report = root / "report"
            environment = os.environ.copy()
            environment.update(
                {
                    "TRAFFIC_LOG_FILE": str(root / "missing-access.log"),
                    "TRAFFIC_REPORT_DIR": str(report),
                    "TRAFFIC_REPORT_PLACEHOLDER": str(TRAFFIC_REPORT_PLACEHOLDER),
                    "TRAFFIC_REPORT_THEME": str(TRAFFIC_REPORT_THEME),
                }
            )
            subprocess.run(
                [BASH, str(TRAFFIC_REPORT_SCRIPT), "--once"],
                text=True,
                capture_output=True,
                check=True,
                env=environment,
            )

            published = report / "index.html"
            self.assertTrue(published.is_file())
            self.assertGreater(published.stat().st_size, 0)
            self.assertIn("Report is warming up", published.read_text())
            self.assertTrue((report / "traffic-theme.css").is_file())
            self.assertTrue((report / ".generator-healthy").is_file())

    def test_setup_installs_single_systemd_scheduler_and_backup_timer(self) -> None:
        setup = SETUP_SCRIPT.read_text(encoding="utf-8")

        self.assertIn("--automation-only", setup)
        self.assertIn("security-recipes-deploy.service", setup)
        self.assertIn("security-recipes-deploy.timer", setup)
        self.assertIn("OnUnitInactiveSec=${DEPLOY_INTERVAL_MINUTES}min", setup)
        self.assertIn("security-recipes-backup.service", setup)
        self.assertIn("security-recipes-backup.timer", setup)
        self.assertIn("Persistent=true", setup)
        self.assertIn("remove_legacy_deploy_cron", setup)
        self.assertIn("index($0, deploy) == 0", setup)
        self.assertIn("DEPLOY_MIN_AVAILABLE_MEMORY_MB=256", setup)
        self.assertIn("DEPLOY_SITE_IMAGE_REPOSITORY=ghcr.io/", setup)
        self.assertIn("DEPLOY_MCP_IMAGE_REPOSITORY=ghcr.io/", setup)
        self.assertIn("compose_cmd up -d --no-build", setup)
        self.assertNotIn("compose_cmd up -d --build", setup)
        self.assertIn("DEPLOY_MIN_AVAILABLE_MEMORY_MB=1536' \"${DEPLOY_ENV_FILE}\"", setup)
        self.assertIn("SECURITY_RECIPES_TRAFFIC_LOGS_SOURCE=${CADDY_LOG_DIR}", setup)
        self.assertIn("output file ${CADDY_LOG_DIR}/access.log", setup)
        self.assertIn("compose_cmd up -d --no-deps --wait traffic-report", setup)
        self.assertIn("nftables", setup)
        self.assertIn("configure_caddy_404_ban", setup)
        self.assertIn("scripts/configure_caddy_404_ban.sh", setup)
        self.assertLess(
            setup.rfind("\nconfigure_caddy\n"),
            setup.rfind("\nconfigure_caddy_404_ban\n"),
        )

    def test_deploy_has_resource_freshness_and_success_heartbeat_guards(self) -> None:
        source = DEPLOY_SCRIPT.read_text(encoding="utf-8")
        main = source[source.index("main() {") :]

        self.assertIn('MIN_FREE_MB="${DEPLOY_MIN_FREE_MB:-2048}"', source)
        self.assertIn(
            'MIN_AVAILABLE_MEMORY_MB="${DEPLOY_MIN_AVAILABLE_MEMORY_MB:-256}"',
            source,
        )
        self.assertIn("ensure_disk_headroom", source)
        self.assertIn("ensure_memory_headroom", source)
        self.assertIn("/proc/meminfo", source)
        self.assertIn("MemAvailable:", source)
        self.assertIn("SwapFree:", source)
        self.assertLess(
            main.index("ensure_memory_headroom"),
            main.index(
                'pull_candidate "${CANDIDATE_SERVICE}" "${CANDIDATE_IMAGE}" "${TARGET}"'
            ),
        )
        self.assertIn("docker builder prune --help", source)
        self.assertIn("--reserved-space", source)
        self.assertIn("--keep-storage", source)
        self.assertIn('blue_ref="$(docker inspect', source)
        self.assertIn('green_ref="$(docker inspect', source)
        self.assertIn("validate_catalog_freshness", source)
        self.assertIn("catalog_updated_at", source)
        self.assertIn("send_success_heartbeat", source)
        self.assertNotIn("docker compose build", source)
        self.assertIn('docker pull "${image}"', source)
        self.assertIn("org.opencontainers.image.revision", source)

    def test_backup_requires_encryption_before_off_host_upload(self) -> None:
        source = BACKUP_SCRIPT.read_text(encoding="utf-8")

        self.assertIn("SECURITY_RECIPES_BACKUP_AGE_RECIPIENT", source)
        self.assertIn("Set SECURITY_RECIPES_BACKUP_AGE_RECIPIENT", source)
        self.assertLess(source.index("age --recipient"), source.index("rclone copyto"))
        self.assertIn("SECURITY_RECIPES_BACKUP_RETENTION_DAYS", source)
        self.assertIn("security-recipes-caddy-404.conf", source)
        self.assertIn("security-recipes-caddy-404.local", source)

    def test_uninstall_removes_only_the_managed_caddy_404_jail(self) -> None:
        source = UNINSTALL_SCRIPT.read_text(encoding="utf-8")

        self.assertIn(
            "/etc/fail2ban/filter.d/security-recipes-caddy-404.conf",
            source,
        )
        self.assertIn(
            "/etc/fail2ban/jail.d/security-recipes-caddy-404.local",
            source,
        )
        self.assertIn("Removing managed Caddy 404 fail2ban filter and jail", source)
        self.assertNotIn("rm -rf /etc/fail2ban", source)

    def test_proxy_uses_primary_and_warm_fallback_health_checks(self) -> None:
        caddy = CADDYFILE.read_text(encoding="utf-8")
        setup = SETUP_SCRIPT.read_text(encoding="utf-8")

        for source in (caddy, setup):
            self.assertIn("SECURITY_RECIPES_PRIMARY_UPSTREAM", source)
            self.assertIn("SECURITY_RECIPES_FALLBACK_UPSTREAM", source)
            self.assertIn("lb_policy first", source)
            self.assertIn("health_uri /", source)
            self.assertIn("fail_duration 30s", source)
        self.assertIn("./docker/caddy:/etc/caddy:ro", COMPOSE_FILE.read_text())
        self.assertIn("ExecStart=/usr/bin/caddy run --environ --resume", setup)
        self.assertIn("ExecReload=", setup)

    def test_deploy_never_recreates_edge_or_runs_project_wide_up(self) -> None:
        source = DEPLOY_SCRIPT.read_text(encoding="utf-8")

        self.assertNotIn("docker compose down", source)
        self.assertNotIn("docker compose stop", source)
        self.assertNotIn("docker compose restart", source)
        self.assertNotIn("systemctl restart caddy", source)
        self.assertNotIn("--remove-orphans", source)
        self.assertNotIn("up -d --pull never --remove-orphans", source)
        self.assertIn("up -d --no-deps --force-recreate --pull never", source)
        self.assertIn("docker compose exec -T", source)
        self.assertIn("caddy reload --force", source)

    def test_candidate_is_verified_by_exact_revision_before_cutover(self) -> None:
        source = DEPLOY_SCRIPT.read_text(encoding="utf-8")
        main = source[source.index("main() {") :]
        dockerfile = DOCKERFILE.read_text(encoding="utf-8")

        self.assertIn("public/.well-known/deploy-revision", dockerfile)
        self.assertIn('org.opencontainers.image.revision="${REVISION}"', dockerfile)
        self.assertIn('CANDIDATE_IMAGE="${SITE_IMAGE_REPOSITORY}:${TARGET}"', main)
        self.assertLess(
            main.index('git reset --hard "${TARGET}"'),
            main.index("ensure_caddy_404_ban"),
        )
        pull = main.index(
            'pull_candidate "${CANDIDATE_SERVICE}" "${CANDIDATE_IMAGE}" "${TARGET}"'
        )
        withdraw = main.index('switch_proxy "${PREVIOUS_ACTIVE}" ""')
        start = main.index(
            'start_candidate "${CANDIDATE_SERVICE}" "${CANDIDATE_IMAGE}" "${TARGET}"'
        )
        cutover = main.index(
            'switch_proxy "${CANDIDATE_SERVICE}" "${CUTOVER_FALLBACK_SERVICE}"'
        )
        verify = main.index('wait_for_proxy_revision "${TARGET}"')
        record = main.index(
            'write_deploy_state \\\n'
            '    "${CANDIDATE_SERVICE}" "${TARGET}"'
        )
        self.assertLess(pull, withdraw)
        self.assertLess(withdraw, start)
        self.assertLess(start, cutover)
        self.assertLess(cutover, verify)
        self.assertLess(verify, record)
        self.assertIn(
            'slot_serves_revision "${ACTIVE_SERVICE}" "${TARGET}"',
            main,
        )
        self.assertIn(
            'proxy_serves_revision "${TARGET}"',
            main,
        )


@unittest.skipIf(os.name == "nt", "deployment integration shims run on Linux CI")
@unittest.skipUnless(BASH and shutil.which("jq"), "bash and jq are required")
class DeployScriptIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.repo = Path(self.tempdir.name)
        self.fake_bin = self.repo / "fake-bin"
        self.fake_bin.mkdir()
        (self.repo / ".git").mkdir()
        (self.repo / "docker" / "caddy").mkdir(parents=True)
        (self.repo / "docker-compose.yml").write_text(
            "services:\n"
            "  security-recipes: {}\n"
            "  security-recipes-green: {}\n"
            "  caddy: {}\n"
            "  traffic-report: {}\n"
            "  mcp-server: {}\n",
            encoding="utf-8",
        )
        shutil.copy2(DEPLOY_SCRIPT, self.repo / "deploy.sh")
        shutil.copy2(CADDYFILE, self.repo / "docker" / "caddy" / "Caddyfile")
        self.host_caddyfile = self.repo / "host-Caddyfile"
        self.host_caddyfile.write_text(
            "# Managed by security-recipes.ai setup script.\n"
            "security-recipes.test {\n"
            "\tencode zstd gzip\n"
            "\treverse_proxy "
            "{$SECURITY_RECIPES_PRIMARY_UPSTREAM:http://127.0.0.1:18080} "
            "{$SECURITY_RECIPES_FALLBACK_UPSTREAM:http://127.0.0.1:18081}\n"
            "}\n",
            encoding="utf-8",
        )
        (self.repo / ".env").write_text(
            "SECURITY_RECIPES_BASE_URL=http://proxy.test/\n"
            "SECURITY_RECIPES_HTTP_PORT=127.0.0.1:18080\n"
            "SECURITY_RECIPES_GREEN_HTTP_PORT=127.0.0.1:18081\n",
            encoding="utf-8",
        )

        self.current_sha = self.repo / "current-sha"
        self.target_sha = self.repo / "target-sha"
        self.command_log = self.repo / "commands.log"
        self.ci_response = self.repo / "ci-response.json"
        self.blue_revision = self.repo / "blue-revision"
        self.green_revision = self.repo / "green-revision"
        self.blue_health = self.repo / "blue-health"
        self.green_health = self.repo / "green-health"
        self.proxy_active = self.repo / "proxy-active"
        self.proxy_fallback = self.repo / "proxy-fallback"
        self.outage = self.repo / "outage"
        self.current_sha.write_text("a" * 40, encoding="utf-8")
        self.target_sha.write_text("b" * 40, encoding="utf-8")
        self.command_log.write_text("", encoding="utf-8")
        self.blue_revision.write_text("a" * 40, encoding="utf-8")
        self.green_revision.write_text("a" * 40, encoding="utf-8")
        self.blue_health.write_text("1", encoding="utf-8")
        self.green_health.write_text("1", encoding="utf-8")
        self.proxy_active.write_text("security-recipes", encoding="utf-8")
        self.proxy_fallback.write_text("security-recipes-green", encoding="utf-8")
        (self.repo / ".git" / "deploy-state").write_text(
            "version=2\n"
            "active_service=security-recipes\n"
            f"deployed_sha={'a' * 40}\n"
            "fallback_service=security-recipes-green\n"
            f"fallback_sha={'a' * 40}\n",
            encoding="utf-8",
        )

        self.write_executable(
            "git",
            r"""#!/usr/bin/env bash
set -eu
printf 'git %s\n' "$*" >> "$FAKE_COMMAND_LOG"
case "${1:-}" in
  remote)
    printf '%s\n' 'git@github.com:stevologic/security-recipes.ai.git'
    ;;
  fetch|checkout|clean)
    exit 0
    ;;
  cat-file)
    exit 0
    ;;
  rev-parse)
    if [[ "${2:-}" == "--short=12" ]]; then
      cut -c1-12 "$FAKE_CURRENT_SHA"
    elif [[ "${2:-}" == "HEAD" ]]; then
      cat "$FAKE_CURRENT_SHA"
    else
      cat "$FAKE_TARGET_SHA"
    fi
    ;;
  reset)
    printf '%s' "${@: -1}" > "$FAKE_CURRENT_SHA"
    ;;
  *)
    printf 'unexpected fake git command: %s\n' "$*" >&2
    exit 2
    ;;
esac
""",
        )
        self.write_executable(
            "docker",
            r"""#!/usr/bin/env bash
set -eu
printf 'docker %s\n' "$*" >> "$FAKE_COMMAND_LOG"

if [[ -n "${FAKE_DOCKER_FAIL_MATCH:-}" && "$*" == *"${FAKE_DOCKER_FAIL_MATCH}"* ]]; then
  exit 1
fi

if [[ "${1:-}" == "inspect" ]]; then
  if [[ "$*" == *"org.opencontainers.image.revision"* ]]; then
    cat "$FAKE_TARGET_SHA"
    exit 0
  fi
  if [[ "$*" == *".Config.Cmd"* && "${@: -1}" == "caddy-id" ]]; then
    printf '%s\n' "${FAKE_CADDY_CMD:-[\"run\",\"--resume\",\"--config\",\"/etc/caddy/Caddyfile\",\"--adapter\",\"caddyfile\"]}"
    exit 0
  fi
  if [[ "$*" == *".State.Health"* && "${@: -1}" == "traffic-report-id" ]]; then
    printf '%s\n' "${FAKE_TRAFFIC_HEALTH:-healthy}"
    exit 0
  fi
  case "${@: -1}" in
    blue-id) printf '%s\n' "${FAKE_BLUE_IMAGE:-legacy-blue}" ;;
    green-id) printf '%s\n' "${FAKE_GREEN_IMAGE:-legacy-green}" ;;
  esac
  exit 0
fi

if [[ "${1:-}" == "image" ]]; then
  exit 0
fi

[[ "${1:-}" == "compose" ]] || exit 0
shift

case "${1:-}" in
  version|config|pull|build)
    exit 0
    ;;
  ps)
    if [[ "$*" == *"traffic-report"* && "${FAKE_TRAFFIC_RUNNING:-true}" != "false" ]]; then
      printf '%s\n' 'traffic-report-id'
    elif [[ "$*" == *"caddy"* && "${FAKE_BUNDLED_CADDY:-true}" != "false" ]]; then
      printf '%s\n' 'caddy-id'
    elif [[ "$*" == *"security-recipes-green"* ]]; then
      printf '%s\n' 'green-id'
    elif [[ "$*" == *"security-recipes"* ]]; then
      printf '%s\n' 'blue-id'
    fi
    exit 0
    ;;
  port)
    case "${2:-}" in
      security-recipes) printf '%s\n' '127.0.0.1:18080' ;;
      security-recipes-green) printf '%s\n' '127.0.0.1:18081' ;;
      *) exit 1 ;;
    esac
    exit 0
    ;;
  exec)
    primary=""
    fallback=""
    for argument in "$@"; do
      case "$argument" in
        SECURITY_RECIPES_PRIMARY_UPSTREAM=*)
          primary="${argument#*=}"
          primary="${primary%:80}"
          ;;
        SECURITY_RECIPES_FALLBACK_UPSTREAM=*)
          fallback="${argument#*=}"
          fallback="${fallback%:80}"
          ;;
      esac
    done
    if [[ -n "$primary" ]]; then
      printf '%s' "$primary" > "$FAKE_PROXY_ACTIVE"
    fi
    printf '%s' "$fallback" > "$FAKE_PROXY_FALLBACK"
    # Model the ambiguous real failure boundary where Caddy accepted the new
    # config but the reload client lost its success response.
    if [[ -n "${FAKE_PROXY_FAIL_PRIMARY:-}" && "$primary" == "$FAKE_PROXY_FAIL_PRIMARY" ]]; then
      exit 1
    fi
    exit 0
    ;;
  up)
    service="${@: -1}"
    case "$service" in
      caddy)
        printf 'edge recreated\n' >> "$FAKE_OUTAGE"
        exit 9
        ;;
      security-recipes|security-recipes-green)
        active="$(cat "$FAKE_PROXY_ACTIVE")"
        fallback="$(cat "$FAKE_PROXY_FALLBACK")"
        if [[ "$service" == "$active" || "$service" == "$fallback" ]]; then
          printf 'recreated routed slot %s\n' "$service" >> "$FAKE_OUTAGE"
          exit 8
        fi
        revision="${SECURITY_RECIPES_IMAGE_REVISION:-unknown}"
        if [[ -n "${FAKE_CANDIDATE_REVISION_OVERRIDE:-}" ]]; then
          revision="$FAKE_CANDIDATE_REVISION_OVERRIDE"
        fi
        if [[ "$service" == "security-recipes" ]]; then
          printf '%s' "$revision" > "$FAKE_BLUE_REVISION"
          printf '%s' "${FAKE_CANDIDATE_HEALTH:-1}" > "$FAKE_BLUE_HEALTH"
        else
          printf '%s' "$revision" > "$FAKE_GREEN_REVISION"
          printf '%s' "${FAKE_CANDIDATE_HEALTH:-1}" > "$FAKE_GREEN_HEALTH"
        fi
        ;;
      traffic-report|mcp-server)
        ;;
      *)
        printf 'unscoped compose up: %s\n' "$*" >> "$FAKE_OUTAGE"
        exit 7
        ;;
    esac
    exit 0
    ;;
esac

exit 0
""",
        )
        self.write_executable(
            "systemctl",
            r"""#!/usr/bin/env bash
set -eu
case "${1:-}" in
  is-active)
    exit 0
    ;;
  show)
    if [[ "$*" == *"ExecStart"* ]]; then
      printf '%s\n' '/usr/bin/caddy run --environ --resume --config /etc/caddy/Caddyfile'
    fi
    exit 0
    ;;
esac
exit 0
""",
        )
        self.write_executable(
            "caddy",
            r"""#!/usr/bin/env bash
set -eu
printf 'caddy %s\n' "$*" >> "$FAKE_COMMAND_LOG"
if [[ "${1:-}" == "reload" ]]; then
  case "${SECURITY_RECIPES_PRIMARY_UPSTREAM:-}" in
    *18080) printf '%s' 'security-recipes' > "$FAKE_PROXY_ACTIVE" ;;
    *18081) printf '%s' 'security-recipes-green' > "$FAKE_PROXY_ACTIVE" ;;
  esac
  case "${SECURITY_RECIPES_FALLBACK_UPSTREAM:-}" in
    *18080) printf '%s' 'security-recipes' > "$FAKE_PROXY_FALLBACK" ;;
    *18081) printf '%s' 'security-recipes-green' > "$FAKE_PROXY_FALLBACK" ;;
    '') printf '%s' '' > "$FAKE_PROXY_FALLBACK" ;;
  esac
fi
exit 0
""",
        )
        self.write_executable(
            "getent",
            r"""#!/usr/bin/env bash
set -eu
if [[ "${1:-}" == "passwd" && "${2:-}" == "caddy" ]]; then
  printf '%s\n' 'caddy:x:999:999:Caddy:/var/lib/caddy:/usr/sbin/nologin'
  exit 0
fi
exit 2
""",
        )
        self.write_executable(
            "install",
            r"""#!/usr/bin/env bash
set -eu
if [[ " $* " == *" -d "* ]]; then
  mkdir -p "${@: -1}"
  exit 0
fi
source_path="${@: -2:1}"
destination="${@: -1}"
cp "$source_path" "$destination"
""",
        )
        self.write_executable(
            "curl",
            r"""#!/usr/bin/env bash
set -eu
printf 'curl %s\n' "$*" >> "$FAKE_COMMAND_LOG"
url="${@: -1}"

for argument in "$@"; do
  if [[ "$argument" == *"/actions/runs" ]]; then
    cat "$FAKE_CI_RESPONSE"
    exit 0
  fi
done

if [[ "$url" == *"/api/cve-catalog/manifest.json"* ]]; then
  updated_at="${FAKE_CATALOG_UPDATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
  printf '{"catalog_updated_at":"%s"}\n' "$updated_at"
  exit 0
fi

serve_slot() {
  health_file="$1"
  revision_file="$2"
  if [[ "$(cat "$health_file")" != "1" ]]; then
    exit 22
  fi
  if [[ "$url" == *"/.well-known/deploy-revision"* ]]; then
    cat "$revision_file"
  fi
  exit 0
}

case "$url" in
  http://127.0.0.1:18080/*)
    serve_slot "$FAKE_BLUE_HEALTH" "$FAKE_BLUE_REVISION"
    ;;
  http://127.0.0.1:18081/*)
    serve_slot "$FAKE_GREEN_HEALTH" "$FAKE_GREEN_REVISION"
    ;;
  http://proxy.test/*)
    active="$(cat "$FAKE_PROXY_ACTIVE")"
    if [[ "$active" == "security-recipes" ]]; then
      health_file="$FAKE_BLUE_HEALTH"
      revision_file="$FAKE_BLUE_REVISION"
    else
      health_file="$FAKE_GREEN_HEALTH"
      revision_file="$FAKE_GREEN_REVISION"
    fi
    if [[ "$(cat "$health_file")" != "1" ]]; then
      exit 22
    fi
    if [[ "$url" == *"/.well-known/deploy-revision"* ]]; then
      if [[ -n "${FAKE_PROXY_REVISION_OVERRIDE:-}" &&
            ( -z "${FAKE_PROXY_OVERRIDE_ACTIVE:-}" ||
              "$active" == "$FAKE_PROXY_OVERRIDE_ACTIVE" ) ]]; then
        printf '%s' "$FAKE_PROXY_REVISION_OVERRIDE"
      else
        cat "$revision_file"
      fi
    fi
    exit 0
    ;;
esac

exit 0
""",
        )

    def write_executable(self, name: str, source: str) -> None:
        path = self.fake_bin / name
        path.write_text(source, encoding="utf-8", newline="\n")
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    def workflow_response(self, conclusion: str = "success") -> None:
        payload = {
            "total_count": 2,
            "workflow_runs": [
                {
                    "id": 1,
                    "run_attempt": 1,
                    "name": "Build",
                    "head_branch": "main",
                    "head_sha": "b" * 40,
                    "event": "push",
                    "status": "completed",
                    "conclusion": conclusion,
                    "html_url": "https://github.test/runs/1",
                },
                {
                    "id": 2,
                    "run_attempt": 1,
                    "name": "CodeQL",
                    "head_branch": "main",
                    "head_sha": "b" * 40,
                    "event": "dynamic",
                    "status": "completed",
                    "conclusion": "success",
                    "html_url": "https://github.test/runs/2",
                },
            ],
        }
        self.ci_response.write_text(json.dumps(payload), encoding="utf-8")

    def run_deploy(self, **extra_environment: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        requested_path = f"{self.fake_bin}{os.pathsep}{environment['PATH']}"
        if os.name == "nt":
            # Git Bash prepends its own /usr/bin entries when translating the
            # inherited Windows PATH. DEPLOY_PATH is the script's documented
            # escape hatch and keeps the fakes ahead of the real curl binary.
            requested_path = subprocess.run(
                [
                    BASH,
                    "-lc",
                    'printf "%s:%s" "$(cygpath -u "$1")" "$PATH"',
                    "bash",
                    str(self.fake_bin),
                ],
                text=True,
                capture_output=True,
                check=True,
                env=environment,
            ).stdout
        environment.update(
            {
                "PATH": requested_path,
                "DEPLOY_PATH": requested_path,
                "DEPLOY_REPO_DIR": str(self.repo),
                "DEPLOY_LOCK_FILE": str(self.repo / "deploy.lock"),
                "DEPLOY_PROXY_MODE": "bundled",
                "DEPLOY_PROXY_HEALTH_URL": "http://proxy.test",
                "DEPLOY_CI_TIMEOUT": "5",
                "DEPLOY_CI_POLL_SECONDS": "1",
                "DEPLOY_CI_SETTLE_SECONDS": "0",
                "DEPLOY_HEALTH_TIMEOUT": "2",
                "DEPLOY_MIN_AVAILABLE_MEMORY_MB": "1",
                "FAKE_COMMAND_LOG": str(self.command_log),
                "FAKE_CURRENT_SHA": str(self.current_sha),
                "FAKE_TARGET_SHA": str(self.target_sha),
                "FAKE_CI_RESPONSE": str(self.ci_response),
                "FAKE_BLUE_REVISION": str(self.blue_revision),
                "FAKE_GREEN_REVISION": str(self.green_revision),
                "FAKE_BLUE_HEALTH": str(self.blue_health),
                "FAKE_GREEN_HEALTH": str(self.green_health),
                "FAKE_PROXY_ACTIVE": str(self.proxy_active),
                "FAKE_PROXY_FALLBACK": str(self.proxy_fallback),
                "FAKE_OUTAGE": str(self.outage),
            }
        )
        environment.update(extra_environment)
        return subprocess.run(
            [BASH, str(self.repo / "deploy.sh")],
            text=True,
            capture_output=True,
            env=environment,
            timeout=20,
        )

    def commands(self) -> list[str]:
        return self.command_log.read_text(encoding="utf-8").splitlines()

    def deploy_state(self) -> dict[str, str]:
        values: dict[str, str] = {}
        for line in (self.repo / ".git" / "deploy-state").read_text().splitlines():
            key, _, value = line.partition("=")
            values[key] = value
        return values

    def assert_no_outage(self) -> None:
        if self.outage.exists():
            self.fail(self.outage.read_text(encoding="utf-8"))

    def test_happy_path_builds_only_inactive_slot_then_switches(self) -> None:
        self.workflow_response()

        result = self.run_deploy()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.blue_revision.read_text(), "a" * 40)
        self.assertEqual(self.green_revision.read_text(), "b" * 40)
        self.assertEqual(self.proxy_active.read_text(), "security-recipes-green")
        self.assertEqual(self.proxy_fallback.read_text(), "security-recipes")
        self.assertEqual(self.current_sha.read_text(), "b" * 40)
        self.assertEqual(self.deploy_state()["active_service"], "security-recipes-green")
        self.assertEqual(self.deploy_state()["deployed_sha"], "b" * 40)
        self.assert_no_outage()
        commands = self.commands()
        traffic_report_up = (
            "docker compose up -d --no-deps --force-recreate --pull never "
            "--wait --wait-timeout 2 traffic-report"
        )
        self.assertEqual(commands.count(traffic_report_up), 1)
        traffic_report_index = commands.index(traffic_report_up)
        pull_index = next(
            index
            for index, command in enumerate(commands)
            if command.startswith(
                "docker pull ghcr.io/stevologic/security-recipes.ai-site:"
            )
        )
        up_index = next(
            index
            for index, command in enumerate(commands)
            if "compose up " in command and command.endswith("security-recipes-green")
        )
        switch_index = next(
            index
            for index, command in enumerate(commands)
            if "PRIMARY_UPSTREAM=security-recipes-green:80" in command
        )
        self.assertLess(traffic_report_index, pull_index)
        self.assertLess(pull_index, up_index)
        self.assertLess(up_index, switch_index)
        self.assertFalse(any(command.endswith(" caddy") and "compose up" in command for command in commands))

    def test_traffic_report_failure_stops_before_site_mutation(self) -> None:
        self.workflow_response()

        result = self.run_deploy(
            FAKE_DOCKER_FAIL_MATCH=(
                "compose up -d --no-deps --force-recreate --pull never "
                "--wait --wait-timeout 2 traffic-report"
            )
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.blue_revision.read_text(), "a" * 40)
        self.assertEqual(self.green_revision.read_text(), "a" * 40)
        self.assertEqual(self.current_sha.read_text(), "a" * 40)
        self.assertFalse(
            any(
                "compose build --pull security-recipes" in command
                for command in self.commands()
            )
        )
        self.assert_no_outage()

    def test_host_caddy_is_migrated_and_runs_the_traffic_report(self) -> None:
        self.workflow_response()
        host_log_dir = self.repo / "host-caddy-logs"

        result = self.run_deploy(
            DEPLOY_PROXY_MODE="host",
            DEPLOY_HOST_CADDYFILE=str(self.host_caddyfile),
            DEPLOY_HOST_CADDY_LOG_DIR=str(host_log_dir),
            FAKE_BUNDLED_CADDY="false",
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            f"output file {host_log_dir}/access.log",
            self.host_caddyfile.read_text(),
        )
        self.assertIn(
            f"SECURITY_RECIPES_TRAFFIC_LOGS_SOURCE={host_log_dir}",
            (self.repo / ".env").read_text(),
        )
        self.assertTrue(
            any(
                "compose up -d --no-deps --force-recreate --pull never" in command
                and command.endswith("traffic-report")
                for command in self.commands()
            )
        )
        self.assert_no_outage()

    def test_next_release_alternates_into_blue_without_touching_active_green(self) -> None:
        self.workflow_response()
        first = self.run_deploy()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)

        self.target_sha.write_text("c" * 40)
        payload = json.loads(self.ci_response.read_text())
        for run in payload["workflow_runs"]:
            run["head_sha"] = "c" * 40
        self.ci_response.write_text(json.dumps(payload))
        self.command_log.write_text("")

        second = self.run_deploy()

        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(self.blue_revision.read_text(), "c" * 40)
        self.assertEqual(self.green_revision.read_text(), "b" * 40)
        self.assertEqual(self.proxy_active.read_text(), "security-recipes")
        self.assertEqual(self.proxy_fallback.read_text(), "security-recipes-green")
        self.assert_no_outage()

    def test_first_run_migrates_a_single_blue_slot_without_assuming_head_is_live(self) -> None:
        (self.repo / ".git" / "deploy-state").unlink()
        self.green_health.write_text("0")
        self.workflow_response()

        result = self.run_deploy()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.blue_revision.read_text(), "a" * 40)
        self.assertEqual(self.green_revision.read_text(), "b" * 40)
        self.assertEqual(self.proxy_active.read_text(), "security-recipes-green")
        self.assertEqual(self.proxy_fallback.read_text(), "security-recipes")
        self.assertEqual(self.deploy_state()["deployed_sha"], "b" * 40)
        self.assert_no_outage()

    def test_missing_state_recovers_the_revision_already_served_by_caddy(self) -> None:
        (self.repo / ".git" / "deploy-state").unlink()
        self.green_revision.write_text("b" * 40)
        self.proxy_active.write_text("security-recipes-green")
        self.proxy_fallback.write_text("security-recipes")

        result = self.run_deploy()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.proxy_active.read_text(), "security-recipes-green")
        self.assertEqual(self.proxy_fallback.read_text(), "security-recipes")
        self.assertEqual(self.deploy_state()["active_service"], "security-recipes-green")
        self.assertEqual(self.deploy_state()["deployed_sha"], "b" * 40)
        self.assertEqual(self.deploy_state()["fallback_service"], "security-recipes")
        self.assertEqual(self.deploy_state()["fallback_sha"], "a" * 40)
        self.assertFalse(any("compose build" in command for command in self.commands()))
        self.assert_no_outage()

    def test_missing_state_fails_closed_when_public_revision_matches_no_slot(self) -> None:
        (self.repo / ".git" / "deploy-state").unlink()
        self.green_revision.write_text("b" * 40)
        self.proxy_active.write_text("security-recipes-green")
        self.proxy_fallback.write_text("security-recipes")

        result = self.run_deploy(FAKE_PROXY_REVISION_OVERRIDE="c" * 40)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("neither blue/green slot serves that exact revision", result.stdout)
        self.assertEqual(self.proxy_active.read_text(), "security-recipes-green")
        self.assertEqual(self.proxy_fallback.read_text(), "security-recipes")
        self.assertFalse(any("compose exec" in command for command in self.commands()))
        self.assertFalse(any("compose build" in command for command in self.commands()))
        self.assertFalse(any("compose up" in command for command in self.commands()))
        self.assert_no_outage()

    def test_unchanged_release_skips_ci_build_and_compose_up(self) -> None:
        self.target_sha.write_text("a" * 40)

        result = self.run_deploy()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        commands = self.commands()
        self.assertFalse(any("/actions/runs" in command for command in commands))
        self.assertFalse(any("compose build" in command for command in commands))
        self.assertFalse(any("compose up" in command for command in commands))
        self.assertFalse(any("compose exec" in command for command in commands))
        self.assert_no_outage()

    def test_unchanged_release_repairs_a_missing_traffic_report(self) -> None:
        self.target_sha.write_text("a" * 40)

        result = self.run_deploy(FAKE_TRAFFIC_RUNNING="false")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        commands = self.commands()
        self.assertEqual(
            sum(
                "compose up -d --no-deps --force-recreate --pull never" in command
                and command.endswith("traffic-report")
                for command in commands
            ),
            1,
        )
        self.assertFalse(
            any(
                "compose build --pull security-recipes" in command
                for command in commands
            )
        )
        self.assert_no_outage()

    def test_unchanged_healthy_release_sends_success_heartbeat(self) -> None:
        self.target_sha.write_text("a" * 40)

        result = self.run_deploy(
            DEPLOY_SUCCESS_HEARTBEAT_URL="https://heartbeat.test/private-id"
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(
            any(
                "curl --config - " in command
                for command in self.commands()
            )
        )
        self.assertFalse(
            any(
                "heartbeat.test/private-id" in command
                for command in self.commands()
            )
        )
        self.assertIn("Success heartbeat delivered", result.stdout)

    def test_stale_live_catalog_fails_without_success_heartbeat(self) -> None:
        self.target_sha.write_text("a" * 40)

        result = self.run_deploy(
            DEPLOY_SUCCESS_HEARTBEAT_URL="https://heartbeat.test/private-id",
            FAKE_CATALOG_UPDATED_AT="2000-01-01T00:00:00Z",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("live CVE catalog is stale", result.stdout)
        self.assertFalse(
            any(
                "curl --config - " in command
                for command in self.commands()
            )
        )
        self.assert_no_outage()

    def test_previously_failed_target_remains_a_visible_service_failure(self) -> None:
        (self.repo / ".git" / "deploy-failed-sha").write_text("b" * 40)

        result = self.run_deploy()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("remains undeployed", result.stdout)
        self.assertFalse(any("/actions/runs" in command for command in self.commands()))
        self.assertFalse(any("compose build" in command for command in self.commands()))
        self.assert_no_outage()

    def test_low_disk_cleanup_preserves_slots_and_stops_before_build(self) -> None:
        self.write_executable(
            "df",
            r"""#!/usr/bin/env bash
printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
printf 'fake 10000000 9999000 %s 99%% /\n' "${FAKE_FREE_KB:-1024}"
""",
        )
        self.workflow_response()

        result = self.run_deploy(FAKE_FREE_KB="1024")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Insufficient safe disk headroom", result.stdout)
        self.assertTrue(
            any("docker builder prune --force" in command for command in self.commands())
        )
        self.assertFalse(any("compose build" in command for command in self.commands()))
        self.assertFalse(any("compose up" in command for command in self.commands()))
        self.assert_no_outage()

    def test_low_memory_stops_before_any_build_or_cutover(self) -> None:
        self.workflow_response()

        result = self.run_deploy(
            DEPLOY_MIN_AVAILABLE_MEMORY_MB="999999999"
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Insufficient safe memory/swap headroom", result.stdout)
        self.assertFalse(any("compose build" in command for command in self.commands()))
        self.assertFalse(any("compose up" in command for command in self.commands()))
        self.assertFalse(any("compose exec" in command for command in self.commands()))
        self.assert_no_outage()

    def test_unverified_recorded_fallback_is_withdrawn_before_unchanged_exit(self) -> None:
        self.target_sha.write_text("a" * 40)
        self.green_revision.write_text("wrong")

        result = self.run_deploy()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.proxy_active.read_text(), "security-recipes")
        self.assertEqual(self.proxy_fallback.read_text(), "")
        self.assertEqual(self.deploy_state()["fallback_service"], "")
        self.assertEqual(self.deploy_state()["fallback_sha"], "")
        self.assertFalse(any("compose build" in command for command in self.commands()))
        self.assert_no_outage()

    def test_non_resuming_caddy_is_rejected_before_deployment(self) -> None:
        result = self.run_deploy(
            FAKE_CADDY_CMD='["run","--config","/etc/caddy/Caddyfile"]'
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not restart-durable", result.stdout)
        self.assertFalse(any("compose build" in command for command in self.commands()))
        self.assert_no_outage()

    def test_failed_ci_stops_before_candidate_mutation(self) -> None:
        self.workflow_response("failure")

        result = self.run_deploy()

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.blue_revision.read_text(), "a" * 40)
        self.assertEqual(self.green_revision.read_text(), "a" * 40)
        self.assertFalse(any("compose up" in command for command in self.commands()))
        self.assert_no_outage()

    def test_required_build_must_conclude_successfully(self) -> None:
        self.workflow_response("neutral")

        result = self.run_deploy()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Required workflow Build did not conclude successfully", result.stdout)
        self.assertFalse(any("compose up" in command for command in self.commands()))

    def test_incomplete_workflow_page_fails_closed(self) -> None:
        self.workflow_response()
        payload = json.loads(self.ci_response.read_text())
        payload["total_count"] = 101
        self.ci_response.write_text(json.dumps(payload))

        result = self.run_deploy()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("refusing an incomplete CI view", result.stdout)
        self.assertFalse(any("compose up" in command for command in self.commands()))

    def test_wrong_commit_workflow_response_fails_closed(self) -> None:
        self.workflow_response()
        payload = json.loads(self.ci_response.read_text())
        payload["workflow_runs"][0]["head_sha"] = "c" * 40
        self.ci_response.write_text(json.dumps(payload))

        result = self.run_deploy()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("returned workflow runs outside", result.stdout)
        self.assertFalse(any("compose up" in command for command in self.commands()))

    def test_candidate_pull_failure_keeps_blue_active(self) -> None:
        self.workflow_response()

        result = self.run_deploy(
            FAKE_DOCKER_FAIL_MATCH="pull ghcr.io/stevologic/security-recipes.ai-site:"
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.proxy_active.read_text(), "security-recipes")
        self.assertEqual(self.proxy_fallback.read_text(), "security-recipes-green")
        self.assertEqual(self.blue_revision.read_text(), "a" * 40)
        self.assertEqual(self.green_revision.read_text(), "a" * 40)
        self.assertEqual(self.current_sha.read_text(), "a" * 40)
        self.assert_no_outage()

    def test_bad_candidate_revision_cannot_be_masked_by_live_public_site(self) -> None:
        self.workflow_response()

        result = self.run_deploy(FAKE_CANDIDATE_REVISION_OVERRIDE="wrong")

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.proxy_active.read_text(), "security-recipes")
        self.assertEqual(self.proxy_fallback.read_text(), "")
        self.assertEqual(self.blue_revision.read_text(), "a" * 40)
        self.assertEqual(self.deploy_state()["active_service"], "security-recipes")
        self.assert_no_outage()

    def test_ambiguous_proxy_reload_failure_restores_previous_route(self) -> None:
        self.workflow_response()

        result = self.run_deploy(
            FAKE_PROXY_FAIL_PRIMARY="security-recipes-green"
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.proxy_active.read_text(), "security-recipes")
        self.assertEqual(self.proxy_fallback.read_text(), "")
        self.assertEqual(self.deploy_state()["active_service"], "security-recipes")
        self.assert_no_outage()

    def test_post_switch_verification_failure_routes_back_to_blue(self) -> None:
        self.workflow_response()

        result = self.run_deploy(
            FAKE_PROXY_REVISION_OVERRIDE="wrong",
            FAKE_PROXY_OVERRIDE_ACTIVE="security-recipes-green",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.proxy_active.read_text(), "security-recipes")
        self.assertEqual(self.proxy_fallback.read_text(), "")
        self.assertEqual(self.deploy_state()["active_service"], "security-recipes")
        self.assertEqual(self.current_sha.read_text(), "a" * 40)
        self.assert_no_outage()


if __name__ == "__main__":
    unittest.main()
