from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SITE_DOCKERFILE = ROOT / "Dockerfile"
DOCKERFILE = ROOT / "Dockerfile.mcp-server"
BUILD_WORKFLOW = ROOT / ".github" / "workflows" / "build.yml"

CANONICAL = (
    '<link rel="canonical" '
    'href="https://security-recipes.ai/cve/CVE-2024-3400/">'
)
ROBOTS = (
    '<meta name="robots" content="index,follow,max-image-preview:large,'
    'max-snippet:-1,max-video-preview:-1">'
)
IDENTITY = 'data-cve-id="CVE-2024-3400"'
ARTICLE_TYPE = '"@type":"Article"'
ARTICLE_SEMANTICS = '"additionalType":"https://schema.org/TechArticle"'


class MCPImageContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.site_dockerfile = SITE_DOCKERFILE.read_text(encoding="utf-8")
        cls.dockerfile = DOCKERFILE.read_text(encoding="utf-8")
        cls.workflow = BUILD_WORKFLOW.read_text(encoding="utf-8")

    def test_site_image_removes_the_stock_nginx_error_page(self) -> None:
        self.assertIn(
            "rm -f /etc/nginx/conf.d/default.conf /usr/share/nginx/html/50x.html",
            self.site_dockerfile,
        )

    def test_container_healthcheck_requires_the_complete_landing_contract(self) -> None:
        healthcheck = self.dockerfile.split("HEALTHCHECK", maxsplit=1)[1]

        self.assertIn(
            "RECIPES_PUBLIC_SITE_BASE_URL=https://security-recipes.ai/",
            self.dockerfile,
        )
        self.assertIn("RECIPES_PUBLIC_SITE_BASE_URL", healthcheck)
        self.assertIn("rstrip('/')", healthcheck)
        self.assertIn("{base}/cve/CVE-2024-3400/", healthcheck)
        for marker in (ROBOTS, IDENTITY, ARTICLE_TYPE, ARTICLE_SEMANTICS):
            with self.subTest(marker=marker):
                self.assertIn(marker.replace('"', '\\"'), healthcheck)

    def test_container_healthcheck_reports_readiness_within_deploy_window(self) -> None:
        healthcheck = self.dockerfile.split("HEALTHCHECK", maxsplit=1)[1]

        self.assertIn("--interval=10s", healthcheck)
        self.assertIn("--timeout=8s", healthcheck)
        self.assertIn("--start-period=30s", healthcheck)
        self.assertIn("--retries=20", healthcheck)

    def test_production_image_requires_the_manifest_pinned_search_database(self) -> None:
        self.assertIn(
            "RECIPES_MCP_CVE_SEARCH_DB_PATH=/app/runtime/cve-search.sqlite3",
            self.dockerfile,
        )
        self.assertIn(
            "RECIPES_MCP_REQUIRE_CVE_SEARCH_DATABASE=true",
            self.dockerfile,
        )
        self.assertIn(
            "--metadata-output /app/runtime/cve-search.sqlite3.metadata.json",
            self.dockerfile,
        )

    def test_build_starts_image_and_waits_for_docker_health(self) -> None:
        self.assertIn(
            'mcp_container="$(docker run --detach --name "${mcp_name}"',
            self.workflow,
        )
        self.assertIn("--publish 127.0.0.1::80", self.workflow)
        self.assertIn(
            '--env "RECIPES_PUBLIC_SITE_BASE_URL=${SECURITY_RECIPES_BASE_URL}"',
            self.workflow,
        )
        self.assertIn(".State.Health.Status", self.workflow)
        self.assertIn('if [ "${mcp_health}" != "healthy" ]', self.workflow)
        self.assertIn(
            'docker rm --force "${site_name}" "${mcp_name}"',
            self.workflow,
        )
        self.assertIn('docker network rm "${smoke_network}"', self.workflow)

    def test_build_inspects_the_running_container_response(self) -> None:
        self.assertIn(
            '"http://127.0.0.1:${mcp_port}/cve/CVE-2024-3400/"',
            self.workflow,
        )
        self.assertIn(
            'expected_canonical="${SECURITY_RECIPES_BASE_URL%/}/cve/CVE-2024-3400/"',
            self.workflow,
        )
        self.assertIn(
            'href=\\"${expected_canonical}\\"',
            self.workflow,
        )
        for marker in (ROBOTS, IDENTITY, ARTICLE_TYPE, ARTICLE_SEMANTICS):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.workflow)

    def test_build_exercises_revision_pinned_sqlite_search_through_site(self) -> None:
        self.assertIn(
            "/api/cve-catalog/search?q=remote%20code%20execution&revision=${catalog_revision}&limit=5",
            self.workflow,
        )
        self.assertIn('payload["schema_version"] == 1', self.workflow)
        self.assertIn('payload["revision"] == sys.argv[2]', self.workflow)
        self.assertIn('1 <= len(payload["results"]) <= 5', self.workflow)
        self.assertIn("X-Robots-Tag: noindex", self.workflow)
        self.assertIn(
            "^X-CVE-Search-Backend:[[:space:]]*sqlite[[:space:]]*$",
            self.workflow,
        )
        mcp_healthy = self.workflow.index('if [ "${mcp_health}" != "healthy" ]')
        broad_search = self.workflow.index("/api/cve-catalog/search?q=remote%20code%20execution")
        self.assertLess(mcp_healthy, broad_search)

    def test_build_exercises_revision_pinned_exact_record_api_through_site(self) -> None:
        self.assertIn(
            "/api/cve-catalog/records/CVE-2024-3400?revision=${catalog_revision}",
            self.workflow,
        )
        self.assertIn('payload["record"]["cve"] == "CVE-2024-3400"', self.workflow)
        self.assertIn(
            "^X-CVE-Record-Backend:[[:space:]]*verified-shard[[:space:]]*$",
            self.workflow,
        )
        mcp_healthy = self.workflow.index('if [ "${mcp_health}" != "healthy" ]')
        record_lookup = self.workflow.index(
            "/api/cve-catalog/records/CVE-2024-3400?revision=${catalog_revision}"
        )
        self.assertLess(mcp_healthy, record_lookup)

    def test_build_validates_the_rendered_site_config_and_static_cve_offline(self) -> None:
        self.assertIn('docker network create "${smoke_network}"', self.workflow)
        self.assertIn('--env "MCP_UPSTREAM=${mcp_name}"', self.workflow)
        self.assertIn('"${SITE_IMAGE}" nginx -t', self.workflow)
        self.assertIn(
            'site_container="$(docker run --detach --name "${site_name}"',
            self.workflow,
        )
        self.assertIn(
            '"http://127.0.0.1:${site_port}/cve/CVE-2024-3400/"',
            self.workflow,
        )
        self.assertIn(
            "Qualified CVE unexpectedly reached the runtime fallback.",
            self.workflow,
        )
        static_fetch = self.workflow.index(
            '"http://127.0.0.1:${site_port}/cve/CVE-2024-3400/"'
        )
        mcp_start = self.workflow.index(
            'mcp_container="$(docker run --detach --name "${mcp_name}"'
        )
        self.assertLess(static_fetch, mcp_start)

    def test_build_runs_the_complete_seo_gate_against_the_no_git_image(self) -> None:
        self.assertIn(
            'docker cp "${site_container}:/usr/share/nginx/html/." "${image_output}/"',
            self.workflow,
        )
        self.assertIn(
            'SITE_OUTPUT_DIR="${image_output}" node scripts/check_site_performance.js',
            self.workflow,
        )
        image_gate = self.workflow.index(
            'SITE_OUTPUT_DIR="${image_output}" node scripts/check_site_performance.js'
        )
        static_fetch = self.workflow.index(
            '"http://127.0.0.1:${site_port}/cve/CVE-2024-3400/"'
        )
        self.assertLess(image_gate, static_fetch)

    def test_build_exercises_runtime_fallback_and_case_canonicalization(self) -> None:
        self.assertIn('nonqualified_cve="$(python3 - <<\'PY\'', self.workflow)
        self.assertIn('catalog_root / "search-indexable.json"', self.workflow)
        self.assertIn(
            '"http://127.0.0.1:${site_port}/cve/${nonqualified_cve}/"',
            self.workflow,
        )
        self.assertIn(
            '<meta name="robots" content="noindex,follow">',
            self.workflow,
        )
        self.assertIn("grep -Eqi '^X-CVE-Cache:'", self.workflow)
        self.assertIn(
            '"http://127.0.0.1:${site_port}/cve/cve-2024-3400/"',
            self.workflow,
        )
        self.assertIn('if [ "${lowercase_status}" != "308" ]', self.workflow)
        self.assertIn(
            'grep -Fqi "location: ${expected_canonical}"',
            self.workflow,
        )
        mcp_healthy = self.workflow.index(
            'if [ "${mcp_health}" != "healthy" ]'
        )
        runtime_fetch = self.workflow.index(
            '"http://127.0.0.1:${site_port}/cve/${nonqualified_cve}/"'
        )
        self.assertLess(mcp_healthy, runtime_fetch)


if __name__ == "__main__":
    unittest.main()
