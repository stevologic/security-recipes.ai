from __future__ import annotations

import contextlib
import io
import json
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.security_recipes_remediation.suite import (
    Finding,
    build_remediation_packet,
    load_domain_registry,
    redact_sensitive_data,
    write_packet,
)
from tools.security_recipes_remediation.webapp import (
    MAX_DASHBOARD_REQUEST_BYTES,
    build_dashboard_plan,
    default_dashboard_config,
    load_dashboard_config,
    save_dashboard_config,
    sanitize_dashboard_config,
)


class RemediationPacketRedactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = load_domain_registry()
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        self.root = Path(self.temp_directory.name)
        self.recipe_source = self.root / "recipes.json"
        self.recipe_source.write_text(
            json.dumps(
                [
                    {
                        "title": "Rotate an exposed credential",
                        "summary": "Invalidate and replace a leaked credential.",
                        "url": "https://security-recipes.ai/recipes/rotate-credential/",
                        "tags": ["credential", "rotation"],
                    }
                ]
            ),
            encoding="utf-8",
        )

    @staticmethod
    def _finding() -> Finding:
        return Finding(
            finding_id="finding-42",
            title="Credential found in an Authorization: Bearer top-secret-bearer-value header",
            source="scanner",
            severity="high",
            asset="service-api",
            location="config/service.env:8",
            description=(
                'Keep this useful evidence; password=hunter2 and embedded "api_key": '
                r'"short-secret" plus api_token="escaped-prefix\"escaped-suffix" '
                "must not leave the planner."
            ),
            raw={
                "api_key": "sk-live-1234567890abcdefghijkl",
                "clientSecret": "camel-client-secret",
                "userPassword": "camel-user-password",
                "AWS_SECRET_ACCESS_KEY": "aws-secret-access-key",
                "nested": {
                    "client_secret": "client-secret-value",
                    "evidence": "postgres://analyst:database-password@db.internal/security",
                    "safe_metadata": "retain this",
                },
                "contains_secret": "string-metadata-secret",
                "has_secret": True,
                "rule": "credential-in-source",
            },
        )

    def test_packet_redacts_secrets_but_preserves_useful_metadata(self) -> None:
        packet = build_remediation_packet(
            domain_key="recommend",
            findings=[self._finding()],
            registry=self.registry,
            recipe_source=self.recipe_source,
            llm_mode="prompt",
        )
        encoded = json.dumps(packet, sort_keys=True)

        for secret in (
            "top-secret-bearer-value",
            "hunter2",
            "short-secret",
            "escaped-prefix",
            "escaped-suffix",
            "sk-live-1234567890abcdefghijkl",
            "camel-client-secret",
            "camel-user-password",
            "aws-secret-access-key",
            "string-metadata-secret",
            "client-secret-value",
            "database-password",
        ):
            self.assertNotIn(secret, encoded)
        self.assertIn("[REDACTED]", encoded)
        self.assertIn("Keep this useful evidence", encoded)
        self.assertEqual(packet["findings"][0]["raw"]["nested"]["safe_metadata"], "retain this")
        self.assertTrue(packet["findings"][0]["raw"]["has_secret"])
        self.assertEqual(packet["findings"][0]["raw"]["contains_secret"], "[REDACTED]")
        self.assertEqual(packet["findings"][0]["raw"]["rule"], "credential-in-source")

    def test_write_packet_redacts_untrusted_callers_at_stdout_and_file_boundaries(self) -> None:
        unsafe_packet = {
            "password": "direct-password",
            "clientSecret": "direct-camel-secret",
            "AWS_SECRET_ACCESS_KEY": "direct-aws-secret",
            "contains_secret": "direct-metadata-secret",
            "message": "Cookie: session=browser-cookie\nordinary diagnostic",
            "private_key": "-----BEGIN PRIVATE KEY-----\nprivate-material\n-----END PRIVATE KEY-----",
            "safe": "preserve me",
        }

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            write_packet(unsafe_packet, None)
        stdout_text = stdout.getvalue()

        output_path = self.root / "packet.json"
        write_packet(unsafe_packet, output_path)
        file_text = output_path.read_text(encoding="utf-8")

        for output in (stdout_text, file_text):
            self.assertNotIn("direct-password", output)
            self.assertNotIn("direct-camel-secret", output)
            self.assertNotIn("direct-aws-secret", output)
            self.assertNotIn("direct-metadata-secret", output)
            self.assertNotIn("browser-cookie", output)
            self.assertNotIn("private-material", output)
            self.assertIn("[REDACTED]", output)
            self.assertIn("preserve me", output)

    def test_redaction_is_idempotent(self) -> None:
        original = "Authorization: Bearer repeated-secret"
        redacted = redact_sensitive_data(original)
        self.assertEqual(redacted, "Authorization: [REDACTED]")
        self.assertEqual(redact_sensitive_data(redacted), redacted)

        assignment = "DB_PASSWORD=database-secret"
        redacted_assignment = redact_sensitive_data(assignment)
        self.assertEqual(redacted_assignment, "DB_PASSWORD=[REDACTED]")
        self.assertEqual(redact_sensitive_data(redacted_assignment), redacted_assignment)

    def test_free_text_environment_assignments_are_redacted(self) -> None:
        original = (
            "DB_PASSWORD=db-password\n"
            "OPENAI_API_KEY=openai-value\n"
            "GITHUB_TOKEN=github-value\n"
            "AWS_SECRET_ACCESS_KEY=aws-value\n"
            "userPassword=camel-value\n"
            "serviceAccountKey=service-value\n"
            "SAFE_SETTING=preserved"
        )

        redacted = str(redact_sensitive_data(original))

        for secret in (
            "db-password",
            "openai-value",
            "github-value",
            "aws-value",
            "camel-value",
            "service-value",
        ):
            self.assertNotIn(secret, redacted)
        self.assertIn("SAFE_SETTING=preserved", redacted)
        self.assertEqual(redact_sensitive_data(redacted), redacted)

    def test_redacted_finding_cannot_select_recipe_containing_its_secret(self) -> None:
        secret = "crossboundarysecret"
        secret_recipe_source = self.root / "secret-recipes.json"
        secret_recipe_source.write_text(
            json.dumps([{"title": secret, "url": "https://example.invalid/secret"}]),
            encoding="utf-8",
        )
        finding = Finding(
            finding_id="finding-recipe-collision",
            title="Unclassified scanner output",
            source="scanner",
            severity="unknown",
            asset="asset",
            location="location",
            description="Review the structured evidence.",
            raw={"clientSecret": secret},
        )

        packet = build_remediation_packet(
            domain_key="recommend",
            findings=[finding],
            registry=self.registry,
            recipe_source=secret_recipe_source,
            llm_mode="prompt",
        )

        self.assertNotIn(secret, json.dumps(packet, sort_keys=True))
        self.assertEqual(packet["recipe_import"]["matches"], [])

    def test_packet_redacts_adjacent_structured_and_embedded_credential_forms(self) -> None:
        secrets = {
            "encryptionKey": "structured-encryption-secret",
            "secretValue": "structured-secret-value",
            "accountKey": "structured-account-secret",
            "masterKey": "structured-master-secret",
            "privateKeyData": "structured-private-secret",
            "credentialsJson": "structured-credentials-secret",
            "dbPwd": "structured-db-pwd-secret",
            "dbPasswd": "structured-db-passwd-secret",
            "DATABASE_DSN": "structured-database-dsn-secret",
            "serviceAccountJson": "structured-service-account-json-secret",
            "PGPASSWORD": "postgres-compact-secret",
            "DBPASS": "database-compact-pass-secret",
            "AWSSECRETACCESSKEY": "aws-compact-secret",
            "SERVICEACCOUNTJSON": "service-account-compact-secret",
            "CREDENTIALSJSON": "credentials-compact-secret",
            "BASIC_AUTH": "basic-auth-secret",
            "BEARER": "bearer-field-secret",
            "PASSWORD_HASH": "password-hash-secret",
            "PRIVATE_KEY_PEM": "private-key-pem-secret",
            "API_KEY_VALUE": "api-key-value-secret",
        }
        benign_metadata = {
            "rule_key": "preserved-rule-key",
            "cache_key": "preserved-cache-key",
            "public_key_algorithm": "preserved-public-key-algorithm",
            "auth_method": "preserved-auth-method",
            "pass_count": "preserved-pass-count",
            "session_type": "preserved-session-type",
            "token_count": "preserved-token-count",
        }
        finding = Finding(
            finding_id="finding-adjacent-forms",
            title="Scanner payload",
            source="scanner",
            severity="high",
            asset="service",
            location="request.log",
            description=(
                "password: correct horse battery staple\n"
                "Authorization=Basic Zm9vOmJhcg==\n"
                r'payload={\"clientSecret\":\"escaped-json-secret\"}'
                "\npassword: prefix,comma-secret-suffix"
                "\npassword: correct horse=staple"
                "\nDB_PASSWORD=[REDACTED] marker-residual-secret"
                '\npayload={"client\\u0053ecret":"unicode-hidden-secret"}'
                "\n"
                r'payload={\"client\u0053ecret\":\"escaped-unicode-secret\"}'
                "\npassword: | # scanner comment\n  yaml-comment-secret"
                "\npassword: |2-\n  yaml-order-secret\nnext: safe"
            ),
            raw={**secrets, **benign_metadata},
        )

        packet = build_remediation_packet(
            domain_key="recommend",
            findings=[finding],
            registry=self.registry,
            recipe_source=self.recipe_source,
            llm_mode="prompt",
        )
        encoded = json.dumps(packet, sort_keys=True)

        for secret in (
            *secrets.values(),
            "correct horse battery staple",
            "Basic Zm9vOmJhcg==",
            "escaped-json-secret",
            "comma-secret-suffix",
            "horse=staple",
            "marker-residual-secret",
            "unicode-hidden-secret",
            "escaped-unicode-secret",
            "yaml-comment-secret",
            "yaml-order-secret",
        ):
            self.assertNotIn(secret, encoded)
        for key in (
            "encryptionKey",
            "secretValue",
            "accountKey",
            "masterKey",
            "privateKeyData",
            "credentialsJson",
            "dbPwd",
            "dbPasswd",
            "DATABASE_DSN",
            "serviceAccountJson",
            "PGPASSWORD",
            "DBPASS",
            "AWSSECRETACCESSKEY",
            "SERVICEACCOUNTJSON",
            "CREDENTIALSJSON",
            "BASIC_AUTH",
            "BEARER",
            "PASSWORD_HASH",
            "PRIVATE_KEY_PEM",
            "API_KEY_VALUE",
        ):
            self.assertEqual(packet["findings"][0]["raw"][key], "[REDACTED]")
        for key in (
            "rule_key",
            "cache_key",
            "public_key_algorithm",
            "auth_method",
            "pass_count",
            "session_type",
            "token_count",
        ):
            self.assertEqual(packet["findings"][0]["raw"][key], benign_metadata[key])

    def test_dashboard_plan_redacts_response_and_does_not_persist_finding_input(self) -> None:
        finding_input = json.dumps(
            {
                "id": "finding-dashboard",
                "title": "Dashboard finding",
                "description": "Authorization: Bearer dashboard-secret",
                "api_token": "dashboard-api-token",
                "clientSecret": "dashboard-camel-secret",
                "AWS_SECRET_ACCESS_KEY": "dashboard-aws-secret",
            }
        )
        payload = {
            "domain": "recommend",
            "recipes_source": str(self.recipe_source),
            "finding_input": finding_input,
            "llm_mode": "prompt",
        }
        response = build_dashboard_plan(payload, registry=self.registry)
        encoded = json.dumps(response, sort_keys=True)
        self.assertNotIn("dashboard-secret", encoded)
        self.assertNotIn("dashboard-api-token", encoded)
        self.assertNotIn("dashboard-camel-secret", encoded)
        self.assertNotIn("dashboard-aws-secret", encoded)
        self.assertIn("[REDACTED]", encoded)

        config = sanitize_dashboard_config(payload)
        save_dashboard_config(self.root, config)
        stored_text = (self.root / "dashboard-config.json").read_text(encoding="utf-8")
        self.assertNotIn("dashboard-secret", stored_text)
        self.assertNotIn("dashboard-api-token", stored_text)
        self.assertEqual(load_dashboard_config(self.root)["finding_input"], "")

    def test_dashboard_llm_defaults_target_xai(self) -> None:
        config = default_dashboard_config()
        llm = config["llm_config"]
        self.assertEqual(llm["endpoint"], "https://api.x.ai/v1/chat/completions")
        self.assertEqual(llm["model"], "grok-4.6")
        self.assertEqual(llm["api_key_env"], "XAI_API_KEY")
        sanitized = sanitize_dashboard_config({})
        self.assertEqual(sanitized["llm_config"]["api_key_env"], "XAI_API_KEY")

    def test_legacy_dashboard_state_is_scrubbed_on_first_load(self) -> None:
        legacy_marker = "legacy-dashboard-marker"
        legacy_config = sanitize_dashboard_config(
            {
                "domain": "recommend",
                "recipes_source": str(self.recipe_source),
                "finding_input": json.dumps(
                    {"title": f"Legacy finding {legacy_marker}"}
                ),
            }
        )
        state_path = self.root / "dashboard-config.json"
        state_path.write_text(
            json.dumps(legacy_config, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.assertIn(legacy_marker, state_path.read_text(encoding="utf-8"))

        loaded = load_dashboard_config(self.root)

        self.assertEqual(loaded["finding_input"], "")
        scrubbed = state_path.read_text(encoding="utf-8")
        self.assertNotIn(legacy_marker, scrubbed)
        self.assertEqual(json.loads(scrubbed)["finding_input"], "")

    def test_corrupt_legacy_dashboard_state_is_replaced(self) -> None:
        legacy_marker = "corrupt-legacy-dashboard-marker"
        state_path = self.root / "dashboard-config.json"
        state_path.write_text(
            '{"finding_input": "'
            + legacy_marker
            + '", "domain": invalid trailing data',
            encoding="utf-8",
        )

        loaded = load_dashboard_config(self.root)

        self.assertEqual(loaded["finding_input"], "")
        scrubbed = state_path.read_text(encoding="utf-8")
        self.assertNotIn(legacy_marker, scrubbed)
        self.assertEqual(json.loads(scrubbed)["finding_input"], "")

    def test_real_dashboard_http_boundaries_scrub_legacy_state_and_plan_output(self) -> None:
        legacy_marker = "legacy-http-dashboard-marker"
        state_dir = self.root / "http-state"
        state_dir.mkdir()
        legacy_config = sanitize_dashboard_config(
            {
                "domain": "recommend",
                "recipes_source": str(self.recipe_source),
                "finding_input": json.dumps({"title": legacy_marker}),
            }
        )
        (state_dir / "dashboard-config.json").write_text(
            json.dumps(legacy_config),
            encoding="utf-8",
        )

        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = int(listener.getsockname()[1])
        process = subprocess.Popen(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "security_recipes_remediation_suite.py"),
                "serve-dashboard",
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--state-dir",
                str(state_dir),
            ],
            cwd=REPO_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(self._stop_process, process)
        base_url = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 10
        while True:
            try:
                with urlopen(f"{base_url}/api/health", timeout=0.5) as response:
                    self.assertEqual(response.status, 200)
                break
            except (OSError, URLError):
                if process.poll() is not None:
                    error = process.stderr.read() if process.stderr else ""
                    self.fail(f"dashboard exited before becoming ready: {error}")
                if time.monotonic() >= deadline:
                    self.fail("dashboard did not become ready")
                time.sleep(0.05)

        with urlopen(f"{base_url}/api/config", timeout=2) as response:
            config_payload = json.loads(response.read())
        self.assertEqual(config_payload["finding_input"], "")
        self.assertNotIn(
            legacy_marker,
            (state_dir / "dashboard-config.json").read_text(encoding="utf-8"),
        )

        with socket.create_connection(("127.0.0.1", port), timeout=5) as client:
            client.sendall(
                (
                    "POST /api/plan HTTP/1.0\r\n"
                    "Host: 127.0.0.1\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {MAX_DASHBOARD_REQUEST_BYTES + 1}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii")
            )
            oversized_response = client.recv(1024)
        self.assertIn(b" 413 ", oversized_response.split(b"\r\n", 1)[0])

        plan_secret = "http-plan-secret"
        request = Request(
            f"{base_url}/api/plan",
            data=json.dumps(
                {
                    "domain": "recommend",
                    "recipes_source": str(self.recipe_source),
                    "finding_input": json.dumps(
                        {"title": "HTTP finding", "clientSecret": plan_secret}
                    ),
                    "llm_mode": "prompt",
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=5) as response:
            plan_payload = json.loads(response.read())
        encoded = json.dumps(plan_payload, sort_keys=True)
        self.assertNotIn(plan_secret, encoded)
        self.assertIn("[REDACTED]", encoded)

    @staticmethod
    def _stop_process(process: subprocess.Popen[str]) -> None:
        try:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        finally:
            if process.stderr is not None:
                process.stderr.close()


if __name__ == "__main__":
    unittest.main()
