"""Browser workbench for the security-recipes.ai remediation suite."""

from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .suite import (
    DEFAULT_LOCAL_RECIPES,
    DEFAULT_REMOTE_RECIPES,
    build_remediation_packet,
    domain_by_key,
    load_domain_registry,
    load_finding_text,
)

MAX_DASHBOARD_REQUEST_BYTES = 1024 * 1024


class RequestBodyTooLarge(ValueError):
    """Raised before reading an oversized dashboard request body."""


REPO_ROOT = Path(__file__).resolve().parents[2]
UI_ROOT = REPO_ROOT / "tools" / "security_recipes_remediation" / "ui"
DEFAULT_STATE_DIR = REPO_ROOT / "tmp" / "remediation-suite-dashboard"


def build_dashboard_plan(
    payload: dict[str, Any],
    *,
    registry: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the API response for a dashboard plan request."""

    selected_registry = registry or load_domain_registry()
    config = sanitize_dashboard_config(payload)
    findings = load_finding_text(str(config.get("finding_input", "")))
    packet = build_remediation_packet(
        domain_key=str(config["domain"]),
        findings=findings,
        registry=selected_registry,
        recipe_source=config.get("recipes_source") or None,
        tooling=config.get("tooling", []),
        ecosystem=config.get("ecosystem") or None,
        llm_config=config.get("llm_config") or {},
        llm_mode=str(config.get("llm_mode") or "off"),
        max_recipes=int(config.get("max_recipes") or 6),
    )
    return {"packet": packet}


def run_dashboard(
    *,
    host: str,
    port: int,
    state_dir: str | Path | None = None,
) -> None:
    """Run the remediation-suite browser dashboard."""
    dashboard_state_dir = Path(state_dir) if state_dir else DEFAULT_STATE_DIR
    dashboard_state_dir.mkdir(parents=True, exist_ok=True)
    registry = load_domain_registry()

    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "SecurityRecipesDashboard/2026.06"

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == "/":
                return self._serve_file(UI_ROOT / "index.html", "text/html; charset=utf-8")
            if path == "/app.js":
                return self._serve_file(UI_ROOT / "app.js", "application/javascript; charset=utf-8")
            if path == "/app.css":
                return self._serve_file(UI_ROOT / "app.css", "text/css; charset=utf-8")
            if path == "/api/health":
                return self._send_json({"status": "ok"})
            if path == "/api/domains":
                domains = [
                    {
                        "id": domain["id"],
                        "title": domain["title"],
                        "command": domain["command"],
                        "page": domain.get("page"),
                        "purpose": domain.get("purpose"),
                        "signals": domain.get("signals", []),
                        "recipe_queries": domain.get("recipe_queries", []),
                    }
                    for domain in registry["domains"]
                ]
                return self._send_json({"suite": registry.get("suite", {}), "domains": domains})
            if path == "/api/config":
                return self._send_json(load_dashboard_config(dashboard_state_dir))
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")

        def do_POST(self) -> None:  # noqa: N802
            if self.path == "/api/config":
                payload = self._read_json()
                config = sanitize_dashboard_config(payload)
                save_dashboard_config(dashboard_state_dir, config)
                return self._send_json({"saved": True, "config": {**config, "finding_input": ""}})
            if self.path == "/api/plan":
                payload = self._read_json()
                return self._send_json(build_dashboard_plan(payload, registry=registry))
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            return

        def _read_json(self) -> dict[str, Any]:
            raw_length = self.headers.get("Content-Length", "0").strip() or "0"
            length = int(raw_length)
            if length < 0:
                raise ValueError("Content-Length cannot be negative")
            if length > MAX_DASHBOARD_REQUEST_BYTES:
                raise RequestBodyTooLarge(
                    f"request body exceeds {MAX_DASHBOARD_REQUEST_BYTES} bytes"
                )
            body = self.rfile.read(length) if length else b"{}"
            if not body:
                return {}
            try:
                payload = json.loads(body.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON body: {exc}") from exc
            if not isinstance(payload, dict):
                raise ValueError("request body must be a JSON object")
            return payload

        def _serve_file(self, path: Path, content_type: str) -> None:
            if not path.exists():
                self.send_error(HTTPStatus.NOT_FOUND, "Not found")
                return
            content = path.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def _send_json(self, payload: dict[str, Any], *, status: int = HTTPStatus.OK) -> None:
            encoded = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def handle_one_request(self) -> None:
            try:
                super().handle_one_request()
            except RequestBodyTooLarge as exc:
                self._send_json(
                    {"error": str(exc)},
                    status=HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                )
            except ValueError as exc:
                self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
            except Exception as exc:  # pragma: no cover - HTTP edge-case safety
                self._send_json({"error": str(exc)}, status=HTTPStatus.INTERNAL_SERVER_ERROR)

    httpd = ThreadingHTTPServer((host, port), DashboardHandler)
    print(
        f"security-recipes remediation dashboard listening on http://{host}:{port} "
        f"(state: {dashboard_state_dir})"
    )
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()


def load_dashboard_config(state_dir: Path) -> dict[str, Any]:
    path = state_dir / "dashboard-config.json"
    if not path.exists():
        return default_dashboard_config()

    try:
        with path.open("r", encoding="utf-8") as handle:
            stored = json.load(handle)
        if not isinstance(stored, dict):
            raise ValueError("stored dashboard configuration is not an object")
        contained_finding = bool(stored.get("finding_input"))
        config = sanitize_dashboard_config({**stored, "finding_input": ""})
        if contained_finding:
            save_dashboard_config(state_dir, config)
        return config
    except Exception:
        config = default_dashboard_config()
        try:
            save_dashboard_config(state_dir, config)
        except OSError:
            pass
        return config


def save_dashboard_config(state_dir: Path, config: dict[str, Any]) -> None:
    path = state_dir / "dashboard-config.json"
    persisted_config = {**config, "finding_input": ""}
    path.write_text(json.dumps(persisted_config, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def default_dashboard_config() -> dict[str, Any]:
    return {
        "domain": "recommend",
        "recipes_source": str(DEFAULT_LOCAL_RECIPES if DEFAULT_LOCAL_RECIPES.exists() else DEFAULT_REMOTE_RECIPES),
        "tooling": ["github", "snyk", "jira"],
        "ecosystem": "",
        "llm_mode": "prompt",
        "max_recipes": 6,
        "finding_input": "",
        "llm_config": {
            "endpoint": "https://api.x.ai/v1/chat/completions",
            "model": "grok-4.6",
            "api_key_env": "XAI_API_KEY",
            "temperature": 0.2,
            "timeout": 30,
        },
        "access_context": {
            "notes": "Configure read-only recipe and scanner context first. Keep write credentials outside the planner.",
            "context_sources": [
                "Recipe JSON endpoint",
                "Scanner export or ticket payload",
                "Enterprise tooling hints",
            ],
        },
    }


def sanitize_dashboard_config(payload: dict[str, Any]) -> dict[str, Any]:
    base = default_dashboard_config()
    merged = {**base, **payload}

    domain = str(merged.get("domain") or base["domain"]).strip()
    tooling = merged.get("tooling", [])
    if isinstance(tooling, str):
        tooling = [item.strip() for item in tooling.split(",") if item.strip()]
    elif isinstance(tooling, list):
        tooling = [str(item).strip() for item in tooling if str(item).strip()]
    else:
        tooling = list(base["tooling"])

    llm_config = merged.get("llm_config", {})
    if not isinstance(llm_config, dict):
        llm_config = dict(base["llm_config"])

    access_context = merged.get("access_context", {})
    if not isinstance(access_context, dict):
        access_context = dict(base["access_context"])

    normalized = {
        "domain": domain,
        "recipes_source": str(merged.get("recipes_source") or base["recipes_source"]).strip(),
        "tooling": tooling,
        "ecosystem": str(merged.get("ecosystem") or "").strip(),
        "llm_mode": str(merged.get("llm_mode") or base["llm_mode"]).strip().lower(),
        "max_recipes": max(1, int(merged.get("max_recipes") or base["max_recipes"])),
        "finding_input": str(merged.get("finding_input") or ""),
        "llm_config": {
            "endpoint": str(llm_config.get("endpoint") or "").strip(),
            "model": str(llm_config.get("model") or "").strip(),
            "api_key_env": str(llm_config.get("api_key_env") or "XAI_API_KEY").strip(),
            "temperature": float(llm_config.get("temperature", 0.2)),
            "timeout": int(llm_config.get("timeout", 30)),
        },
        "access_context": {
            "notes": str(access_context.get("notes") or base["access_context"]["notes"]).strip(),
            "context_sources": [
                str(item).strip()
                for item in access_context.get("context_sources", base["access_context"]["context_sources"])
                if str(item).strip()
            ],
        },
    }

    llm_mode = normalized["llm_mode"]
    if llm_mode not in {"off", "prompt", "call"}:
        normalized["llm_mode"] = base["llm_mode"]

    domain_by_key(load_domain_registry(), normalized["domain"])
    return normalized


__all__ = [
    "DEFAULT_STATE_DIR",
    "MAX_DASHBOARD_REQUEST_BYTES",
    "build_dashboard_plan",
    "load_dashboard_config",
    "run_dashboard",
    "sanitize_dashboard_config",
    "save_dashboard_config",
]
