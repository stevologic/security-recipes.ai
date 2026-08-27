#!/usr/bin/env python3
"""Diagnose xAI access without logging credentials or provider response bodies.

Metadata requests do not generate content. The final Responses probe is the
same bounded request used by automation; metadata success alone cannot prove
that inference permissions or billing are ready.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

try:
    from scripts import cve_ai_enrichment as enrichment
except ModuleNotFoundError:
    import cve_ai_enrichment as enrichment  # type: ignore[no-redef]


METADATA_ENDPOINTS = {
    "key": "https://api.x.ai/v1/api-key",
    "models": "https://api.x.ai/v1/language-models",
}
MAX_METADATA_BYTES = 256 * 1024


def _metadata(
    kind: str, key: str, opener: Callable[..., Any]
) -> tuple[dict[str, object], dict[str, Any] | None]:
    request = Request(
        METADATA_ENDPOINTS[kind],
        headers={
            "Authorization": f"Bearer {key}",
            "Accept": "application/json",
            "User-Agent": "security-recipes.ai/xai-credential-diagnostics",
        },
    )
    try:
        with opener(request, timeout=30) as response:
            raw = response.read(MAX_METADATA_BYTES + 1)
            http_status = response.status
        if len(raw) > MAX_METADATA_BYTES:
            return {"http_status": http_status, "result": "invalid_response"}, None
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            return {"http_status": http_status, "result": "invalid_response"}, None
        return {"http_status": http_status, "result": "ready"}, payload
    except HTTPError as exc:
        # Classification consumes the body but returns only a fixed category.
        return {
            "http_status": exc.code,
            "result": enrichment.classify_provider_http_error(exc),
        }, None
    except (TimeoutError, URLError, OSError):
        return {"http_status": None, "result": "unreachable"}, None
    except (ValueError, UnicodeError):
        # Neither invalid headers nor malformed JSON may leak an exception body.
        return {"http_status": None, "result": "invalid_response"}, None


def _boolean(payload: dict[str, Any], name: str) -> bool | None:
    value = payload.get(name)
    return value if isinstance(value, bool) else None


def diagnose(
    api_key: str,
    *,
    model: str = enrichment.DEFAULT_MODEL,
    opener: Callable[..., Any] | None = None,
) -> dict[str, object]:
    key = api_key.strip()
    if not key:
        return {"key_present": False, "result": "missing"}
    # Report formatting mistakes as booleans, never a key fragment or hash.
    formatting = {
        "has_bearer_prefix": key.lower().startswith("bearer "),
        "has_surrounding_quotes": key.startswith(("'", '"'))
        or key.endswith(("'", '"')),
        "has_internal_whitespace": any(char.isspace() for char in key),
        "has_control_characters": not key.isprintable(),
    }
    if any(formatting.values()) or not key.isascii():
        return {"key_present": True, "formatting": formatting, "result": "invalid_format"}

    request_opener = opener or urlopen
    key_report, key_payload = _metadata("key", key, request_opener)
    if key_payload is not None:
        for name in ("api_key_disabled", "api_key_blocked", "team_blocked"):
            key_report[name] = _boolean(key_payload, name)
        acls = key_payload.get("acls")
        if isinstance(acls, list) and all(isinstance(item, str) for item in acls):
            key_report["all_models_allowed"] = "api-key:model:*" in acls
            key_report["configured_model_explicitly_allowed"] = (
                f"api-key:model:{model}" in acls
            )
            key_report["all_endpoints_allowed"] = "api-key:endpoint:*" in acls
        # No raw ACL, name, ID, timestamp, or redacted key is copied into output.

    model_report, model_payload = _metadata("models", key, request_opener)
    if model_payload is not None:
        models = model_payload.get("models")
        if isinstance(models, list) and all(isinstance(item, dict) for item in models):
            model_report["configured_model_listed"] = any(
                item.get("id") == model
                or (
                    isinstance(item.get("aliases"), list)
                    and model in item["aliases"]
                )
                for item in models
            )

    status = enrichment.probe_xai_credentials(key, model=model, opener=request_opener)
    return {
        "key_present": True,
        "formatting": formatting,
        "key_metadata": key_report,
        "model_metadata": model_report,
        "responses_probe": {
            "usable": status.usable,
            "reason": status.reason,
            "http_status": status.http_status,
            "error_category": status.error_category,
        },
    }


def main() -> int:
    report = diagnose(
        os.environ.get("XAI_API_KEY", ""),
        model=os.environ.get("XAI_MODEL", "").strip() or enrichment.DEFAULT_MODEL,
    )
    print("XAI_DIAGNOSTIC_JSON=" + json.dumps(report, sort_keys=True))
    # This command reports diagnostics; it must not start repair-agent cascades.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
