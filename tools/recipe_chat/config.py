"""Locked product numbers and environment names for Recipe chat."""

from __future__ import annotations

import os
from urllib.parse import urlparse

FREE_MESSAGE_LIMIT = 6
FREE_WINDOW_SECONDS = 24 * 60 * 60
PAID_MESSAGE_LIMIT = 100
PAID_TTL_SECONDS = 30 * 24 * 60 * 60
UNLOCK_AMOUNT_CENTS = 500
UNLOCK_CURRENCY = "usd"
UNLOCK_PRODUCT_NAME = "Recipe chat"
UNLOCK_PRODUCT_DESCRIPTION = "100 messages, valid 30 days"

MODEL = "grok-4.6"
XAI_API_URL = "https://api.x.ai/v1/responses"
REASONING_EFFORT = "low"
MAX_OUTPUT_TOKENS = 900
XAI_TIMEOUT_SECONDS = 45
MAX_MESSAGE_CHARS = 2000
MAX_SOURCES = 6
MAX_SOURCE_CHARS = 1400

COOKIE_NAME = "sr_recipe_chat"
COOKIE_MAX_AGE = PAID_TTL_SECONDS
XAI_API_KEY_ENV = "XAI_API_KEY"
SIGNING_SECRET_ENV = "RECIPE_CHAT_SIGNING_SECRET"
STRIPE_SECRET_KEY_ENV = "STRIPE_SECRET_KEY"
STRIPE_WEBHOOK_SECRET_ENV = "STRIPE_WEBHOOK_SECRET"
STRIPE_PUBLISHABLE_KEY_ENV = "STRIPE_PUBLISHABLE_KEY"
STRIPE_API_URL = "https://api.stripe.com/v1"
STRIPE_API_VERSION = "2026-07-29.dahlia"

# Docs-only cost basis for grok-4.6.
GROK_INPUT_USD_PER_MILLION = 2
GROK_OUTPUT_USD_PER_MILLION = 6
GROUNDED_TURN_COST_CENTS = "1-3"

DEV_HOST_MARKERS = (
    "dev.security-recipes.ai",
    "localhost",
    "127.0.0.1",
)


def env_text(name: str, default: str = "") -> str:
    return str(os.environ.get(name, default) or "").strip()


def xai_api_key() -> str:
    return env_text(XAI_API_KEY_ENV)


def chat_enabled() -> bool:
    return bool(xai_api_key())


def signing_secret() -> str:
    explicit = env_text(SIGNING_SECRET_ENV)
    if explicit:
        return explicit
    key = xai_api_key()
    if key:
        return f"recipe-chat:{key}"
    return ""


def stripe_secret_key() -> str:
    return env_text(STRIPE_SECRET_KEY_ENV)


def stripe_webhook_secret() -> str:
    return env_text(STRIPE_WEBHOOK_SECRET_ENV)


def stripe_publishable_key() -> str:
    return env_text(STRIPE_PUBLISHABLE_KEY_ENV)


def is_development_host(host: str) -> bool:
    hostname = (host or "").split(":", 1)[0].strip().lower()
    return any(hostname == marker or hostname.endswith(f".{marker}") for marker in DEV_HOST_MARKERS)


def request_host(headers: dict[str, str] | None, fallback: str = "") -> str:
    if not headers:
        return fallback
    for name in ("x-forwarded-host", "host"):
        raw = str(headers.get(name) or headers.get(name.title()) or "").strip()
        if raw:
            return raw.split(",", 1)[0].strip()
    return fallback


def public_origin(headers: dict[str, str] | None, fallback: str = "https://security-recipes.ai") -> str:
    host = request_host(headers)
    if not host:
        return fallback.rstrip("/")
    proto = ""
    if headers:
        proto = str(headers.get("x-forwarded-proto") or headers.get("X-Forwarded-Proto") or "").split(",", 1)[0]
    if not proto:
        proto = "http" if is_development_host(host) and host.split(":")[0] in {"localhost", "127.0.0.1"} else "https"
    return f"{proto}://{host}".rstrip("/")


def site_base_url() -> str:
    raw = env_text("RECIPES_PUBLIC_SITE_BASE_URL") or env_text("SECURITY_RECIPES_BASE_URL")
    if not raw:
        return "https://security-recipes.ai"
    parsed = urlparse(raw)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return raw.rstrip("/")


def stripe_key_is_live(secret: str) -> bool:
    return secret.startswith(("sk_live_", "rk_live_"))


def stripe_key_is_test(secret: str) -> bool:
    return secret.startswith(("sk_test_", "rk_test_"))
