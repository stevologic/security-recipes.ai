"""Minimal Stripe Checkout for the $5 / 100-message Recipe chat unlock."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any
from urllib.parse import urlencode

import httpx

from .config import (
    STRIPE_API_URL,
    STRIPE_API_VERSION,
    UNLOCK_AMOUNT_CENTS,
    UNLOCK_CURRENCY,
    UNLOCK_PRODUCT_DESCRIPTION,
    UNLOCK_PRODUCT_NAME,
    is_development_host,
    stripe_key_is_live,
    stripe_publishable_key,
    stripe_secret_key,
    stripe_webhook_secret,
)


class StripeError(RuntimeError):
    def __init__(self, message: str, *, status_code: int = 502) -> None:
        super().__init__(message)
        self.status_code = status_code


class StripeConfigError(StripeError):
    def __init__(self, message: str) -> None:
        super().__init__(message, status_code=503)


def configured(secret: str | None = None) -> bool:
    return bool((secret if secret is not None else stripe_secret_key()))


def reject_live_key_on_development(host: str, secret: str) -> None:
    if is_development_host(host) and stripe_key_is_live(secret):
        raise StripeConfigError(
            "Development and localhost must use Stripe test keys only. "
            "Do not set a live STRIPE_SECRET_KEY on dev.security-recipes.ai."
        )


def _headers(secret: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {secret}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Stripe-Version": STRIPE_API_VERSION,
        "User-Agent": "security-recipes.ai/recipe-chat",
    }


class StripeCheckout:
    def __init__(
        self,
        secret: str | None = None,
        webhook_secret: str | None = None,
        publishable: str | None = None,
        *,
        api_url: str = STRIPE_API_URL,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.secret = secret if secret is not None else stripe_secret_key()
        self.webhook_secret = webhook_secret if webhook_secret is not None else stripe_webhook_secret()
        self.publishable = publishable if publishable is not None else stripe_publishable_key()
        self.api_url = api_url.rstrip("/")
        self.transport = transport

    def status(self, host: str = "") -> dict[str, Any]:
        try:
            if self.secret:
                reject_live_key_on_development(host, self.secret)
            ready = bool(self.secret)
        except StripeConfigError:
            ready = False
        return {
            "configured": ready,
            "publishable_key": self.publishable if ready else "",
            "amount_cents": UNLOCK_AMOUNT_CENTS,
            "currency": UNLOCK_CURRENCY,
            "messages": 100,
            "valid_days": 30,
        }

    def create_session(
        self,
        *,
        visitor_id: str,
        success_url: str,
        cancel_url: str,
        host: str = "",
    ) -> dict[str, str]:
        if not self.secret:
            raise StripeConfigError("Stripe Checkout is not configured.")
        reject_live_key_on_development(host, self.secret)
        form = {
            "mode": "payment",
            "success_url": success_url,
            "cancel_url": cancel_url,
            "client_reference_id": visitor_id,
            "integration_identifier": "rchatdev",
            "metadata[visitor_id]": visitor_id,
            "metadata[product]": "recipe_chat_100",
            "line_items[0][quantity]": "1",
            "line_items[0][price_data][currency]": UNLOCK_CURRENCY,
            "line_items[0][price_data][unit_amount]": str(UNLOCK_AMOUNT_CENTS),
            "line_items[0][price_data][product_data][name]": UNLOCK_PRODUCT_NAME,
            "line_items[0][price_data][product_data][description]": UNLOCK_PRODUCT_DESCRIPTION,
        }
        payload = self._request("POST", "/checkout/sessions", data=form)
        session_id = str(payload.get("id") or "")
        url = str(payload.get("url") or "")
        if not session_id or not url:
            raise StripeError("Stripe Checkout did not return a session URL.")
        return {"id": session_id, "url": url}

    def retrieve_session(self, session_id: str, host: str = "") -> dict[str, Any]:
        if not self.secret:
            raise StripeConfigError("Stripe Checkout is not configured.")
        reject_live_key_on_development(host, self.secret)
        if not session_id.startswith("cs_"):
            raise StripeError("Invalid Checkout session.", status_code=400)
        return self._request("GET", f"/checkout/sessions/{session_id}")

    def paid_visitor_id(self, session: dict[str, Any]) -> str:
        if str(session.get("payment_status") or "") != "paid" and str(session.get("status") or "") != "complete":
            return ""
        metadata = session.get("metadata") if isinstance(session.get("metadata"), dict) else {}
        visitor_id = str(metadata.get("visitor_id") or session.get("client_reference_id") or "").strip()
        return visitor_id

    def verify_webhook(self, payload: bytes, signature_header: str) -> dict[str, Any]:
        if not self.webhook_secret:
            raise StripeConfigError("STRIPE_WEBHOOK_SECRET is not configured.")
        if not verify_stripe_signature(payload, signature_header, self.webhook_secret):
            raise StripeError("Invalid Stripe webhook signature.", status_code=400)
        try:
            parsed = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise StripeError("Invalid Stripe webhook payload.", status_code=400) from exc
        if not isinstance(parsed, dict):
            raise StripeError("Invalid Stripe webhook payload.", status_code=400)
        return parsed

    def _request(self, method: str, path: str, data: dict[str, str] | None = None) -> dict[str, Any]:
        url = f"{self.api_url}{path}"
        try:
            with httpx.Client(timeout=20, transport=self.transport) as client:
                response = client.request(
                    method,
                    url,
                    headers=_headers(self.secret),
                    content=urlencode(data) if data else None,
                )
        except httpx.HTTPError as exc:
            raise StripeError("Stripe request failed.") from exc
        if response.status_code >= 400:
            raise StripeError("Stripe request failed.", status_code=502)
        try:
            parsed = response.json()
        except ValueError as exc:
            raise StripeError("Stripe returned non-JSON.") from exc
        if not isinstance(parsed, dict):
            raise StripeError("Stripe returned an unusable response.")
        return parsed


def verify_stripe_signature(payload: bytes, header: str, secret: str, *, tolerance: int = 300) -> bool:
    items = {}
    for part in (header or "").split(","):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        items.setdefault(key.strip(), []).append(value.strip())
    try:
        timestamp = int((items.get("t") or [""])[0])
    except (TypeError, ValueError):
        return False
    signatures = items.get("v1") or []
    if not signatures:
        return False
    if abs(int(time.time()) - timestamp) > tolerance:
        return False
    signed = f"{timestamp}.".encode("utf-8") + payload
    expected = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, signature) for signature in signatures)
