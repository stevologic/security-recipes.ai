"""Orchestrate Recipe chat: policy, grounding, quota, xAI, and Stripe."""

from __future__ import annotations

from typing import Any

from .config import (
    FREE_MESSAGE_LIMIT,
    GROK_INPUT_USD_PER_MILLION,
    GROK_OUTPUT_USD_PER_MILLION,
    GROUNDED_TURN_COST_CENTS,
    MAX_MESSAGE_CHARS,
    MODEL,
    PAID_MESSAGE_LIMIT,
    PAID_TTL_SECONDS,
    UNLOCK_AMOUNT_CENTS,
    UNLOCK_CURRENCY,
    chat_enabled,
    public_origin,
    request_host,
)
from .grounding import (
    CveLookup,
    PlaybookLookup,
    RecipeSearcher,
    extract_cves,
    format_context,
    invented_cves,
    missing_named_cve_reply,
    retrieve_sources,
)
from .policy import classify_request
from .quota import QuotaExhausted, QuotaStore, VisitorState, client_ip
from .stripe_checkout import StripeCheckout, StripeConfigError, StripeError
from .xai_client import XAIClient, XAIError


class ChatDisabled(RuntimeError):
    pass


class ChatRequestError(RuntimeError):
    def __init__(self, message: str, *, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


class RecipeChatService:
    def __init__(
        self,
        *,
        recipe_index: RecipeSearcher | None = None,
        cve_catalog: CveLookup | None = None,
        playbook_registry: PlaybookLookup | None = None,
        quota: QuotaStore | None = None,
        xai: XAIClient | None = None,
        stripe: StripeCheckout | None = None,
    ) -> None:
        self.recipe_index = recipe_index
        self.cve_catalog = cve_catalog
        self.playbook_registry = playbook_registry
        self.quota = quota or QuotaStore()
        self.xai = xai or XAIClient()
        self.stripe = stripe or StripeCheckout()

    def enabled(self) -> bool:
        return chat_enabled() and bool(self.quota.secret)

    def public_status(self, headers: dict[str, str] | None, cookie: str, remote_ip: str = "") -> dict[str, Any]:
        host = request_host(headers)
        enabled = self.enabled()
        state = self._visitor(cookie, remote_ip, headers)
        payload = {
            "enabled": enabled,
            "label": "Recipe chat",
            "model": MODEL if enabled else "",
            "read_only": True,
            "free_limit": FREE_MESSAGE_LIMIT,
            "paid_limit": PAID_MESSAGE_LIMIT,
            "paid_days": PAID_TTL_SECONDS // (24 * 60 * 60),
            "unlock_amount_cents": UNLOCK_AMOUNT_CENTS,
            "unlock_currency": UNLOCK_CURRENCY,
            "cost_basis": {
                "model": MODEL,
                "input_usd_per_million": GROK_INPUT_USD_PER_MILLION,
                "output_usd_per_million": GROK_OUTPUT_USD_PER_MILLION,
                "grounded_turn_cents": GROUNDED_TURN_COST_CENTS,
            },
            "quota": state.snapshot() if enabled else {
                "visitor_id": "",
                "free_remaining": 0,
                "free_limit": FREE_MESSAGE_LIMIT,
                "paid_active": False,
                "paid_remaining": 0,
                "paid_expires_at": 0,
                "can_send": False,
            },
            "stripe": self.stripe.status(host) if enabled else {
                "configured": False,
                "publishable_key": "",
                "amount_cents": UNLOCK_AMOUNT_CENTS,
                "currency": UNLOCK_CURRENCY,
                "messages": PAID_MESSAGE_LIMIT,
                "valid_days": 30,
            },
        }
        return payload

    async def answer(
        self,
        message: str,
        *,
        cookie: str,
        headers: dict[str, str] | None,
        remote_ip: str = "",
        page_url: str = "",
        previous_response_id: str = "",
    ) -> tuple[dict[str, Any], VisitorState]:
        if not self.enabled():
            raise ChatDisabled("Recipe chat is off because XAI_API_KEY is not set.")
        text = str(message or "").strip()
        if not text:
            raise ChatRequestError("Message is required.")
        if len(text) > MAX_MESSAGE_CHARS:
            raise ChatRequestError(f"Message must be {MAX_MESSAGE_CHARS} characters or fewer.")

        state = self._visitor(cookie, remote_ip, headers)
        if previous_response_id and not state.previous_response_id:
            state.previous_response_id = previous_response_id
        if not state.can_send():
            raise QuotaExhausted()

        refusal = classify_request(text)
        if refusal is not None:
            state, _bucket = self.quota.consume(state, client_ip(headers, remote_ip))
            return self._reply(
                state,
                refusal.message,
                sources=[],
                refused=refusal.kind,
            ), state

        retrieval = await retrieve_sources(
            text,
            recipe_index=self.recipe_index,
            cve_catalog=self.cve_catalog,
            playbook_registry=self.playbook_registry,
            page_url=page_url,
        )
        named = extract_cves(text)
        missing_named = [cve for cve in named if cve in retrieval["missing_cves"]]
        if missing_named and not retrieval["known_cves"] and not retrieval["sources"]:
            state, _bucket = self.quota.consume(state, client_ip(headers, remote_ip))
            return self._reply(
                state,
                missing_named_cve_reply(missing_named),
                sources=[],
                refused="ungrounded_cve",
            ), state

        context = format_context(retrieval)
        try:
            answer, response_id = self.xai.complete(text, context, state.previous_response_id)
        except XAIError:
            raise

        invented = invented_cves(answer, retrieval)
        if invented:
            answer = missing_named_cve_reply(invented)

        if response_id:
            state.previous_response_id = response_id
        state, _bucket = self.quota.consume(state, client_ip(headers, remote_ip))
        return self._reply(state, answer, sources=retrieval["sources"]), state

    def start_checkout(
        self,
        *,
        cookie: str,
        headers: dict[str, str] | None,
        remote_ip: str = "",
        return_path: str = "/",
    ) -> tuple[dict[str, Any], VisitorState]:
        if not self.enabled():
            raise ChatDisabled("Recipe chat is off because XAI_API_KEY is not set.")
        state = self._visitor(cookie, remote_ip, headers)
        origin = public_origin(headers)
        path = return_path if return_path.startswith("/") else "/"
        success = f"{origin}{path}?chat_unlock=1&session_id={{CHECKOUT_SESSION_ID}}"
        cancel = f"{origin}{path}?chat_unlock=0"
        session = self.stripe.create_session(
            visitor_id=state.visitor_id,
            success_url=success,
            cancel_url=cancel,
            host=request_host(headers),
        )
        return {"checkout_url": session["url"], "session_id": session["id"], "quota": state.snapshot()}, state

    def complete_checkout(
        self,
        session_id: str,
        *,
        cookie: str,
        headers: dict[str, str] | None,
        remote_ip: str = "",
    ) -> tuple[dict[str, Any], VisitorState]:
        if not self.enabled():
            raise ChatDisabled("Recipe chat is off because XAI_API_KEY is not set.")
        state = self._visitor(cookie, remote_ip, headers)
        session = self.stripe.retrieve_session(session_id, host=request_host(headers))
        visitor_id = self.stripe.paid_visitor_id(session)
        if not visitor_id:
            raise ChatRequestError("Checkout is not paid yet.", status_code=402)
        if visitor_id != state.visitor_id:
            raise ChatRequestError("Checkout does not match this visitor.", status_code=403)
        state.grant_paid(str(session.get("id") or session_id))
        return {"unlocked": True, "quota": state.snapshot()}, state

    def apply_webhook(self, payload: bytes, signature: str) -> dict[str, Any]:
        event = self.stripe.verify_webhook(payload, signature)
        event_type = str(event.get("type") or "")
        data = event.get("data") if isinstance(event.get("data"), dict) else {}
        session = data.get("object") if isinstance(data, dict) else None
        if event_type in {"checkout.session.completed", "checkout.session.async_payment_succeeded"} and isinstance(
            session, dict
        ):
            visitor_id = self.stripe.paid_visitor_id(session)
            return {"received": True, "visitor_id": visitor_id, "type": event_type}
        return {"received": True, "type": event_type}

    def _visitor(self, cookie: str, remote_ip: str, headers: dict[str, str] | None) -> VisitorState:
        state = self.quota.load_cookie(cookie)
        return self.quota.bind_ip(state, client_ip(headers, remote_ip))

    @staticmethod
    def _reply(
        state: VisitorState,
        message: str,
        *,
        sources: list[dict[str, str]],
        refused: str = "",
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "reply": message,
            "sources": sources,
            "quota": state.snapshot(),
            "previous_response_id": state.previous_response_id,
            "read_only": True,
        }
        if refused:
            payload["refused"] = refused
        return payload


def error_payload(exc: Exception) -> tuple[int, dict[str, Any]]:
    if isinstance(exc, ChatDisabled):
        return 503, {"error": "chat_disabled", "message": str(exc), "enabled": False}
    if isinstance(exc, QuotaExhausted):
        return 402, {
            "error": "paywall",
            "message": (
                f"Free sample is {FREE_MESSAGE_LIMIT} messages per 24 hours. "
                f"Unlock {PAID_MESSAGE_LIMIT} more for ${UNLOCK_AMOUNT_CENTS // 100} "
                "for 30 days."
            ),
        }
    if isinstance(exc, ChatRequestError):
        return exc.status_code, {"error": "invalid_request", "message": str(exc)}
    if isinstance(exc, (StripeConfigError,)):
        return exc.status_code, {"error": "stripe_unconfigured", "message": str(exc)}
    if isinstance(exc, StripeError):
        return exc.status_code, {"error": "stripe_error", "message": str(exc)}
    if isinstance(exc, XAIError):
        return exc.status_code, {"error": "model_error", "message": str(exc)}
    return 500, {"error": "chat_unavailable", "message": "Recipe chat is temporarily unavailable."}
