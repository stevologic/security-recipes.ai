"""Starlette routes for Recipe chat, mounted on the existing MCP server."""

from __future__ import annotations

from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse

from .config import COOKIE_MAX_AGE, COOKIE_NAME, chat_enabled
from .quota import parse_cookie_header
from .service import RecipeChatService, error_payload

_NO_STORE = {
    "Cache-Control": "no-store",
    "X-Robots-Tag": "noindex, nofollow, noarchive",
    "X-Content-Type-Options": "nosniff",
}


def _headers(request: Request) -> dict[str, str]:
    return {key.lower(): value for key, value in request.headers.items()}


def _cookie(request: Request) -> str:
    return parse_cookie_header(request.headers.get("cookie"))


def _remote_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _secure(request: Request) -> bool:
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "").split(",", 1)[0]
    return proto.strip().lower() == "https"


def _json(payload: dict[str, Any], status_code: int = 200) -> JSONResponse:
    return JSONResponse(payload, status_code=status_code, headers=dict(_NO_STORE))


def register_recipe_chat_routes(
    mcp,
    *,
    recipe_index,
    cve_catalog,
    playbook_registry,
    service: RecipeChatService | None = None,
) -> RecipeChatService:
    chat = service or RecipeChatService(
        recipe_index=recipe_index,
        cve_catalog=cve_catalog,
        playbook_registry=playbook_registry,
    )

    def cookie_response(request: Request, payload: dict[str, Any], state, status_code: int = 200) -> JSONResponse:
        response = _json(payload, status_code=status_code)
        if state is not None and chat.quota.secret:
            response.set_cookie(
                COOKIE_NAME,
                chat.quota.dump_cookie(state),
                max_age=COOKIE_MAX_AGE,
                httponly=True,
                secure=_secure(request),
                samesite="lax",
                path="/",
            )
        return response

    @mcp.custom_route("/api/chat/status", methods=["GET"], name="recipe-chat-status", include_in_schema=False)
    async def chat_status(request: Request) -> JSONResponse:
        headers = _headers(request)
        payload = chat.public_status(headers, _cookie(request), _remote_ip(request))
        state = chat._visitor(_cookie(request), _remote_ip(request), headers) if payload.get("enabled") else None
        return cookie_response(request, payload, state)

    @mcp.custom_route("/api/chat", methods=["POST"], name="recipe-chat-message", include_in_schema=False)
    async def chat_message(request: Request) -> JSONResponse:
        if not chat_enabled():
            return _json(
                {
                    "error": "chat_disabled",
                    "message": "Recipe chat is off because XAI_API_KEY is not set.",
                    "enabled": False,
                },
                status_code=503,
            )
        try:
            body = await request.json()
        except Exception:
            return _json({"error": "invalid_request", "message": "JSON body is required."}, status_code=400)
        if not isinstance(body, dict):
            return _json({"error": "invalid_request", "message": "JSON object is required."}, status_code=400)
        try:
            payload, state = await chat.answer(
                str(body.get("message") or ""),
                cookie=_cookie(request),
                headers=_headers(request),
                remote_ip=_remote_ip(request),
                page_url=str(body.get("page_url") or ""),
                previous_response_id=str(body.get("previous_response_id") or ""),
            )
        except Exception as exc:
            status, error = error_payload(exc)
            state = None
            if status == 402:
                state = chat._visitor(_cookie(request), _remote_ip(request), _headers(request))
                error["quota"] = state.snapshot()
            return cookie_response(request, error, state, status_code=status)
        return cookie_response(request, payload, state)

    @mcp.custom_route("/api/chat/checkout", methods=["POST"], name="recipe-chat-checkout", include_in_schema=False)
    async def chat_checkout(request: Request) -> JSONResponse:
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        try:
            payload, state = chat.start_checkout(
                cookie=_cookie(request),
                headers=_headers(request),
                remote_ip=_remote_ip(request),
                return_path=str(body.get("return_path") or "/"),
            )
        except Exception as exc:
            status, error = error_payload(exc)
            return _json(error, status_code=status)
        return cookie_response(request, payload, state)

    @mcp.custom_route(
        "/api/chat/checkout/session",
        methods=["GET"],
        name="recipe-chat-checkout-session",
        include_in_schema=False,
    )
    async def chat_checkout_session(request: Request) -> JSONResponse:
        session_id = str(request.query_params.get("session_id") or "")
        try:
            payload, state = chat.complete_checkout(
                session_id,
                cookie=_cookie(request),
                headers=_headers(request),
                remote_ip=_remote_ip(request),
            )
        except Exception as exc:
            status, error = error_payload(exc)
            return _json(error, status_code=status)
        return cookie_response(request, payload, state)

    @mcp.custom_route(
        "/api/chat/stripe/webhook",
        methods=["POST"],
        name="recipe-chat-stripe-webhook",
        include_in_schema=False,
    )
    async def chat_stripe_webhook(request: Request) -> JSONResponse:
        payload = await request.body()
        signature = request.headers.get("stripe-signature") or ""
        try:
            result = chat.apply_webhook(payload, signature)
        except Exception as exc:
            status, error = error_payload(exc)
            return _json(error, status_code=status)
        return _json(result)

    return chat
