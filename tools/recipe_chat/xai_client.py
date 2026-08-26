"""Official xAI Responses API client for Recipe chat."""

from __future__ import annotations

from typing import Any, Callable

import httpx

from .config import (
    MAX_OUTPUT_TOKENS,
    MODEL,
    REASONING_EFFORT,
    XAI_API_URL,
    XAI_TIMEOUT_SECONDS,
    xai_api_key,
)
from .grounding import SYSTEM_INSTRUCTIONS


class XAIError(RuntimeError):
    def __init__(self, message: str, *, status_code: int = 502) -> None:
        super().__init__(message)
        self.status_code = status_code


def extract_output_text(payload: dict[str, Any]) -> str:
    chunks: list[str] = []
    output = payload.get("output")
    if isinstance(output, list):
        for item in output:
            if not isinstance(item, dict):
                continue
            content = item.get("content")
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") in {"output_text", "text"}:
                        text = str(block.get("text") or "").strip()
                        if text:
                            chunks.append(text)
            elif item.get("type") in {"output_text", "text"}:
                text = str(item.get("text") or "").strip()
                if text:
                    chunks.append(text)
    if chunks:
        return "\n\n".join(chunks).strip()
    for key in ("output_text", "text"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


class XAIClient:
    def __init__(
        self,
        api_key: str | None = None,
        *,
        api_url: str = XAI_API_URL,
        transport: httpx.BaseTransport | None = None,
        post: Callable[..., Any] | None = None,
    ) -> None:
        self.api_key = api_key if api_key is not None else xai_api_key()
        self.api_url = api_url
        self.transport = transport
        self._post = post

    def _payload(self, message: str, context: str, previous_response_id: str = "") -> dict[str, Any]:
        user = message.strip()
        if context.strip():
            user = f"{user}\n\n{context.strip()}"
        payload: dict[str, Any] = {
            "model": MODEL,
            "instructions": SYSTEM_INSTRUCTIONS,
            "input": user,
            "reasoning": {"effort": REASONING_EFFORT},
            "max_output_tokens": MAX_OUTPUT_TOKENS,
        }
        if previous_response_id:
            payload["previous_response_id"] = previous_response_id
        return payload

    def complete(
        self,
        message: str,
        context: str,
        previous_response_id: str = "",
    ) -> tuple[str, str]:
        if not self.api_key:
            raise XAIError("Recipe chat is off because XAI_API_KEY is not set.", status_code=503)
        payload = self._payload(message, context, previous_response_id)
        if self._post is not None:
            response_payload = self._post(payload)
        else:
            response_payload = self._http_post(payload)
        if not isinstance(response_payload, dict):
            raise XAIError("xAI returned an unusable response.")
        text = extract_output_text(response_payload)
        if not text:
            raise XAIError("xAI returned an empty answer.")
        response_id = str(response_payload.get("id") or previous_response_id or "")
        return text, response_id

    def _http_post(self, payload: dict[str, Any]) -> dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "security-recipes.ai/recipe-chat",
        }
        try:
            with httpx.Client(timeout=XAI_TIMEOUT_SECONDS, transport=self.transport) as client:
                response = client.post(self.api_url, json=payload, headers=headers)
        except httpx.HTTPError as exc:
            raise XAIError("xAI request failed.") from exc
        if response.status_code == 401:
            raise XAIError("xAI rejected XAI_API_KEY.", status_code=503)
        if response.status_code == 429:
            raise XAIError("xAI is rate limiting Recipe chat. Try again shortly.", status_code=429)
        if response.status_code >= 400:
            raise XAIError("xAI request failed.")
        try:
            parsed = response.json()
        except ValueError as exc:
            raise XAIError("xAI returned non-JSON.") from exc
        if not isinstance(parsed, dict):
            raise XAIError("xAI returned an unusable response.")
        return parsed
