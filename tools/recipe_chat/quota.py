"""Signed-cookie plus hashed-IP quota for free and paid Recipe chat."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from .config import (
    COOKIE_NAME,
    FREE_MESSAGE_LIMIT,
    FREE_WINDOW_SECONDS,
    PAID_MESSAGE_LIMIT,
    PAID_TTL_SECONDS,
    signing_secret,
)

COOKIE_VERSION = 1


def _now() -> int:
    return int(time.time())


def hash_ip(ip: str, secret: str) -> str:
    raw = (ip or "0.0.0.0").strip().encode("utf-8")
    return hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()[:32]


def client_ip(headers: dict[str, str] | None, remote: str = "") -> str:
    if headers:
        forwarded = str(headers.get("x-forwarded-for") or headers.get("X-Forwarded-For") or "")
        if forwarded:
            return forwarded.split(",", 1)[0].strip()
    return (remote or "").strip() or "0.0.0.0"


@dataclass
class VisitorState:
    visitor_id: str
    free_timestamps: list[int] = field(default_factory=list)
    paid_expires_at: int = 0
    paid_remaining: int = 0
    paid_session_id: str = ""
    previous_response_id: str = ""

    def prune(self, now: int | None = None) -> None:
        current = now if now is not None else _now()
        cutoff = current - FREE_WINDOW_SECONDS
        self.free_timestamps = [ts for ts in self.free_timestamps if ts >= cutoff]
        if self.paid_expires_at and self.paid_expires_at <= current:
            self.paid_expires_at = 0
            self.paid_remaining = 0
            self.paid_session_id = ""

    def free_used(self, now: int | None = None) -> int:
        self.prune(now)
        return len(self.free_timestamps)

    def free_remaining(self, now: int | None = None) -> int:
        return max(0, FREE_MESSAGE_LIMIT - self.free_used(now))

    def paid_active(self, now: int | None = None) -> bool:
        self.prune(now)
        return self.paid_expires_at > (now if now is not None else _now()) and self.paid_remaining > 0

    def can_send(self, now: int | None = None) -> bool:
        return self.paid_active(now) or self.free_remaining(now) > 0

    def consume(self, now: int | None = None) -> str:
        current = now if now is not None else _now()
        self.prune(current)
        if self.paid_active(current):
            self.paid_remaining -= 1
            return "paid"
        if self.free_remaining(current) <= 0:
            raise QuotaExhausted()
        self.free_timestamps.append(current)
        return "free"

    def grant_paid(self, session_id: str, now: int | None = None) -> None:
        current = now if now is not None else _now()
        self.paid_expires_at = current + PAID_TTL_SECONDS
        self.paid_remaining = PAID_MESSAGE_LIMIT
        self.paid_session_id = session_id

    def snapshot(self, now: int | None = None) -> dict[str, Any]:
        current = now if now is not None else _now()
        self.prune(current)
        return {
            "visitor_id": self.visitor_id,
            "free_remaining": self.free_remaining(current),
            "free_limit": FREE_MESSAGE_LIMIT,
            "paid_active": self.paid_active(current),
            "paid_remaining": self.paid_remaining if self.paid_active(current) else 0,
            "paid_expires_at": self.paid_expires_at if self.paid_active(current) else 0,
            "can_send": self.can_send(current),
        }

    def to_payload(self) -> dict[str, Any]:
        return {
            "v": COOKIE_VERSION,
            "vid": self.visitor_id,
            "free": list(self.free_timestamps),
            "paid_exp": self.paid_expires_at,
            "paid_left": self.paid_remaining,
            "paid_sid": self.paid_session_id,
            "rid": self.previous_response_id,
        }

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> VisitorState:
        visitor_id = str(payload.get("vid") or "").strip() or str(uuid.uuid4())
        free_raw = payload.get("free") or []
        free_timestamps = []
        if isinstance(free_raw, list):
            for item in free_raw:
                try:
                    free_timestamps.append(int(item))
                except (TypeError, ValueError):
                    continue
        try:
            paid_expires_at = int(payload.get("paid_exp") or 0)
        except (TypeError, ValueError):
            paid_expires_at = 0
        try:
            paid_remaining = int(payload.get("paid_left") or 0)
        except (TypeError, ValueError):
            paid_remaining = 0
        return cls(
            visitor_id=visitor_id,
            free_timestamps=free_timestamps,
            paid_expires_at=max(0, paid_expires_at),
            paid_remaining=max(0, paid_remaining),
            paid_session_id=str(payload.get("paid_sid") or ""),
            previous_response_id=str(payload.get("rid") or ""),
        )


class QuotaExhausted(RuntimeError):
    """Visitor has no remaining free or paid messages."""


class QuotaStore:
    """Cookie-backed quota with a process-local hashed-IP ledger."""

    def __init__(self, secret: str | None = None) -> None:
        self.secret = secret if secret is not None else signing_secret()
        self._ip_free: dict[str, list[int]] = {}

    def _sign(self, body: str) -> str:
        return hmac.new(self.secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()

    def dump_cookie(self, state: VisitorState) -> str:
        body = json.dumps(state.to_payload(), separators=(",", ":"), sort_keys=True)
        return f"{_b64(body)}.{self._sign(body)}"

    def load_cookie(self, raw: str | None) -> VisitorState:
        if not raw or "." not in raw or not self.secret:
            return VisitorState(visitor_id=str(uuid.uuid4()))
        encoded, signature = raw.rsplit(".", 1)
        try:
            body = _unb64(encoded)
        except ValueError:
            return VisitorState(visitor_id=str(uuid.uuid4()))
        expected = self._sign(body)
        if not hmac.compare_digest(expected, signature):
            return VisitorState(visitor_id=str(uuid.uuid4()))
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return VisitorState(visitor_id=str(uuid.uuid4()))
        if not isinstance(payload, dict) or payload.get("v") != COOKIE_VERSION:
            return VisitorState(visitor_id=str(uuid.uuid4()))
        state = VisitorState.from_payload(payload)
        state.prune()
        return state

    def bind_ip(self, state: VisitorState, ip: str, now: int | None = None) -> VisitorState:
        current = now if now is not None else _now()
        digest = hash_ip(ip, self.secret or "recipe-chat")
        timestamps = [ts for ts in self._ip_free.get(digest, []) if ts >= current - FREE_WINDOW_SECONDS]
        self._ip_free[digest] = timestamps
        if len(timestamps) > state.free_used(current):
            state.free_timestamps = list(timestamps)
        return state

    def record_ip_free(self, ip: str, timestamp: int) -> None:
        digest = hash_ip(ip, self.secret or "recipe-chat")
        cutoff = timestamp - FREE_WINDOW_SECONDS
        existing = [ts for ts in self._ip_free.get(digest, []) if ts >= cutoff]
        existing.append(timestamp)
        self._ip_free[digest] = existing

    def consume(self, state: VisitorState, ip: str, now: int | None = None) -> tuple[VisitorState, str]:
        current = now if now is not None else _now()
        self.bind_ip(state, ip, current)
        bucket = state.consume(current)
        if bucket == "free":
            self.record_ip_free(ip, current)
        return state, bucket


def parse_cookie_header(header: str | None, name: str = COOKIE_NAME) -> str:
    if not header:
        return ""
    for part in header.split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        if key.strip() == name:
            return value.strip()
    return ""


def _b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")


def _unb64(text: str) -> str:
    padding = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + padding).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("invalid cookie") from exc
