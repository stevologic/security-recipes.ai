"""Unittest package bootstrap.

Install a process-wide hermetic socket guard so no test can open a real
outbound connection to hosts such as api.x.ai or DigitalOcean.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from typing import Any

LOOPBACK_HOSTNAMES = frozenset({"localhost", "localhost.", "ip6-localhost", "ip6-loopback"})


class HermeticNetworkError(RuntimeError):
    """Raised when a test tries to open a non-loopback socket."""


_ORIGINAL_SOCKET_CONNECT: Callable[..., Any] = socket.socket.connect
_ORIGINAL_CREATE_CONNECTION: Callable[..., Any] = socket.create_connection
_GUARD_INSTALLED = False


def _address_host(address: object) -> str | None:
    """Return the peer hostname/IP, or None for UNIX-domain addresses."""
    if isinstance(address, (str, bytes)):
        return None
    if not (isinstance(address, tuple) and address):
        return ""
    host = address[0]
    if isinstance(host, bytes):
        try:
            host = host.decode("ascii")
        except UnicodeDecodeError:
            return ""
    if host is None:
        return ""
    return str(host)


def is_loopback_host(host: str) -> bool:
    """Return True when *host* is a loopback name or address."""
    normalized = host.strip().strip("[]").lower()
    if not normalized:
        return False
    if normalized in LOOPBACK_HOSTNAMES:
        return True
    if "%" in normalized:
        normalized = normalized.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    if ip.is_loopback:
        return True
    mapped = getattr(ip, "ipv4_mapped", None)
    return bool(mapped is not None and mapped.is_loopback)


def _reject_if_remote(address: object) -> None:
    host = _address_host(address)
    if host is None:
        return
    if is_loopback_host(host):
        return
    raise HermeticNetworkError(
        f"hermetic test guard blocked outbound connect to {host!r}"
    )


def _guarded_socket_connect(self: socket.socket, address: object) -> None:
    _reject_if_remote(address)
    return _ORIGINAL_SOCKET_CONNECT(self, address)


def _guarded_create_connection(address: object, *args: object, **kwargs: object) -> socket.socket:
    _reject_if_remote(address)
    return _ORIGINAL_CREATE_CONNECTION(address, *args, **kwargs)


def install_hermetic_socket_guard() -> None:
    """Patch socket.connect and socket.create_connection for this process."""
    global _GUARD_INSTALLED
    if _GUARD_INSTALLED:
        return
    socket.socket.connect = _guarded_socket_connect  # type: ignore[method-assign]
    socket.create_connection = _guarded_create_connection  # type: ignore[assignment]
    _GUARD_INSTALLED = True


install_hermetic_socket_guard()
