"""Process-wide hermetic socket guard for the unittest suite."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from typing import Any

LOOPBACK_HOSTNAMES = frozenset({"localhost", "localhost.", "ip6-localhost", "ip6-loopback"})


class HermeticNetworkError(BaseException):
    """Raised when a test tries to open a non-loopback socket.

    Subclasses ``BaseException`` so ``except Exception`` cannot swallow it.
    """


_ORIGINAL_SOCKET_CONNECT: Callable[..., Any] = socket.socket.connect
_ORIGINAL_SOCKET_CONNECT_EX: Callable[..., Any] = socket.socket.connect_ex
_ORIGINAL_SOCKET_SENDTO: Callable[..., Any] = socket.socket.sendto
_ORIGINAL_SOCKET_SENDMSG: Callable[..., Any] = socket.socket.sendmsg
_ORIGINAL_CREATE_CONNECTION: Callable[..., Any] = socket.create_connection
_ORIGINAL_GETADDRINFO: Callable[..., Any] = socket.getaddrinfo
_GUARD_INSTALLED = False


def _mark(func: Callable[..., Any]) -> Callable[..., Any]:
    func._hermetic_guard = True  # type: ignore[attr-defined]
    return func


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


def _reject_if_remote_host(host: object, *, family: int = 0) -> None:
    if family == socket.AF_UNIX:
        return
    if host is None:
        return
    if isinstance(host, bytes):
        try:
            host = host.decode("ascii")
        except UnicodeDecodeError:
            host = ""
    if not isinstance(host, str):
        host = str(host)
    if host == "":
        return
    if is_loopback_host(host):
        return
    raise HermeticNetworkError(
        f"hermetic test guard blocked outbound connect to {host!r}"
    )


@_mark
def _guarded_socket_connect(self: socket.socket, address: object) -> None:
    _reject_if_remote(address)
    return _ORIGINAL_SOCKET_CONNECT(self, address)


@_mark
def _guarded_socket_connect_ex(self: socket.socket, address: object) -> int:
    _reject_if_remote(address)
    return _ORIGINAL_SOCKET_CONNECT_EX(self, address)


@_mark
def _guarded_socket_sendto(self: socket.socket, data: object, *args: object) -> int:
    if args:
        _reject_if_remote(args[-1])
    return _ORIGINAL_SOCKET_SENDTO(self, data, *args)


@_mark
def _guarded_socket_sendmsg(
    self: socket.socket,
    buffers: object,
    ancdata: object = None,
    flags: int = 0,
    address: object = None,
) -> int:
    if address is not None:
        _reject_if_remote(address)
    return _ORIGINAL_SOCKET_SENDMSG(self, buffers, ancdata, flags, address)


@_mark
def _guarded_create_connection(address: object, *args: object, **kwargs: object) -> socket.socket:
    _reject_if_remote(address)
    return _ORIGINAL_CREATE_CONNECTION(address, *args, **kwargs)


@_mark
def _guarded_getaddrinfo(
    host: object,
    port: object,
    family: int = 0,
    type: int = 0,
    proto: int = 0,
    flags: int = 0,
) -> list[tuple[Any, ...]]:
    _reject_if_remote_host(host, family=family)
    return _ORIGINAL_GETADDRINFO(host, port, family, type, proto, flags)


def guard_is_active() -> bool:
    """Return True when the live socket module is wrapped by this guard."""
    return bool(
        getattr(socket.create_connection, "_hermetic_guard", False)
        and getattr(socket.getaddrinfo, "_hermetic_guard", False)
        and getattr(socket.socket.connect, "_hermetic_guard", False)
        and getattr(socket.socket.connect_ex, "_hermetic_guard", False)
        and getattr(socket.socket.sendto, "_hermetic_guard", False)
        and getattr(socket.socket.sendmsg, "_hermetic_guard", False)
    )


def install_hermetic_socket_guard() -> None:
    """Patch outbound socket APIs for this process."""
    global _GUARD_INSTALLED
    if _GUARD_INSTALLED and guard_is_active():
        return
    socket.socket.connect = _guarded_socket_connect  # type: ignore[method-assign]
    socket.socket.connect_ex = _guarded_socket_connect_ex  # type: ignore[method-assign]
    socket.socket.sendto = _guarded_socket_sendto  # type: ignore[method-assign]
    socket.socket.sendmsg = _guarded_socket_sendmsg  # type: ignore[method-assign]
    socket.create_connection = _guarded_create_connection  # type: ignore[assignment]
    socket.getaddrinfo = _guarded_getaddrinfo  # type: ignore[assignment]
    _GUARD_INSTALLED = True


install_hermetic_socket_guard()
