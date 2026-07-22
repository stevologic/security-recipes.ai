#!/usr/bin/env python3
"""Fail2Ban ignorecommand for forward-confirmed Googlebot addresses.

Exit 0 only when the supplied public IP has a googlebot.com PTR hostname and
that hostname resolves back to the same IP. Every error fails closed so the
candidate remains subject to the jail.
"""

from __future__ import annotations

import ipaddress
import signal
import socket
import sys
from collections.abc import Callable, Sequence


GOOGLEBOT_SUFFIX = ".googlebot.com"
LOOKUP_TIMEOUT_SECONDS = 5

ReverseLookup = Callable[[str], tuple[str, list[str], list[str]]]
ForwardLookup = Callable[..., Sequence[tuple[object, object, object, str, tuple[object, ...]]]]


def _is_googlebot_hostname(hostname: str) -> bool:
    normalized = hostname.rstrip(".").lower()
    return bool(normalized) and normalized.endswith(GOOGLEBOT_SUFFIX)


def is_verified_googlebot(
    raw_ip: str,
    *,
    reverse_lookup: ReverseLookup = socket.gethostbyaddr,
    forward_lookup: ForwardLookup = socket.getaddrinfo,
) -> bool:
    """Return whether raw_ip passes Google's reverse-then-forward DNS check."""

    try:
        candidate = ipaddress.ip_address(raw_ip)
    except ValueError:
        return False
    if not candidate.is_global:
        return False

    try:
        hostname = reverse_lookup(str(candidate))[0].rstrip(".").lower()
    except (OSError, socket.herror, socket.gaierror):
        return False
    if not _is_googlebot_hostname(hostname):
        return False

    family = socket.AF_INET if candidate.version == 4 else socket.AF_INET6
    try:
        answers = forward_lookup(hostname, None, family, socket.SOCK_STREAM)
    except (OSError, socket.herror, socket.gaierror):
        return False

    for answer in answers:
        socket_address = answer[4]
        if not socket_address:
            continue
        try:
            resolved = ipaddress.ip_address(str(socket_address[0]).split("%", 1)[0])
        except ValueError:
            continue
        if resolved == candidate:
            return True
    return False


class _LookupTimedOut(Exception):
    pass


def _timeout_handler(_signum: int, _frame: object) -> None:
    raise _LookupTimedOut


def verify_with_deadline(raw_ip: str) -> bool:
    """Bound resolver latency when invoked by Fail2Ban on Linux."""

    if not hasattr(signal, "SIGALRM"):
        return is_verified_googlebot(raw_ip)

    previous_handler = signal.signal(signal.SIGALRM, _timeout_handler)
    signal.alarm(LOOKUP_TIMEOUT_SECONDS)
    try:
        return is_verified_googlebot(raw_ip)
    except _LookupTimedOut:
        return False
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_handler)


def main(argv: Sequence[str]) -> int:
    if len(argv) != 2:
        print(f"Usage: {argv[0]} IP", file=sys.stderr)
        return 2
    try:
        ipaddress.ip_address(argv[1])
    except ValueError:
        print("IP must be one valid IPv4 or IPv6 address.", file=sys.stderr)
        return 2
    return 0 if verify_with_deadline(argv[1]) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
