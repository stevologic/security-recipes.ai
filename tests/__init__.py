"""Unittest package bootstrap.

Importing this package installs a process-wide hermetic socket guard so no
discovered test can open a real outbound connection to hosts such as api.x.ai.
``python -m unittest discover -s tests -t .`` loads this module; a direct
``python tests/test_x.py`` run does not.
"""

from __future__ import annotations

from tests.hermetic_network import (
    HermeticNetworkError,
    guard_is_active,
    install_hermetic_socket_guard,
    is_loopback_host,
)

install_hermetic_socket_guard()

__all__ = [
    "HermeticNetworkError",
    "guard_is_active",
    "install_hermetic_socket_guard",
    "is_loopback_host",
]
