from __future__ import annotations

import socket
import unittest

from tests.hermetic_network import guard_is_active


class HermeticGuardBootstrapTests(unittest.TestCase):
    def test_guard_is_active_without_depending_on_import_order(self) -> None:
        self.assertTrue(guard_is_active())
        self.assertTrue(getattr(socket.create_connection, "_hermetic_guard", False))
        self.assertTrue(getattr(socket.getaddrinfo, "_hermetic_guard", False))
        self.assertTrue(getattr(socket.socket.connect, "_hermetic_guard", False))
        self.assertTrue(getattr(socket.socket.connect_ex, "_hermetic_guard", False))
        self.assertTrue(getattr(socket.socket.sendto, "_hermetic_guard", False))
        self.assertTrue(getattr(socket.socket.sendmsg, "_hermetic_guard", False))


if __name__ == "__main__":
    unittest.main()
