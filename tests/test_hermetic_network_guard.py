from __future__ import annotations

import socket
import unittest
from urllib.request import urlopen

from tests import HermeticNetworkError, guard_is_active, is_loopback_host


class HermeticNetworkGuardTests(unittest.TestCase):
    def test_guard_is_active_on_the_live_socket_module(self) -> None:
        self.assertTrue(guard_is_active())

    def test_loopback_hosts_are_allowed(self) -> None:
        for host in ("127.0.0.1", "127.1.2.3", "::1", "localhost", "localhost."):
            with self.subTest(host=host):
                self.assertTrue(is_loopback_host(host))

    def test_remote_hosts_are_rejected(self) -> None:
        for host in ("api.x.ai", "api.digitalocean.com", "1.1.1.1", "8.8.8.8", "example.com"):
            with self.subTest(host=host):
                self.assertFalse(is_loopback_host(host))

    def test_create_connection_to_xai_is_blocked(self) -> None:
        with self.assertRaises(HermeticNetworkError) as raised:
            socket.create_connection(("api.x.ai", 443), timeout=2)
        self.assertIn("hermetic", str(raised.exception))
        self.assertIn("api.x.ai", str(raised.exception))

    def test_connect_ex_to_public_ip_is_blocked(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            with self.assertRaises(HermeticNetworkError) as raised:
                sock.connect_ex(("1.1.1.1", 443))
        self.assertIn("1.1.1.1", str(raised.exception))

    def test_getaddrinfo_for_example_com_is_blocked(self) -> None:
        with self.assertRaises(HermeticNetworkError) as raised:
            socket.getaddrinfo("example.com", 443)
        self.assertIn("example.com", str(raised.exception))

    def test_udp_sendto_to_public_resolver_is_blocked(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            with self.assertRaises(HermeticNetworkError) as raised:
                sock.sendto(b"\x00", ("1.1.1.1", 53))
        self.assertIn("1.1.1.1", str(raised.exception))

    def test_urlopen_to_xai_api_is_blocked(self) -> None:
        with self.assertRaises(HermeticNetworkError) as raised:
            urlopen("https://api.x.ai/v1/models", timeout=2)
        self.assertIn("hermetic", str(raised.exception).lower())
        self.assertIn("api.x.ai", str(raised.exception))

    def test_exception_handler_cannot_swallow_the_guard(self) -> None:
        swallowed = False
        try:
            try:
                urlopen("https://api.x.ai/v1/models", timeout=2)
            except Exception:
                swallowed = True
        except HermeticNetworkError:
            self.assertFalse(swallowed)
            return
        self.fail("hermetic guard was swallowed by except Exception")

    def test_loopback_create_connection_still_works(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            with socket.create_connection(("127.0.0.1", port), timeout=1) as client:
                self.assertEqual(client.getpeername()[0], "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
