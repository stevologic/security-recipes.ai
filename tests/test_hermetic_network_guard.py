from __future__ import annotations

import socket
import _socket
import unittest
from collections.abc import Callable
from typing import Any
from urllib.request import urlopen

from tests import (
    HermeticNetworkError,
    guard_is_active,
    hermetic_network as hn,
    install_hermetic_socket_guard,
    is_loopback_host,
)

TEST_NET_IP = "192.0.2.1"
NUMERIC_NAMEINFO_FLAGS = socket.NI_NUMERICHOST | socket.NI_NUMERICSERV


class HermeticNetworkGuardTests(unittest.TestCase):
    def _assert_unpatched_lookup_gets_through(
        self,
        module: Any,
        name: str,
        original: Callable[..., Any],
        call: Callable[[], Any],
        *,
        expect_error: tuple[type[BaseException], ...] = (),
        expected: Any = None,
    ) -> None:
        """Remove one patch and prove the original lookup is what runs."""
        setattr(module, name, original)
        try:
            self.assertFalse(getattr(getattr(module, name), "_hermetic_guard", False))
            try:
                result = call()
            except HermeticNetworkError:
                self.fail(f"unpatched {name} lookup was still blocked")
            except expect_error:
                result = None
            else:
                if expected is not None:
                    self.assertEqual(result, expected)
        finally:
            install_hermetic_socket_guard()
        self.assertTrue(getattr(getattr(module, name), "_hermetic_guard", False))

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

    def test_gethostbyaddr_for_test_net_is_blocked(self) -> None:
        with self.assertRaises(HermeticNetworkError) as raised:
            socket.gethostbyaddr(TEST_NET_IP)
        self.assertIn(TEST_NET_IP, str(raised.exception))

    def test_getnameinfo_for_test_net_is_blocked(self) -> None:
        with self.assertRaises(HermeticNetworkError) as raised:
            socket.getnameinfo((TEST_NET_IP, 80), 0)
        self.assertIn(TEST_NET_IP, str(raised.exception))

    def test_raw_socket_getaddrinfo_is_blocked(self) -> None:
        with self.assertRaises(HermeticNetworkError) as raised:
            _socket.getaddrinfo(TEST_NET_IP, 80)
        self.assertIn(TEST_NET_IP, str(raised.exception))

    def test_raw_socket_gethostbyaddr_is_blocked(self) -> None:
        with self.assertRaises(HermeticNetworkError) as raised:
            _socket.gethostbyaddr(TEST_NET_IP)
        self.assertIn(TEST_NET_IP, str(raised.exception))

    def test_raw_socket_getnameinfo_is_blocked(self) -> None:
        if not hasattr(_socket, "getnameinfo"):
            self.skipTest("_socket.getnameinfo is not available")
        with self.assertRaises(HermeticNetworkError) as raised:
            _socket.getnameinfo((TEST_NET_IP, 80), 0)
        self.assertIn(TEST_NET_IP, str(raised.exception))

    def test_gethostbyaddr_lookup_gets_through_when_unpatched(self) -> None:
        self._assert_unpatched_lookup_gets_through(
            socket,
            "gethostbyaddr",
            hn._ORIGINAL_GETHOSTBYADDR,
            lambda: socket.gethostbyaddr(TEST_NET_IP),
            expect_error=(OSError,),
        )

    def test_getnameinfo_lookup_gets_through_when_unpatched(self) -> None:
        self._assert_unpatched_lookup_gets_through(
            socket,
            "getnameinfo",
            hn._ORIGINAL_GETNAMEINFO,
            lambda: socket.getnameinfo((TEST_NET_IP, 80), NUMERIC_NAMEINFO_FLAGS),
            expected=(TEST_NET_IP, "80"),
        )

    def test_raw_getaddrinfo_lookup_gets_through_when_unpatched(self) -> None:
        self._assert_unpatched_lookup_gets_through(
            _socket,
            "getaddrinfo",
            hn._ORIGINAL_C_GETADDRINFO,
            lambda: _socket.getaddrinfo(TEST_NET_IP, 80, socket.AF_INET, socket.SOCK_STREAM),
            expected=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", (TEST_NET_IP, 80))],
        )

    def test_raw_gethostbyaddr_lookup_gets_through_when_unpatched(self) -> None:
        self._assert_unpatched_lookup_gets_through(
            _socket,
            "gethostbyaddr",
            hn._ORIGINAL_GETHOSTBYADDR,
            lambda: _socket.gethostbyaddr(TEST_NET_IP),
            expect_error=(OSError,),
        )

    def test_raw_getnameinfo_lookup_gets_through_when_unpatched(self) -> None:
        if not hasattr(_socket, "getnameinfo"):
            self.skipTest("_socket.getnameinfo is not available")
        self._assert_unpatched_lookup_gets_through(
            _socket,
            "getnameinfo",
            hn._ORIGINAL_GETNAMEINFO,
            lambda: _socket.getnameinfo((TEST_NET_IP, 80), NUMERIC_NAMEINFO_FLAGS),
            expected=(TEST_NET_IP, "80"),
        )

    def test_gethostbyname_for_example_com_is_blocked(self) -> None:
        with self.assertRaises(HermeticNetworkError) as raised:
            socket.gethostbyname("example.com")
        self.assertIn("example.com", str(raised.exception))

    def test_gethostbyname_ex_for_example_com_is_blocked(self) -> None:
        with self.assertRaises(HermeticNetworkError) as raised:
            socket.gethostbyname_ex("example.com")
        self.assertIn("example.com", str(raised.exception))

    def test_raw_socket_gethostbyname_is_blocked(self) -> None:
        with self.assertRaises(HermeticNetworkError) as raised:
            _socket.gethostbyname("example.com")
        self.assertIn("example.com", str(raised.exception))

    def test_raw_socket_connect_to_public_ip_is_blocked(self) -> None:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        try:
            with self.assertRaises(HermeticNetworkError) as raised:
                sock.connect(("1.1.1.1", 443))
            self.assertIn("1.1.1.1", str(raised.exception))
        finally:
            sock.close()

    def test_loopback_gethostbyname_still_works(self) -> None:
        self.assertEqual(socket.gethostbyname("127.0.0.1"), "127.0.0.1")

    def test_loopback_gethostbyaddr_still_works(self) -> None:
        name, _aliases, addresses = socket.gethostbyaddr("127.0.0.1")
        self.assertTrue(name)
        self.assertIn("127.0.0.1", addresses)

    def test_loopback_getnameinfo_still_works(self) -> None:
        host, port = socket.getnameinfo(("127.0.0.1", 80), NUMERIC_NAMEINFO_FLAGS)
        self.assertEqual(host, "127.0.0.1")
        self.assertEqual(port, "80")

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
