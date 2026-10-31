from __future__ import annotations

import socket
import unittest
from urllib.error import URLError
from urllib.request import urlopen

from tests import HermeticNetworkError, is_loopback_host


class HermeticNetworkGuardTests(unittest.TestCase):
    def test_loopback_hosts_are_allowed(self) -> None:
        for host in ("127.0.0.1", "127.1.2.3", "::1", "localhost", "localhost."):
            with self.subTest(host=host):
                self.assertTrue(is_loopback_host(host))

    def test_remote_hosts_are_rejected(self) -> None:
        for host in ("api.x.ai", "api.digitalocean.com", "1.1.1.1", "8.8.8.8"):
            with self.subTest(host=host):
                self.assertFalse(is_loopback_host(host))

    def test_create_connection_to_xai_is_blocked(self) -> None:
        with self.assertRaises(HermeticNetworkError) as raised:
            socket.create_connection(("api.x.ai", 443), timeout=2)
        self.assertIn("hermetic", str(raised.exception))
        self.assertIn("api.x.ai", str(raised.exception))

    def test_urlopen_to_xai_api_is_blocked(self) -> None:
        with self.assertRaises((HermeticNetworkError, URLError)) as raised:
            urlopen("https://api.x.ai/v1/models", timeout=2)
        message = str(raised.exception)
        if isinstance(raised.exception, URLError):
            message = str(raised.exception.reason)
        self.assertIn("hermetic", message.lower())
        self.assertIn("api.x.ai", message)

    def test_loopback_create_connection_still_works(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            with socket.create_connection(("127.0.0.1", port), timeout=1) as client:
                self.assertEqual(client.getpeername()[0], "127.0.0.1")


if __name__ == "__main__":
    unittest.main()
