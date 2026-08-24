from __future__ import annotations

import io
import json
import os
import unittest
from typing import Any
from unittest.mock import patch

from scripts.upsert_dev_dns_record import DnsError, main, upsert_a_record


class FakeResponse:
    def __init__(self, payload: dict[str, Any]):
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._raw

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


class UpsertDevDnsRecordTests(unittest.TestCase):
    def test_creates_missing_a_record(self) -> None:
        calls: list[tuple[str, str]] = []

        def opener(request: Any, timeout: int = 30) -> FakeResponse:
            del timeout
            calls.append((request.get_method(), request.full_url))
            if request.get_method() == "GET":
                return FakeResponse({"domain_records": []})
            body = json.loads(request.data.decode("utf-8"))
            self.assertEqual(body["name"], "dev")
            self.assertEqual(body["data"], "64.227.98.210")
            return FakeResponse(
                {"domain_record": {"id": 11, "name": "dev", "data": body["data"], "ttl": 300}}
            )

        result = upsert_a_record("token", "security-recipes.ai", "dev", "64.227.98.210", 300, opener)
        self.assertEqual(result["action"], "created")
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0], "GET")
        self.assertEqual(calls[1][0], "POST")

    def test_leaves_matching_record_unchanged(self) -> None:
        def opener(request: Any, timeout: int = 30) -> FakeResponse:
            del timeout
            self.assertEqual(request.get_method(), "GET")
            return FakeResponse(
                {
                    "domain_records": [
                        {"id": 11, "type": "A", "name": "dev", "data": "64.227.98.210", "ttl": 300}
                    ]
                }
            )

        result = upsert_a_record("token", "security-recipes.ai", "dev", "64.227.98.210", 300, opener)
        self.assertEqual(result["action"], "unchanged")

    def test_updates_wrong_ipv4(self) -> None:
        methods: list[str] = []

        def opener(request: Any, timeout: int = 30) -> FakeResponse:
            del timeout
            methods.append(request.get_method())
            if request.get_method() == "GET":
                return FakeResponse(
                    {
                        "domain_records": [
                            {"id": 11, "type": "A", "name": "dev", "data": "1.2.3.4", "ttl": 300}
                        ]
                    }
                )
            return FakeResponse(
                {"domain_record": {"id": 11, "name": "dev", "data": "64.227.98.210", "ttl": 300}}
            )

        result = upsert_a_record("token", "security-recipes.ai", "dev", "64.227.98.210", 300, opener)
        self.assertEqual(result["action"], "updated")
        self.assertEqual(methods, ["GET", "PUT"])

    def test_refuses_duplicate_a_records(self) -> None:
        def opener(request: Any, timeout: int = 30) -> FakeResponse:
            del timeout
            return FakeResponse(
                {
                    "domain_records": [
                        {"id": 11, "type": "A", "name": "dev", "data": "1.2.3.4"},
                        {"id": 12, "type": "A", "name": "dev", "data": "5.6.7.8"},
                    ]
                }
            )

        with self.assertRaises(DnsError):
            upsert_a_record("token", "security-recipes.ai", "dev", "64.227.98.210", 300, opener)

    def test_missing_token_is_a_config_error(self) -> None:
        stderr = io.StringIO()
        env = {
            key: value
            for key, value in os.environ.items()
            if key != "DIGITALOCEAN_ACCESS_TOKEN"
        }
        with patch.dict("os.environ", env, clear=True):
            with patch("sys.stderr", stderr):
                self.assertEqual(main(["--domain", "security-recipes.ai"]), 2)
        self.assertIn("DIGITALOCEAN_ACCESS_TOKEN is not set", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
