from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import time
import unittest
from pathlib import Path
from unittest import mock

from tools.recipe_chat.config import (
    FREE_MESSAGE_LIMIT,
    PAID_MESSAGE_LIMIT,
    UNLOCK_AMOUNT_CENTS,
    is_development_host,
)
from tools.recipe_chat.grounding import invented_cves, missing_named_cve_reply
from tools.recipe_chat.policy import classify_request
from tools.recipe_chat.quota import QuotaExhausted, QuotaStore, VisitorState
from tools.recipe_chat.service import RecipeChatService, error_payload
from tools.recipe_chat.stripe_checkout import StripeConfigError, reject_live_key_on_development
from tools.recipe_chat.xai_client import extract_output_text


ROOT = Path(__file__).resolve().parents[1]


class FakeRecipes:
    def __init__(self, docs: list[dict]) -> None:
        self.docs = docs

    async def search(self, query: str, limit: int | None = None) -> list[dict]:
        query_l = query.lower()
        hits = [doc for doc in self.docs if query_l in json.dumps(doc).lower()]
        return hits[: limit or 6]

    async def get_doc(self, slug_or_path: str) -> dict | None:
        for doc in self.docs:
            if slug_or_path in {doc.get("slug"), doc.get("path"), doc.get("url")}:
                return doc
        return None


class FakeCves:
    def __init__(self, records: dict[str, dict]) -> None:
        self.records = records

    def get_recipe(self, cve: str) -> dict:
        record = self.records.get(cve.upper())
        if not record:
            return {"found": False, "cve": cve.upper()}
        return {
            "found": True,
            "cve": cve.upper(),
            "source_record": record,
        }


class FakePlaybooks:
    def list_playbooks(self, query: str | None = None, limit: int = 8) -> dict:
        return {"results": []}

    def get_playbook(self, playbook_id: str) -> dict | None:
        return None


class PolicyTests(unittest.TestCase):
    def test_refuses_scan_exploit_and_autofix(self) -> None:
        self.assertEqual(classify_request("scan my repo for vulns").kind, "scan")
        self.assertEqual(classify_request("write an exploit for this CVE").kind, "exploit")
        self.assertEqual(classify_request("autofix this in my repository").kind, "autofix")
        self.assertEqual(classify_request("deploy this to production").kind, "deploy")
        self.assertIsNone(classify_request("Which recipe covers Log4Shell?"))


class QuotaTests(unittest.TestCase):
    def test_free_quota_then_paywall(self) -> None:
        store = QuotaStore(secret="test-secret")
        state = VisitorState(visitor_id="visitor-1")
        for _ in range(FREE_MESSAGE_LIMIT):
            state, bucket = store.consume(state, "203.0.113.10")
            self.assertEqual(bucket, "free")
        with self.assertRaises(QuotaExhausted):
            store.consume(state, "203.0.113.10")
        state.grant_paid("cs_test_paid")
        state, bucket = store.consume(state, "203.0.113.10")
        self.assertEqual(bucket, "paid")
        self.assertEqual(state.paid_remaining, PAID_MESSAGE_LIMIT - 1)

    def test_cleared_cookie_still_counts_hashed_ip(self) -> None:
        store = QuotaStore(secret="test-secret")
        state = VisitorState(visitor_id="visitor-1")
        for _ in range(FREE_MESSAGE_LIMIT):
            state, _bucket = store.consume(state, "198.51.100.4")
        fresh = VisitorState(visitor_id="visitor-2")
        with self.assertRaises(QuotaExhausted):
            store.consume(fresh, "198.51.100.4")

    def test_cookie_survives_round_trip(self) -> None:
        store = QuotaStore(secret="test-secret")
        state = VisitorState(visitor_id="visitor-9")
        store.consume(state, "192.0.2.8")
        restored = store.load_cookie(store.dump_cookie(state))
        self.assertEqual(restored.visitor_id, "visitor-9")
        self.assertEqual(restored.free_used(), 1)


class ServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.recipes = FakeRecipes(
            [
                {
                    "slug": "log4shell",
                    "title": "Log4Shell remediation",
                    "url": "/recipes/cve/cve-2021-44228/",
                    "summary": "Bounded Log4j workflow",
                    "content": "Upgrade Log4j and verify the classpath.",
                }
            ]
        )
        self.catalog = FakeCves(
            {
                "CVE-2021-44228": {
                    "title": "Apache Log4j RCE",
                    "summary": "JNDI lookup remote code execution.",
                }
            }
        )

    def _service(self, complete) -> RecipeChatService:
        return RecipeChatService(
            recipe_index=self.recipes,
            cve_catalog=self.catalog,
            playbook_registry=FakePlaybooks(),
            quota=QuotaStore(secret="test-secret"),
            xai=mock.Mock(complete=complete),
        )

    def test_hidden_without_xai_key(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("XAI_API_KEY", None)
            service = self._service(lambda *_args, **_kwargs: ("unused", "resp_1"))
            status = service.public_status({}, "", "127.0.0.1")
            self.assertFalse(status["enabled"])

    def test_refuses_scan_without_calling_model(self) -> None:
        complete = mock.Mock(side_effect=AssertionError("model should not run"))
        service = self._service(complete)
        with mock.patch("tools.recipe_chat.service.chat_enabled", return_value=True):
            payload, _state = asyncio.run(
                service.answer(
                    "scan my production hosts",
                    cookie="",
                    headers={"host": "dev.security-recipes.ai"},
                    remote_ip="203.0.113.8",
                )
            )
        self.assertEqual(payload["refused"], "scan")
        self.assertIn("does not scan", payload["reply"])
        complete.assert_not_called()

    def test_does_not_invent_a_cve_missing_from_the_site(self) -> None:
        complete = mock.Mock(
            return_value=(
                "CVE-1999-0001 is a critical RCE with CVSS 10.0 at ExampleCorp.",
                "resp_invented",
            )
        )
        service = self._service(complete)
        with mock.patch("tools.recipe_chat.service.chat_enabled", return_value=True):
            payload, _state = asyncio.run(
                service.answer(
                    "What is CVE-1999-0001?",
                    cookie="",
                    headers={"host": "dev.security-recipes.ai"},
                    remote_ip="203.0.113.9",
                )
            )
        self.assertEqual(payload["refused"], "ungrounded_cve")
        self.assertIn("not in the published catalog", payload["reply"])
        self.assertNotIn("ExampleCorp", payload["reply"])
        complete.assert_not_called()

    def test_strips_invented_cve_from_model_output(self) -> None:
        complete = mock.Mock(
            return_value=("Also see CVE-2099-0001 at ExampleCorp.", "resp_2")
        )
        service = self._service(complete)
        with mock.patch("tools.recipe_chat.service.chat_enabled", return_value=True):
            payload, _state = asyncio.run(
                service.answer(
                    "How do I remediate Log4Shell?",
                    cookie="",
                    headers={"host": "dev.security-recipes.ai"},
                    remote_ip="203.0.113.11",
                )
            )
        self.assertNotIn("ExampleCorp", payload["reply"])
        self.assertIn("not in the published catalog", payload["reply"])

    def test_paywall_after_free_sample(self) -> None:
        complete = mock.Mock(return_value=("Use the Log4Shell recipe.", "resp_3"))
        service = self._service(complete)
        cookie = ""
        with mock.patch("tools.recipe_chat.service.chat_enabled", return_value=True):
            for index in range(FREE_MESSAGE_LIMIT):
                payload, state = asyncio.run(
                    service.answer(
                        "Which recipe covers Log4Shell?",
                        cookie=cookie,
                        headers={"host": "localhost"},
                        remote_ip="203.0.113.12",
                    )
                )
                cookie = service.quota.dump_cookie(state)
                self.assertNotIn("refused", payload)
                self.assertEqual(payload["quota"]["free_remaining"], FREE_MESSAGE_LIMIT - index - 1)
            with self.assertRaises(QuotaExhausted):
                asyncio.run(
                    service.answer(
                        "Which recipe covers Log4Shell?",
                        cookie=cookie,
                        headers={"host": "localhost"},
                        remote_ip="203.0.113.12",
                    )
                )
            status, error = error_payload(QuotaExhausted())
            self.assertEqual(status, 402)
            self.assertEqual(error["error"], "paywall")
            self.assertIn("$5", error["message"])

    def test_same_thread_continues_after_unlock(self) -> None:
        complete = mock.Mock(return_value=("Keep going from the same thread.", "resp_4"))
        service = self._service(complete)
        state = VisitorState(visitor_id="same-thread", previous_response_id="resp_3")
        state.grant_paid("cs_test_continue")
        cookie = service.quota.dump_cookie(state)
        with mock.patch("tools.recipe_chat.service.chat_enabled", return_value=True):
            payload, updated = asyncio.run(
                service.answer(
                    "Continue with the Log4Shell recipe.",
                    cookie=cookie,
                    headers={"host": "localhost"},
                    remote_ip="203.0.113.13",
                )
            )
        self.assertEqual(updated.previous_response_id, "resp_4")
        self.assertTrue(payload["quota"]["paid_active"])
        complete.assert_called_once()
        self.assertEqual(complete.call_args.args[2], "resp_3")


class StripeGateTests(unittest.TestCase):
    def test_development_rejects_live_stripe_keys(self) -> None:
        self.assertTrue(is_development_host("dev.security-recipes.ai"))
        with self.assertRaises(StripeConfigError):
            reject_live_key_on_development("dev.security-recipes.ai", "sk_live_example")

    def test_development_accepts_test_keys(self) -> None:
        reject_live_key_on_development("dev.security-recipes.ai", "sk_test_example")


class GroundingHelperTests(unittest.TestCase):
    def test_invented_cve_detection(self) -> None:
        retrieval = {
            "known_cves": ["CVE-2021-44228"],
            "sources": [{"title": "Log4Shell", "excerpt": "", "url": "/cve/CVE-2021-44228/"}],
        }
        self.assertEqual(invented_cves("See CVE-2099-0001", retrieval), ["CVE-2099-0001"])
        self.assertEqual(invented_cves("See CVE-2021-44228", retrieval), [])

    def test_missing_cve_copy(self) -> None:
        text = missing_named_cve_reply(["CVE-1999-0001"])
        self.assertIn("CVE-1999-0001", text)
        self.assertIn("will not invent", text)


class XAIParseTests(unittest.TestCase):
    def test_extracts_output_text(self) -> None:
        payload = {
            "id": "resp_1",
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": "Use the published recipe."}],
                }
            ],
        }
        self.assertEqual(extract_output_text(payload), "Use the published recipe.")


class WiringContractTests(unittest.TestCase):
    def test_nginx_forwards_chat_cookies_to_mcp(self) -> None:
        nginx = (ROOT / "docker" / "nginx" / "default.conf").read_text(encoding="utf-8")
        self.assertIn("location ^~ /api/chat {", nginx)
        block = nginx.split("location ^~ /api/chat {", 1)[1].split("\n    }", 1)[0]
        self.assertIn("proxy_pass $recipe_chat_api$request_uri;", block)
        self.assertNotIn('proxy_set_header Cookie "";', block)
        self.assertIn("limit_req zone=recipe_chat", block)
        self.assertLess(nginx.index("location ^~ /api/chat {"), nginx.index("location ~* \\.(json|xml)$"))

    def test_compose_and_env_document_exact_secret_names(self) -> None:
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
        for name in (
            "XAI_API_KEY",
            "STRIPE_SECRET_KEY",
            "STRIPE_WEBHOOK_SECRET",
            "STRIPE_PUBLISHABLE_KEY",
        ):
            self.assertIn(name, compose)
            self.assertIn(name, env_example)
        self.assertIn("*test* keys", env_example)
        self.assertIn("never sk_live_", env_example)

    def test_pages_include_hidden_chat_entry(self) -> None:
        home = (ROOT / "_includes" / "layouts" / "home-static.html").read_text(encoding="utf-8")
        docs = (ROOT / "_includes" / "layouts" / "docs.njk").read_text(encoding="utf-8")
        partial = (ROOT / "_includes" / "partials" / "recipe-chat.njk").read_text(encoding="utf-8")
        self.assertIn("data-recipe-chat", partial)
        self.assertIn("hidden", partial)
        self.assertIn("Recipe chat", partial)
        self.assertNotIn("copilot", partial.lower())
        self.assertIn("recipe-chat.njk", home)
        self.assertIn('page.url == "/recipes/"', docs)
        self.assertIn('page.url == "/cve-database/"', docs)
        self.assertIn('page.url == "/mcp-servers/"', docs)

    def test_mcp_image_copies_recipe_chat(self) -> None:
        dockerfile = (ROOT / "Dockerfile.mcp-server").read_text(encoding="utf-8")
        self.assertIn("COPY tools/recipe_chat /app/tools/recipe_chat", dockerfile)
        server = (ROOT / "mcp_server.py").read_text(encoding="utf-8")
        self.assertIn("register_recipe_chat_routes", server)

    def test_development_deploy_refreshes_singleton_mcp(self) -> None:
        deploy = (ROOT / "deploy.sh").read_text(encoding="utf-8")
        self.assertIn("start_development_mcp", deploy)
        self.assertIn("${MCP_IMAGE_REPOSITORY}:${target}${DEVELOPMENT_IMAGE_SUFFIX}", deploy)
        self.assertIn("run_mcp_compose mcp-server", deploy)
        track = deploy[deploy.index("deploy_development_track() {") :]
        self.assertLess(
            track.index("start_development_mcp"),
            track.index("start_development_slot"),
        )

    def test_locked_price_numbers(self) -> None:
        self.assertEqual(FREE_MESSAGE_LIMIT, 6)
        self.assertEqual(PAID_MESSAGE_LIMIT, 100)
        self.assertEqual(UNLOCK_AMOUNT_CENTS, 500)


class WebhookSignatureTests(unittest.TestCase):
    def test_accepts_valid_stripe_signature(self) -> None:
        from tools.recipe_chat.stripe_checkout import verify_stripe_signature

        secret = "whsec_test"
        payload = b'{"type":"checkout.session.completed"}'
        timestamp = str(int(time.time()))
        digest = hmac.new(
            secret.encode("utf-8"),
            f"{timestamp}.".encode("utf-8") + payload,
            hashlib.sha256,
        ).hexdigest()
        self.assertTrue(verify_stripe_signature(payload, f"t={timestamp},v1={digest}", secret))
        self.assertFalse(verify_stripe_signature(payload, f"t={timestamp},v1=deadbeef", secret))


if __name__ == "__main__":
    unittest.main()
