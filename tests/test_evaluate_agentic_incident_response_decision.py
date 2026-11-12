from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from scripts.evaluate_agentic_incident_response_decision import (
    UNRESOLVED_MONITOR_INTEGRITY_DECISION,
    UNRESOLVED_MONITOR_INTEGRITY_REASON,
    evaluate_agentic_incident_response_decision,
    parse_args,
    request_from_args,
    unresolved_monitor_integrity_violation,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
MONITOR_INTEGRITY_FLAGS = (
    "agent_can_access_monitors",
    "monitor_tampering_or_outage",
    "resume_without_verified_containment",
)
CLI_FLAG_BY_FIELD = {
    "agent_can_access_monitors": "--agent-can-access-monitors",
    "monitor_tampering_or_outage": "--monitor-tampering-or-outage",
    "resume_without_verified_containment": "--resume-without-verified-containment",
}


def _minimal_pack() -> dict[str, object]:
    return {
        "incident_classes": [
            {
                "id": "mcp-authorization-confused-deputy",
                "title": "MCP authorization confused deputy or token passthrough",
                "default_severity": "sev0",
                "default_decision": "kill_session_and_escalate_board",
            },
            {
                "id": "uninstructed-control-compromise",
                "title": "Uninstructed control-compromise or monitor interference",
                "default_severity": "sev0",
                "default_decision": "kill_session_and_escalate_board",
            },
            {
                "id": "evidence-integrity-gap",
                "title": "Evidence integrity, receipt, or replay gap",
                "default_severity": "sev2",
                "default_decision": "hold_for_forensics",
            },
            {
                "id": "context-poisoning",
                "title": "Context poisoning or prompt-injection intake",
                "default_severity": "sev3",
                "default_decision": "triage_and_monitor",
            },
        ],
        "workflow_response_matrix": [
            {
                "workflow_id": "vulnerable-dependency-remediation",
                "title": "Vulnerable dependency remediation",
                "default_response_decision": "contain_and_open_war_room",
                "readiness_decision": "hold",
                "risk_tier": "medium",
                "severity_floor": "sev1",
            }
        ],
        "response_phases": [{"id": "detect-and-classify"}],
        "incident_contract": {
            "required_runtime_fields": [
                "incident_id",
                "workflow_id",
                "run_id",
                "agent_id",
                "identity_id",
                "tenant_id",
                "correlation_id",
                "incident_class_id",
                "receipt_id",
            ]
        },
    }


def _request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "incident_id": "inc-ci",
        "workflow_id": "vulnerable-dependency-remediation",
        "run_id": "run-ci",
        "agent_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "identity_id": "sr-agent::vulnerable-dependency-remediation::codex",
        "tenant_id": "tenant-demo",
        "correlation_id": "corr-ci",
        "incident_class_id": "evidence-integrity-gap",
        "severity_signal": "sev2",
        "source_event_ids": ["event-1"],
        "receipt_id": "receipt-ci",
        "context_source_ids": ["workflow-manifest"],
        "context_source_hashes": ["hash-ci"],
        "mcp_namespaces": ["repo.contents"],
        "authorization_decisions": ["allow_authorized_mcp_request"],
        "containment_action_ids": ["pause_agent_run"],
        "replay_case_ids": ["replay-ci"],
        "agent_can_access_monitors": False,
        "monitor_tampering_or_outage": False,
        "resume_without_verified_containment": False,
    }
    request.update(overrides)
    return request


def _monitor_clear_request(**overrides: object) -> dict[str, object]:
    payload = _request(
        incident_class_id="context-poisoning",
        severity_signal="sev3",
    )
    payload.update(overrides)
    return payload


def _cli_argv(*extra: str) -> list[str]:
    return [
        "--incident-id",
        "inc-ci",
        "--workflow-id",
        "vulnerable-dependency-remediation",
        "--run-id",
        "run-ci",
        "--agent-id",
        "sr-agent::vulnerable-dependency-remediation::codex",
        "--identity-id",
        "sr-agent::vulnerable-dependency-remediation::codex",
        "--tenant-id",
        "tenant-demo",
        "--correlation-id",
        "corr-ci",
        "--incident-class-id",
        "context-poisoning",
        "--severity-signal",
        "sev3",
        "--source-event-id",
        "event-1",
        "--receipt-id",
        "receipt-ci",
        "--context-source-id",
        "workflow-manifest",
        "--context-source-hash",
        "hash-ci",
        "--mcp-namespace",
        "repo.contents",
        "--authorization-decision",
        "allow_authorized_mcp_request",
        "--containment-action-id",
        "pause_agent_run",
        "--replay-case-id",
        "replay-ci",
        *extra,
    ]


def _evaluate_cli(*extra: str) -> dict[str, object]:
    return evaluate_agentic_incident_response_decision(
        _minimal_pack(),
        request_from_args(parse_args(_cli_argv(*extra))),
    )


def _evaluate_json(payload: dict[str, object]) -> dict[str, object]:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "runtime-request.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        request = request_from_args(parse_args(["--runtime-request", str(path)]))
    return evaluate_agentic_incident_response_decision(_minimal_pack(), request)


class MonitorIsolationDecisionTests(unittest.TestCase):
    def test_unspecified_monitor_evidence_keeps_token_passthrough_kill(self) -> None:
        result = evaluate_agentic_incident_response_decision(
            _minimal_pack(),
            _request(
                incident_class_id="mcp-authorization-confused-deputy",
                severity_signal="sev1",
                token_passthrough=True,
            ),
        )
        self.assertEqual(result["decision"], "kill_session_and_escalate_board")
        self.assertIn("raw MCP or provider token passthrough was observed", result["violations"])

    def test_explicit_false_monitor_flags_do_not_kill_or_hold(self) -> None:
        result = evaluate_agentic_incident_response_decision(
            _minimal_pack(),
            _monitor_clear_request(),
        )
        self.assertEqual(result["decision"], "monitor_no_incident")
        self.assertTrue(result["allowed"])

    def test_agent_can_access_monitors_kills_the_session(self) -> None:
        result = evaluate_agentic_incident_response_decision(
            _minimal_pack(),
            _request(
                incident_class_id="uninstructed-control-compromise",
                severity_signal="sev1",
                agent_can_access_monitors=True,
            ),
        )
        self.assertEqual(result["decision"], "kill_session_and_escalate_board")
        self.assertFalse(result["allowed"])
        self.assertIn(
            "agent can access or interfere with monitoring processes and logs",
            result["violations"],
        )

    def test_monitor_tampering_or_outage_kills_the_session(self) -> None:
        result = evaluate_agentic_incident_response_decision(
            _minimal_pack(),
            _request(
                incident_class_id="uninstructed-control-compromise",
                severity_signal="sev1",
                monitor_tampering_or_outage=True,
            ),
        )
        self.assertEqual(result["decision"], "kill_session_and_escalate_board")
        self.assertIn("monitor tampering or outage was observed", result["violations"])

    def test_resume_without_verified_containment_holds_for_forensics(self) -> None:
        result = evaluate_agentic_incident_response_decision(
            _minimal_pack(),
            _request(resume_without_verified_containment=True),
        )
        self.assertEqual(result["decision"], "hold_for_forensics")
        self.assertFalse(result["allowed"])
        self.assertIn("resume attempted without verified containment", result["violations"])

    def test_sev0_still_kills_when_resume_is_attempted(self) -> None:
        result = evaluate_agentic_incident_response_decision(
            _minimal_pack(),
            _request(
                incident_class_id="uninstructed-control-compromise",
                severity_signal="sev0",
                resume_without_verified_containment=True,
            ),
        )
        self.assertEqual(result["decision"], "kill_session_and_escalate_board")


class MonitorIntegrityCliJsonPathTests(unittest.TestCase):
    def test_cli_agent_can_access_monitors_kills_via_request_from_args(self) -> None:
        result = _evaluate_cli("--agent-can-access-monitors")
        self.assertIs(
            request_from_args(parse_args(_cli_argv("--agent-can-access-monitors")))[
                "agent_can_access_monitors"
            ],
            True,
        )
        self.assertEqual(result["decision"], "kill_session_and_escalate_board")
        self.assertIn(
            "agent can access or interfere with monitoring processes and logs",
            result["violations"],
        )

    def test_cli_monitor_tampering_or_outage_kills_via_request_from_args(self) -> None:
        result = _evaluate_cli("--monitor-tampering-or-outage")
        self.assertIs(
            request_from_args(parse_args(_cli_argv("--monitor-tampering-or-outage")))[
                "monitor_tampering_or_outage"
            ],
            True,
        )
        self.assertEqual(result["decision"], "kill_session_and_escalate_board")
        self.assertIn("monitor tampering or outage was observed", result["violations"])

    def test_cli_resume_without_verified_containment_holds_via_request_from_args(self) -> None:
        result = _evaluate_cli("--resume-without-verified-containment")
        self.assertIs(
            request_from_args(parse_args(_cli_argv("--resume-without-verified-containment")))[
                "resume_without_verified_containment"
            ],
            True,
        )
        self.assertEqual(result["decision"], "hold_for_forensics")
        self.assertFalse(result["allowed"])
        self.assertIn("resume attempted without verified containment", result["violations"])

    def test_cli_without_monitor_flags_stays_monitor_no_incident(self) -> None:
        request = request_from_args(parse_args(_cli_argv()))
        for key in MONITOR_INTEGRITY_FLAGS:
            self.assertIn(key, request)
            self.assertIs(request[key], False)
        result = evaluate_agentic_incident_response_decision(_minimal_pack(), request)
        self.assertEqual(result["decision"], "monitor_no_incident")
        self.assertTrue(result["allowed"])

    def test_json_string_false_agent_can_access_monitors_does_not_kill(self) -> None:
        result = _evaluate_json(_monitor_clear_request(agent_can_access_monitors="false"))
        self.assertEqual(result["decision"], "monitor_no_incident")
        self.assertTrue(result["allowed"])

    def test_json_string_false_monitor_tampering_or_outage_does_not_kill(self) -> None:
        result = _evaluate_json(_monitor_clear_request(monitor_tampering_or_outage="false"))
        self.assertEqual(result["decision"], "monitor_no_incident")
        self.assertTrue(result["allowed"])

    def test_json_string_false_resume_without_verified_containment_does_not_hold(self) -> None:
        result = _evaluate_json(
            _monitor_clear_request(resume_without_verified_containment="false")
        )
        self.assertEqual(result["decision"], "monitor_no_incident")
        self.assertTrue(result["allowed"])


class MonitorIntegrityFailClosedTests(unittest.TestCase):
    def _assert_fail_closed(self, result: dict[str, object], *flags: str) -> None:
        self.assertEqual(result["decision"], UNRESOLVED_MONITOR_INTEGRITY_DECISION)
        self.assertNotEqual(result["decision"], "monitor_no_incident")
        self.assertNotEqual(result["decision"], "hold_for_forensics")
        self.assertNotEqual(result["decision"], "kill_session_and_escalate_board")
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], UNRESOLVED_MONITOR_INTEGRITY_REASON)
        self.assertIn(unresolved_monitor_integrity_violation(list(flags)), result["violations"])

    def test_json_missing_agent_can_access_monitors_fail_closes(self) -> None:
        payload = _monitor_clear_request()
        del payload["agent_can_access_monitors"]
        self._assert_fail_closed(_evaluate_json(payload), "agent_can_access_monitors")

    def test_json_missing_monitor_tampering_or_outage_fail_closes(self) -> None:
        payload = _monitor_clear_request()
        del payload["monitor_tampering_or_outage"]
        self._assert_fail_closed(_evaluate_json(payload), "monitor_tampering_or_outage")

    def test_json_missing_resume_without_verified_containment_fail_closes(self) -> None:
        payload = _monitor_clear_request()
        del payload["resume_without_verified_containment"]
        self._assert_fail_closed(
            _evaluate_json(payload), "resume_without_verified_containment"
        )

    def test_json_unparseable_monitor_flags_fail_close(self) -> None:
        for key in MONITOR_INTEGRITY_FLAGS:
            for value in ("maybe", None, "", "  "):
                with self.subTest(key=key, value=value):
                    payload = _monitor_clear_request(**{key: value})
                    self._assert_fail_closed(_evaluate_json(payload), key)

    def test_help_documents_required_monitor_fields(self) -> None:
        buffer = io.StringIO()
        with self.assertRaises(SystemExit) as caught, redirect_stdout(buffer):
            parse_args(["--help"])
        self.assertEqual(caught.exception.code, 0)
        help_text = buffer.getvalue()
        for field in MONITOR_INTEGRITY_FLAGS:
            self.assertIn(field, help_text)
        self.assertIn("contain_and_open_war_room", help_text)
        self.assertIn("allowed=false", help_text)

    def test_cli_unwired_monitor_flags_fail_close_and_do_not_resume(self) -> None:
        for key, flag in CLI_FLAG_BY_FIELD.items():
            with self.subTest(key=key):
                request = request_from_args(parse_args(_cli_argv(flag)))
                self.assertIs(request[key], True)
                del request[key]
                result = evaluate_agentic_incident_response_decision(_minimal_pack(), request)
                self._assert_fail_closed(result, key)
                if key == "resume_without_verified_containment":
                    self.assertNotIn(
                        "resume attempted without verified containment",
                        result["violations"],
                    )
                else:
                    self.assertNotEqual(result["decision"], "kill_session_and_escalate_board")


if __name__ == "__main__":
    unittest.main()
