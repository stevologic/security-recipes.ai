from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

_MISSING_GUARD_MESSAGE = "hermetic guard is missing or did not block outbound connect"

# Import only ``tests`` (not ``tests.hermetic_network``) so this fails if
# ``tests/__init__.py`` stops installing the guard. The hermetic_network
# module must not auto-install on import. Probe TEST-NET-1 (RFC 5737) so a
# missing guard never opens a real public connection.
_BOOTSTRAP_RESULT_HANDLER = f"""\
except BaseException as exc:
    if type(exc).__name__ == "HermeticNetworkError":
        raise SystemExit(0)
    raise SystemExit({_MISSING_GUARD_MESSAGE!r})
raise SystemExit({_MISSING_GUARD_MESSAGE!r})
"""

_BOOTSTRAP_PROBE = f"""\
import socket
import tests

try:
    socket.create_connection(("192.0.2.1", 443), timeout=2)
{_BOOTSTRAP_RESULT_HANDLER}
"""


class HermeticGuardBootstrapTests(unittest.TestCase):
    def _run_snippet(self, snippet: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(REPO_ROOT)
        return subprocess.run(
            [sys.executable, "-c", snippet],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_importing_tests_package_blocks_outbound_connect(self) -> None:
        completed = self._run_snippet(_BOOTSTRAP_PROBE)
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"stdout={completed.stdout!r} stderr={completed.stderr!r}",
        )

    def test_timeout_without_guard_reports_missing_guard(self) -> None:
        completed = self._run_snippet(
            f"""\
try:
    raise TimeoutError("timed out")
{_BOOTSTRAP_RESULT_HANDLER}
"""
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(_MISSING_GUARD_MESSAGE, completed.stderr)
        self.assertNotIn("unexpected TimeoutError", completed.stderr)
        self.assertNotIn("unexpected TimeoutError", completed.stdout)

    def test_unblocked_connect_reports_missing_guard(self) -> None:
        completed = self._run_snippet(
            f"""\
try:
    pass
{_BOOTSTRAP_RESULT_HANDLER}
"""
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn(_MISSING_GUARD_MESSAGE, completed.stderr)

    def test_bootstrap_probe_uses_plain_missing_guard_message(self) -> None:
        self.assertIn(_MISSING_GUARD_MESSAGE, _BOOTSTRAP_PROBE)
        self.assertNotIn("unexpected ", _BOOTSTRAP_PROBE)


if __name__ == "__main__":
    unittest.main()
