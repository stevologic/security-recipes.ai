from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Import only ``tests`` (not ``tests.hermetic_network``) so this fails if
# ``tests/__init__.py`` stops installing the guard. The hermetic_network
# module must not auto-install on import. Probe TEST-NET-1 (RFC 5737) so a
# missing guard never opens a real public connection.
_BOOTSTRAP_PROBE = """\
import socket
import tests

try:
    socket.create_connection(("192.0.2.1", 443), timeout=2)
except BaseException as exc:
    if type(exc).__name__ == "HermeticNetworkError":
        raise SystemExit(0)
    raise SystemExit(f"unexpected {type(exc).__name__}: {exc}")
raise SystemExit("importing tests did not block outbound socket connect")
"""


class HermeticGuardBootstrapTests(unittest.TestCase):
    def test_importing_tests_package_blocks_outbound_connect(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(REPO_ROOT)
        completed = subprocess.run(
            [sys.executable, "-c", _BOOTSTRAP_PROBE],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"stdout={completed.stdout!r} stderr={completed.stderr!r}",
        )


if __name__ == "__main__":
    unittest.main()
