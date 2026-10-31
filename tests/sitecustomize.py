"""Install the hermetic socket guard when a test file is run directly.

``python tests/test_foo.py`` puts this directory on ``sys.path`` before
``site`` imports ``sitecustomize``. Package discovery uses ``-t .`` and
``tests/__init__.py`` instead.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tests.hermetic_network import install_hermetic_socket_guard

install_hermetic_socket_guard()
