"""What a fresh interpreter has loaded after one import.

Inside pytest, ``sys.modules`` holds whatever earlier tests imported, so an
in-process "is X loaded?" check passes or fails on test order rather than on
the import graph. ``loaded_after_import`` asks a NEW interpreter instead,
started in the shared package root so ``-c`` puts this checkout's ``shared``
first on ``sys.path``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

# agents/shared/: this file is agents/shared/tests/support/fresh_import.py.
_SHARED_ROOT = Path(__file__).resolve().parents[2]


def loaded_after_import(module: str, watch: tuple[str, ...]) -> list[str]:
    """The names in ``watch`` present in ``sys.modules`` after ``import module``.

    The probe prints its answer as JSON on its LAST stdout line, so an import
    that writes to stdout cannot corrupt it. A failed import fails the caller
    with the probe's stderr (``No module named ...``) in the message.
    """
    probe = (
        "import json, sys\n"
        f"import {module}\n"
        f"print(json.dumps([m for m in {watch!r} if m in sys.modules]))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=str(_SHARED_ROOT),
        # PYTHONSAFEPATH would drop the cwd from sys.path and let an installed
        # `shared` answer for this checkout.
        env={k: v for k, v in os.environ.items() if k != "PYTHONSAFEPATH"},
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, f"probe failed to import {module}:\n{proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])
