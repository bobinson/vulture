"""Feature 0074 test hygiene — the isolation fixture must not hide user-site
packages from SUBPROCESS tests.

``tests.support.isolation.isolate`` moves ``HOME`` under the test's tmp dir so
the L5 cache's ``~/.vulture`` default lands there. Python derives the user site
(``~/.local/lib/pythonX.Y/site-packages``) from ``HOME`` too, so a subprocess
started by a test lost every package installed with ``pip install --user`` —
``test_0074_agent_logging`` and the subprocess case of
``test_0074_use_llm_tokens`` failed with ``ModuleNotFoundError`` whenever the
dependencies lived there rather than in a virtualenv. The fixture now pins the
ORIGINAL user base for children; the L5 cache relocation is unaffected.
"""

from __future__ import annotations

import os
import site
import subprocess
import sys


def test_subprocess_sees_the_original_user_base(tmp_path) -> None:
    assert os.environ["HOME"] == str(tmp_path)  # precondition: HOME was moved
    out = subprocess.run(
        [sys.executable, "-c", "import site; print(site.getuserbase())"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert out == site.getuserbase()
    assert not out.startswith(str(tmp_path)), "the moved HOME must not decide the user site"


def test_l5_cache_still_moves_with_home(tmp_path) -> None:
    from shared.validate import l5_cache

    assert l5_cache._default_path().startswith(str(tmp_path))
