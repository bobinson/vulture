"""The prove wire never carries two consecutive user turns.

Feature 0089, item 4.5 follow-up. `_system_turn()` renders whatever role the
LIBRARY says the JSON-API message belongs in. Under ADAPT with a profile that
has no system role (LLD rule 2), that comes back as a USER turn — and the call
site concatenated it in front of the real user turn, putting `['user', 'user']`
on the wire where the pre-flip baseline sent `['system', 'user']`.

The family that motivates rule 2 is gemma, whose chat template is
alternation-strict, so the flip broke precisely the case it was made for. The
item's own guard test asserted a true fact about the LIBRARY (`render()` places
the text in the user turn) and let it stand for a false one about PRODUCTION
(that the call site folds it). Found by adversarial review, not by the suite.

These assertions therefore run against the real `llm_helper` assembly, not
against `render()`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

_PROVE = Path(__file__).resolve().parents[2]
_SHARED = _PROVE.parent / "shared"

# One subprocess per model: `_PROMPT_PROFILE` and `_SYSTEM_TURN` are resolved at
# import from the environment, so re-importing in-process reuses the first
# model's profile. An earlier in-process check reported a false failure that way.
_PROBE = """
import sys, json
sys.path.insert(0, {shared!r}); sys.path.insert(0, {prove!r})
import prove_agent.llm_helper as L
t = L._compose_turns("BODY")
print(json.dumps({{
    "system_role": L._PROMPT_PROFILE.system_role,
    "roles": [x["role"] for x in t],
    "body": "BODY" in t[-1]["content"],
}}))
"""


def _roles(model: str) -> tuple[bool, list[str], bool]:
    out = subprocess.run(
        [sys.executable, "-c", _PROBE.format(shared=str(_SHARED), prove=str(_PROVE))],
        capture_output=True, text=True, env={"VULTURE_LLM_MODEL": model, "PATH": "/usr/bin:/bin"},
    )
    assert out.returncode == 0, out.stderr[-800:]
    d = json.loads(out.stdout.strip().splitlines()[-1])
    return d["system_role"], d["roles"], d["body"]


@pytest.mark.parametrize("model", ["gpt-4o", "google/gemma-4-31b", "qwen/qwen3.6-35b-a3b",
                                   "claude-sonnet-5", "glm-4.6", "kimi-k2"])
def test_no_two_consecutive_user_turns_on_the_wire(model: str):
    _, roles, _ = _roles(model)
    pairs = list(zip(roles, roles[1:]))
    assert not any(a == "user" and b == "user" for a, b in pairs), (
        f"{model}: {roles} — an alternation-strict template rejects or mangles this"
    )


@pytest.mark.parametrize("model", ["gpt-4o", "google/gemma-4-31b"])
def test_the_system_text_reaches_the_model_either_way(model: str):
    """Relocation must not become deletion.

    A fold that dropped the JSON-API instruction would also satisfy the test
    above, so assert the text survives in whichever turn it ends up in.
    """
    has_system, roles, body_present = _roles(model)
    assert body_present, f"{model}: the caller's own prompt was lost"
    assert roles[-1] == "user"
    if has_system:
        assert roles == ["system", "user"], f"{model}: a system-capable profile lost its system turn"
    else:
        assert roles == ["user"], f"{model}: expected the system text folded into the user turn"
