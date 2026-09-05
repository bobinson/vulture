"""Write the committed golden render of every manifest. Feature 0089.

A SCRIPT, not a test: pytest must not collect it (no `test_` name, no
module-level work), because writing the file it is asked to compare against
would make the golden gate unfalsifiable. `test_0089_goldens.py` imports
`golden_text` from here so the writer and the checker share one formatter.

Run from `agents/shared`:

    python tests/unit/prompt/capture_goldens.py

Output is byte-deterministic across runs and across machines: TRANSCRIBE emits
no nonce (and no manifest here has slots), nothing in the layout carries a
timestamp or a hostname, and the four captured sections are the profile-
independent ones — the environment can move `output_budget_hint`, which is
deliberately not in the file.
"""

from __future__ import annotations

from pathlib import Path

from shared.prompt import Mode, profile_for, render
from shared.prompt.manifests import MANIFESTS

GOLDEN_DIR = Path(__file__).resolve().parents[3] / "shared" / "prompt" / "goldens"
GOLDEN_PROFILE = "gpt-4o"
CAPTURE_CMD = "cd agents/shared && python tests/unit/prompt/capture_goldens.py"

_NONE = "(none)"


def golden_text(spec, rp) -> str:
    """The golden file body for one rendered manifest.

    Sections are fixed and always all four present, so a prompt that loses its
    system turn shows up as an empty section rather than as a missing one.
    """
    tools = ", ".join(spec.tools) or _NONE
    rf = repr(rp.response_format) if rp.response_format is not None else _NONE
    return "\n".join((
        "=== SYSTEM ===", rp.instructions,
        "=== USER ===", rp.user,
        "=== TOOLS ===", tools,
        "=== RESPONSE_FORMAT ===", rf,
    )) + "\n"


def golden_path(manifest_id: str) -> Path:
    """Where one manifest's golden lives.

    A manifest id may contain `/` (`generate/cwe`), so this is a nested path,
    not a flat filename — and the checker calls the same function, so the two
    cannot disagree about where to look.
    """
    return GOLDEN_DIR / f"{manifest_id}.default.txt"


def capture_one(manifest_id: str) -> Path:
    spec = MANIFESTS[manifest_id]
    rp = render(spec, profile_for(GOLDEN_PROFILE), mode=Mode.TRANSCRIBE)
    path = golden_path(manifest_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(golden_text(spec, rp), encoding="utf-8")
    return path


def main() -> int:
    for manifest_id in sorted(MANIFESTS):
        print(f"wrote {capture_one(manifest_id)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
