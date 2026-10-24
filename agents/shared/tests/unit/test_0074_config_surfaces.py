"""Feature 0074 fix round — the operator surfaces say what the code does.

Three drift guards, each over a file an operator or CI reads rather than code:

* #27: ``VULTURE_DEDUP_PREFER_DETERMINISTIC`` has had no reader since the
  deterministic-wins preference was hard-wired, so no operator surface may
  still offer it as a prerequisite or a rollback (the same no-op-switch class
  0074 retired ``VULTURE_LLM_TRUST_MODEL_CHECK_ID`` for).
* #23: the documented window-reason vocabulary is the code's closed set
  (``shared.tools.window.WINDOW_REASONS``), and the docs name the anchor stamp's
  ``past_eof`` next to ``out_of_range``, the window stage's name for that fact.
* #33: every test job gates the image build, so ``docker-build`` cannot publish
  an image whose MCP tests failed.

Pure file reads. No network, no model.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[4]

_DEAD_SWITCH = "VULTURE_DEDUP_PREFER_DETERMINISTIC"
# Every surface that told an operator to set the dead switch, or told a reader
# of the code that it still gates anything.
_DEAD_SWITCH_SURFACES = (
    "env.example", "CLAUDE.md", "docker-compose.yml", "docker-compose.readonly.yml",
    "backend/internal/handler/stream_handler.go", "backend/internal/handler/path_canon.go",
)
_GO_ENV_READ = re.compile(r"(Getenv|LookupEnv|EnvFlag|EnvTruthy)\(\s*\"" + _DEAD_SWITCH)

# The two documents that list the window-reason vocabulary for operators.
_WINDOW_DOCS = ("CLAUDE.md", "env.example")


def _read(rel: str) -> str:
    return (_REPO / rel).read_text()


def test_no_go_code_reads_the_dead_dedup_switch():
    """Precondition for #27: the switch really is dead (no Go reader)."""
    readers = [str(p.relative_to(_REPO)) for p in (_REPO / "backend").rglob("*.go")
               if _reads_dead_switch(p)]
    assert readers == [], f"{_DEAD_SWITCH} is read by {readers}; #27 assumes it is dead"


def _reads_dead_switch(path: Path) -> bool:
    """A production Go file that reads the dead switch from the environment."""
    return not path.name.endswith("_test.go") and bool(_GO_ENV_READ.search(path.read_text()))


@pytest.mark.parametrize("surface", _DEAD_SWITCH_SURFACES)
def test_no_surface_offers_the_dead_dedup_switch(surface):
    """#27: a knob with no reader must not be documented as a prerequisite or a
    rollback, nor forwarded to the backend container."""
    assert _DEAD_SWITCH not in _read(surface), (
        f"{surface} still offers {_DEAD_SWITCH}, which no code reads"
    )


@pytest.mark.parametrize("doc", _WINDOW_DOCS)
def test_window_reason_docs_list_the_code_vocabulary(doc):
    """#23: every member of the closed WINDOW_REASONS set is documented."""
    from shared.tools.window import WINDOW_REASONS

    text = _read(doc)
    missing = sorted(r for r in WINDOW_REASONS if not re.search(rf"\b{r}\b", text))
    assert missing == [], f"{doc} omits window reasons {missing}"


@pytest.mark.parametrize("doc", _WINDOW_DOCS)
def test_window_reason_docs_cross_reference_past_eof(doc):
    """#23: one fact, two names. The window stage says `out_of_range`, the
    anchor stamp says `past_eof`; the docs must say they are the same fact."""
    from shared.anchor import RANGE_PAST_EOF
    from shared.tools.window import WINDOW_OUT_OF_RANGE

    lines = [ln for ln in _read(doc).splitlines() if WINDOW_OUT_OF_RANGE in ln]
    window = "\n".join(lines)
    assert RANGE_PAST_EOF in window, (
        f"{doc} documents {WINDOW_OUT_OF_RANGE} without naming {RANGE_PAST_EOF} beside it"
    )


def _needs(job: dict) -> set[str]:
    """A CI job's `needs`, string or list form, as a set."""
    needs = job.get("needs") or []
    return {needs} if isinstance(needs, str) else set(needs)


def test_every_test_job_gates_docker_build():
    """#33: `docker-build` needs every `test-*` job, test-mcp included."""
    jobs = yaml.safe_load(_read(".github/workflows/ci.yml"))["jobs"]
    tests = {j for j in jobs if j.startswith("test-")}
    missing = sorted(tests - _needs(jobs["docker-build"]))
    assert missing == [], f"docker-build does not wait for {missing}"
