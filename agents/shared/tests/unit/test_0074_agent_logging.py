"""Feature 0074 AC7: the run's ``llm_window`` line reaches every agent's log.

Agents run as ``python -m uvicorn <agent>.main:app``. uvicorn's log config
attaches handlers to its OWN loggers only, so a ``shared.*`` record found no
handler and fell to Python's ``logging.lastResort``, which is WARNING-level:
every INFO line (``llm_window``, ``inferred_ctx``, ``audit_start``...) was
dropped while the WARNING lines appeared. These tests drive the real path —
``uvicorn.Config(...).load()`` configures logging and then imports the app
exactly as the launcher does — in a fresh interpreter per agent, and read
the process's stderr, never ``caplog``.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from shared.transport.sse_app import create_sse_app

_AGENTS_DIR = Path(__file__).resolve().parents[3]
_AGENT_APPS = sorted(
    f"{p.parent.name}.main:app" for p in _AGENTS_DIR.glob("*/*_agent/main.py")
)

_SCRIPT = """
import logging, sys, uvicorn
uvicorn.Config(sys.argv[1], log_level="info").load()
from shared.llm.provider import publish_llm_window
publish_llm_window("gpt-4o")
logging.getLogger("shared.audit_runner").warning("probe_warning_0074")
logging.getLogger(sys.argv[1].split(".")[0] + ".x").info("probe_agent_info_0074")
"""


def _agent_stderr(app_path: str) -> list[str]:
    proc = subprocess.run(
        [sys.executable, "-c", _SCRIPT, app_path],
        capture_output=True, text=True, timeout=120, env=dict(os.environ),
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stderr.splitlines()


def test_every_agent_main_is_discovered() -> None:
    assert len(_AGENT_APPS) >= 10, _AGENT_APPS


def _window_lines(lines: list[str]) -> list[str]:
    return [ln for ln in lines if ln.startswith("llm_window resolved=")]


def _has_window_fields(line: str) -> bool:
    return "provenance=" in line and "model=gpt-4o" in line


@pytest.mark.parametrize("app_path", _AGENT_APPS)
def test_llm_window_line_reaches_agent_log(app_path: str) -> None:
    lines = _agent_stderr(app_path)
    window = _window_lines(lines)
    counts = {
        # The run's single window line, with its provenance and model.
        "llm_window": len(window),
        "llm_window_fields": sum(map(_has_window_fields, window)),
        # Existing visible lines keep their bare format, printed exactly once.
        "warning": lines.count("probe_warning_0074"),
        # The agent's own package logs at INFO through the same setup.
        "agent_info": lines.count("probe_agent_info_0074"),
    }
    assert counts == dict.fromkeys(counts, 1), lines


def _noop_handler(*_args: object) -> None:
    return None


def test_setup_is_idempotent_across_app_builds() -> None:
    for _ in range(3):
        create_sse_app("probe", {}, _noop_handler)
    handlers = logging.getLogger("shared").handlers
    assert sum(getattr(h, "_vulture_agent_log", False) for h in handlers) == 1
