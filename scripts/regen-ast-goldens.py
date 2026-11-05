#!/usr/bin/env python3
"""Regenerate the feature 0102 golden structural hashes (LLD D14; "goldens as a reviewed diff").

The golden inputs and the digest have ONE definition (D19):
``agents/shared/tests/unit/ast/test_0102_golden.py``. This script imports that module, writes
each input's ``structural_digest`` of its ``model_for`` into
``_golden/<language>/<input>.sha256`` (one line, 64 lowercase hex digits) and removes every
golden that has no input. Each input is parsed once, through a real worker and the real
grammar, exactly as the test parses it.

An input whose model contradicts its declared parse — a clean input whose model has an ERROR
node, or a syntax-error input whose model has none — is REFUSED: its golden is left as it is
and the run exits 1, because no golden may enshrine a misparse (§16 risk 18). Fix the layer,
then regenerate.

Run it with the agents' interpreter (the workers need ``tree_sitter``), then review the diff:

    agents/.venv/bin/python scripts/regen-ast-goldens.py           # write, report each golden
    agents/.venv/bin/python scripts/regen-ast-goldens.py --check   # report only, write nothing
    git diff -- agents/shared/tests/unit/ast/_golden

Exit status: 0 when every golden is current (written, or already so); 1 when an input was
refused or, under ``--check``, a golden would change.
"""

from __future__ import annotations

import argparse
import importlib
import sys
import tempfile
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

REPO = Path(__file__).resolve().parent.parent
SHARED = REPO / "agents" / "shared"
GOLDEN_MODULE = "tests.unit.ast.test_0102_golden"

# A golden this run would rewrite, and what "current" means for the exit status.
_STALE = frozenset({"new", "changed", "removed"})
# The actions that write the input's digest.
_WRITTEN = frozenset({"new", "changed"})

Plan = list[tuple[str, Path]]


def _golden_module() -> ModuleType:
    """The golden test module of THIS checkout: ``agents/shared`` goes first on ``sys.path``,
    so neither an installed nor an editable ``shared`` of another checkout answers."""
    sys.path.insert(0, str(SHARED))
    try:
        return importlib.import_module(GOLDEN_MODULE)
    except ModuleNotFoundError as exc:
        raise SystemExit(f"{exc}: run with the agents interpreter, agents/.venv/bin/python") from exc


def _content(digest: str) -> bytes:
    """A golden file's bytes: the digest and one newline."""
    return f"{digest}\n".encode("ascii")


def _misparse(case: Any, model: Any) -> str | None:
    """Why ``case`` (a ``GoldenCase``) has a model that contradicts its declared parse, or
    None when the two agree."""
    if (model.error_nodes == 0) == case.clean:
        return None
    declared = "clean" if case.clean else "a syntax error"
    return f"declared {declared}, but its model has {model.error_nodes} ERROR node(s)"


def _measured(golden: ModuleType, case: Any, workdir: Path) -> tuple[str, str | None]:
    """One input's current digest and its refusal (None: none), both from ONE model."""
    model = golden.model_for(case.name, case.source, workdir / case.language)
    return golden.structural_digest(model), _misparse(case, model)


def _measure(golden: ModuleType) -> tuple[dict[Path, str], dict[Path, str]]:
    """The current digests and the refusals, from a private scratch tree; the pool's workers
    are ended before returning."""
    from shared.ast.pool import get_pool

    with tempfile.TemporaryDirectory(prefix="ast-goldens-") as scratch:
        try:
            measured = {case.golden: _measured(golden, case, Path(scratch)) for case in golden.CASES}
        finally:
            get_pool().close()
    return _split(measured)


def _split(measured: Mapping[Path, tuple[str, str | None]]) -> tuple[dict[Path, str], dict[Path, str]]:
    """Each input's digest, and each refused input's reason."""
    digests = {path: digest for path, (digest, _) in measured.items()}
    refused = {path: reason for path, (_, reason) in measured.items() if reason is not None}
    return digests, refused


def _status(path: Path, digest: str) -> str:
    """``new``, ``unchanged`` or ``changed``: the golden on disk against ``digest``."""
    if not path.is_file():
        return "new"
    return "unchanged" if path.read_bytes() == _content(digest) else "changed"


def _plan(digests: Mapping[Path, str], refused: Mapping[Path, str], on_disk: set[Path]) -> Plan:
    """One action per golden: each input's status (or ``refused``), then every stray file."""
    inputs = [
        ("refused" if path in refused else _status(path, digest), path)
        for path, digest in sorted(digests.items())
    ]
    return inputs + [("removed", path) for path in sorted(on_disk - digests.keys())]


def _write(path: Path, digest: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_content(digest))


def _apply(plan: Plan, digests: Mapping[Path, str]) -> None:
    """Carry the plan out: write each new or changed golden, delete each stray one."""
    for action, path in plan:
        if action in _WRITTEN:
            _write(path, digests[path])
        elif action == "removed":
            path.unlink()


def _prune(golden_dir: Path) -> None:
    """Drop a language directory the removals left empty."""
    for directory in golden_dir.glob("*/"):
        if not any(directory.iterdir()):
            directory.rmdir()


def _line(action: str, path: Path, refused: Mapping[Path, str]) -> str:
    """One golden's action, its repository path and, when refused, why."""
    reason = f"  ({refused[path]})" if path in refused else ""
    return f"{action:9} {path.relative_to(REPO)}{reason}"


def _exit_status(counts: Counter[str], check: bool) -> int:
    """1 when an input was refused, or when ``--check`` finds a golden that would change."""
    stale = check and not _STALE.isdisjoint(counts)
    return int(counts["refused"] > 0 or stale)


def _report(plan: Plan, refused: Mapping[Path, str], check: bool) -> int:
    """Print one line per golden and a summary; the exit status."""
    print("\n".join(_line(action, path, refused) for action, path in plan))
    counts = Counter(action for action, _ in plan)
    print(", ".join(f"{count} {action}" for action, count in sorted(counts.items())))
    return _exit_status(counts, check)


def _grammar_line() -> str:
    """The ten package versions the goldens are generated against (D15)."""
    from shared.ast.profile import GRAMMAR_VERSIONS

    return "grammar pack: " + ", ".join(f"{n} {v}" for n, v in sorted(GRAMMAR_VERSIONS.items()))


def main(argv: list[str] | None = None) -> int:
    """Regenerate (or, with ``--check``, compare) every golden; the exit status."""
    parser = argparse.ArgumentParser(description="Regenerate the feature 0102 AST goldens.")
    parser.add_argument("--check", action="store_true", help="report only; write nothing")
    args = parser.parse_args(argv)
    golden = _golden_module()
    print(_grammar_line())
    digests, refused = _measure(golden)
    # The test module's own stray-file inventory, so "stray" means what its test means.
    plan = _plan(digests, refused, golden._golden_files())
    if not args.check:
        _apply(plan, digests)
        _prune(golden.GOLDEN_DIR)
    return _report(plan, refused, args.check)


if __name__ == "__main__":
    sys.exit(main())
