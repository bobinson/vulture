"""Feature 0101 revision 3 (RED-R3R2-B1) -- one CWE-209 scan never sees another's state.

The agent runs audits on a thread pool, so two scans of the CWE-209 rule can
overlap in one process. Measured on the revision-2 module: 8 threads scanning
two 40-file trees, 20 trials -- 9 of 160 thread-runs raised `KeyError` while
evicting the shared per-file state cache. The revision-3 arms add per-scan
state (the emitted rows, the line being judged, rule P's parameter frames, the
tree's declaration index), so the contract is pinned here:

* concurrent scans of disjoint trees each report exactly what they report alone,
  and raise nothing;
* scanning the same content twice in one process gives identical rows;
* a per-file memo is never reused for a different file whose line list happens
  to get the same `id()` (a clean file after a disclosing one stays clean).
"""
from __future__ import annotations

import gc
import shutil
import sys
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from cwe_agent.skills import info_exposure_check as iec

FILES = 40
THREADS = 8
TRIALS = 20
REUSE_ROUNDS = 200
FILLERS = 9


def _source(k: int, tag: str) -> str:
    """Base-rule sinks and revision-3 arm shapes (F, W, C1) in one file."""
    return (
        f"async function load{tag}{k}(id) {{\n"
        f"  try {{ return {{ ok: true, data: await store.read(id) }}; }}\n"
        f"  catch (err) {{ return {{ ok: false, error: err.message }}; }}\n"
        f"}}\n"
        f"export async function show{tag}{k}(req, res) {{\n"
        f"  const outcome = await load{tag}{k}(req.params.id);\n"
        f"  if (!outcome.ok) return res.status(500).json({{ error: outcome.error }});\n"
        f"  try {{ await go{k}(); }} catch (err) {{ res.status(500).json({{ error: err.message }}); }}\n"
        f"}}\n"
        f"export function fill{tag}{k}(req, res) {{\n"
        f"  const out: any = {{ ok: true }};\n"
        f"  try {{ run{k}(); }} catch (err) {{ out.error = String(err); }}\n"
        f"  res.json(out);\n"
        f"  try {{ run{k}(); }} catch (err) {{ jsonError(res, 500, String(err)); }}\n"
        f"}}\n"
    )


def _tree(base: Path, tag: str) -> Path:
    root = base / f"tree{tag}" / "app"
    root.mkdir(parents=True)
    for k in range(FILES):
        (root / f"{tag}{k}.ts").write_text(_source(k, tag))
    return root


@pytest.fixture(scope="module")
def trees() -> Iterator[tuple[Path, Path]]:
    """Two disjoint trees in a plain temporary directory (pytest's own names a test path)."""
    base = Path(tempfile.mkdtemp())
    try:
        yield _tree(base, "a"), _tree(base, "b")
    finally:
        shutil.rmtree(base)


def _rows(root: Path) -> list[tuple[str, int, str]]:
    found = iec.check_information_exposure(str(root))["findings"]
    return sorted((Path(f["file_path"]).name, f["line_start"], f["category"]) for f in found)


def test_concurrent_scans_equal_their_solo_scans(trees: tuple[Path, Path]) -> None:
    roots = list(trees) * (THREADS // 2)
    solo = {root: _rows(root) for root in trees}
    errors: list[str] = []
    wrong = 0
    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        for _ in range(TRIALS):
            out: dict[int, object] = {}
            threads = [threading.Thread(target=_scan_into, args=(out, i, root)) for i, root in enumerate(roots)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            errors += [v for v in out.values() if isinstance(v, str)]
            wrong += sum(1 for i, v in out.items() if not isinstance(v, str) and v != solo[roots[i]])
    finally:
        sys.setswitchinterval(previous)
    assert not errors, f"{len(errors)} of {TRIALS * len(roots)} thread-runs raised: {errors[0]}"
    assert wrong == 0, f"{wrong} of {TRIALS * len(roots)} thread-runs differ from the solo scan"
    # the trees exercise the arms (F, W, C1) as well as the base rule: four rows per file
    assert all(len(rows) >= 4 * FILES for rows in solo.values()), {r.parent.name: len(v) for r, v in solo.items()}


def _scan_into(out: dict[int, object], i: int, root: Path) -> None:
    try:
        out[i] = _rows(root)
    except Exception as exc:  # the failure itself is what is counted
        out[i] = f"{type(exc).__name__}: {exc}"


def test_a_repeat_scan_is_identical(trees: tuple[Path, Path]) -> None:
    first = _rows(trees[0])
    assert first and _rows(trees[0]) == first


A_SRC = ("class Outcome { constructor(ok, error) { this.ok = ok; this.error = error; } }\n"
         "function load0(id) { try { return new Outcome(true); } catch (e) { return new Outcome(false, e.message); } }\n"
         "export function show0(req, res) { const o = load0(req.id); res.json({ error: o.error }); }\n")
B_SRC = A_SRC.replace("e.message", '"load failed"')
FILLER = "const x = 1;\nconst y = 2;\nconst z = 3;\n"


def _judge(name: str, src: str) -> list[dict]:
    path = Path("/srv/app") / name
    lines = tuple(src.splitlines())
    found: list[dict] = []
    for n, line in enumerate(lines, 1):
        iec._check_error_disclosure(path, line, n, lines, found)
    return [f for f in found if f["category"] == "CWE-209"]


def test_a_reused_line_list_id_never_carries_a_verdict() -> None:
    """A then nine fillers then B, many times: line-list ids get reused, B (clean) never reports."""
    assert [f["line_start"] for f in _judge("a.ts", A_SRC)] == [3]
    false_hits = 0
    for _ in range(REUSE_ROUNDS):
        _judge("a.ts", A_SRC)
        for k in range(FILLERS):
            _judge(f"d{k}.ts", FILLER)
        false_hits += bool(_judge("b.ts", B_SRC))
        gc.collect()
    assert false_hits == 0
