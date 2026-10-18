"""Feature 0102 — bench harness for the shared AST layer (LLD §13.5, plan task 1.7).

Run it from the shared package, with ``shared`` resolving inside the checkout under test::

    cd agents/shared && PYTHONPATH=$PWD:$PWD/../cwe ../.venv/bin/python tests/perf/bench_ast.py

The exit code is 0 only when every gate holds. A breach exits 1, and so does a run that is
not measuring what it claims to measure (NON-VACUITY).

TREE
    ``gen_tree.generate``: 1,000 files, exactly 5 MB, JavaScript and Python, seeded, at
    real-code density (A6: ``gen_tree.DENSITY`` model nodes per 10^6 bytes, the spike
    target's ~94k, not the 160k of code without comments). Its sha256 and its measured
    density are printed so a drifted tree is visible. The tree is written once to a
    temporary directory, and every run reads it.

METHOD
    There are ``RUNS`` fresh child processes (``--child``). Each one measures, in order:

    * **baseline**: the child's resident size after the agent's own scanner is imported and
      before ``shared.ast`` is, i.e. what the agent holds without the layer;
    * **cold parse+model**: ``get_model`` over every file, in a process whose model cache,
      read cache and worker pool start empty. This covers worker spawn, read, ship, parse,
      boundary validation and ``FileModel.from_doc``, one file at a time, as one consumer
      skill asks;
    * **warm pass**: the same loop again. Every model must come back from the cache as the
      same object; otherwise the warm figure is not a warm figure;
    * **scope+flow**: ``model.analysis()`` and ``candidates(family)`` for the three
      families on every model (``shared.ast.flow``, plan tasks 2.1 and 2.3). The analysis is
      built with every family's candidates and charged to its model's cache entry (A35), so
      the cache's evictions during this pass are part of what it times.

    Each run needs a fresh process: the model cache, the read cache and the pool are
    process-wide, so a second pass in the same interpreter would measure the cache. Times
    are medians across runs. A stray page-cache miss or a preemption is a one-sided outlier.

    One more fresh child (``--footprint``) weighs every model of the tree (A17) and each
    model's analysis (A35) with ``_weigh``: each file is read, encoded and parsed through the
    layer's public seams, its reply built twice (``validate_reply``, then
    ``FileModel.from_doc``) - the first build warms per-process memos, the second runs under
    ``tracemalloc`` with only its model left alive - and the analysis weighed the same way, as
    a consumer holds it. A ratio is the summed footprint over the summed ``bytes_estimate``, as
    a cache full of these models would weigh (the method of ``test_0102_bytes_estimate.py``,
    there on its own inputs, here on the whole tree); the model ratio is gated, the analysis
    ratio printed (its band is pinned by that test). The child is a process of its own because
    ``tracemalloc`` slows and inflates the process it traces: the timed runs never see it.

WHOLE-CGROUP PEAK
    The agent's cgroup holds the agent process and its parse workers, so the peak is taken
    over that set of processes. While the child runs, the parent samples ``/proc`` every
    ``SAMPLE_S``, from outside the child so that it does not compete for the child's GIL.
    It records the summed ``VmRSS`` of the child and its own children (the workers), and
    each process's ``VmHWM``. The peak is the larger of the summed sample and the child's
    own high-water mark. The gated figure is the worst run's peak minus that run's baseline.
    A child is counted only once it has exec'd (its argv differs from the agent's). Between
    fork or vfork and exec, ``/proc`` still shows the agent's own memory, so a sample in
    that window would count the agent twice.

    Two readings are deliberately not used. One is the cgroup's ``memory.peak``: on a
    developer host that cgroup also holds every other process of the session. The other is
    ``ru_maxrss`` for worker size: at ``exec``, Linux folds the hiwater of the image a child
    was forked or vforked from into the child's ``maxrss``, so every worker would "peak" at
    the agent's own size at spawn time. ``VmHWM`` belongs to the process's post-exec memory
    map and is exact. Without ``/proc`` (macOS), the peak is the labelled upper bound
    ``ru_maxrss(self) + workers x ru_maxrss(children)``. It may overstate, and never
    understates.

GATES (``shared.testing.timing.budget`` scales each TIME reference figure to this machine)
    median cold parse+model             <= budget(2.0) s                 (LLD §13.5)
    worst peak - baseline               <= model_cache_budget + W x MAX_WORKER_RSS_MB + 16 MB
                                                                         (LLD §13.5, A5)
    median scope+flow                   <= budget(3.0) s                 (LLD §13.5)
                                        <= 0.6 x median cold parse+model (A34; the same runs)
    footprint / bytes_estimate          in [0.8, 1.25]                   (A17; a band, gated
                                                                          as its two bounds)

    The memory bound is DERIVED, not a figure scaled by CPU speed (A5): what the layer may
    hold over the agent's own baseline is its model cache (``pool.model_cache_budget`` of
    the deployment limit, as the child reads it), one ``MAX_WORKER_RSS_MB`` per worker of
    the pool (``limits.py``), and ``MEMORY_SLACK_MB`` for the read cache and allocator slack.
    Since A35 the cache charges each built analysis to its model's entry, so the bound covers
    the analyses as well.

    The relative scope+flow gate is SPEED-INDEPENDENT (A34): both medians come from the same
    fresh children on the same machine, so no figure is scaled. The proxy is ``py_cost.py``'s
    dict pass (LLD §2): 0.29 s for 2.33 M captures, or 8 M ops/s, so on this tree it is
    ``0.29 s x nodes / 2.33 M``. Its ratio to scope+flow is PRINTED, never gated (A34: the
    former 5x allowance was an estimate; the measured pass, which does def-use work the dict
    pass does not, was 45x it).

NON-VACUITY
    In every run, every file is modelled with no ERROR node (otherwise the cold pass timed
    the fallback path) and every warm lookup hits the cache. The node count is identical
    across runs, and its density is within ``DENSITY_TOLERANCE`` of ``gen_tree.DENSITY``
    (otherwise the tree, or the grammars, no longer have the density the budget assumes).
    The flow pass must find at least one candidate, because the tree is seeded with
    source-to-sink units for every family.
"""

from __future__ import annotations

import gc
import importlib
import json
import os
import resource
import statistics
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from itertools import chain
from pathlib import Path
from typing import Any

import _weigh
import gen_tree

from shared.testing.timing import budget, speed_factor
from shared.tools import membudget

RUNS = 3
SAMPLE_S = 0.005  # the parent's sampling interval for the process-tree peak
CHILD_TIMEOUT_S = 600.0  # a child never runs longer; it is killed and the bench fails

# LLD §13.5 reference figures, scaled by ``budget()``.
PARSE_MODEL_REF_S = 2.0
SCOPE_FLOW_REF_S = 3.0
# A5: the derived memory gate's slack over the model cache and the workers, in MB.
MEMORY_SLACK_MB = 16.0
# A6: how far the measured density may sit from gen_tree.DENSITY before the run is vacuous.
DENSITY_TOLERANCE = 0.10
# A17: the band tracemalloc's footprint over bytes_estimate must lie in, over the whole tree.
FOOTPRINT_BAND = (0.8, 1.25)
# A34: scope+flow may take at most this share of the same runs' cold parse+model median.
SCOPE_FLOW_SHARE = 0.6
# LLD §2 (``py_cost.py``): the dict-pass proxy, printed beside scope+flow (A34: never gated).
PROXY_PASS_S = 0.29
PROXY_CAPTURES = 2_330_000

_MIB = 1 << 20
_PROC = Path("/proc")
_STATUS_KEYS = frozenset({"VmRSS:", "VmHWM:"})  # /proc/<pid>/status rows read, in kB
_SAMPLED = f"/proc sampled every {SAMPLE_S * 1000:g} ms: agent VmRSS + workers' VmRSS"
_BOUND = "upper bound without /proc: ru_maxrss(self) + workers x ru_maxrss(children)"


# ── resident sizes ───────────────────────────────────────────────────────────


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="ascii")
    except (OSError, ValueError):
        return ""


def _listdir(path: Path) -> list[str]:
    try:
        return os.listdir(path)
    except OSError:
        return []


@dataclass(frozen=True, slots=True)
class _Memory:
    """One process's resident bytes now (``VmRSS``) and since its exec (``VmHWM``)."""

    rss: int = 0
    hwm: int = 0


def _memory(pid: int) -> _Memory:
    """``pid``'s ``/proc/<pid>/status`` sizes; zeros when it is gone or there is no /proc."""
    rows = map(str.split, _read(_PROC / str(pid) / "status").splitlines())
    kb = {row[0]: int(row[1]) for row in rows if row[0] in _STATUS_KEYS}
    return _Memory(kb.get("VmRSS:", 0) << 10, kb.get("VmHWM:", 0) << 10)


def _children(pid: int) -> list[int]:
    """``pid``'s direct children: every thread's ``children`` list (Linux)."""
    tasks = _PROC / str(pid) / "task"
    return [int(c) for task in _listdir(tasks) for c in _read(tasks / task / "children").split()]


def _argv(pid: int) -> bytes:
    try:
        return (_PROC / str(pid) / "cmdline").read_bytes()
    except OSError:
        return b""


# This process's argv: a child showing it has not exec'd yet (see WHOLE-CGROUP PEAK).
_OWN_ARGV = _argv(os.getpid())


@dataclass(slots=True)
class _Peaks:
    """What the parent's sampler saw of one child: the summed tree, the child, a worker. A
    sample reads ``status`` files only, once the child's argv (read until it has exec'd) and
    each worker's exec are known: an argv never changes again."""

    tree: int = 0
    agent: int = 0
    worker: int = 0
    argv: bytes = b""  # the child's, once it has exec'd
    execd: set[int] = field(default_factory=set)  # its children seen to have exec'd

    def take(self, pid: int) -> None:
        own = _memory(pid)
        workers = list(map(_memory, self._workers(pid)))
        self.tree = max(self.tree, own.rss + sum(w.rss for w in workers))
        self.agent = max(self.agent, own.hwm)
        self.worker = max(self.worker, *(w.hwm for w in workers), 0)

    def _workers(self, pid: int) -> list[int]:
        """``pid``'s children that have exec'd (``_has_execd``)."""
        own = self._argv(pid)
        return [child for child in _children(pid) if self._has_execd(child, own)]

    def _has_execd(self, child: int, own: bytes) -> bool:
        """``child`` has exec'd: seen to before, or its argv now differs from ``own`` (its
        parent's) - read until it does, never after."""
        if child in self.execd:
            return True
        if _argv(child) == own:
            return False
        self.execd.add(child)
        return True

    def _argv(self, pid: int) -> bytes:
        """The child's argv, read until it differs from this process's (it has exec'd)."""
        if not self.argv:
            argv = _argv(pid)
            self.argv = b"" if argv == _OWN_ARGV else argv
        return self.argv or _OWN_ARGV


# ── child: one fresh process, one run ────────────────────────────────────────


def _timed[T](work: Callable[[], T]) -> tuple[float, T]:
    start = time.perf_counter()
    result = work()
    return time.perf_counter() - start, result


def _files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*") if path.is_file())


def run_child(root: Path) -> dict[str, Any]:
    """One run of METHOD in this process; every number as a JSON-ready dict."""
    importlib.import_module("shared.tools.file_scanner")  # the agent's own, inside the baseline
    paths = _files(root)
    baseline = membudget.rss_now()  # the reader that sizes W (its peak where /proc is absent)
    from shared.ast.cache import get_model
    from shared.ast.pool import Limits, model_cache_budget, worker_count

    limits = Limits.read()
    workers = worker_count(limits)
    cold_s, models = _timed(lambda: list(map(get_model, paths)))
    warm_s, again = _timed(lambda: list(map(get_model, paths)))
    return {
        "cold_s": cold_s,
        "warm_s": warm_s,
        "baseline_mb": baseline / _MIB,
        "workers": workers,
        "cache_budget_mb": model_cache_budget(limits.memory_limit) / _MIB,
        **_model_facts(paths, models, again),
        **_scope_flow(models),
        **_teardown(),
    }


def _present(models: Sequence[Any]) -> list[Any]:
    """The models a pass built: every lookup that did not decline its file (None)."""
    return [model for model in models if model is not None]


def _model_facts(paths: Sequence[Path], models: list[Any], again: list[Any]) -> dict[str, Any]:
    """What the two passes produced: files, models, ERROR-node files, nodes, warm hits."""
    modeled = _present(models)
    return {
        "files": len(paths),
        "modeled": len(modeled),
        "error_files": sum(bool(model.error_nodes) for model in modeled),
        "nodes": sum(model.node_count for model in modeled),
        "warm_hits": sum(map(_same_model, models, again)),
    }


def _same_model(cold: Any, warm: Any) -> bool:
    """A warm hit: the warm lookup returned the very model the cold pass built."""
    return cold is not None and cold is warm


def _scope_flow(models: Sequence[Any]) -> dict[str, Any]:
    """The scope+flow pass, timed: each model's analysis asked every family's candidates, in
    the order its build meets them (``FAMILIES``, read once, past the baseline)."""
    from shared.ast.profiles import FAMILIES  # the three families (LLD §6.3)

    present = _present(models)
    seconds, found = _timed(lambda: sum(_candidates(model, FAMILIES) for model in present))
    return {"scope_flow_s": seconds, "candidates": found}


def _candidates(model: Any, families: Sequence[str]) -> int:
    analysis = model.analysis()
    return sum(len(analysis.candidates(family)) for family in families)


def _teardown() -> dict[str, Any]:
    """End the pool so its workers are reaped; the rusage peaks the no-/proc bound reads."""
    import shared
    from shared.ast.pool import get_pool
    from shared.ast.profile import GRAMMAR_PACK_VERSION

    get_pool().close()
    return {
        "self_maxrss_mb": membudget.peak_rss(resource.RUSAGE_SELF) / _MIB,
        "children_maxrss_mb": membudget.peak_rss(resource.RUSAGE_CHILDREN) / _MIB,
        "shared_file": shared.__file__,
        "grammar_pack": GRAMMAR_PACK_VERSION,
    }


# ── child: the footprint of every model and its analysis (A17, A35) ─────────


def _weights(reply: _weigh.Shipped) -> tuple[int, int, int, int]:
    """One file's model weighed (``_weigh.weighed``), then its analysis, held as a consumer
    holds it, on a model built for it: (model footprint, model estimate, analysis footprint,
    analysis estimate)."""
    model_weight = _weigh.weighed(lambda: _weigh.built(reply))
    model = _weigh.built(reply)
    return (*model_weight, *_weigh.weighed(lambda: _weigh.held(model)))


def run_footprint(root: Path) -> dict[str, Any]:
    """A17 and A35 over every file of the tree: the summed footprints, the summed estimates,
    the ratios. Every object alive before the weighing is frozen out of the collector's scans,
    so each ``gc.collect()`` reads only what one weighing made."""
    replies = list(map(_weigh.shipped, _files(root)))
    gc.collect()
    gc.freeze()
    weighed = list(map(_weights, replies))
    kept, estimate, analysis_kept, analysis_estimate = (sum(column) for column in zip(*weighed, strict=True))
    return {
        "files": len(weighed),
        "kept": kept,
        "estimate": estimate,
        "ratio": kept / estimate,
        "analysis_ratio": analysis_kept / analysis_estimate,
    }


# ── parent: the tree, the runs, the gates ────────────────────────────────────


def _child_command(mode: str, root: Path) -> list[str]:
    """This script, re-run as a fresh child in ``mode`` (``--child`` / ``--footprint``)."""
    return [sys.executable, str(Path(__file__).resolve()), mode, str(root)]


def _last_json(stdout: str) -> dict[str, Any]:
    """A child's answer: the JSON object on the last line it printed."""
    return json.loads(stdout.strip().splitlines()[-1])


def _footprint(root: Path) -> dict[str, Any]:
    """One fresh child's A17 weighing of the whole tree (never inside a timed run)."""
    command = _child_command("--footprint", root)
    done = subprocess.run(command, stdout=subprocess.PIPE, text=True, timeout=CHILD_TIMEOUT_S)
    if done.returncode != 0:
        raise SystemExit(f"bench footprint child exited {done.returncode}")
    return _last_json(done.stdout)


def _measure(root: Path) -> dict[str, Any]:
    """One fresh child: its own numbers, plus its process-tree peaks sampled from outside."""
    command = _child_command("--child", root)
    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as child:
        peaks = _sample(child)
        out, _ = child.communicate()
    if child.returncode != 0:
        raise SystemExit(f"bench child exited {child.returncode}")
    run = _last_json(out)
    run.update(_peak_fields(run, peaks))
    run["delta_mb"] = run["peak_mb"] - run["baseline_mb"]
    return run


def _sample(child: subprocess.Popen[str]) -> _Peaks:
    """Poll the child's process tree until it exits (or is killed at the timeout)."""
    peaks = _Peaks()
    deadline = time.monotonic() + CHILD_TIMEOUT_S
    while child.poll() is None and time.monotonic() < deadline:
        peaks.take(child.pid)
        time.sleep(SAMPLE_S)
    if child.poll() is None:
        child.kill()
    return peaks


def _peak_fields(run: dict[str, Any], peaks: _Peaks) -> dict[str, Any]:
    """The run's whole-tree peak, agent and worker peaks, and how they were obtained."""
    if peaks.tree:
        return {
            "peak_mb": max(peaks.tree, peaks.agent) / _MIB,
            "agent_peak_mb": peaks.agent / _MIB,
            "worker_rss_mb": peaks.worker / _MIB,
            "peak_method": _SAMPLED,
        }
    bound = run["self_maxrss_mb"] + run["workers"] * run["children_maxrss_mb"]
    return {
        "peak_mb": bound,
        "agent_peak_mb": run["self_maxrss_mb"],
        "worker_rss_mb": None,
        "peak_method": _BOUND,
    }


def _over_runs(
    runs: Sequence[dict[str, Any]], key: str, reduce: Callable[[list[float]], float]
) -> float | None:
    """``reduce`` over the runs that measured ``key``; None when none did."""
    values = [run[key] for run in runs if run[key] is not None]
    return reduce(values) if values else None


def _summary(
    tree: gen_tree.Tree, runs: Sequence[dict[str, Any]], footprint: dict[str, Any]
) -> dict[str, Any]:
    first = runs[0]
    parse_model_s = _over_runs(runs, "cold_s", statistics.median)
    scope_flow_s = _over_runs(runs, "scope_flow_s", statistics.median)
    proxy_s = PROXY_PASS_S * first["nodes"] / PROXY_CAPTURES
    return {
        "seed": gen_tree.SEED,
        "files": len(tree.paths),
        "bytes": tree.total_bytes,
        "digest": tree.digest,
        "nodes": first["nodes"],
        "runs": len(runs),
        "workers": first["workers"],
        "cache_budget_mb": first["cache_budget_mb"],
        "density": first["nodes"] / tree.total_bytes * 1e6,
        "memory_bound_mb": _memory_bound(first),
        "speed_factor": speed_factor(),
        "parse_model_s": parse_model_s,
        "warm_s": _over_runs(runs, "warm_s", statistics.median),
        "baseline_mb": _over_runs(runs, "baseline_mb", statistics.median),
        "peak_mb": _over_runs(runs, "peak_mb", max),
        "peak_delta_mb": _over_runs(runs, "delta_mb", max),
        "agent_peak_mb": _over_runs(runs, "agent_peak_mb", max),
        "worker_rss_mb": _over_runs(runs, "worker_rss_mb", max),
        "peak_method": first["peak_method"],
        "scope_flow_s": scope_flow_s,
        "candidates": first["candidates"],
        "scope_flow_share": scope_flow_s / parse_model_s,
        "proxy_s": proxy_s,
        "proxy_ratio": scope_flow_s / proxy_s,
        "shared_file": first["shared_file"],
        "grammar_pack": first["grammar_pack"],
        "footprint_files": footprint["files"],
        "footprint_ratio": footprint["ratio"],
        "analysis_ratio": footprint["analysis_ratio"],
    }


def _memory_bound(run: dict[str, Any]) -> float:
    """A5: the layer's derived allowance over the baseline, in MB."""
    from shared.ast.limits import MAX_WORKER_RSS_MB

    return run["cache_budget_mb"] + run["workers"] * MAX_WORKER_RSS_MB + MEMORY_SLACK_MB


def _gates(summary: dict[str, Any]) -> list[tuple[str, float, float]]:
    """(label, measured value, budget on this machine)."""
    flow, ratio = summary["scope_flow_s"], summary["footprint_ratio"]
    low, high = FOOTPRINT_BAND
    parse = summary["parse_model_s"]
    return [
        ("cold parse+model, median s", parse, budget(PARSE_MODEL_REF_S)),
        ("peak - baseline, worst run MB", summary["peak_delta_mb"], summary["memory_bound_mb"]),
        ("scope+flow, median s", flow, budget(SCOPE_FLOW_REF_S)),
        # A34: speed-independent, so the share of the same runs' parse median is not scaled.
        (f"scope+flow vs {SCOPE_FLOW_SHARE:g} x parse+model, s", flow, SCOPE_FLOW_SHARE * parse),
        # A17's band, as its two bounds: footprint <= 1.25 x estimate, estimate <= footprint / 0.8.
        ("footprint / bytes_estimate", ratio, high),
        ("bytes_estimate / footprint", 1 / ratio, 1 / low),
    ]


def _verdict(value: float, limit: float) -> str:
    return "OK" if value <= limit else "OVER"


def _breaches(gates: Sequence[tuple[str, float, float]]) -> list[str]:
    return [
        f"{label}: {value:.3f} exceeds budget {limit:.3f}"
        for label, value, limit in gates
        if value > limit
    ]


def _run_problems(run: dict[str, Any]) -> list[str]:
    """NON-VACUITY for one run: each failed check's message."""
    files = run["files"]
    checks = (
        (files == gen_tree.FILES, f"saw {files} files, expected {gen_tree.FILES}"),
        (run["modeled"] == files, f"{files - run['modeled']} files fell back: cold timed fallback"),
        (run["error_files"] == 0, f"{run['error_files']} files have ERROR nodes"),
        (run["warm_hits"] == files, f"{files - run['warm_hits']} warm lookups missed the cache"),
        (run["candidates"] != 0, "scope+flow found no candidate in a tree seeded with sinks"),
    )
    return [message for ok, message in checks if not ok]


def _vacuity(summary: dict[str, Any], runs: Sequence[dict[str, Any]]) -> list[str]:
    """NON-VACUITY over all runs, and of the footprint child (it weighed the whole tree)."""
    checks = (
        (len({run["nodes"] for run in runs}) == 1,
         "the node count differs between runs: they did not measure one tree"),
        (summary["footprint_files"] == gen_tree.FILES,
         f"the footprint child weighed {summary['footprint_files']} files, not {gen_tree.FILES}"),
        (abs(summary["density"] / gen_tree.DENSITY - 1) <= DENSITY_TOLERANCE,
         f"{summary['density']:.0f} nodes/MB is not the calibrated {gen_tree.DENSITY} (A6)"),
    )
    problems = list(chain.from_iterable(map(_run_problems, runs)))
    return problems + [message for ok, message in checks if not ok]


def _shown(value: float | None) -> str:
    return "-" if value is None else f"{value:.3f}"


def _report(summary: dict[str, Any], gates: Sequence[tuple[str, float, float]]) -> None:
    print(
        f"0102 AST bench: {summary['files']} files, {summary['bytes']} bytes, seed "
        f"{summary['seed']}, sha256 {summary['digest'][:16]}; {summary['nodes']} nodes "
        f"({summary['density']:.0f} per 10^6 B, calibrated {gen_tree.DENSITY}); "
        f"{summary['runs']} fresh runs; W={summary['workers']}; speed factor "
        f"{summary['speed_factor']:.2f}"
    )
    print(f"  shared = {summary['shared_file']}")
    print(f"  warm pass, median s: {summary['warm_s']:.3f}")
    print(
        f"  baseline {summary['baseline_mb']:.1f} MB; whole-tree peak {summary['peak_mb']:.1f} "
        f"MB; agent process peak {_shown(summary['agent_peak_mb'])} MB; largest worker "
        f"{_shown(summary['worker_rss_mb'])} MB ({summary['peak_method']})"
    )
    print(
        f"  memory bound = model cache {summary['cache_budget_mb']:.0f} MB + W x "
        f"MAX_WORKER_RSS_MB + {MEMORY_SLACK_MB:g} MB (A5)"
    )
    print(
        f"  footprint / bytes_estimate = {summary['footprint_ratio']:.3f} over "
        f"{summary['footprint_files']} models (A17 band {FOOTPRINT_BAND[0]:g} .. "
        f"{FOOTPRINT_BAND[1]:g}); their analyses' = {summary['analysis_ratio']:.3f} (A35; "
        f"printed, not gated: test_0102_bytes_estimate.py pins its band)"
    )
    print(
        f"  scope+flow / cold parse+model = {summary['scope_flow_share']:.3f} (A34 gate: "
        f"{SCOPE_FLOW_SHARE:g}); scaled proxy {summary['proxy_s']:.3f} s, scope+flow / proxy = "
        f"{summary['proxy_ratio']:.3f} (printed, not gated: A34)"
    )
    for label, value, limit in gates:
        print(f"  {label:<32}{value:>10.3f}  budget {limit:>8.3f}  {_verdict(value, limit)}")


def main() -> int:
    """Generate the tree, run ``RUNS`` fresh children, print the numbers, gate them."""
    with tempfile.TemporaryDirectory(prefix="bench_ast_") as tmp:
        tree = gen_tree.generate(Path(tmp))
        runs = [_measure(tree.root) for _ in range(RUNS)]
        footprint = _footprint(tree.root)
    summary = _summary(tree, runs, footprint)
    gates = _gates(summary)
    _report(summary, gates)
    problems = _vacuity(summary, runs) + _breaches(gates)
    for problem in problems:
        print(f"FAIL: {problem}")
    print(json.dumps(summary, sort_keys=True))
    return 1 if problems else 0


# The child modes: one timed run, or the A17 weighing.
_CHILDREN: dict[str, Callable[[Path], dict[str, Any]]] = {
    "--child": run_child,
    "--footprint": run_footprint,
}


def _entry(argv: list[str]) -> int:
    child = _CHILDREN.get(argv[0]) if argv else None
    if child is not None:
        print(json.dumps(child(Path(argv[1]))))
        return 0
    return main()


if __name__ == "__main__":
    raise SystemExit(_entry(sys.argv[1:]))
