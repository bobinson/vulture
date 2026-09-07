"""Item 4.1's measurement, as a repeatable test rather than a scratch script.

`PHASE_TABLE["…llm_judge.py::_judge_prompt"]` (tests/unit/prompt/
test_0089_mode_matches_phase.py) records the number this file produces:

    "the prompt-TEXT half of its item landed first (4.1/4.1b qualified the
     three abstention sites and took the tool-call rate 0 -> 100% on
     qwen3.6-35b-a3b)"

That number had only ever been taken with throwaway scripts, so the claim in
the table was unreproducible by anyone but its author. (The row read
"…without flipping the mode" until the flip landed; the mode is now ADAPT and
the measurement below is unaffected by it — it is a property of the fragments,
which item 4.1 changed first and the flip does not touch.) `test_probe_tool_call_rate`
is the same measurement, written down: given findings whose window CANNOT
settle the question, what fraction of them make the judge reach for a tool?

WHAT IT MEASURES, AND WHY THAT IS THE RIGHT QUANTITY. Item 4.1 changed the
judge's fragments so that "I cannot tell from this window" stops being a
blessed answer (`BLESSES_ABSTENTION` -> `BLESSES_ABSTENTION_AFTER_LOOKING`
alongside `PERMITS_TOOL_USE`). A prompt-bytes test can see that the words
changed; only a model can say whether the behaviour did. So the observable is
the tool-call RATE over a fixture set built to be unanswerable from the window
— not verdict accuracy, which mixes the prompt change with the model's own
judgement.

NOT RUN IN CI, TWICE OVER.

  1. `@pytest.mark.probe`, and `agents/shared/pyproject.toml` carries
     `addopts = ["-m", "not probe"]`. A default `pytest tests/unit/` — which is
     what `make test` and `.github/workflows/ci.yml` run — DESELECTS it. Run it
     deliberately:

         cd agents/shared && python -m pytest tests/unit/validate/\
test_0089_4_1_tool_call_rate.py -m probe -rs -v

  2. Even when selected, it needs a live OpenAI-compatible endpoint serving
     `PROBE_MODEL`. The gate is a real reachability check against the resolved
     `OPENAI_BASE_URL` (`endpoint_status`), never an env var saying whether one
     is expected: an env-var gate reports the operator's belief, and the whole
     point of a probe is to report the world.

A SKIP MUST NEVER READ AS A PASS. Three things enforce that here:

  * the only SKIP is "nothing is listening" — a reachable endpoint that cannot
    be interrogated, or that does not serve `PROBE_MODEL`, is a FAILURE. A
    typo'd model id would otherwise skip forever and look like a clean run.
  * the skip reason opens with `MEASUREMENT NOT TAKEN`, and the rate assertion
    names the same phrase, so a grep over either output distinguishes them.
  * every fixture must produce a judged verdict before the rate is computed.
    A batch lost to the deadline leaves `out[i]` empty, which fails outright
    rather than being counted as "made no tool call" — an understated rate is
    the one wrong answer this probe could give quietly.

The fixture ledger and the instrumentation are checked by the tests BELOW the
probe, which are ordinary unit tests and DO run in CI. They read the real tree,
so a fixture whose anchor moves fails there, offline, instead of surfacing as a
mystery zero the next time someone runs the probe.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from shared.tools.window import CODE_SNIPPET_START
from shared.validate import llm_judge
from shared.validate.judge_tools import JudgeToolExecutor
from shared.validate.types import ValidateConfig

# ── the probe's constants ─────────────────────────────────────────────────

PROBE_MODEL = "qwen/qwen3.6-35b-a3b"
DEFAULT_BASE_URL = "http://localhost:1234/v1"

# The floor item 4.1 is measured against. Below this the fragments did not buy
# the behaviour they were changed for; the hand-run probe reported 1.0.
MIN_TOOL_CALL_RATE = 0.5

_SKIP_BANNER = "MEASUREMENT NOT TAKEN"


def _repo_root() -> Path:
    """The vulture checkout, found by landmark rather than by parent count.

    Same technique as `tests/unit/prompt/test_0089_mode_matches_phase.py`, and
    for the same reason: a `parents[N]` that is off by one shows up as a skip,
    which is precisely the failure mode this file is built to make impossible.
    On the machine this probe was written for the answer is
    `/home/user/src/vulture`; the landmark is what keeps it correct anywhere else.
    """
    for parent in Path(__file__).resolve().parents:
        if (parent / "agents").is_dir() and (parent / "backend").is_dir():
            return parent
    raise RuntimeError(f"no vulture checkout above {__file__}")


ROOT = _repo_root()


# ── the fixture ledger ────────────────────────────────────────────────────
#
# Each row is a finding whose question the WINDOW cannot answer. The window is
# not typed out here — it is read from the tree at run time around `anchor`, so
# the bytes the judge is shown are the bytes that are actually in the file and
# the bytes its `read_file` tool will return. A hand-copied snippet would
# diverge from the file the moment either moved, and the judge would then be
# told two different things about the same coordinates.
#
# `answer_in` names where the question is actually settled: (path, substring)
# pairs asserted to be OUTSIDE the window and INSIDE the tree. That pair of
# assertions is what makes "insufficient window" a checked property of the
# fixture rather than the author's opinion of it.


@dataclass(frozen=True)
class Insufficient:
    key: str
    rel_path: str
    anchor: str
    context: int
    category: str
    severity: str
    title: str
    description: str
    answer_in: tuple[tuple[str, str], ...]
    why: str


LEDGER: tuple[Insufficient, ...] = (
    Insufficient(
        key="traversal",
        rel_path="agents/shared/shared/validate/judge_tools.py",
        anchor="lines = read_file_lines(resolved)",
        context=3,
        category="CWE-22",
        severity="high",
        title="Model-supplied path read without confinement to the audited tree",
        description=(
            "A path chosen by the LLM is resolved and read here. The window "
            "does not show where `resolved` comes from, so it cannot show "
            "whether the path was confined to the scan root."
        ),
        answer_in=(
            ("agents/shared/shared/validate/judge_tools.py", "def _readable"),
            ("agents/shared/shared/validate/judge_tools.py", "def _is_excluded"),
        ),
        why=(
            "The confinement chokepoint is ~40 lines above the read and the "
            "skip-list logic ~180 above that. Nothing in the window decides it."
        ),
    ),
    Insufficient(
        key="sql_fstring",
        rel_path="agents/shared/shared/validate/l5_cache.py",
        anchor='conn.execute(f"ALTER TABLE l5_cache ADD COLUMN',
        context=1,
        category="CWE-89",
        severity="critical",
        title="SQL statement built by f-string interpolation",
        description=(
            "A DDL statement is assembled with an f-string. The window does "
            "not show where `col` and `decl` come from, so it cannot show "
            "whether either is attacker-influenced."
        ),
        answer_in=(
            ("agents/shared/shared/validate/l5_cache.py", '("window_sufficient", "INTEGER")'),
        ),
        why=(
            "Both names are bound by a literal tuple six lines above the "
            "sink — the single fact that decides the finding, and the one "
            "fact a three-line window omits."
        ),
    ),
    Insufficient(
        key="subprocess",
        rel_path="agents/shared/shared/tools/git_history.py",
        anchor="result = subprocess.run(",
        context=2,
        category="CWE-78",
        severity="high",
        title="Subprocess invoked with a caller-influenced argument vector",
        description=(
            "An external command is executed here. The window shows only the "
            "name `cmd`, not how it was built, so it cannot show whether a "
            "caller-supplied value reaches the argument vector unquoted."
        ),
        answer_in=(
            ("agents/shared/shared/tools/git_history.py", 'cmd = ['),
            ("agents/shared/shared/tools/git_history.py", 'cmd.extend(["--", file])'),
        ),
        why=(
            "`cmd` is a list literal, and `file` is appended after a `--` "
            "separator — a list vector with no shell is the whole answer, and "
            "it is nine lines above the call."
        ),
    ),
    Insufficient(
        key="regex_dos",
        rel_path="agents/shared/shared/validate/judge_tools.py",
        anchor="results = _shared_search_pattern(str(self.root), pattern)",
        context=2,
        category="CWE-1333",
        severity="medium",
        title="Model-supplied pattern reaches a tree-wide search unbounded",
        description=(
            "A pattern chosen by the LLM is handed to a repository-wide "
            "search. The window does not show what the callee does with it, "
            "so it cannot show whether it is compiled as a regular "
            "expression, nor whether the walk is bounded."
        ),
        answer_in=(
            ("agents/shared/shared/tools/pattern_matcher.py", "def search_pattern"),
        ),
        why=(
            "The answer is in a DIFFERENT FILE, which no widening of this "
            "window can reach — the case a `read_file` alone cannot close."
        ),
    ),
    Insufficient(
        key="broker_url",
        rel_path="agents/shared/shared/llm/broker.py",
        anchor="return BrokerConfig(base_url=url, api_key=token)",
        context=2,
        category="CWE-319",
        severity="high",
        title="Per-run credential paired with an endpoint of unverified scheme",
        description=(
            "A secret-class token is bound to a base URL here. The window "
            "does not show where `url` comes from, so it cannot show whether "
            "an `http://` endpoint would be accepted."
        ),
        answer_in=(
            ("agents/shared/shared/llm/broker.py", 'os.environ.get("VULTURE_LLM_BROKER_URL"'),
        ),
        why=(
            "The URL is read from the environment three lines above the "
            "window's top edge, with no scheme check anywhere in view."
        ),
    ),
    Insufficient(
        key="client_key",
        rel_path="agents/shared/shared/llm/broker.py",
        anchor="return AsyncOpenAI(base_url=base_url, api_key=api_key,",
        context=1,
        category="CWE-522",
        severity="medium",
        title="API key forwarded to a base URL supplied by the caller",
        description=(
            "A credential is handed to an HTTP client aimed at a "
            "caller-supplied base URL. Both parameters arrive from outside "
            "the window, so it cannot show what constrains either."
        ),
        answer_in=(
            ("agents/shared/shared/llm/broker.py", "def _default_client_factory"),
            ("agents/shared/shared/llm/broker.py", "client_factory or _default_client_factory"),
        ),
        why=(
            "The factory's only caller, and therefore the only constraint on "
            "its arguments, is a different function in the same file."
        ),
    ),
)


# ── building the findings from the tree ───────────────────────────────────


def _lines(rel_path: str) -> list[str]:
    return (ROOT / rel_path).read_text(encoding="utf-8").splitlines()


def anchor_line(row: Insufficient) -> int:
    """1-based line of `row.anchor`, which must occur exactly once.

    Uniqueness is required, not merely convenient: a second occurrence would
    make the window's coordinates ambiguous, and the whole fixture depends on
    the window's line numbers being the file's own (item 4.2).
    """
    hits = [i for i, line in enumerate(_lines(row.rel_path), 1) if row.anchor in line]
    assert len(hits) == 1, (
        f"{row.key}: anchor {row.anchor!r} occurs {len(hits)} times in "
        f"{row.rel_path} (expected exactly 1) — the fixture has rotted; "
        "re-point it at the sink it means to cite."
    )
    return hits[0]


def window_for(row: Insufficient) -> tuple[str, int, int, int]:
    """(snippet, first_file_line, line_start, line_end) read from the tree."""
    lines = _lines(row.rel_path)
    n = anchor_line(row)
    lo = max(1, n - row.context)
    hi = min(len(lines), n + row.context)
    return "\n".join(lines[lo - 1:hi]), lo, n, n


def finding_for(row: Insufficient) -> dict:
    snippet, start, ls, le = window_for(row)
    return {
        "id": f"probe-{row.key}",
        "check_id": row.category,
        "category": row.category,
        "severity": row.severity,
        "title": row.title,
        "description": row.description,
        "file_path": row.rel_path,
        "line_start": ls,
        "line_end": le,
        "code_snippet": snippet,
        CODE_SNIPPET_START: start,
        "validation": {"checks": []},
    }


def probe_findings() -> list[dict]:
    return [finding_for(row) for row in LEDGER]


# ── endpoint reachability ─────────────────────────────────────────────────
#
# A real check, not an env var. `absent` is the ONLY status that skips.

ABSENT = "absent"
REACHABLE = "reachable"
BROKEN = "broken"


def base_url() -> str:
    return (os.getenv("OPENAI_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")


def endpoint_status(url: str, timeout: float = 3.0) -> tuple[str, str, list[str]]:
    """Interrogate `{url}/models`. Returns (status, detail, model_ids).

    * `absent`    — nothing answered (refused, unresolvable, timed out).
    * `broken`    — something answered but could not be read as a model list.
    * `reachable` — a model list came back; `model_ids` is what it holds.

    The three are kept apart because only the first is a legitimate reason to
    decline the measurement. Folding `broken` into `absent` is how a probe
    starts skipping permanently against a half-working endpoint.
    """
    target = f"{url}/models"
    try:
        with urllib.request.urlopen(target, timeout=timeout) as resp:
            body = resp.read()
    except urllib.error.HTTPError as exc:
        return BROKEN, f"{target} answered HTTP {exc.code}", []
    except (urllib.error.URLError, OSError) as exc:
        return ABSENT, f"{target}: {exc}", []
    try:
        payload = json.loads(body)
        ids = [str(m["id"]) for m in payload["data"]]
    except (ValueError, KeyError, TypeError) as exc:
        return BROKEN, f"{target} returned an unreadable model list: {exc}", []
    return REACHABLE, f"{target} serves {len(ids)} model(s)", ids


# ── instrumentation ───────────────────────────────────────────────────────


@dataclass
class ToolCallLedger:
    """Counts `JudgeToolExecutor.execute` calls, attributed per finding.

    Attribution is by THREAD, bound around the real `_judge_batch`: the pool
    runs one batch per worker thread and the probe's batch size is 1, so the
    thread that issues a tool call is the thread judging exactly one finding.
    Counting calls without attributing them would answer "were any tools used",
    which is not the quantity item 4.1 is measured on.
    """

    lock: threading.Lock = field(default_factory=threading.Lock)
    _local: threading.local = field(default_factory=threading.local)
    calls: list[tuple[str, str, str]] = field(default_factory=list)
    batches: list[str] = field(default_factory=list)

    def bind(self, finding_id: str) -> None:
        self._local.finding_id = finding_id
        with self.lock:
            self.batches.append(finding_id)

    def unbind(self) -> None:
        self._local.finding_id = None

    def record(self, tool: str, arguments: str) -> None:
        with self.lock:
            self.calls.append(
                (getattr(self._local, "finding_id", None) or "<unattributed>",
                 tool, arguments))

    def finding_ids_that_called_a_tool(self) -> set[str]:
        with self.lock:
            return {fid for fid, _, _ in self.calls}


def install_counters(monkeypatch, ledger: ToolCallLedger) -> None:
    """Wrap — never replace — the two production entry points we count at.

    `execute` DELEGATES to the real executor. A canned return value would be a
    different experiment: the model would be answered with bytes the tree does
    not contain, and whether it then asks again is a property of the stub, not
    of the prompt.
    """
    real_execute = JudgeToolExecutor.execute
    real_judge_batch = llm_judge._judge_batch

    def counting_execute(self, name, raw_arguments):
        ledger.record(name, raw_arguments)
        return real_execute(self, name, raw_arguments)

    def counting_judge_batch(*, batch, **kw):
        ledger.bind(batch[0][1]["id"])
        try:
            return real_judge_batch(batch=batch, **kw)
        finally:
            ledger.unbind()

    monkeypatch.setattr(JudgeToolExecutor, "execute", counting_execute)
    monkeypatch.setattr(llm_judge, "_judge_batch", counting_judge_batch)


def probe_config() -> ValidateConfig:
    """The config the hand-run probe used, verbatim.

    `l5_batch_size=1` is load-bearing twice: it makes a batch a finding (so the
    rate has a denominator) and it stops one finding's tool calls from being
    credited to the four it shared a request with.
    """
    return ValidateConfig(
        enable_l5=True,
        enable_l5_override=True,
        l5_model_override=PROBE_MODEL,
        l5_batch_size=1,
    )


# ── cache isolation ───────────────────────────────────────────────────────


@pytest.fixture
def cold_l5_cache(monkeypatch, tmp_path):
    """Point the L5 verdict cache at a fresh file for the duration of a test.

    WITHOUT THIS THE PROBE MEASURES ZERO ON ITS SECOND RUN. `_judge_batch`
    opens with `_partition_batch_by_cache`, and a cache hit returns the stored
    verdict having made no LLM call and therefore no tool call. The entry is
    keyed on (schema version, file_path, line_start, line_end, check_id, model,
    file_sig) — every one of which this probe holds fixed by construction — so
    the second run hits on all six fixtures, reports a rate of 0.00 and fails,
    while `out[i]` is non-empty and the completeness assertion sees nothing
    wrong. A measurement that is only valid the first time is not repeatable,
    which is the entire reason this file exists.

    The default store is real and shared: `~/.vulture/l5_cache.db`, 30-day TTL,
    written by every local audit on the machine. So the collision is not
    hypothetical even on a first run — a dogfood scan of this same tree can
    have judged the same sink at the same line under the same model.

    Teardown resets again rather than relying on `monkeypatch.undo`: the module
    caches a live sqlite connection in `_CONN`, and restoring the environment
    variable does not close it. Leaving it bound to a deleted tmp file would
    hand the next test in the session a stale handle.
    """
    from shared.validate import l5_cache

    db = tmp_path / "l5_probe_cache.db"
    monkeypatch.setenv("VULTURE_L5_CACHE_PATH", str(db))
    l5_cache.reset_for_tests()
    yield db
    l5_cache.reset_for_tests()


# ══════════════════════════════════════════════════════════════════════════
# THE PROBE — live model, deselected by default. See the module docstring.
# ══════════════════════════════════════════════════════════════════════════


@pytest.mark.probe
def test_probe_tool_call_rate(monkeypatch, record_property, cold_l5_cache):
    """Item 4.1's number: the fraction of insufficient-window findings that
    make the judge reach for a tool. Must be at least `MIN_TOOL_CALL_RATE`.

    `cold_l5_cache` makes every run a cold one. See that fixture: without it
    the second run of this probe is answered from the shared verdict cache,
    makes no LLM call and therefore no tool call, and reports 0.00.
    """
    url = base_url()
    monkeypatch.setenv("OPENAI_BASE_URL", url)
    # The judge's model must come from the config, so no leftover env may
    # outrank it (`_resolve_model` reads VULTURE_VALIDATE_LLM_MODEL first) and
    # the broker must stay out of the path (it would repoint the client away
    # from the endpoint this test just reachability-checked).
    for var in ("VULTURE_VALIDATE_LLM_MODEL", "VULTURE_VALIDATE_LLM_MODEL_EXPLICIT",
                "VULTURE_LLM_BROKER", "VULTURE_LLM_BROKER_URL"):
        monkeypatch.delenv(var, raising=False)
    # A local 35B answering a tool loop is not a 30-second operation, and a
    # deadline expiry would understate the rate rather than fail. Both ceilings
    # are the module's existing env knobs, raised so this is a measurement of
    # behaviour and not of latency; the completeness assertion below is what
    # actually guarantees no batch was silently lost.
    monkeypatch.setenv("VULTURE_VALIDATE_LLM_PER_BATCH_TIMEOUT_MS", "300000")
    monkeypatch.setenv("VULTURE_VALIDATE_LLM_TIMEOUT_MS", "1800000")
    llm_judge.reset_client_cache()

    status, detail, models = endpoint_status(url)
    if status == ABSENT:
        pytest.skip(
            f"{_SKIP_BANNER}: no OpenAI-compatible endpoint at {url} ({detail}). "
            f"Start LM Studio serving {PROBE_MODEL} and re-run with -m probe. "
            "This is a SKIP, not a pass — item 4.1's tool-call rate is unmeasured."
        )
    assert status == REACHABLE, (
        f"{url} answered but could not be interrogated ({detail}). Refusing to "
        "skip: a half-working endpoint must not look like an absent one."
    )
    assert PROBE_MODEL in models, (
        f"{url} does not serve {PROBE_MODEL} (it serves {sorted(models)}). "
        "Refusing to skip: the rate is only comparable against the model the "
        "phase table names."
    )

    findings = probe_findings()
    assert len(findings) == len(LEDGER) >= 4, "too few fixtures to form a rate"

    ledger = ToolCallLedger()
    install_counters(monkeypatch, ledger)

    out = llm_judge.run_l5(
        findings,
        [[] for _ in findings],
        probe_config(),
        audit_id="0089-4.1-probe",
        source_path=str(ROOT),
    )

    # Completeness BEFORE the rate. An empty entry means that finding's batch
    # never completed, and counting it as "made no tool call" is exactly the
    # quiet understatement this probe must not produce.
    unjudged = [f["id"] for f, checks in zip(findings, out, strict=True) if not checks]
    assert unjudged == [], (
        f"{_SKIP_BANNER} (incomplete): {unjudged} produced no llm_judge check — "
        "the batch was not selected, timed out, or errored. The rate below "
        "would be understated, so it is not reported."
    )
    assert sorted(ledger.batches) == sorted(f["id"] for f in findings), (
        f"batch attribution is broken: judged {sorted(ledger.batches)}")

    called = ledger.finding_ids_that_called_a_tool()
    rate = len(called) / len(findings)
    record_property("tool_call_rate", rate)
    record_property("tool_calls", len(ledger.calls))
    detail_lines = "\n".join(
        f"  {f['id']:<24} {'TOOL' if f['id'] in called else 'no tool':<8} "
        f"{f['category']}"
        for f in findings
    )
    # Printed, not just recorded: emitting the measurement is the point of
    # running this at all, and `-s` is not always on.
    print(
        f"\n[0089 item 4.1] model={PROBE_MODEL} endpoint={url}\n"
        f"[0089 item 4.1] tool-call rate = {len(called)}/{len(findings)} = "
        f"{rate:.2f} over {len(ledger.calls)} tool call(s)\n{detail_lines}"
    )
    assert rate >= MIN_TOOL_CALL_RATE, (
        f"tool-call rate {rate:.2f} ({len(called)}/{len(findings)}) is below "
        f"{MIN_TOOL_CALL_RATE}. Item 4.1's fragments were changed so that an "
        "insufficient window makes the judge LOOK; on these fixtures it mostly "
        f"did not.\n{detail_lines}"
    )


# ══════════════════════════════════════════════════════════════════════════
# The probe's own preconditions — offline, and these DO run in CI.
# ══════════════════════════════════════════════════════════════════════════


def test_the_probe_is_marked_and_therefore_deselected_by_default():
    """The marker is the mechanism the plan names for keeping it out of CI.

    Read off the function object rather than restated, so removing the
    decorator fails here instead of quietly enrolling a live-model call in
    every CI run.
    """
    marks = {m.name for m in test_probe_tool_call_rate.pytestmark}
    assert "probe" in marks, marks


def test_the_marker_is_registered_and_deselected_by_the_shared_config():
    """`probe` must be a known marker AND excluded by default.

    Reads `agents/shared/pyproject.toml`, because a marker that is only
    decorated is still collected: without the `addopts` line a bare
    `pytest tests/unit/` would run this file against whatever happens to be
    listening on port 1234 on the machine doing the run.
    """
    import tomllib

    cfg = tomllib.loads(
        (ROOT / "agents/shared/pyproject.toml").read_text(encoding="utf-8"))
    ini = cfg["tool"]["pytest"]["ini_options"]
    assert any(m.startswith("probe:") for m in ini.get("markers", [])), ini.get("markers")
    assert ini.get("addopts") == ["-m", "not probe"], (
        "without this addopts line a bare `pytest tests/` collects and RUNS the "
        f"live-model probe against whatever is listening. Got {ini.get('addopts')!r}")


@pytest.mark.parametrize("row", LEDGER, ids=lambda r: r.key)
def test_every_fixture_anchor_still_resolves_in_the_tree(row):
    """Fixture rot fails offline, in CI, not as a mystery zero in the probe."""
    n = anchor_line(row)
    snippet, start, ls, le = window_for(row)
    assert start <= n <= start + len(snippet.splitlines()) - 1
    assert (ls, le) == (n, n)
    assert row.anchor in snippet


@pytest.mark.parametrize("row", LEDGER, ids=lambda r: r.key)
def test_every_fixture_window_is_genuinely_insufficient(row):
    """"The answer is not in the window" is a CHECKED property, not a claim.

    Both halves are needed. That the deciding text is absent from the window
    is what makes the finding unanswerable; that it is present in the tree is
    what makes it answerable AT ALL — a question with no answer anywhere would
    measure the model's willingness to give up, not its willingness to look.
    """
    snippet, _, _, _ = window_for(row)
    assert row.answer_in, f"{row.key}: names nowhere the answer lives"
    for rel_path, needle in row.answer_in:
        haystack = (ROOT / rel_path).read_text(encoding="utf-8")
        assert needle in haystack, (
            f"{row.key}: {needle!r} is no longer in {rel_path}")
        assert needle not in snippet, (
            f"{row.key}: {needle!r} IS in the window — the fixture answers "
            "its own question and cannot measure anything")
    assert len(row.why.strip()) > 40, f"{row.key}: no reason recorded"


@pytest.mark.parametrize("row", LEDGER, ids=lambda r: r.key)
def test_every_fixture_would_actually_be_judged(row):
    """A finding L5 declines to select can never make a tool call.

    Driven through the judge's own selector, so a change to the selection rule
    that silently drops these fixtures fails here rather than halving the
    measured rate for a reason no one connects to selection.
    """
    finding = finding_for(row)
    assert llm_judge._has_code_window(finding), "empty window: never judged"
    selected, skips = llm_judge._classify_selection([finding], [[]], 1000)
    assert selected == [0], f"{row.key} was skipped: {skips}"


def test_the_ledger_is_large_enough_and_distinct():
    """A one-fixture ledger would make the rate 0.0 or 1.0 and nothing else."""
    assert len(LEDGER) >= 4, len(LEDGER)
    assert len({r.key for r in LEDGER}) == len(LEDGER), "duplicate keys"
    assert len({(r.rel_path, r.anchor) for r in LEDGER}) == len(LEDGER), "duplicate sinks"
    assert len({r.category for r in LEDGER}) >= 4, "too few defect classes"
    assert MIN_TOOL_CALL_RATE * len(LEDGER) >= 2, (
        "the floor must require more than a single fixture to clear")


def test_absent_and_broken_endpoints_are_told_apart():
    """The skip gate, exercised offline against a port nothing listens on.

    Port 9 is discard/unassigned; the assertion is on the STATUS, not on the
    OS's error text, so it holds whether the connection is refused, filtered
    or unresolvable.
    """
    status, detail, models = endpoint_status("http://127.0.0.1:9/v1", timeout=1.0)
    assert status == ABSENT, (status, detail)
    assert models == []
    assert "127.0.0.1:9" in detail


def test_the_base_url_falls_back_to_the_documented_endpoint(monkeypatch):
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    assert base_url() == DEFAULT_BASE_URL
    monkeypatch.setenv("OPENAI_BASE_URL", "http://example.invalid:9999/v1/")
    assert base_url() == "http://example.invalid:9999/v1"


def test_the_skip_banner_cannot_collide_with_a_pass():
    """Both non-measuring exits carry the same grep-able phrase.

    Read out of the probe's own source rather than restated, so deleting the
    banner from either message fails here.
    """
    src = Path(__file__).read_text(encoding="utf-8")
    body = src.split("def test_probe_tool_call_rate", 1)[1].split(
        "\ndef test_the_probe_is_marked", 1)[0]
    assert body.count("{_SKIP_BANNER}") == 2, (
        "the skip and the incompleteness abort must both name the banner")


def test_the_counters_wrap_production_rather_than_replacing_it(monkeypatch, tmp_path):
    """The instrumentation must not be the thing under measurement.

    Drives the wrapped `execute` against a real executor over a real file: a
    stub that returned a canned string would pass a call-counting assertion
    while measuring nothing about the judge's tools.
    """
    (tmp_path / "probe.py").write_text("VALUE = 41 + 1\n", encoding="utf-8")
    ledger = ToolCallLedger()
    install_counters(monkeypatch, ledger)
    ledger.bind("probe-x")
    out = JudgeToolExecutor(str(tmp_path)).execute(
        "read_file", json.dumps({"path": "probe.py"}))
    ledger.unbind()
    assert "VALUE = 41 + 1" in out, out
    assert ledger.finding_ids_that_called_a_tool() == {"probe-x"}
    assert [(t, "probe.py" in a) for _, t, a in ledger.calls] == [("read_file", True)]


def test_an_unattributed_tool_call_is_labelled_not_dropped(monkeypatch, tmp_path):
    """A call outside any bound batch must not silently credit a finding."""
    (tmp_path / "probe.py").write_text("x = 1\n", encoding="utf-8")
    ledger = ToolCallLedger()
    install_counters(monkeypatch, ledger)
    JudgeToolExecutor(str(tmp_path)).execute(
        "read_file", json.dumps({"path": "probe.py"}))
    assert ledger.finding_ids_that_called_a_tool() == {"<unattributed>"}


def test_a_verdict_cached_by_an_earlier_run_would_answer_this_one(
    cold_l5_cache, tmp_path, monkeypatch,
):
    """The hazard the `cold_l5_cache` fixture exists for, driven for real.

    Both directions, through the production short-circuit itself
    (`_partition_batch_by_cache`, the first thing `_judge_batch` does) rather
    than through an assertion about the fixture:

      * a verdict stored under run 1's database makes the fixture's own finding
        a CACHE HIT, and a hit is returned with no LLM call and hence no tool
        call — which is a tool-call rate of 0.00 reported as a measurement;
      * re-pointed at run 2's database the identical finding is uncached again
        and reaches the model, which is what the probe must do every time.

    The key is computed by `llm_judge._cache_key_for`, so this stays true if
    the key's composition changes.
    """
    from shared.validate import l5_cache

    finding = finding_for(LEDGER[0])
    entry = [(0, finding, "python")]
    key = llm_judge._cache_key_for(finding, PROBE_MODEL)

    def point_at(db) -> None:
        monkeypatch.setenv("VULTURE_L5_CACHE_PATH", str(db))
        l5_cache.reset_for_tests()

    point_at(tmp_path / "run1.db")
    l5_cache.store(key, exploitable=0.9, reasoning="judged by an earlier run",
                   model=PROBE_MODEL, language="python")
    assert l5_cache.lookup(key) is not None, "fixture assumption: it really caches"
    hits, uncached = llm_judge._partition_batch_by_cache(entry, PROBE_MODEL)
    assert hits and not uncached, (
        "a cached verdict short-circuits the LLM call — this is the state that "
        "would silently report a tool-call rate of 0.00")

    point_at(tmp_path / "run2.db")
    assert l5_cache.lookup(key) is None, "the isolated run must not see run 1"
    hits, uncached = llm_judge._partition_batch_by_cache(entry, PROBE_MODEL)
    assert not hits and uncached == entry, (
        "an isolated run must reach the model for every fixture")


def test_the_probe_takes_the_cold_cache_fixture():
    """The isolation must be WIRED, not merely available.

    Read off the function's own signature — a fixture the probe does not
    request does not run, and the failure it prevents only appears on the
    second live run, by which time the first run's number is already recorded.
    """
    import inspect

    params = inspect.signature(test_probe_tool_call_rate).parameters
    assert "cold_l5_cache" in params, sorted(params)


def test_the_default_verdict_cache_is_shared_and_persistent(monkeypatch):
    """Why the isolation is needed: the default store outlives the process."""
    import os

    from shared.validate import l5_cache

    monkeypatch.delenv("VULTURE_L5_CACHE_PATH", raising=False)
    monkeypatch.delenv("VULTURE_DATA_DIR", raising=False)
    assert l5_cache._default_path() == os.path.join(
        os.path.expanduser("~"), ".vulture", "l5_cache.db")


def test_the_probe_config_is_the_one_the_phase_table_names():
    cfg = probe_config()
    assert (cfg.enable_l5, cfg.enable_l5_override) == (True, True)
    assert cfg.l5_model_override == PROBE_MODEL
    assert llm_judge._resolve_batch_size(cfg) == 1
    assert llm_judge._resolve_model(cfg) == PROBE_MODEL


def test_the_raised_timeouts_the_probe_sets_actually_reach_the_runtime(monkeypatch):
    """The two env names must be the ones production reads.

    A rename or a typo here does not fail loudly: the probe would simply run
    with the 30s-per-batch default, a local 35B in a tool loop would blow it,
    and the run would abort on the completeness assertion with no hint that a
    timeout — rather than the prompt — was what went wrong. Driven through
    `_resolve_l5_runtime`, the same resolver `run_l5` uses, and asserted as the
    SECONDS the runtime ends up holding, not as the strings that were set.
    """
    monkeypatch.setenv("VULTURE_VALIDATE_LLM_PER_BATCH_TIMEOUT_MS", "300000")
    monkeypatch.setenv("VULTURE_VALIDATE_LLM_TIMEOUT_MS", "1800000")
    rt = llm_judge._resolve_l5_runtime(probe_config(), str(ROOT))
    assert rt.per_batch_timeout_s == 300.0, rt.per_batch_timeout_s
    assert rt.total_timeout_s == 1800.0, rt.total_timeout_s
    # And the whole ledger must fit inside the total even if every batch runs
    # to its own ceiling with no concurrency at all — otherwise the deadline,
    # not the model, decides the rate.
    assert len(LEDGER) * rt.per_batch_timeout_s <= rt.total_timeout_s, (
        f"{len(LEDGER)} fixtures x {rt.per_batch_timeout_s}s exceeds the "
        f"{rt.total_timeout_s}s total; the probe could time out mid-sweep")


def test_the_judge_would_hold_tools_for_this_source_root():
    """`tools_on` is derived from the source path; without it the rate is 0.

    Rendered through `_resolve_l5_runtime`, which is what `run_l5` calls, so a
    change that stops offering tools fails here with the reason rather than in
    the probe with a zero.
    """
    rt = llm_judge._resolve_l5_runtime(probe_config(), str(ROOT))
    assert rt is not None
    assert rt.tools_on is True
    assert rt.max_tool_calls > 0
    assert rt.model == PROBE_MODEL
    assert rt.batch_size == 1
