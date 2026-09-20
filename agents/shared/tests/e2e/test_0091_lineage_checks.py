"""Feature 0091 P1 — agent-side lineage evidence checks, end to end.

TDD: this file is the CONTRACT. It is written BEFORE the implementation and
MUST currently FAIL (RED) because `shared.lineage_checks` / `shared.quote_store`
do not exist yet and `run_combined_audit` does not yet accept or answer the new
wire keys — never because of an unrelated setup problem.

WHY THIS EXISTS. The LLM tier is told by the memory system's prior-findings
block to "skip known issues and report NEW findings only". The model complies,
the finding is absent from the result, and the backend's absence-means-fixed
rule reads that silence as repair — closing a lineage row whose offending line
is still in the file byte for byte. Absence from an LLM result is never
evidence. Closure has to come from the CODE.

Only the agent can supply that evidence. The evidence quote never leaves the
agent process (`_PRIVATE_FIELDS` strips it before SSE, and the Go backend has
no reference to it), so the backend cannot re-verify anything. It therefore
ASKS, and the agent ANSWERS.

THE WIRE CONTRACT (LLD §6.1), both halves of which are asserted below.

Request — the audit request gains one key::

    "lineage_checks_requested": {
      "schema": 1,
      "rows": [{"lineage_id": ..., "fingerprint_v2": ..., "rel_path": ...,
                "line_start": 7, "line_end": 7, "quote_hash": "sha256:...",
                "status": "open" | "fixed", "file_hash": "sha256:..."}]}

Result — the `result` event gains three keys::

    "result_schema": 2
    "pruned_dirs": ["<root-relative prefix>", ...]
    "lineage_checks": [{"lineage_id": ..., "outcome": ..., "reason": ...,
                        "line_start": ..., "line_end": ..., "file_hash": ...}]

`result_schema` is what tells the backend this agent speaks 0091 at all. An
agent that omits it disables every LLM-tier and pruned-dir closure for the scan
(S26), so the two schema assertions here are load-bearing for the Go side too:
if the agent forgets the key, the backend correctly refuses to close anything
and the feature silently does nothing.

THE VERIFICATION ALGORITHM (LLD §6.2), in priority order::

    quote missing from the local cache, or sha256(norm(quote)) != quote_hash
                                                    -> unconfirmable(no_quote)
    file missing                                    -> gone(file_missing)
    file unreadable / binary / over MAX_FILE_SIZE   -> unconfirmable(<reason>)
    the verifier raises ANY exception               -> unconfirmable(error:...)
    anchor exact | near_miss                        -> confirmed
    anchor reanchored | found_elsewhere             -> reanchored (+ new window)
    anchor ambiguous                                -> ambiguous
    anchor absent                                   -> gone

The ordering is the design, not an implementation detail. `gone` is the ONLY
outcome that closes a finding, so every failure mode that is a fact about the
*checker* rather than about the *code* — a lost cache entry, an unreadable
file, a crashing verifier — has to land on `unconfirmable` instead. A checker
that reports `gone` when it simply could not look is the cheapest possible way
to close every finding in a codebase at once.

SYMBOLS THIS CONTRACT INTRODUCES (LLD §6.2, plan P1):

* ``shared.quote_store`` — the agent-local, never-egressing store of the
  normalised evidence quote, keyed by ``fingerprint_v2``, living in the same
  cache DB as the L5 verdicts (``VULTURE_L5_CACHE_PATH``, default
  ``~/.vulture/l5_cache.db``). ``store(fingerprint_v2, quote)`` /
  ``lookup(fingerprint_v2)`` / ``reset_for_tests()``.
* ``shared.lineage_checks.quote_hash(quote)`` — the ONE definition of the hash
  the lineage row carries: sha256 over the whitespace-normalised quote,
  ``"sha256:"``-prefixed. It is single-sourced here rather than recomputed in
  the test so the two sides cannot disagree about normalisation.
* ``run_combined_audit(..., lineage_checks_requested=...)``.

No LLM is involved: the checks run off the stored quote and the file cache the
skill phase already warmed, so this suite is network-free like the rest of
tests/e2e.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from shared import quote_store
from shared.audit_runner import run_combined_audit
from shared.lineage_checks import quote_hash

# --------------------------------------------------------------------------- #
# Fixture tree
# --------------------------------------------------------------------------- #

# Each row gets its OWN distinctive quote. The 0076 verifier can report
# `found_elsewhere` when a quote turns up in another file of the same batch, so
# sharing one quote across the fixture files would make the expected outcomes
# depend on search order rather than on the case under test.

QUOTE_PRESENT = (
    'token = request.headers.get("X-Api-Token")\n'
    'if token == "s3cr3t-static-token-value":'
)

QUOTE_REMOVED = (
    'cursor.execute("DELETE FROM audit_log WHERE id = " + str(record_id))\n'
    "connection.commit()"
)

QUOTE_VANISHED_FILE = (
    'subprocess.run(shell_command, shell=True, check=False)\n'
    'logger.info("ran legacy migration helper")'
)

QUOTE_OVERSIZE = (
    'PRIVATE_DEPLOY_KEY = "AAAAB3NzaC1yc2EAAAADAQABAAABgQDoversizedfixture"\n'
    "def rotate_deploy_key(previous_value: str) -> str:"
)

QUOTE_UNCACHED = (
    'password_hash = hashlib.md5(raw_password.encode()).hexdigest()\n'
    "store_credentials(username, password_hash)"
)

QUOTE_HASH_MISMATCH = (
    'eval(compile(user_supplied_template, "<config>", "exec"))\n'
    "return rendered_configuration"
)

# A well-formed hash of the right shape that matches nothing. Used for the row
# whose cached quote no longer agrees with the hash the lineage row carries —
# the "the cache moved on without the row" case, which §6.2 folds into
# `no_quote` because the cached text can no longer be trusted as the evidence
# the finding was made from.
WRONG_HASH = "sha256:" + "0" * 64

# Text that is nowhere near any quote above, so a file "whose cited line was
# deleted" cannot come back as `near_miss` (similarity >= 0.6) and be read as
# still present.
UNRELATED_BODY = (
    "import dataclasses\n"
    "\n"
    "\n"
    "@dataclasses.dataclass(frozen=True)\n"
    "class Rectangle:\n"
    "    width: int\n"
    "    height: int\n"
    "\n"
    "    def area(self) -> int:\n"
    "        return self.width * self.height\n"
)


def _file_with_quote(path: Path, quote: str) -> tuple[int, int]:
    """Write a small module that carries ``quote`` at a known 1-based window."""
    preamble = [
        '"""Fixture module."""',
        "",
        "import hashlib",
        "import subprocess",
        "",
        "",
        "def handle(request, record_id, cursor, connection):",
    ]
    quote_lines = quote.splitlines()
    tail = ["        pass"] if quote_lines[-1].rstrip().endswith(":") else []
    body = preamble + ["    " + line for line in quote_lines] + tail + ["    return None", ""]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(body), encoding="utf-8")
    start = len(preamble) + 1
    return start, start + len(quote_lines) - 1


def _oversize_file(path: Path, quote: str) -> None:
    """A file comfortably past the 512KB default ``VULTURE_MAX_FILE_SIZE``.

    The quote really is in there — the point of the case is that the reader
    refuses to look, not that the evidence is gone. `unconfirmable` and `gone`
    must not be confusable here.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    filler = "# padding to exceed the per-file read cap\n" * 20000
    path.write_text(filler + quote + "\n", encoding="utf-8")
    assert path.stat().st_size > 512 * 1024, "fixture must exceed the default read cap"


@pytest.fixture()
def lineage_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A scannable tree plus the request rows that cite it.

    Returns ``{"root": Path, "rows": [...], "lines": {lineage_id: (start, end)}}``.
    """
    # The quote store is agent-LOCAL persistent state. Point it at the tmp dir
    # so the suite never reads or writes the developer's ~/.vulture cache.
    monkeypatch.setenv("VULTURE_L5_CACHE_PATH", str(tmp_path / "cache" / "l5_cache.db"))
    quote_store.reset_for_tests()

    root = tmp_path / "tree"
    (root / "src").mkdir(parents=True)

    # A pruned directory: `node_modules` is in the scanner's hardcoded
    # SKIP_DIRS, so the walker never descends into it. The backend needs that
    # prefix reported to know the scan could not have seen anything under it
    # (LLD §6.5) — without it, a row inside a pruned tree looks "absent".
    (root / "node_modules" / "left-pad").mkdir(parents=True)
    (root / "node_modules" / "left-pad" / "index.js").write_text(
        "module.exports = function () { return 1; };\n", encoding="utf-8"
    )

    lines: dict[str, tuple[int, int]] = {}

    present_start, present_end = _file_with_quote(root / "src" / "app.py", QUOTE_PRESENT)
    lines["ln-present"] = (present_start, present_end)

    # The cited line was deleted: the file still exists, the quote does not.
    removed_start, removed_end = _file_with_quote(root / "src" / "purge.py", QUOTE_REMOVED)
    (root / "src" / "purge.py").write_text(UNRELATED_BODY, encoding="utf-8")
    lines["ln-line-deleted"] = (removed_start, removed_end)

    # The whole file was deleted. `src/vanished.py` is deliberately never created.
    lines["ln-file-deleted"] = (7, 8)

    _oversize_file(root / "src" / "huge.py", QUOTE_OVERSIZE)
    lines["ln-oversize"] = (20001, 20002)

    uncached_start, uncached_end = _file_with_quote(root / "src" / "hashing.py", QUOTE_UNCACHED)
    lines["ln-uncached"] = (uncached_start, uncached_end)

    mismatch_start, mismatch_end = _file_with_quote(root / "src" / "render.py", QUOTE_HASH_MISMATCH)
    lines["ln-hash-mismatch"] = (mismatch_start, mismatch_end)

    # What the agent remembers. Everything except `ln-uncached`, which models a
    # pre-0076 row, a lost cache or a fresh container (S9).
    quote_store.store("fp2-present", QUOTE_PRESENT)
    quote_store.store("fp2-line-deleted", QUOTE_REMOVED)
    quote_store.store("fp2-file-deleted", QUOTE_VANISHED_FILE)
    quote_store.store("fp2-oversize", QUOTE_OVERSIZE)
    quote_store.store("fp2-hash-mismatch", QUOTE_HASH_MISMATCH)

    def _row(lineage_id: str, fp2: str, rel_path: str, qhash: str) -> dict[str, Any]:
        start, end = lines[lineage_id]
        return {
            "lineage_id": lineage_id,
            "fingerprint_v2": fp2,
            "rel_path": rel_path,
            "line_start": start,
            "line_end": end,
            "quote_hash": qhash,
            "status": "open",
            "file_hash": "sha256:" + "1" * 64,
        }

    rows = [
        _row("ln-present", "fp2-present", "src/app.py", quote_hash(QUOTE_PRESENT)),
        _row("ln-line-deleted", "fp2-line-deleted", "src/purge.py", quote_hash(QUOTE_REMOVED)),
        _row("ln-file-deleted", "fp2-file-deleted", "src/vanished.py", quote_hash(QUOTE_VANISHED_FILE)),
        _row("ln-oversize", "fp2-oversize", "src/huge.py", quote_hash(QUOTE_OVERSIZE)),
        _row("ln-uncached", "fp2-uncached", "src/hashing.py", quote_hash(QUOTE_UNCACHED)),
        _row("ln-hash-mismatch", "fp2-hash-mismatch", "src/render.py", WRONG_HASH),
    ]

    yield {"root": root, "rows": rows, "lines": lines}

    quote_store.reset_for_tests()


# --------------------------------------------------------------------------- #
# Harness
# --------------------------------------------------------------------------- #


def _noop_skill(_source_path: str) -> dict:
    """A real skill that finds nothing.

    The evidence pass is about carrying EXISTING lineage forward, so the scan
    deliberately reports no findings of its own — the same shape as the
    incident, where the model was told to skip the one known issue.
    """
    return {"findings": []}


def _parse_event(events: list[str], event_name: str) -> dict:
    for event in events:
        if f"event: {event_name}" in event:
            data_line = next(ln for ln in event.split("\n") if ln.startswith("data:"))
            return json.loads(data_line[5:])
    raise AssertionError(f"no '{event_name}' event found in SSE output")


def _run(root: Path, requested: dict[str, Any] | None) -> dict:
    events = list(
        run_combined_audit(
            run_id="0091-e2e",
            source_path=str(root),
            categories=["noop"],
            skill_map={"noop": _noop_skill},
            lineage_checks_requested=requested,
        )
    )
    return _parse_event(events, "result")


def _checks_by_id(result: dict) -> dict[str, dict]:
    return {check["lineage_id"]: check for check in result["lineage_checks"]}


# --------------------------------------------------------------------------- #
# The contract
# --------------------------------------------------------------------------- #


class TestResultSchemaAndScope:
    """`result_schema` and `pruned_dirs` — what makes the result trustworthy."""

    def test_result_declares_schema_2_and_pruned_dirs_without_any_request(
        self, lineage_tree: dict[str, Any]
    ) -> None:
        """A scan that was asked nothing still has to declare what it saw.

        The backend keys S26 off `result_schema`: absent (or < 2) means "old
        agent, scope unknown, close nothing in the LLM tier". So the key cannot
        be conditional on a request being present — an agent that emitted it
        only when asked for checks would silently disable closure for every
        ordinary scan.
        """
        result = _run(lineage_tree["root"], None)

        assert result["result_schema"] == 2
        assert isinstance(result["pruned_dirs"], list)
        assert result.get("lineage_checks", []) == []

    def test_pruned_dirs_reports_the_prefixes_the_walker_skipped(
        self, lineage_tree: dict[str, Any]
    ) -> None:
        """`node_modules` was never descended into, so it is out of scope.

        Reported as a root-relative prefix. Without it the backend cannot tell
        "this scan proved nothing is there" from "this scan never looked", and
        the latter would close every row under the pruned tree.
        """
        result = _run(lineage_tree["root"], {"schema": 1, "rows": lineage_tree["rows"]})

        pruned = {str(p).strip("/") for p in result["pruned_dirs"]}
        assert "node_modules" in pruned, f"pruned_dirs = {result['pruned_dirs']!r}"
        # Root-relative, not absolute: the backend joins these onto the scanned
        # root itself and cannot do that with a host path.
        for prefix in result["pruned_dirs"]:
            assert not str(prefix).startswith("/"), f"{prefix!r} is not root-relative"


class TestLineageCheckOutcomes:
    """LLD §6.2, one case per branch of the priority ladder."""

    def test_every_requested_row_gets_exactly_one_check(
        self, lineage_tree: dict[str, Any]
    ) -> None:
        """No row may be dropped.

        A requested row that comes back with no check is treated by the backend
        as `unconfirmable(missing)` (LLD §6.4) — deliberately, so a buggy agent
        cannot close a finding by forgetting it. Dropping rows would therefore
        degrade every affected finding to `unconfirmed` on every scan.
        """
        rows = lineage_tree["rows"]
        result = _run(lineage_tree["root"], {"schema": 1, "rows": rows})

        checks = result["lineage_checks"]
        assert len(checks) == len(rows)
        assert _checks_by_id(result).keys() == {row["lineage_id"] for row in rows}

    def test_quote_present_and_unchanged_is_confirmed(
        self, lineage_tree: dict[str, Any]
    ) -> None:
        """S5, the acceptance case: the code is still there, so the row lives.

        This is the outcome that turns the incident's silent closure into a
        carry-forward. It also carries the window and the file hash the backend
        stores as `evidence_*` on the lineage row.
        """
        result = _run(lineage_tree["root"], {"schema": 1, "rows": lineage_tree["rows"]})
        check = _checks_by_id(result)["ln-present"]

        assert check["outcome"] == "confirmed"
        start, end = lineage_tree["lines"]["ln-present"]
        assert check["line_start"] == start
        assert check["line_end"] == end
        assert check["file_hash"].startswith("sha256:")

    def test_cited_line_deleted_is_gone(self, lineage_tree: dict[str, Any]) -> None:
        """S7: the file is still there, the quoted code is not. That is repair.

        `gone` is the ONLY outcome that closes a finding, and this is the only
        case in this suite that earns it from a readable file.
        """
        result = _run(lineage_tree["root"], {"schema": 1, "rows": lineage_tree["rows"]})
        check = _checks_by_id(result)["ln-line-deleted"]

        assert check["outcome"] == "gone"

    def test_file_deleted_is_gone_with_file_missing(
        self, lineage_tree: dict[str, Any]
    ) -> None:
        """S8: the whole file went away. Also repair — but a distinct reason.

        `file_missing` is separated from an absent quote because the two are
        different pieces of history for whoever reads the timeline later.
        """
        result = _run(lineage_tree["root"], {"schema": 1, "rows": lineage_tree["rows"]})
        check = _checks_by_id(result)["ln-file-deleted"]

        assert check["outcome"] == "gone"
        assert check["reason"] == "file_missing"

    def test_oversize_file_is_unconfirmable_never_gone(
        self, lineage_tree: dict[str, Any]
    ) -> None:
        """S23: the reader refused to open the file. That is not evidence.

        The quote IS in this file. Reporting `gone` here would close a live
        finding purely because a file grew past the read cap — so the read
        guard has to resolve to `unconfirmable`, and the reason has to name the
        size so the operator can act on it.
        """
        result = _run(lineage_tree["root"], {"schema": 1, "rows": lineage_tree["rows"]})
        check = _checks_by_id(result)["ln-oversize"]

        assert check["outcome"] == "unconfirmable", (
            "a file too large to read is a fact about the reader, not the code"
        )
        assert "oversize" in check["reason"]

    def test_quote_absent_from_cache_is_unconfirmable_no_quote(
        self, lineage_tree: dict[str, Any]
    ) -> None:
        """S9: nothing to verify against — a pre-0076 row, or a lost cache.

        The row stays active and visible forever rather than being closed on a
        gap in the agent's own memory. Losing the cache must degrade to
        `unconfirmed`, never to `fixed`.
        """
        result = _run(lineage_tree["root"], {"schema": 1, "rows": lineage_tree["rows"]})
        check = _checks_by_id(result)["ln-uncached"]

        assert check["outcome"] == "unconfirmable"
        assert check["reason"] == "no_quote"

    def test_cached_quote_disagreeing_with_the_hash_is_unconfirmable(
        self, lineage_tree: dict[str, Any]
    ) -> None:
        """The cache holds *a* quote, but not the one this row was made from.

        §6.2 folds a hash mismatch into `no_quote` rather than verifying the
        stale text: confirming a finding against evidence it was not made from
        would be worse than not confirming it at all.
        """
        result = _run(lineage_tree["root"], {"schema": 1, "rows": lineage_tree["rows"]})
        check = _checks_by_id(result)["ln-hash-mismatch"]

        assert check["outcome"] == "unconfirmable"
        assert check["reason"] == "no_quote"


class TestQuoteNeverEgresses:
    """LLD §4: the quote is agent-local, in every configuration."""

    def test_no_quote_text_appears_anywhere_on_the_result_event(
        self, lineage_tree: dict[str, Any]
    ) -> None:
        """The lineage row carries a HASH; the text stays in the agent.

        Adding a second consumer of the quote is exactly the moment it could
        start leaking, so the wire is checked directly rather than trusting the
        `_PRIVATE_FIELDS` strip to still cover a field it never saw.
        """
        result = _run(lineage_tree["root"], {"schema": 1, "rows": lineage_tree["rows"]})
        wire = json.dumps(result)

        for quote in (
            QUOTE_PRESENT,
            QUOTE_REMOVED,
            QUOTE_VANISHED_FILE,
            QUOTE_OVERSIZE,
            QUOTE_UNCACHED,
            QUOTE_HASH_MISMATCH,
        ):
            for line in quote.splitlines():
                assert line.strip() not in wire, (
                    f"evidence quote leaked onto the result event: {line!r}"
                )
