"""Feature 0091 §6.2 — the ladder branches the E2E suite cannot stage cheaply.

The E2E file owns the acceptance cases (present / line deleted / file deleted /
oversize / uncached / hash mismatch). These cover the rest of the ladder, and
in particular the two rules that keep it safe:

  * ``gone`` is the ONLY outcome that closes a finding, so every fact about the
    CHECKER — a crashing verifier, a binary file, an unreadable one — has to
    resolve to ``unconfirmable``;
  * no row is ever dropped, because the backend reads a missing check as
    ``unconfirmable(missing)`` and a dropped row would degrade a live finding
    on every scan.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shared import anchor, lineage_checks, quote_store
from shared.lineage_checks import quote_hash, verify_lineage_checks

QUOTE = (
    'token = request.headers.get("X-Api-Token")\n'
    'if token == "s3cr3t-static-token-value":'
)

BODY = (
    '"""Fixture."""\n'
    "\n"
    "\n"
    "def handle(request):\n"
    '    token = request.headers.get("X-Api-Token")\n'
    '    if token == "s3cr3t-static-token-value":\n'
    "        pass\n"
    "    return None\n"
)
QUOTE_LINE = 5


@pytest.fixture(autouse=True)
def _local_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("VULTURE_L5_CACHE_PATH", str(tmp_path / "cache" / "l5_cache.db"))
    quote_store.reset_for_tests()
    anchor.clear_cache()
    yield
    quote_store.reset_for_tests()
    anchor.clear_cache()


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "tree"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text(BODY, encoding="utf-8")
    quote_store.store("fp2-present", QUOTE)
    return root


def _row(**over: object) -> dict:
    row = {
        "lineage_id": "ln-1",
        "fingerprint_v2": "fp2-present",
        "rel_path": "src/app.py",
        "line_start": QUOTE_LINE,
        "line_end": QUOTE_LINE + 1,
        "quote_hash": quote_hash(QUOTE),
        "status": "open",
        "file_hash": "sha256:" + "1" * 64,
    }
    row.update(over)
    return row


class TestRequestHandling:
    def test_no_request_is_no_answer(self, tree: Path) -> None:
        assert verify_lineage_checks(None, tree) == []
        assert verify_lineage_checks([], tree) == []

    def test_every_row_is_answered_in_request_order(self, tree: Path) -> None:
        rows = [_row(lineage_id="a"), _row(lineage_id="b", rel_path="src/gone.py"),
                _row(lineage_id="c", fingerprint_v2="fp2-unknown", quote_hash="")]

        checks = verify_lineage_checks(rows, tree)

        assert [c["lineage_id"] for c in checks] == ["a", "b", "c"]

    def test_a_file_cited_by_several_rows_is_read_once(self, tree: Path) -> None:
        """LLD P2: cost is one read per distinct FILE, never per row."""
        reads: list[Path] = []

        def _counting_reader(path: Path) -> str | None:
            reads.append(path)
            return path.read_text(encoding="utf-8")

        rows = [_row(lineage_id=f"ln-{i}") for i in range(5)]

        verify_lineage_checks(rows, tree, _counting_reader)

        assert len(reads) == 1


class TestNeverGoneOnACheckerFault:
    def test_a_crashing_verifier_is_unconfirmable(
        self, tree: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """S25. `gone` closes a finding; an exception is not evidence of repair."""
        def _boom(*_args: object, **_kwargs: object) -> None:
            raise ValueError("verifier exploded")

        monkeypatch.setattr(lineage_checks.anchor, "verify_anchor", _boom)

        check = verify_lineage_checks([_row()], tree)[0]

        assert check["outcome"] == "unconfirmable"
        assert check["reason"] == "error:ValueError"

    def test_a_binary_file_is_unconfirmable(self, tree: Path) -> None:
        (tree / "src" / "blob.bin").write_bytes(b"\x00\x01\x02" * 100)

        check = verify_lineage_checks([_row(rel_path="src/blob.bin")], tree)[0]

        assert check["outcome"] == "unconfirmable"
        assert check["reason"] == "binary"

    def test_an_unreadable_file_is_unconfirmable(self, tree: Path) -> None:
        def _refuse(_path: Path) -> str | None:
            return None

        check = verify_lineage_checks([_row()], tree, _refuse)[0]

        assert check["outcome"] == "unconfirmable"
        assert check["reason"] == "unreadable"

    def test_a_quote_below_the_signal_floor_is_unconfirmable_not_gone(
        self, tree: Path,
    ) -> None:
        """0076's floor rejects a degenerate quote as EVIDENCE.

        `});` matches hundreds of lines, so it can neither confirm nor refute —
        and refuting on it would close findings wholesale.
        """
        quote_store.store("fp2-tiny", "pass")
        row = _row(fingerprint_v2="fp2-tiny", quote_hash=quote_hash("pass"))

        check = verify_lineage_checks([row], tree)[0]

        assert check["outcome"] == "unconfirmable"


class TestWindowAndHash:
    def test_a_confirmed_row_carries_the_verified_window(self, tree: Path) -> None:
        check = verify_lineage_checks([_row()], tree)[0]

        assert check["outcome"] == "confirmed"
        assert (check["line_start"], check["line_end"]) == (QUOTE_LINE, QUOTE_LINE + 1)

    def test_a_moved_quote_reanchors_onto_its_new_window(self, tree: Path) -> None:
        """S22: the code did not change, the line number did."""
        shifted = "\n" * 6 + BODY
        (tree / "src" / "app.py").write_text(shifted, encoding="utf-8")

        check = verify_lineage_checks([_row()], tree)[0]

        assert check["outcome"] == "reanchored"
        assert check["line_start"] == QUOTE_LINE + 6
        assert check["line_end"] == QUOTE_LINE + 7

    def test_the_file_hash_is_reported_and_tracks_content(self, tree: Path) -> None:
        first = verify_lineage_checks([_row()], tree)[0]["file_hash"]
        assert first.startswith("sha256:")

        (tree / "src" / "app.py").write_text(BODY + "# touched\n", encoding="utf-8")
        from shared.tools.file_scanner import clear_caches

        clear_caches()

        assert verify_lineage_checks([_row()], tree)[0]["file_hash"] != first

    def test_a_missing_file_reports_no_hash(self, tree: Path) -> None:
        check = verify_lineage_checks([_row(rel_path="src/vanished.py")], tree)[0]

        assert check["outcome"] == "gone"
        assert check["reason"] == "file_missing"
        assert check["file_hash"] is None


class TestQuoteResolution:
    def test_the_hash_fallback_finds_a_content_addressed_row(self, tree: Path) -> None:
        """The EMIT path has no fingerprint_v2, so it writes by content hash.

        Without this fallback every row the agent itself remembered would come
        back `no_quote` and degrade to `unconfirmed` on the very next scan.
        """
        quote_store.reset_for_tests()
        quote_store.store_by_hash(QUOTE)

        check = verify_lineage_checks([_row(fingerprint_v2="fp2-unknown")], tree)[0]

        assert check["outcome"] == "confirmed"

    def test_a_cached_quote_that_disagrees_with_the_hash_is_refused(
        self, tree: Path,
    ) -> None:
        check = verify_lineage_checks(
            [_row(quote_hash="sha256:" + "0" * 64)], tree,
        )[0]

        assert check["outcome"] == "unconfirmable"
        assert check["reason"] == "no_quote"


class TestOnlyAMissingFileIsGone:
    """`gone` is reserved for "the file is not there".

    ``Path.is_file()`` answers False for two entirely different facts — "there
    is no such file" and "I could not find out" — and the ladder's whole point
    is that only the first may close a finding. A directory, a symlink loop, a
    non-directory component and an empty citation are all the second kind.
    """

    def test_a_directory_is_unconfirmable_not_gone(self, tree: Path) -> None:
        """An architectural finding legitimately cites a package directory.

        chaos ("no circuit breaker patterns detected") and asvs ("endpoints may
        lack rate limiting") name a directory, not a line. A directory is not
        evidence that the code inside it was repaired.
        """
        check = verify_lineage_checks([_row(rel_path="src")], tree)[0]

        assert check["outcome"] == "unconfirmable"
        assert check["reason"] == "not_a_file"

    def test_a_symlink_loop_is_unconfirmable_not_gone(self, tree: Path) -> None:
        """ELOOP is a fact about the checker. `Path.exists()` also swallows it,
        so classifying by errno is the only thing that separates it from
        ENOENT."""
        loop = tree / "src" / "loop.py"
        loop.symlink_to(loop)

        check = verify_lineage_checks([_row(rel_path="src/loop.py")], tree)[0]

        assert check["outcome"] == "unconfirmable"
        assert check["reason"].startswith("unreadable:")

    def test_a_non_directory_component_is_unconfirmable_not_gone(
        self, tree: Path,
    ) -> None:
        """ENOTDIR: the tree was restructured, not necessarily repaired."""
        check = verify_lineage_checks([_row(rel_path="src/app.py/child.py")], tree)[0]

        assert check["outcome"] == "unconfirmable"
        assert check["reason"].startswith("unreadable:")

    def test_an_empty_rel_path_is_unconfirmable_not_gone(self, tree: Path) -> None:
        """An empty citation used to resolve to the scan ROOT and be stat'ed."""
        check = verify_lineage_checks([_row(rel_path="")], tree)[0]

        assert check["outcome"] == "unconfirmable"
        assert check["reason"] == "no_path"

    def test_a_deleted_file_is_still_gone(self, tree: Path) -> None:
        """The control: the one case that MUST keep closing findings."""
        (tree / "src" / "app.py").unlink()

        check = verify_lineage_checks([_row()], tree)[0]

        assert check["outcome"] == "gone"
        assert check["reason"] == "file_missing"


class TestRootConfinement:
    """`rel_path` is resolved against the scan root and may not escape it.

    ``base / rel`` returns ``rel`` verbatim when ``rel`` is absolute, and
    pathlib does not collapse ``..``. ``audit_runner._resolve_finding_path``
    documents this exact threat for the finding path and refuses it; the
    lineage checker is a SECOND file-reading path on the same untrusted string
    and applied no confinement at all.
    """

    @pytest.fixture()
    def outside(self, tmp_path: Path) -> Path:
        secret = tmp_path / "outside" / "secret.env"
        secret.parent.mkdir(parents=True, exist_ok=True)
        secret.write_text(BODY, encoding="utf-8")
        return secret

    def test_an_absolute_rel_path_is_refused(self, tree: Path, outside: Path) -> None:
        check = verify_lineage_checks([_row(rel_path=str(outside))], tree)[0]

        assert check["outcome"] == "unconfirmable"
        assert check["reason"] == "outside_root"

    def test_a_traversal_rel_path_is_refused(self, tree: Path, outside: Path) -> None:
        check = verify_lineage_checks(
            [_row(rel_path="../outside/secret.env")], tree,
        )[0]

        assert check["outcome"] == "unconfirmable"
        assert check["reason"] == "outside_root"

    def test_a_refused_path_is_never_read_or_hashed(
        self, tree: Path, outside: Path,
    ) -> None:
        """The refusal has to happen BEFORE the read: the sha256 of an
        out-of-tree file is persisted by the backend as `evidence_file_hash`.
        """
        reads: list[Path] = []

        def _recording_reader(path: Path) -> str | None:
            reads.append(path)
            return path.read_text(encoding="utf-8")

        check = verify_lineage_checks(
            [_row(rel_path=str(outside))], tree, _recording_reader,
        )[0]

        assert reads == []
        assert check["file_hash"] is None

    def test_an_in_tree_path_is_still_checked(self, tree: Path) -> None:
        """The control: confinement must not refuse the ordinary case."""
        check = verify_lineage_checks([_row(rel_path="./src/app.py")], tree)[0]

        assert check["outcome"] == "confirmed"
