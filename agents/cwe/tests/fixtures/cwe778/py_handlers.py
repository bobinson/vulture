"""Ingest helpers for the reporting service.

CWE-778 exception-family fixture for feature 0087. Every handler site is
marked with ``EXPECT: finding`` / ``EXPECT: clean`` on the comment line
IMMEDIATELY ABOVE the handler header; ``EXPECTATIONS.md`` in this directory
records the exact line number and the reason for every marked site.

Nothing imports or executes this module -- it is read as text by the
detector under test.
"""
# ruff: noqa: E701, E722
from __future__ import annotations

import contextlib
import json
import logging
import os
import shutil
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)

MANIFEST_NAME = "ingest-manifest.json"
SNAPSHOT_TIMEOUT = 15.0


def load_manifest(root: Path) -> dict[str, object]:
    """Read the ingest manifest, tolerating a corrupt or missing file."""
    manifest = root / MANIFEST_NAME
    try:
        with manifest.open(encoding="utf-8") as handle:
            return json.load(handle)
    # EXPECT: finding -- id=py_swallow_multi -- `except (A, B) as e` returns a
    # default and records nothing about why the manifest could not be read.
    except (OSError, json.JSONDecodeError) as exc:
        return {"_manifest_error": type(exc).__name__, "entries": []}


def read_rows(db_path: Path, limit: int) -> list[tuple[str, str]]:
    """Return pending ingest rows, or an empty batch if the table is gone."""
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.execute(
            "SELECT id, payload FROM ingest_rows WHERE state = 'pending' LIMIT ?",
            (limit,),
        )
        return cursor.fetchall()
    # EXPECT: finding -- id=py_bare_except -- bare `except:` swallows every
    # exception class, including KeyboardInterrupt, and leaves no trace.
    except:
        return []
    finally:
        conn.close()


def fetch_snapshot(url: str, opener) -> bytes | None:
    """Fetch the upstream snapshot, degrading to the cached copy on timeout."""
    try:
        with opener(url, timeout=SNAPSHOT_TIMEOUT) as response:
            return response.read()
    # EXPECT: clean -- id=py_logs -- the handler records the failure before it
    # degrades to the cached copy.
    except TimeoutError as exc:
        logger.warning("snapshot fetch timed out for %s: %s", url, exc)
        return None


def purge_partial(path: Path) -> None:
    """Delete a half-written artefact left behind by a crashed ingest run."""
    try:
        path.unlink()
    # EXPECT: clean -- id=py_header_line_log -- the whole handler body sits on
    # the header line and it logs (Python analogue of defect B1).
    except FileNotFoundError as exc: logger.info("nothing to purge at %s: %s", path, exc)


def parse_row(raw: str) -> dict[str, object]:
    """Parse one NDJSON ingest row."""
    try:
        return json.loads(raw)
    # EXPECT: clean -- id=py_reraise -- wrapped and re-raised, so the caller
    # still receives the evidence.
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed ingest row: {raw[:80]!r}") from exc


def stat_mtime(path: Path) -> float | None:
    """Return the mtime of ``path``, or None when it cannot be stat'ed."""
    try:
        return os.stat(path).st_mtime
    # EXPECT: finding -- id=py_scope_leak -- defect B2: swallowed here, and the
    # only nearby log call belongs to purge_cache() below. A different
    # function's logging must not excuse this handler.
    except OSError:
        return None


def purge_cache(root: Path) -> int:
    """Delete stale temp files under ``root`` and report how many went."""
    removed = 0
    logger.info("purging cache under %s", root)
    for entry in root.glob("*.tmp"):
        entry.unlink(missing_ok=True)
        removed += 1
    return removed


def optional_index(root: Path) -> Path | None:
    """Return the prebuilt index shipped with the dataset, if there is one."""
    try:
        return next(root.glob("*.idx"))
    # EXPECT: finding -- id=py_trailing_comment_header -- defect B4: the
    # trailing comment on the header defeats `_PY_EXCEPT`'s `\s*$` anchor, so
    # the swallow is invisible today.
    except StopIteration:  # rebuilt lazily, so a missing index is tolerable
        return None


def env_int(name: str, default: int) -> int:
    """Read an integer tunable from the environment."""
    try:
        return int(os.environ[name])
    # EXPECT: finding -- id=py_inline_pass -- same-line trivial body.
    except KeyError: pass
    return default


def drop_workdir(path: Path) -> None:
    """Remove a scratch directory at the end of an ingest run."""
    # EXPECT: finding -- id=py_suppress -- contextlib.suppress discards the
    # error with no record at all.
    with contextlib.suppress(FileNotFoundError, PermissionError):
        shutil.rmtree(path)
