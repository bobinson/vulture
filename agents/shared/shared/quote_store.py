"""Feature 0091 §4/§6.2 — the agent-local store of evidence quotes.

WHY IT EXISTS. Closure of an LLM-tier finding may not come from the model's
silence (§4: "absence from an LLM result is never evidence"); it has to come
from the code. The only artefact that can decide "is the accused line still
there" is the ``evidence_quote`` the model produced under 0076 — and that
string never leaves this process: ``audit_runner._PRIVATE_FIELDS`` strips it
before SSE and the Go backend has no reference to it. So the backend cannot
re-verify anything. It asks; the agent answers from what it remembers, and this
module is that memory.

WHERE IT LIVES. The same SQLite file the L5 verdict cache already uses
(``VULTURE_L5_CACHE_PATH``, default ``~/.vulture/l5_cache.db``), reached through
``validate.l5_cache._connect()`` — one file, one connection, one lock, one set
of permissions (0700/0600) to reason about. A second DB would double the
data-posture surface for no gain.

WHAT IT HOLDS. ``evidence_quotes(fingerprint_v2 PK, quote, quote_hash,
updated_at)``. The quote is stored in its *normalised* form (``anchor.key`` —
whitespace collapsed, presentation lines dropped), which is the only form the
verifier compares against, and NOT redacted: a redacted quote cannot be located
in a file, so redaction here would make the whole check inert. The text
therefore never egresses in any configuration — the lineage row carries only
``quote_hash``, and losing this file degrades a check to ``unconfirmable``,
never to ``fixed`` (S9).

TWO KEYS, DELIBERATELY. ``fingerprint_v2`` is computed by the BACKEND (feature
0079, Go), so the agent does not know it at the moment it emits a finding. The
emit path therefore writes content-addressed via :func:`store_by_hash`, and the
verify path resolves ``fingerprint_v2`` first and falls back to the row's
``quote_hash`` through the indexed column. Both routes end at the same row.

CONCURRENCY. Identical posture to ``l5_cache``: one shared connection in WAL
mode, every statement serialised on that module's lock, no long transactions,
and multiple agent processes sharing the file safely. Every failure is a
warning and a no-op — a cache is a nicety, and a store that raises would lose
the finding it was called on.
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
import time

from shared import anchor

__all__ = [
    "lookup",
    "lookup_by_hash",
    "normalise_quote",
    "quote_hash",
    "reset_for_tests",
    "store",
    "store_by_hash",
]

log = logging.getLogger(__name__)

_TABLE_DDL = """
    CREATE TABLE IF NOT EXISTS evidence_quotes (
        fingerprint_v2 TEXT PRIMARY KEY,
        quote          TEXT NOT NULL,
        quote_hash     TEXT NOT NULL,
        updated_at     REAL NOT NULL
    )
"""
# The verify path resolves by hash whenever it has no fingerprint_v2 row, which
# is the common case until the backend starts feeding v2 back (§7.3).
_INDEX_DDL = (
    "CREATE INDEX IF NOT EXISTS idx_evidence_quotes_hash "
    "ON evidence_quotes (quote_hash)"
)

_SELECT_BY_FP2 = "SELECT quote FROM evidence_quotes WHERE fingerprint_v2 = ? LIMIT 1"
_SELECT_BY_HASH = (
    "SELECT quote FROM evidence_quotes WHERE quote_hash = ? "
    "ORDER BY updated_at DESC LIMIT 1"
)
_UPSERT = (
    "INSERT OR REPLACE INTO evidence_quotes "
    "(fingerprint_v2, quote, quote_hash, updated_at) VALUES (?, ?, ?, ?)"
)

# Whether ``evidence_quotes`` has been created on the CURRENT connection.
# Reset with the connection itself, because a new connection may point at a
# different file (a test swapping VULTURE_L5_CACHE_PATH is exactly that).
_table_ready = False


def normalise_quote(quote: str) -> str:
    """The comparable form of a quote: ``anchor.key`` over its lines.

    Single-sourced on the 0076 verifier rather than re-implemented, because a
    second normalisation would let the hash agree with a quote the verifier
    then fails to locate — the one way this store could confirm a finding
    against evidence it was not made from.
    """
    return anchor.key(str(quote or "").splitlines())


def quote_hash(quote: str) -> str:
    """``"sha256:" + sha256(normalise_quote(quote))``.

    The ONE definition of the hash a lineage row carries. Re-exported by
    ``shared.lineage_checks`` so both sides of the wire (§6.1) resolve the same
    symbol and cannot disagree about normalisation.
    """
    digest = hashlib.sha256(normalise_quote(quote).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def store(fingerprint_v2: str, quote: str) -> None:
    """Remember ``quote`` under ``fingerprint_v2``. Best-effort, never raises."""
    key = str(fingerprint_v2 or "").strip()
    text = normalise_quote(quote)
    if not key or not text:
        return
    conn = _conn()
    if conn is None:
        return
    _execute(conn, _UPSERT, (key, text, quote_hash(text), time.time()), write=True)


def store_by_hash(quote: str) -> str:
    """Content-addressed write for the EMIT path, returning the hash.

    ``audit_runner`` has no ``fingerprint_v2`` when a finding is emitted — the
    backend derives it (0079). Keying the row by its own content hash makes it
    findable by the only identifier the lineage row is guaranteed to carry.
    """
    digest = quote_hash(quote)
    store(digest, quote)
    return digest


def lookup(fingerprint_v2: str) -> str | None:
    """The normalised quote remembered for ``fingerprint_v2``, or ``None``."""
    return _select(_SELECT_BY_FP2, fingerprint_v2)


def lookup_by_hash(hash_value: str) -> str | None:
    """The normalised quote whose hash is ``hash_value``, or ``None``."""
    return _select(_SELECT_BY_HASH, hash_value)


def reset_for_tests() -> None:
    """Drop the shared connection so the next call re-reads the env path.

    Delegates to ``l5_cache`` because the connection is that module's; only the
    table flag is ours.
    """
    global _table_ready
    from shared.validate import l5_cache

    _table_ready = False
    l5_cache.reset_for_tests()


def _conn() -> sqlite3.Connection | None:
    """The shared cache connection with ``evidence_quotes`` present, or ``None``.

    Imported lazily: ``shared.validate.__init__`` pulls in the whole validation
    stack, and this module is imported from the audit runner's parse choke point.
    """
    global _table_ready
    from shared.validate import l5_cache

    conn = l5_cache._connect()
    if conn is None or _table_ready:
        return conn
    try:
        with l5_cache._LOCK:
            conn.execute(_TABLE_DDL)
            conn.execute(_INDEX_DDL)
    except Exception as exc:
        log.warning("[0091.quote_store] table init failed (continuing): %s", exc)
        return None
    _table_ready = True
    return conn


def _select(sql: str, value: str) -> str | None:
    """One row's quote, or ``None`` on miss / unusable cache."""
    key = str(value or "").strip()
    if not key:
        return None
    conn = _conn()
    if conn is None:
        return None
    row = _execute(conn, sql, (key,), write=False)
    return (row[0] or None) if row else None


def _execute(conn: sqlite3.Connection, sql: str, params: tuple,
             *, write: bool) -> tuple | None:
    """Run one statement under the cache lock. Failure is a warning, not a raise.

    Serialising on ``l5_cache._LOCK`` is not optional: the audit runner drives
    several generators per interpreter and the skill pool is multi-threaded, and
    two threads calling ``execute()`` on one sqlite3 connection raise
    SQLITE_MISUSE or tear a cursor read.
    """
    from shared.validate import l5_cache

    try:
        with l5_cache._LOCK:
            cursor = conn.execute(sql, params)
            return None if write else cursor.fetchone()
    except Exception as exc:
        log.warning("[0091.quote_store] %s failed: %s", "store" if write else "lookup", exc)
        return None
