"""Failure descriptions that are safe to put in proof evidence and the stream.

Proof evidence is persisted (prove_results.evidence) and an ``ERROR:`` stream
line becomes the audit's stored error message, so both reach whoever reads
the audit. Exception TEXT does not belong there. Measured on the old
``f"WebSocket error: {exc}"`` shape: a refused WebSocket reads
``[Errno 111] Connect call failed ('10.0.3.7', 9944)`` (an internal
address), a resolver failure names the host it could not resolve, and an
exception raised while handling a finding can quote a source path. Every
``/word`` in attempt evidence was also crawled ON THE TARGET by incremental
discovery, so a path in an exception message was sent to the staging host.

What the reader needs is the KIND of failure, so evidence carries a fixed
category plus the exception class (``connection refused (ConnectError)``),
and an HTTP status only as an integer read from the target's response. The
category is chosen by TYPE, walking ``__cause__``/``__context__``: httpx
reports DNS, refusal and TLS failures as ``ConnectError`` whose cause is the
``gaierror`` / ``ConnectionRefusedError`` / ``SSLError`` that names the real
fault. The full text goes to the server log only, through the existing
``exception_detail`` (cause chain + secret redaction).

The ``failure_reason`` classifiers are deliberately untouched: they read the
message internally to drive protocol fallback and never emit it.
"""

import logging
import socket
import ssl

import httpx
from websockets import exceptions as ws_exc

from shared.llm.errors import exception_detail

INTERNAL_ERROR = "internal error"

# Priority order: the first row whose type appears ANYWHERE in the chain wins,
# so a ConnectError caused by gaierror reads "name resolution failed", not the
# generic "connection failed" its own type would give. InvalidStatus precedes
# the WebSocketException row because it is a subclass of it; the OSError row
# is last because gaierror, SSLError, ConnectionRefusedError and TimeoutError
# all subclass OSError.
_CATEGORIES: tuple[tuple[tuple[type[BaseException], ...], str], ...] = (
    ((socket.gaierror,), "name resolution failed"),
    ((ssl.SSLError,), "TLS handshake failed"),
    ((ConnectionRefusedError,), "connection refused"),
    ((TimeoutError, httpx.TimeoutException), "timed out"),
    ((ws_exc.InvalidStatus,), "handshake rejected"),
    ((httpx.ProtocolError, httpx.UnsupportedProtocol, httpx.DecodingError,
      ws_exc.WebSocketException), "protocol error"),
    ((ConnectionError, httpx.NetworkError, OSError), "connection failed"),
)
# A real chain is 2-3 links (httpx -> httpcore -> socket); the bound only
# matters for a pathological or cyclic chain, or a wide task group.
_MAX_LINKS = 6


def _in_chain(link: BaseException, chain: list[BaseException]) -> bool:
    return any(link is seen for seen in chain)


def _next_links(exc: BaseException) -> list[BaseException | None]:
    """The cause/context link, plus a task group's members: a refused
    connection raised through a TaskGroup arrives as an ExceptionGroup whose
    own type says nothing about the fault."""
    members = list(exc.exceptions) if isinstance(exc, BaseExceptionGroup) else []
    return [exc.__cause__ or exc.__context__, *members]


def _unseen(
    links: list[BaseException | None], chain: list[BaseException],
) -> list[BaseException]:
    return [n for n in links if n is not None and not _in_chain(n, chain)]


def _links(exc: BaseException) -> list[BaseException]:
    """``exc`` and everything reachable from it (cause/context chain, group
    members), breadth first, bounded and cycle-safe."""
    chain = [exc]
    i = 0
    while i < len(chain) < _MAX_LINKS:
        chain += _unseen(_next_links(chain[i]), chain)
        i += 1
    return chain[:_MAX_LINKS]


def failure_category(exc: BaseException) -> str:
    """Fixed label for the kind of failure; never derived from the message."""
    chain = _links(exc)
    for types, label in _CATEGORIES:
        if any(isinstance(link, types) for link in chain):
            return label
    return INTERNAL_ERROR


def _status_suffix(exc: BaseException) -> str:
    """``, HTTP 403`` when the exception carries the target's response status."""
    try:
        code = exc.response.status_code  # type: ignore[attr-defined]
    except Exception:
        return ""
    if type(code) is int and 100 <= code <= 599:
        return f", HTTP {code}"
    return ""


def describe_failure(exc: BaseException) -> str:
    """Public description: ``<category> (<ExceptionClass>[, HTTP nnn])``.

    Never raises: it runs inside failure handlers, where an exception would
    replace a reported problem with an unreported one.
    """
    try:
        return f"{failure_category(exc)} ({type(exc).__name__}{_status_suffix(exc)})"
    except Exception:  # pragma: no cover - defensive, see docstring
        return INTERNAL_ERROR


def log_failure(log: logging.Logger, where: str, exc: BaseException) -> None:
    """Full (secret-redacted) detail to the server log only."""
    log.warning("prove_failure where=%s detail=%s", where, exception_detail(exc))
