"""FastAPI wrapper exposing the vulture-plugin/1.0 contract for Opengrep.

Endpoints:
- ``GET /health`` — supervisor probe.
- ``GET /info``   — capability advertisement consumed by the registry.
- ``POST /run``   — runs Opengrep against ``input.source_path`` and
  streams an SSE event sequence per the contract.

Design notes:
- The engine blocks (it's a synchronous CLI process). We wrap the
  ``subprocess.run`` call in ``loop.run_in_executor`` so the asyncio
  event loop stays responsive to ``/health`` probes during a scan
  (BLOCKER #2 fix from the 0053 cross-cutting review).
- ``source_path`` is validated via ``normalise_source_path`` BEFORE
  any subprocess call to prevent argv-injection (TM4) and symlink
  escape (BLOCKER #9).
- Request hygiene (feature 0102; docs/spec/plugin-v1/contract.md,
  "Authentication and request hygiene"): on a connection that arrived on a
  loopback address every route requires a loopback ``Host`` (403
  ``forbidden host``), which refuses a DNS-rebinding page; the app serves no
  generated docs routes, so no route escapes that check. On any other address
  (the macOS bridge, compose networks) the check does not apply, and the run
  token is what keeps such a page out of ``/run``. ``/run`` requires the
  ``X-Vulture-Agent-Token`` the backend derived for this plugin whenever
  ``VULTURE_AGENT_TOKEN`` is set (403 ``invalid or missing agent token``),
  and a JSON ``Content-Type`` before the body is read (415); a body that is
  not JSON is the caller's error (400), not the server's.
"""

from __future__ import annotations

import asyncio
import email.message
import functools
import hmac
import ipaddress
import json
import logging
import os
import re
import subprocess
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, Final

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import StreamingResponse

from .sse import write_event
from .translate import normalise_source_path, summarize_scam_risk, translate_findings

log = logging.getLogger(__name__)

# The supervisor injects this plugin's own run token under the in-tree agents'
# variable name, and the backend presents it in this header on every /run.
AGENT_TOKEN_ENV: Final = "VULTURE_AGENT_TOKEN"
AGENT_TOKEN_HEADER: Final = "X-Vulture-Agent-Token"

# The Host names the backend's rule (server.isLoopbackHost) accepts verbatim.
# Matching is case-sensitive, as there: "LOCALHOST" is not on the list.
_LOOPBACK_NAMES: Final = frozenset({"localhost", "127.0.0.1", "::1"})
_BRACKETS: Final = frozenset("[]")


def _is_loopback_host(host: str) -> bool:
    """Whether a ``Host`` header value names a loopback target.

    A port of the backend's ``server.isLoopbackHost``; both are tested against
    ``docs/spec/plugin-v1/loopback_host_vectors.json``. An empty Host counts as
    loopback, the port is stripped where Go's ``net.SplitHostPort`` would strip
    it, IPv6 brackets are trimmed, and the rest must be one of
    ``_LOOPBACK_NAMES`` or a loopback IP address.
    """
    if not host:
        return True
    name = _split_host(host).removeprefix("[").removesuffix("]")
    return name in _LOOPBACK_NAMES or _is_loopback_ip(name)


def _split_host(hostport: str) -> str:
    """The host part Go's ``net.SplitHostPort`` returns for ``hostport``, or
    ``hostport`` unchanged where Go reports an error (no port, or a malformed
    form). The port is whatever follows the last colon and holds no bracket."""
    head, colon, port = hostport.rpartition(":")
    host = _host_before_port(head) if colon and _BRACKETS.isdisjoint(port) else None
    return hostport if host is None else host


def _host_before_port(head: str) -> str | None:
    """The host in the text before a port: ``[h]`` gives ``h``, which may hold
    colons (IPv6); a bare host may not. Neither may hold another bracket."""
    if head[:1] + head[-1:] == "[]":
        return _bracket_free(head[1:-1])
    return None if ":" in head else _bracket_free(head)


def _bracket_free(host: str) -> str | None:
    return host if _BRACKETS.isdisjoint(host) else None


def _is_loopback_ip(name: str) -> bool:
    """Whether ``name`` parses as a loopback IP address, as Go's ``net.ParseIP``
    and ``IP.IsLoopback`` decide it: an IPv4-mapped IPv6 address counts, and an
    IPv6 zone (``::1%lo``), which Go does not parse, does not."""
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        return False
    return (
        not getattr(ip, "scope_id", None)
        and (getattr(ip, "ipv4_mapped", None) or ip).is_loopback
    )


async def _require_loopback_host(request: Request) -> None:
    """Refuse a non-loopback ``Host`` on a connection that arrived on loopback.

    Such a request comes from a browser page whose own name an attacker
    resolved to 127.0.0.1 (DNS rebinding). The check is inert where the
    connection arrived on any other address: the bridge and compose networks,
    where the Host is a container name, and the in-process test client
    (``testserver``).
    """
    server = request.scope.get("server")
    if (
        server
        and _is_loopback_ip(server[0])
        and not _is_loopback_host(request.headers.get("host", ""))
    ):
        raise HTTPException(status_code=403, detail="forbidden host")


# The Host guard is an app-wide dependency, which only API routes run. FastAPI's
# generated documentation routes are plain routes that would skip it, so the
# app serves none: every route it has runs the guard.
app = FastAPI(
    dependencies=[Depends(_require_loopback_host)],
    openapi_url=None,
    docs_url=None,
    redoc_url=None,
)

# AUDIT_INPUTS_ROOT is the read-only mount the runtime gives the
# plugin (declared in plugin.toml's runtime.fs.read). Tests substitute
# a tmp_path-based root by monkeypatching this module attribute.
AUDIT_INPUTS_ROOT = "/audit-inputs"

# 0055: vendored/build/VCS dirs to skip. With --no-git-ignore the engine
# would otherwise walk these (e.g. a multi-GB node_modules), producing
# noise and OOM-killing the container. A SAST tool should audit first-
# party source, not third-party dependencies.
_SCAN_EXCLUDES = [
    # VCS + dependencies
    "node_modules", ".git", "vendor", ".venv", "venv", "__pycache__",
    # build outputs — GENERATED artifacts (minified/bundled), not source.
    # Scanning these yields low-value, duplicated findings in framework code
    # (the real hit is in the source the artifact was built from). Keep in
    # sync with agents/shared file_scanner.SKIP_DIRS + backend staging.skipDirs.
    "target", "dist", "build", "out", ".next", ".nuxt", ".output",
    ".svelte-kit", ".angular", ".docusaurus", "storybook-static",
    ".gradle", ".mvn",
    # tool caches + coverage/test reports
    ".turbo", ".parcel-cache", ".cache", "coverage", ".nyc_output",
]

# Test code, which the engine's default ignore skipped until plugin 0.2.0.
# The plugin now ignores .semgrepignore files (their default also matched a
# scan root's own ancestors), so it keeps that behaviour explicitly: on
# Vulture's own tree, test paths were 4,260 of 4,410 findings without it.
_TEST_EXCLUDES = ["test", "tests", "*_test.go"]

# Cap the engine's analysis memory (MB) so a huge tree can't OOM the
# container. Overridable per-audit via config.max_memory_mb.
_DEFAULT_MAX_MEMORY_MB = 2000

_ENGINE_TIMEOUT_S = 1500


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/info")
def info() -> dict:
    return {
        "name": "opengrep",
        "version": "0.2.0",
        "capabilities": [
            {
                "phase": "scan",
                "emits": ["finding", "result", "run_started", "run_finished", "agent_start", "agent_end"],
            }
        ],
    }


def _validate_envelope(body: dict) -> None:
    # Accept either the formal vulture-plugin/1.0 envelope (LLD MAJOR #11)
    # OR the legacy top-level {run_id, source_path, config} shape that the
    # in-tree agent proxy currently emits. The legacy form is detected by
    # the presence of `source_path` at the top level (or by the absence
    # of an `envelope` key). This back-compat lets the bundled plugin
    # work against the running orchestrator without changing the proxy
    # contract; a future feature can unify the shapes.
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object")
    envelope = body.get("envelope")
    if envelope is None and "source_path" in body:
        return  # legacy shape; accept
    if envelope != "vulture-plugin/1.0":
        raise HTTPException(status_code=400, detail="unsupported envelope")


def _resolve_source_path(body: dict) -> str:
    # Prefer the formal envelope's `input.source_path`; fall back to the
    # legacy top-level field for proxies that haven't migrated.
    nested = (body.get("input") or {}).get("source_path")
    raw = nested if nested is not None else body.get("source_path")
    resolved = normalise_source_path(raw, root=AUDIT_INPUTS_ROOT)
    if resolved is None:
        raise HTTPException(status_code=400, detail="invalid source_path")
    return resolved


# 0102: the bundled rules root. Every rule set in it is listed, hashed and
# licensed (MIT or Apache-2.0 only) in RULESET_SNAPSHOT.json; the engine reads
# nothing else: no Semgrep Registry pack (p/..., r/...) ever reaches --config,
# because their licence allows neither redistribution nor use as a service.
# The engine runs from the root's parent, so a set's --config path is
# relative and its rule ids read `rules.<set path>.<id>`.
RULES_DIR = Path(__file__).resolve().parents[1] / "rules"

_MIN_MEMORY_MB = 256
_MAX_MEMORY_MB = 4000  # matches plugin.toml runtime.resources.memory = 4g


@functools.lru_cache(maxsize=4)
def _bundled_sets(rules_dir: Path) -> dict[str, str]:
    """Set name -> path under ``rules_dir``, from its snapshot, sorted by name."""
    sets = json.loads((rules_dir / "RULESET_SNAPSHOT.json").read_text())["sets"]
    return {name: sets[name]["path"] for name in sorted(sets)}


def _has_rules(path: Path) -> bool:
    return path.is_dir() and any(p.suffix in (".yaml", ".yml") for p in path.rglob("*"))


def _selected_sets(config: dict) -> list[str]:
    """The client's ``rule_sets`` that name bundled sets, else every set
    (never zero-config, and never anything but a bundled set's name)."""
    bundled = _bundled_sets(RULES_DIR)
    raw = config.get("rule_sets")
    chosen = [n for n in raw if isinstance(n, str) and n in bundled] if isinstance(raw, list) else []
    return chosen or list(bundled)


def _rule_config_args(config: dict) -> list[str]:
    """``--config`` pairs for the selected sets whose directory holds rules."""
    bundled = _bundled_sets(RULES_DIR)
    args: list[str] = []
    for name in _selected_sets(config):
        if _has_rules(RULES_DIR / bundled[name]):
            args += ["--config", f"{RULES_DIR.name}/{bundled[name]}"]
    return args


def _clamp_memory_mb(config: dict) -> int:
    """Coerce config.max_memory_mb to a bounded positive int (L3)."""
    try:
        n = int(config.get("max_memory_mb"))
    except (TypeError, ValueError):
        return _DEFAULT_MAX_MEMORY_MB
    return max(_MIN_MEMORY_MB, min(n, _MAX_MEMORY_MB))


def _engine_argv(source_path: str, config: dict) -> list[str]:
    # --no-git-ignore: inside the container the bind-mount may not preserve the
    # host's git ownership, causing silent "0 files scanned"; disabling it makes
    # the scan deterministic regardless of how the volume was mounted.
    # --x-ignore-semgrepignore-files: the engine's default ignore also matches
    # the scan root's own ancestors; _SCAN_EXCLUDES + _TEST_EXCLUDES are the
    # explicit skip list instead.
    # --taint-intrafile: follow taint across functions within a file.
    args = [
        "opengrep", "scan", "--json", "--quiet", "--no-git-ignore",
        "--disable-version-check", "--x-ignore-semgrepignore-files", "--taint-intrafile",
    ]
    # 0055: --no-git-ignore makes the engine walk EVERYTHING (node_modules,
    # target, .git, ...) — noise + a hard OOM (a 3 GB node_modules killed the
    # 4 GB container). Exclude vendored/build dirs and cap analysis memory.
    for pattern in _SCAN_EXCLUDES + _TEST_EXCLUDES:
        args += ["--exclude", pattern]
    args += ["--max-memory", str(_clamp_memory_mb(config))]
    args += _rule_config_args(config)
    # L2: terminate options so source_path can never be parsed as a flag
    # (defence-in-depth atop normalise_source_path's leading-dash guard).
    args += ["--", source_path]
    return args


def _terminal_events(run_id: str, result_payload: dict) -> list[bytes]:
    """Build the trailing three events emitted in every termination path."""
    return [
        write_event("result", result_payload),
        write_event("agent_end", {"agent_type": "opengrep"}),
        write_event("run_finished", {"run_id": run_id}),
    ]


async def _invoke_engine(argv: list[str]):
    """Run the engine in the threadpool so the asyncio loop stays free."""
    loop = asyncio.get_event_loop()
    cwd = RULES_DIR.parent
    return await loop.run_in_executor(
        None,
        lambda: subprocess.run(argv, capture_output=True, text=True, timeout=_ENGINE_TIMEOUT_S, cwd=cwd),
    )


# The engine's stderr reaches the user-facing `result` event, so it is redacted
# before it egresses (CodeQL py/stack-trace-exposure). Redaction rather than
# suppression: a failure must stay distinguishable from a clean scan — a bad
# `--project-root` flag once made every scan fail — so the CLI diagnostic
# survives and only the host detail around it is removed. The untouched text
# still goes to the server log for the operator.
_ABS_PATH_RE = re.compile(r"(?<![\w:/])/(?:[\w.+@-]+/)+[\w.+@-]*")
_SECRET_RE = re.compile(
    r"((?:token|secret|key|password|passwd|pwd)[\"'\s]*[:=][\"'\s]*)\S+",
    re.IGNORECASE,
)
# Backstop for bare secret material with no `key=` prefix. Excludes `_` so
# snake_case identifiers in a traceback survive — over-redacting the message
# text would defeat the diagnosability this whole approach exists to keep.
_BLOB_RE = re.compile(r"\b(?=[A-Za-z0-9-]*[0-9])(?=[A-Za-z0-9-]*[A-Za-z])[A-Za-z0-9-]{20,}\b")


def _redact_stderr(text: str | None, limit: int = 2000) -> str:
    """Strip host paths and token material, keeping the diagnostic text."""
    if not text:
        return ""
    out = _SECRET_RE.sub(r"\1<redacted>", text)
    out = _ABS_PATH_RE.sub(lambda m: Path(m.group(0)).name or "<path>", out)
    out = _BLOB_RE.sub("<redacted>", out)
    return out[:limit]


def _classify_exit(proc) -> dict | None:
    """Return a result-event payload if ``proc`` represents a failure,
    or None when the engine ran successfully (exit 0 or 1)."""
    rc = proc.returncode
    if rc in (0, 1):  # 0 = clean, 1 = findings present
        return None
    log.error("opengrep exited rc=%s; stderr: %s", rc, proc.stderr or "")
    return {"error": _redact_stderr(proc.stderr) or f"opengrep exited with status {rc}"}


def _parse_engine_stdout(stdout: str) -> tuple[dict | None, str | None]:
    """Return (parsed_json, error_message). Exactly one is non-None."""
    try:
        return json.loads(stdout or "{}"), None
    except json.JSONDecodeError as exc:
        return None, f"invalid opengrep JSON: {_redact_stderr(str(exc))}"


async def _run_engine_or_failure(argv: list[str]) -> tuple[Any, dict | None]:
    """Invoke the engine; return (proc, failure_payload). On timeout proc
    is None and failure_payload describes the timeout."""
    try:
        proc = await _invoke_engine(argv)
    except subprocess.TimeoutExpired:
        return None, {"error": f"opengrep timeout ({_ENGINE_TIMEOUT_S}s)"}
    return proc, _classify_exit(proc)


async def _stream_run(run_id: str, source_path: str, config: dict) -> AsyncIterator[bytes]:
    yield write_event("run_started", {"run_id": run_id})
    yield write_event("agent_start", {"agent_type": "opengrep"})

    started = time.time()
    proc, failure = await _run_engine_or_failure(_engine_argv(source_path, config))
    if failure is not None:
        for ev in _terminal_events(run_id, failure):
            yield ev
        return

    engine_json, parse_err = _parse_engine_stdout(proc.stdout)
    if parse_err is not None:
        for ev in _terminal_events(run_id, {"error": parse_err}):
            yield ev
        return

    # root=source_path so the engine's file paths are normalized to repo-relative
    # and line up with the in-tree agents' paths in cross-agent dedup (C1).
    findings = translate_findings(engine_json, agent_type="opengrep", root=source_path)
    # P2g: correlate co-occurring scam markers into a composite high-severity
    # finding (the engine can't reason across findings). Appended so it both
    # streams and survives in the authoritative `result` snapshot below.
    findings.extend(summarize_scam_risk(findings, agent_type="opengrep"))
    for f in findings:
        yield write_event("finding", f)
        await asyncio.sleep(0)  # cooperative yield to the event loop

    # The orchestrator's drainResult treats the `result` event as the
    # authoritative snapshot for an agent; when present it supersedes
    # streamed `finding` events. Include the findings list here so
    # they survive persistence. (Without this the StateDelta findings
    # are emitted but dropped at persist time because the snapshot's
    # empty findings list wins.)
    for ev in _terminal_events(
        run_id,
        {
            "findings": findings,
            "findings_count": len(findings),
            "duration_s": time.time() - started,
        },
    ):
        yield ev


def _verify_agent_token(
    x_vulture_agent_token: str | None = Header(None, alias=AGENT_TOKEN_HEADER),
) -> None:
    """Refuse ``/run`` without the run token whenever one is configured.

    The token is read per request, never at import. It is compared as bytes,
    in constant time: a missing, wrong or non-ASCII header is a 403, never a
    500 (``hmac.compare_digest`` raises on non-ASCII ``str``). Unset, the
    plugin was started by hand and ``/run`` stays open; under the backend's
    supervisor a token is always injected.
    """
    expected = os.environ.get(AGENT_TOKEN_ENV, "")
    if not expected:
        _warn_open_run()
        return
    if not hmac.compare_digest((x_vulture_agent_token or "").encode(), expected.encode()):
        raise HTTPException(status_code=403, detail="invalid or missing agent token")


@functools.cache
def _warn_open_run() -> None:
    log.warning(
        "%s is not set: /run accepts every caller. Only a plugin started by hand runs "
        "this way; under the Vulture backend a token is always injected.",
        AGENT_TOKEN_ENV,
    )


def _require_json(request: Request) -> None:
    """Refuse a ``/run`` body not declared as JSON, before it is read.

    FastAPI's own media-type rule (``application/json`` or
    ``application/*+json``, parsed with ``email.message``), except that a
    missing ``Content-Type`` is refused too: a form or multipart post, which a
    browser may send cross-origin without a preflight, never reaches the body.
    """
    if not _is_json_media_type(request.headers.get("content-type", "")):
        raise HTTPException(status_code=415, detail="Content-Type must be application/json")


def _is_json_media_type(content_type: str) -> bool:
    message = email.message.Message()
    message["content-type"] = content_type
    subtype = message.get_content_subtype()
    return message.get_content_maintype() == "application" and (
        subtype == "json" or subtype.endswith("+json")
    )


async def _read_json(req: Request) -> Any:
    try:
        return await req.json()
    except ValueError as exc:  # JSONDecodeError and UnicodeDecodeError alike
        raise HTTPException(status_code=400, detail="invalid JSON body") from exc


@app.post("/run", dependencies=[Depends(_verify_agent_token), Depends(_require_json)])
async def run(req: Request):
    body: Any = await _read_json(req)
    _validate_envelope(body)
    run_id = body.get("run_id", "")
    source_path = _resolve_source_path(body)
    config = body.get("config") or {}
    return StreamingResponse(
        _stream_run(run_id, source_path, config),
        media_type="text/event-stream",
    )
