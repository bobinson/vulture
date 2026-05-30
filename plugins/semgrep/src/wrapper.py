"""FastAPI wrapper exposing the vulture-plugin/1.0 contract for Semgrep.

Endpoints:
- ``GET /health`` — supervisor probe.
- ``GET /info``   — capability advertisement consumed by the registry.
- ``POST /run``   — runs Semgrep against ``input.source_path`` and
  streams an SSE event sequence per the contract.

Design notes:
- Semgrep blocks (it's a synchronous CLI process). We wrap the
  ``subprocess.run`` call in ``loop.run_in_executor`` so the asyncio
  event loop stays responsive to ``/health`` probes during a scan
  (BLOCKER #2 fix from the 0053 cross-cutting review).
- ``source_path`` is validated via ``normalise_source_path`` BEFORE
  any subprocess call to prevent argv-injection (TM4) and symlink
  escape (BLOCKER #9).
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
from typing import Any, AsyncIterator

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse

from .sse import write_event
from .translate import normalise_source_path, translate_findings

app = FastAPI()

# AUDIT_INPUTS_ROOT is the read-only mount the runtime gives the
# plugin (declared in plugin.toml's runtime.fs.read). Tests substitute
# a tmp_path-based root via the VULTURE_SEMGREP_AUDIT_ROOT env var or
# by monkeypatching this module attribute directly.
AUDIT_INPUTS_ROOT = os.environ.get("VULTURE_SEMGREP_AUDIT_ROOT", "/audit-inputs")

_SEMGREP_TIMEOUT_S = 1500


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/info")
def info() -> dict:
    return {
        "name": "semgrep",
        "version": "0.1.0",
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


def _semgrep_argv(source_path: str, config: dict) -> list[str]:
    # p/security-audit is more useful than p/auto on mixed-language
    # repos (auto can produce zero findings when language-detection
    # picks a pack with few rules for the file mix). Operators can
    # override via config.rule_packs.
    rule_packs = config.get("rule_packs") or ["p/security-audit"]
    # --no-git-ignore: by default Semgrep scans only git-tracked
    # files. Inside the container the bind-mount may not preserve
    # the host's git ownership semantics, leading to silent "0 files
    # scanned" results. Disabling git-ignore makes the scan
    # deterministic regardless of how the host volume was mounted.
    args = ["semgrep", "scan", "--json", "--quiet", "--no-git-ignore"]
    for pack in rule_packs:
        args += ["--config", pack]
    args.append(source_path)
    return args


def _terminal_events(run_id: str, result_payload: dict) -> list[bytes]:
    """Build the trailing three events emitted in every termination path."""
    return [
        write_event("result", result_payload),
        write_event("agent_end", {"agent_type": "semgrep"}),
        write_event("run_finished", {"run_id": run_id}),
    ]


async def _invoke_semgrep(argv: list[str]):
    """Run Semgrep in the threadpool so the asyncio loop stays free."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: subprocess.run(argv, capture_output=True, text=True, timeout=_SEMGREP_TIMEOUT_S),
    )


def _classify_exit(proc) -> dict | None:
    """Return a result-event payload if ``proc`` represents a failure,
    or None when Semgrep ran successfully (exit 0 or 1)."""
    rc = proc.returncode
    if rc == 7:
        return {
            "error": "Semgrep requires authentication; set SEMGREP_APP_TOKEN via runtime.env.optional",
        }
    if rc not in (0, 1):  # 0 = clean, 1 = findings present
        return {"error": (proc.stderr or "")[:2000]}
    return None


def _parse_semgrep_stdout(stdout: str) -> tuple[dict | None, str | None]:
    """Return (parsed_json, error_message). Exactly one is non-None."""
    try:
        return json.loads(stdout or "{}"), None
    except json.JSONDecodeError as exc:
        return None, f"invalid semgrep JSON: {exc}"


async def _run_semgrep_or_failure(argv: list[str]) -> tuple[Any, dict | None]:
    """Invoke Semgrep; return (proc, failure_payload). On timeout proc
    is None and failure_payload describes the timeout."""
    try:
        proc = await _invoke_semgrep(argv)
    except subprocess.TimeoutExpired:
        return None, {"error": f"semgrep timeout ({_SEMGREP_TIMEOUT_S}s)"}
    return proc, _classify_exit(proc)


async def _stream_run(run_id: str, source_path: str, config: dict) -> AsyncIterator[bytes]:
    yield write_event("run_started", {"run_id": run_id})
    yield write_event("agent_start", {"agent_type": "semgrep"})

    started = time.time()
    proc, failure = await _run_semgrep_or_failure(_semgrep_argv(source_path, config))
    if failure is not None:
        for ev in _terminal_events(run_id, failure):
            yield ev
        return

    semgrep_json, parse_err = _parse_semgrep_stdout(proc.stdout)
    if parse_err is not None:
        for ev in _terminal_events(run_id, {"error": parse_err}):
            yield ev
        return

    findings = translate_findings(semgrep_json, agent_type="semgrep")
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


@app.post("/run")
async def run(req: Request):
    body: Any = await req.json()
    _validate_envelope(body)
    run_id = body.get("run_id", "")
    source_path = _resolve_source_path(body)
    config = body.get("config") or {}
    return StreamingResponse(
        _stream_run(run_id, source_path, config),
        media_type="text/event-stream",
    )
