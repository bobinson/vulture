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
import functools
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse

from .sse import write_event
from .translate import normalise_source_path, summarize_scam_risk, translate_findings

app = FastAPI()

# AUDIT_INPUTS_ROOT is the read-only mount the runtime gives the
# plugin (declared in plugin.toml's runtime.fs.read). Tests substitute
# a tmp_path-based root via the VULTURE_SEMGREP_AUDIT_ROOT env var or
# by monkeypatching this module attribute directly.
AUDIT_INPUTS_ROOT = os.environ.get("VULTURE_SEMGREP_AUDIT_ROOT", "/audit-inputs")

# 0055: vendored/build/VCS dirs to skip. With --no-git-ignore Semgrep
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

# Cap Semgrep's analysis memory (MB) so a huge tree can't OOM the
# container. Overridable per-audit via config.max_memory_mb.
_DEFAULT_MAX_MEMORY_MB = 2000

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


_DEFAULT_RULE_PACKS = ["p/security-audit"]

# R3/P2d (0058): Vulture-authored, vendored, PINNED taint rules
# (Apache-2.0, `mode: taint`) shipped alongside the registry packs — the
# hybrid ruleset. Resolved relative to this file so it works both in the
# container (/app/rules/vulture) and when running from the repo checkout.
# Overridable via env at import time (tests reload the module).
_DEFAULT_VENDORED_RULES = Path(__file__).resolve().parents[1] / "rules" / "vulture"
VENDORED_RULES_DIR = os.environ.get(
    "VULTURE_SEMGREP_VENDORED_RULES", os.fspath(_DEFAULT_VENDORED_RULES)
)

# H2 (0058 audit): allowlist for config.rule_packs. Only PINNED Semgrep
# registry packs (`p/<name>`) are permitted to reach `--config`. Semgrep's
# `--config` also accepts URLs, local file paths, and `auto`; since the audit
# `config` is client-controlled and this container runs on the host network
# with egress, an unfiltered value is an SSRF / remote-ruleset / arbitrary-file
# sink. Anything not matching this pattern is dropped.
_RULE_PACK_RE = re.compile(r"^p/[a-z0-9._-]+$")

_MIN_MEMORY_MB = 256
_MAX_MEMORY_MB = 4000  # matches plugin.toml runtime.resources.memory = 4g


def _allowed_rule_packs(config: dict) -> list[str]:
    """Return the client-requested packs filtered to the pinned-registry
    allowlist, or the safe default if none survive (never zero-config)."""
    raw = config.get("rule_packs")
    if not isinstance(raw, list):
        return list(_DEFAULT_RULE_PACKS)
    safe = [p for p in raw if isinstance(p, str) and _RULE_PACK_RE.match(p)]
    return safe or list(_DEFAULT_RULE_PACKS)


def _vendored_rules_config(config: dict) -> list[str]:
    """Return the vendored-rules ``--config`` pair, or ``[]``.

    The vendored taint rules join the DEFAULT hybrid set only — an
    explicit client ``rule_packs`` list is an operator pin of the full
    ruleset (H2 semantics), so it is honored verbatim. A missing or
    rule-less vendored dir degrades gracefully (R9-style): no entry.
    """
    if isinstance(config.get("rule_packs"), list):
        return []
    vendored = Path(os.fspath(VENDORED_RULES_DIR))
    if not vendored.is_dir():
        return []
    if not any(p.suffix in (".yaml", ".yml") for p in vendored.rglob("*")):
        return []
    return ["--config", os.fspath(VENDORED_RULES_DIR)]


# r/solidity = the Semgrep REGISTRY Solidity rule namespace (~50 community
# rules). NOTE: there is no `p/solidity` published pack (404); `r/solidity`
# is the real ruleset. It is an OPERATOR default (not client-injectable via
# rule_packs), so it does NOT widen the H2 client allowlist — it rides only
# on the DEFAULT hybrid set, exactly like the vendored rules. It needs
# egress and is unversioned (drift), so it is the best-effort breadth tier
# on top of the hermetic, pinned vendored Solidity rules. Disable with
# VULTURE_SEMGREP_DISABLE_SOLIDITY_REGISTRY for offline/reproducible runs.
_SOLIDITY_REGISTRY_REF = "r/solidity"


def _solidity_registry_config(config: dict) -> list[str]:
    """Return the r/solidity registry ``--config`` pair, or ``[]``.

    Default set only (skipped when the client pins ``rule_packs``, matching
    the vendored-rules semantics), and honors the disable escape hatch.
    """
    if isinstance(config.get("rule_packs"), list):
        return []
    if os.environ.get("VULTURE_SEMGREP_DISABLE_SOLIDITY_REGISTRY", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    ):
        return []
    return ["--config", _SOLIDITY_REGISTRY_REF]


def _clamp_memory_mb(config: dict) -> int:
    """Coerce config.max_memory_mb to a bounded positive int (L3)."""
    try:
        n = int(config.get("max_memory_mb"))
    except (TypeError, ValueError):
        return _DEFAULT_MAX_MEMORY_MB
    return max(_MIN_MEMORY_MB, min(n, _MAX_MEMORY_MB))


@functools.lru_cache(maxsize=1)
def _project_root_supported() -> bool:
    """Whether the installed Semgrep's ``scan`` accepts ``--project-root``.

    The pinned image Semgrep (1.84.0) does NOT and errors on the unknown
    option; newer host/dev Semgrep does. Probed functionally once and
    cached. Defaults to False (the pinned baseline) on any probe failure,
    so a scan can never die on an unknown flag.
    """
    probe = tempfile.mkdtemp(prefix="sg-probe-")
    try:
        proc = subprocess.run(
            ["semgrep", "scan", "--project-root", probe, probe],
            capture_output=True, text=True, timeout=60,
        )
        if "no such option" in (proc.stderr or "").lower():
            return False  # explicitly rejected (e.g. 1.84.0)
        # Only treat as supported when Semgrep actually RAN with the flag
        # (0 = clean, 1 = findings). Any other failure (permission, settings,
        # timeout) fails safe to the pinned baseline so a real scan never
        # dies on an unknown flag.
        return proc.returncode in (0, 1)
    except Exception:
        return False
    finally:
        shutil.rmtree(probe, ignore_errors=True)


def _semgrep_argv(source_path: str, config: dict) -> list[str]:
    # p/security-audit is more useful than p/auto on mixed-language repos and
    # ships the `mode: taint` (dataflow) rules Semgrep OSS runs intra-
    # procedurally. Operators override via config.rule_packs (allowlisted, H2).
    # --no-git-ignore: inside the container the bind-mount may not preserve the
    # host's git ownership, causing silent "0 files scanned"; disabling it makes
    # the scan deterministic regardless of how the volume was mounted.
    args = ["semgrep", "scan", "--json", "--quiet", "--no-git-ignore"]
    # H1: cross-file/interprocedural taint needs the Semgrep Pro engine, which
    # is only available with a token (runtime.env.optional SEMGREP_APP_TOKEN).
    # OSS still runs intraprocedural taint from the packs above; enable Pro when
    # a token is present so the augmentation reaches dataflow CWEs skills miss.
    if os.environ.get("SEMGREP_APP_TOKEN"):
        args.append("--pro")
    # 0055: --no-git-ignore makes Semgrep walk EVERYTHING (node_modules, target,
    # .git, ...) — noise + a hard OOM (a 3 GB node_modules killed the 4 GB
    # container). Exclude vendored/build dirs and cap analysis memory.
    for pattern in _SCAN_EXCLUDES:
        args += ["--exclude", pattern]
    args += ["--max-memory", str(_clamp_memory_mb(config))]
    # 0058: pin the scan target AS the project root so Semgrep resolves
    # .semgrepignore relative to it — otherwise it walks up to an enclosing
    # repo root and applies that project's (or the built-in default) ignore,
    # e.g. the default `tests/` pattern, silently skipping audited files
    # whose path sits under a `tests/` ancestor.
    # VERSION-CONDITIONAL: the pinned image Semgrep (1.84.0) has NO
    # --project-root flag and errors on it (which previously made EVERY
    # audit return 0 findings); newer Semgrep (host/dev) supports it. Probe
    # once and include it only where supported — default off = the pinned
    # baseline, so a scan never dies on an unknown flag.
    if _project_root_supported():
        args += ["--project-root", source_path]
    for pack in _allowed_rule_packs(config):
        args += ["--config", pack]
    # R3/P2a+P2d (0058): vendored Vulture taint rules ride alongside the
    # registry packs (the hybrid set) unless the client pinned rule_packs.
    args += _vendored_rules_config(config)
    args += _solidity_registry_config(config)
    # L2: terminate options so source_path can never be parsed as a flag
    # (defence-in-depth atop normalise_source_path's leading-dash guard).
    args += ["--", source_path]
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

    # root=source_path so Semgrep's file paths are normalized to repo-relative
    # and line up with the in-tree agents' paths in cross-agent dedup (C1).
    findings = translate_findings(semgrep_json, agent_type="semgrep", root=source_path)
    # P2g: correlate co-occurring scam markers into a composite high-severity
    # finding (semgrep can't reason across findings). Appended so it both streams
    # and survives in the authoritative `result` snapshot below.
    findings.extend(summarize_scam_risk(findings, agent_type="semgrep"))
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
