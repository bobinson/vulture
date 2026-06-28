#!/usr/bin/env python3
"""dev/scan.py — submit an audit to a RUNNING Vulture backend and stream it to completion.

Drives the real deployment path end-to-end (backend → agent → LLM → validate → persist),
then prints the per-finding provenance breakdown from both the SSE stream and the
persisted result. The main aid for real-model / local-LLM end-to-end testing.

Note: the backend leaves a freshly-created audit `pending` until a client opens its SSE
stream — opening the stream is what DISPATCHES the agent. This driver opens it and holds
it to the terminal event (the CLI's `--wait` does the same).

Usage:
    python scripts/dev/scan.py <path> [--type cwe ...] [--base URL] [--timeout SECONDS]

Examples:
    python scripts/dev/scan.py /path/to/repo                  # CWE audit, default backend
    python scripts/dev/scan.py ./agents/cwe --type cwe --timeout 900
    VULTURE_BACKEND_URL=http://localhost:28080 python scripts/dev/scan.py ./src

Env:
    VULTURE_BACKEND_URL   backend base URL (default http://localhost:28080)

Requires only the Python stdlib. Run with any python3 (no venv needed).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request


def _post(base: str, path: str, payload: dict) -> dict:
    req = urllib.request.Request(
        base + path, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def _get(base: str, path: str) -> dict:
    with urllib.request.urlopen(base + path, timeout=30) as r:
        return json.loads(r.read())


def _walk_provenance(node, acc: dict) -> None:
    """Tally `provenance` values on any finding-like dict found in the SSE payload."""
    if isinstance(node, dict):
        if "provenance" in node and ("title" in node or "check_id" in node):
            p = str(node.get("provenance"))
            acc[p] = acc.get(p, 0) + 1
        for v in node.values():
            _walk_provenance(v, acc)
    elif isinstance(node, list):
        for v in node:
            _walk_provenance(v, acc)


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan a local path through a running Vulture backend.")
    ap.add_argument("path", help="local source path to scan")
    ap.add_argument("--type", action="append", dest="types",
                    help="audit type (repeatable); default: cwe")
    ap.add_argument("--base", default=os.environ.get("VULTURE_BACKEND_URL", "http://localhost:28080"))
    ap.add_argument("--timeout", type=int, default=900, help="SSE stream timeout (seconds)")
    args = ap.parse_args()

    base = args.base.rstrip("/")
    types = args.types or ["cwe"]

    src = _post(base, "/api/sources", {"type": "local", "path": os.path.abspath(args.path)})
    src_id = src.get("id") or src.get("source", {}).get("id")
    if not src_id:
        print(f"[scan] could not create source: {src}", file=sys.stderr)
        return 2
    print(f"[scan] source id={src_id} file_count={src.get('file_count')}", flush=True)

    aud = _post(base, "/api/audits", {"source_id": src_id, "types": types, "config": {}})
    aud_id = aud.get("id") or aud.get("audit", {}).get("id")
    print(f"[scan] audit id={aud_id} types={types} model={aud.get('llm_model')}", flush=True)

    prov_stream: dict = {}
    llm_text: list = []
    start = time.time()
    print(f"[scan] opening SSE stream (timeout {args.timeout}s; this dispatches the agent)...", flush=True)
    try:
        with urllib.request.urlopen(f"{base}/api/audits/{aud_id}/stream", timeout=args.timeout) as r:
            for raw in r:
                line = raw.decode("utf-8", "replace").rstrip("\n")
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if '"provenance"' in data:
                    try:
                        _walk_provenance(json.loads(data), prov_stream)
                    except Exception:
                        pass
                low = data.lower()
                if any(k in low for k in ("enhancing with llm", "llm discovered",
                                          "additional finding", "skills-only", "llm unavailable")):
                    llm_text.append(data[:200])
                if time.time() - start > args.timeout:
                    print("[scan] stream timeout", flush=True)
                    break
    except urllib.error.URLError as e:
        print(f"[scan] stream error: {e}", flush=True)

    print(f"[scan] stream closed after {time.time() - start:.0f}s", flush=True)

    final = _get(base, f"/api/audits/{aud_id}")
    findings = final.get("findings", []) or []
    prov_api: dict = {}
    for f in findings:
        p = str(f.get("provenance"))
        prov_api[p] = prov_api.get(p, 0) + 1

    print("\n===== RESULT =====")
    print(f"audit_id   = {aud_id}")
    print(f"status     = {final.get('status')}   degraded_reason = {final.get('degraded_reason')}")
    print(f"findings   = {len(findings)}   score = {final.get('score') or final.get('scores')}")
    print(f"provenance (API)    = {prov_api or '{}'}")
    print(f"provenance (stream) = {prov_stream or '{}'}")
    if llm_text:
        print("LLM-phase events:")
        for t in llm_text:
            print(f"  - {t}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
