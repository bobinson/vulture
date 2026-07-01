#!/usr/bin/env python3
"""dev/llm_probe.py — probe an OpenAI-compatible LLM endpoint DIRECTLY (no Vulture agent).

Calls the same endpoint + model the agent uses, and prints the model's RAW output so you
can diagnose LLM-integration failures without the agent in the way:
  - finish_reason          ("length" ⇒ the output was truncated)
  - usage                  (incl. reasoning_tokens for "thinking" models)
  - reasoning_content      (hidden chain-of-thought, separate from the answer)
  - content                (the actual answer) + whether its JSON parses

This is how the L5 "JSON parse failed twice" / empty-generate failures were diagnosed: a
reasoning model (e.g. qwen3) spends the whole output budget on hidden reasoning and the
verdict/findings JSON gets truncated (finish_reason=length). Fix = raise max_tokens
(VULTURE_VALIDATE_LLM_MAX_TOKENS / VULTURE_LLM_MAX_OUTPUT_TOKENS) and/or lower batch size.

Usage:
    python scripts/dev/llm_probe.py --file path/to/code.ts      # security-audit a file
    python scripts/dev/llm_probe.py --prompt 'Return {"ok":true} as JSON only.'
    python scripts/dev/llm_probe.py --file x.py --max-tokens 32000 --model qwen/qwen3.6-35b-a3b

Env / flags:
    OPENAI_BASE_URL    endpoint (default http://localhost:1234/v1 — LM Studio's default)
    VULTURE_LLM_MODEL  model id (or --model); if unset, auto-detects the first non-embedding model
    OPENAI_API_KEY     api key (default "lm-studio"; LM Studio ignores it)

Works for any OpenAI-compatible server (LM Studio, Ollama, vLLM, OpenAI). Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import urllib.request


def _strip_routing_prefix(model: str) -> str:
    """Drop litellm/openai routing prefixes the agent adds (the raw endpoint wants the bare id)."""
    for p in ("litellm/", "openai/"):
        if model.startswith(p):
            model = model[len(p):]
    return model


def _first_model(base: str, key: str) -> str:
    req = urllib.request.Request(base + "/models", headers={"Authorization": f"Bearer {key}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        data = json.loads(r.read())
    for m in data.get("data", []):
        if "embed" not in m.get("id", "").lower():
            return m["id"]
    return data["data"][0]["id"]


_AUDIT_SYS = (
    "You are a CWE security auditor. Find security weaknesses (injection, path traversal, "
    "command injection, improper input validation, etc.), tracing user-controlled data from "
    "its source (request query/body) to dangerous sinks (filesystem, shell, SQL) even when "
    "source and sink are on different lines or in different functions. Reply ONLY as JSON: "
    '{"findings":[{"severity":"","category":"CWE-XX","title":"","file_path":"","line_start":0,'
    '"recommendation":""}]}. No issues ⇒ {"findings":[]}.'
)


def main() -> int:
    ap = argparse.ArgumentParser(description="Probe an OpenAI-compatible LLM endpoint (raw output).")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--file", help="source file to security-audit (uses the agent-style prompt)")
    g.add_argument("--prompt", help="raw user prompt instead of a file")
    ap.add_argument("--base", default=os.environ.get("OPENAI_BASE_URL", "http://localhost:1234/v1"))
    ap.add_argument("--model", default=os.environ.get("VULTURE_LLM_MODEL", "").strip())
    ap.add_argument("--max-tokens", type=int, default=16000)
    ap.add_argument("--key", default=os.environ.get("OPENAI_API_KEY", "lm-studio"))
    args = ap.parse_args()

    base = args.base.rstrip("/")
    model = _strip_routing_prefix(args.model) or _first_model(base, args.key)
    print(f"[probe] base={base} model={model} max_tokens={args.max_tokens}", flush=True)

    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as fh:
            code = fh.read()
        sys_msg = _AUDIT_SYS
        user_msg = f"File: {os.path.basename(args.file)}\n\n```\n{code}\n```"
    else:
        sys_msg = "Reply with ONLY the requested JSON, no prose."
        user_msg = args.prompt or 'Return {"ok": true} as a JSON object.'

    payload = {
        "model": model, "temperature": 0.2, "max_tokens": args.max_tokens,
        "messages": [{"role": "system", "content": sys_msg},
                     {"role": "user", "content": user_msg}],
    }
    req = urllib.request.Request(
        base + "/chat/completions", data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {args.key}"},
        method="POST")
    with urllib.request.urlopen(req, timeout=600) as r:
        resp = json.loads(r.read())

    ch = resp["choices"][0]
    msg = ch["message"]
    content = msg.get("content", "") or ""
    reasoning = msg.get("reasoning_content", "") or msg.get("reasoning", "") or ""

    print(f"=== finish_reason: {ch.get('finish_reason')}")
    print(f"=== usage: {resp.get('usage')}")
    if ch.get("finish_reason") == "length":
        print("=== WARNING: finish_reason=length — OUTPUT TRUNCATED. Raise --max-tokens "
              "(and for the agent: VULTURE_VALIDATE_LLM_MAX_TOKENS / VULTURE_LLM_MAX_OUTPUT_TOKENS); "
              "for reasoning models also lower the batch size — the hidden reasoning ate the budget.")
    print(f"=== reasoning_content: {len(reasoning)} chars"
          + (f" (first 800):\n{reasoning[:800]}" if reasoning else " (none)"))
    print(f"=== content ({len(content)} chars):\n{content}")

    m = re.search(r"\{.*\}", content, re.DOTALL)
    if m:
        try:
            parsed = json.loads(m.group(0))
            fs = parsed.get("findings", [])
            print(f"\n=== content JSON parsed OK; findings: {len(fs)}")
            for f in fs:
                print(f"   {f.get('category')} L{f.get('line_start')}: {f.get('title')}")
        except Exception as e:
            print(f"\n=== content JSON parse FAILED: {e}  "
                  "(this is the same failure mode the agent's L5/generate parsing hits)")
    else:
        print("\n=== no JSON object found in content")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
