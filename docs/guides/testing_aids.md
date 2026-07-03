# Testing aids (`scripts/dev/`)

Small, dependency-free helpers for **manual end-to-end testing of a running Vulture stack**
— especially against real / local LLMs (LM Studio, Ollama, OpenAI-compatible endpoints).
They are developer tools, not part of the product or CI; they drive the real deployment
path (`scripts/vulture.sh dev …`) and the live backend API.

| Tool | What it does |
|------|--------------|
| [`scripts/dev/scan.py`](../../scripts/dev/scan.py) | Submit an audit of a local path to a running backend, stream it to completion, print the per-finding **provenance** breakdown + LLM-phase events. |
| [`scripts/dev/llm_probe.py`](../../scripts/dev/llm_probe.py) | Call the LLM endpoint **directly** (bypassing the agent) to see the model's raw output — `finish_reason`, token usage, reasoning vs. content — for diagnosing local/thinking-model failures. |
| [`scripts/dev/restart_agent.sh`](../../scripts/dev/restart_agent.sh) | Surgically restart **one** agent (reload code / change env) without bouncing the whole stack. |

All three use only the Python/Bash stdlib — no venv required.

## Prerequisites

1. A running dev stack, e.g. (LM Studio provider + Postgres):
   ```
   scripts/vulture.sh dev lmstudio <model> --pg
   ```
   This brings up the backend on `:28080` (local mode = auth bypass) and the 10 agents on
   `:28001–:28010` (cwe = `:28004`). To exercise the **L5 judge** (LLM verification of LLM
   findings), enable it on launch:
   ```
   VULTURE_USE_VALIDATE_LLM=true \
   VULTURE_VALIDATE_LLM_MAX_TOKENS=16000 VULTURE_VALIDATE_LLM_BATCH_SIZE=2 \
     scripts/vulture.sh dev lmstudio <model> --pg
   ```
2. For `llm_probe.py`: an OpenAI-compatible endpoint reachable (LM Studio defaults to
   `http://localhost:1234/v1` with a model loaded).

---

## `scan.py` — end-to-end scan driver

Creates a `local` source, starts an audit, **opens the SSE stream** (which is what
*dispatches* the agent — a fresh audit stays `pending` until a client streams it), holds it
to the terminal event, then reports findings + provenance from both the stream and the
persisted result.

```
python scripts/dev/scan.py <path> [--type cwe ...] [--base URL] [--timeout SECONDS]
```
```
python scripts/dev/scan.py /path/to/repo                     # CWE audit
python scripts/dev/scan.py ./agents/cwe --type cwe --timeout 900
```
Output includes `status`, `findings`, `score`, and the **provenance histogram** — e.g.
`{'skill': 5, 'llm': 2, 'llm_l5_verified': 1}` — so you can confirm the LLM tier engaged
(`llm`) and the L5 judge confirmed/surfaced findings (`llm_l5_verified`). `--base` /
`VULTURE_BACKEND_URL` point at a non-default backend.

> Real-model output is non-deterministic and the LLM phase only adds findings the
> deterministic skills *miss* (it dedups against them). Scanning the **same path twice**
> also dedups against prior findings — use a fresh path to see new `llm` findings.

## `llm_probe.py` — raw LLM endpoint probe

Sends the agent's finding-extraction prompt (or your own) straight to the LLM endpoint and
prints the **raw** response, so you can see what the agent's parser is actually getting.

```
python scripts/dev/llm_probe.py --file path/to/code.ts          # audit a file
python scripts/dev/llm_probe.py --prompt 'Return {"ok":true} as JSON only.'
python scripts/dev/llm_probe.py --file x.py --max-tokens 32000 --model qwen/qwen3.6-35b-a3b
```
Env: `OPENAI_BASE_URL` (default `http://localhost:1234/v1`), `VULTURE_LLM_MODEL`
(auto-detected if unset), `OPENAI_API_KEY` (default `lm-studio`).

**What to look for:** if `finish_reason=length`, the output was **truncated** — a *reasoning*
model (qwen3, etc.) puts its chain-of-thought in a separate `reasoning_content` field but it
still counts against the output budget, so a low `max_tokens` leaves the actual JSON cut off
→ the agent's parser fails (this was the root cause of L5 "JSON parse failed twice" and of
empty generate results). The probe prints `reasoning_tokens` so you can see the budget split.
Fix on the agent side by raising `VULTURE_VALIDATE_LLM_MAX_TOKENS` (L5) /
`VULTURE_LLM_MAX_OUTPUT_TOKENS` (generate) and/or lowering `VULTURE_VALIDATE_LLM_BATCH_SIZE`.

## `restart_agent.sh` — surgical single-agent restart

Restarts one agent's uvicorn in place — handy after editing an agent's Python (the dev
stack import-caches code at start, so a running worker can serve **stale** code) or to
change one agent's env, without a full `scripts/vulture.sh` restart.

```
scripts/dev/restart_agent.sh <agent> <port> [VAR=VAL ...]
scripts/dev/restart_agent.sh cwe 28004
scripts/dev/restart_agent.sh cwe 28004 VULTURE_USE_VALIDATE_LLM=true VULTURE_VALIDATE_LLM_MAX_TOKENS=16000
```
Targets `$VULTURE_RUNTIME_DIR/agents/<agent>` (default `$HOME/.vulture/runtime`). Agent→port
map: chaos 28001 · owasp 28002 · soc2 28003 · cwe 28004 · prove 28005 · xss 28006 ·
ssdf 28007 · discover 28008 · do178c 28009 · asvs 28010.

---

## Recipes

**Prove the LLM generate→verify path against a local model**
```
VULTURE_USE_VALIDATE_LLM=true VULTURE_VALIDATE_LLM_MAX_TOKENS=16000 \
  scripts/vulture.sh dev lmstudio qwen/qwen3-coder-next --pg
python scripts/dev/scan.py /path/with/a/cross-line/bug --type cwe --timeout 900
# look for 'llm' / 'llm_l5_verified' in the provenance histogram
```

**Diagnose "the L5 judge produces 0 verdicts" / empty LLM results**
```
python scripts/dev/llm_probe.py --file /path/to/a/finding.ts
# finish_reason=length + big reasoning_tokens ⇒ raise max_tokens / lower batch size
```

**Reload an agent after editing its code**
```
# edit agents/cwe/... then:
scripts/dev/restart_agent.sh cwe 28004
python scripts/dev/scan.py /path --type cwe   # re-scan against the fresh worker
```

## Notes
- Throwaway run output, scan slices, and evidence belong in `scratchpad/` (git-ignored).
- These aids assume **local mode** (auth bypass), the default for `scripts/vulture.sh dev`.
  Against an auth-enabled server, add a bearer token to the requests.
