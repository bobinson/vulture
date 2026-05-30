# 0053 — Bundled Semgrep Reference Plugin (LLD + plan)

**Author**: tbd
**Status**: PLAN — cross-cutting review applied (22 findings; 5 BLOCKER, 8 MAJOR, 9 MINOR/NIT)
**Created**: 2026-05-28
**Depends on**: 0047 (contract), 0048 (registry), 0049 (router), 0050 (CWE normalisation), 0051 (CLI install), 0052 (runtime supervision)
**Unblocks**: external community plugins (this is the reference); 0050 v1.1 (`mapping_file` external loader is genuinely needed for Semgrep's rule set)

## Review changelog (applied below)

| # | Sev | Axis | Finding | Resolution |
|---|---|---|---|---|
| 2 | BLOCKER | correctness/security | `subprocess.run` freezes asyncio loop | wrapper uses `loop.run_in_executor` for the Semgrep subprocess |
| 3 | BLOCKER | correctness/security | `sanityCheckRuntime` relaxation lets ANY local plugin claim in-tree | relaxation scoped to `Source == "builtin"` only; non-builtin sources still enforce the original constraint |
| 4 | BLOCKER | correctness | `mapping_file` path semantics undefined | removed `mapping_file` from v1 manifest; ship inline `prefix_to_cwe` block only; full rule_to_cwe ships when 0050 v1.1 pins file-loading semantics |
| 5 | BLOCKER | correctness | Semgrep CWE format `"CWE-89: SQL Injection"`, not `"CWE-89"` | translator strips after `:`; fixture uses real Semgrep JSON |
| 9 | MAJOR | security | source_path traversal via symlink / `..` | wrapper calls `os.path.realpath` + asserts prefix is `/audit-inputs` |
| 11 | MAJOR | correctness | wrapper reads top-level fields, contract says `body.input.source_path` | wrapper validates `envelope` field; reads from `input` sub-object |
| 12 | MAJOR | DRY | seed CWE maps duplicate orchestrator data | orchestrator's `internal/cwe/data/check_id_prefix_to_cwe.json` is canonical; plugin manifest's `prefix_to_cwe` carries only entries NOT in orchestrator base |
| 13 | MAJOR | maintenance | no `schema_version` in `rules/*.json` | top-level `"schema_version": "1"` field; loader rejects unknown versions |
| 14 | MINOR | correctness | severity mapping bimodal, breaks L2 rollup grouping | Semgrep ERROR → `high` (not `critical`) to align with in-tree conventions |
| 15 | MINOR | performance | pre-warmed Semgrep rules cached as root, `nobody` can't read | Dockerfile uses `SEMGREP_RULES_CACHE=/srv/semgrep-rules` writable by `nobody` |
| 16 | MINOR | reliability | Semgrep exit 7 (auth required) gives cryptic stderr | wrapper has explicit branch for exit 7 with operator-friendly message |
| 18 | MINOR | community | "30 minutes" fork claim unvalidated | replaced with realistic prerequisites checklist + measured-time TBD |
| 20 | MINOR | community | `publisher = "vulture-core"` confusing template | README explicitly addresses template defaults + concrete examples |
| 21 | NIT | maintenance | Dockerfile said "multi-stage" but was single-stage | text corrected to "single-stage" |

## Problem

The plugin contract works (0047), the registry loads manifests (0048),
the router dispatches (0049), the CWE layer normalises (0050), the
CLI installs with cosign verification (0051), the supervisor starts
containers (0052). **There is no actual external-style plugin.**
Everything works on paper.

0053 ships one. Specifically: a Semgrep plugin, in a clean
`plugins/semgrep/` subdirectory of the Vulture monorepo, that
- works end-to-end (operator runs an audit, gets Semgrep findings)
- is honest about its trust tier (`tier=in-tree` because we ship it)
- doubles as the reference for community plugin authors

When operationally proven, it can be `git filter-repo`'d out into its
own repository, switched to `tier=community-signed`, and signed with
cosign keyless OIDC — with no change to the contract or any
consuming code.

## Goal

Demonstrate the plugin platform with one real external-style scanner
running through it. Provide the canonical reference implementation
for third-party plugin authors. Surface any contract or platform
issues a real plugin exposes (and there will be some).

## Non-goals (deferred)

- **Full Semgrep rule coverage in CWE mapping** — ship ~100 seed
  mappings covering the OWASP-aligned packs (`p/owasp-top-ten`,
  `p/javascript`, `p/python`); add more as findings are seen.
  Comprehensive coverage of all ~2000 Semgrep rules belongs to a
  data-only PR, not 0053.
- **Custom Semgrep rule packs** — v1 uses upstream packs
  (`p/auto` by default). Operator-supplied custom rulesets are a
  v1.1 follow-up.
- **Streaming results** — Semgrep's `--json` output is buffered
  (entire run completes, then JSON is emitted). v1 emits findings
  in a single batch after Semgrep finishes; per-finding streaming
  requires Semgrep's library API and threading concerns, deferred.
- **Multi-language detection / auto-config** — v1 trusts Semgrep's
  `--config p/auto` to pick rules. Per-language explicit pack
  selection is config-driven.
- **Repo extraction** — v1 ships in the monorepo at `plugins/semgrep/`.
  Migration to a standalone repo is a future operational task with
  its own checklist (see "Migration path").
- **Network-source install (operator pulls plugin from GitHub URL)**
  — covered by 0051 v1.1.

## Design

### Directory layout

```
plugins/semgrep/                              ← NEW top-level dir
├── plugin.toml                               ← the manifest
├── Dockerfile
├── pyproject.toml                            ← wrapper deps
├── src/
│   ├── wrapper.py                            ← FastAPI POST /run + SSE
│   ├── translate.py                          ← Semgrep → Vulture finding
│   └── sse.py                                ← SSE writer (shared shape)
├── rules/
│   ├── rule_to_cwe.json                      ← seed map (~100 entries)
│   └── prefix_to_cwe.json                    ← rule-prefix map (~30 entries)
├── tests/
│   ├── unit/
│   │   ├── test_translate.py                 ← mocked Semgrep JSON
│   │   └── test_wrapper.py                   ← FastAPI testclient
│   ├── fixtures/
│   │   ├── semgrep_output_sample.json        ← canned Semgrep JSON
│   │   └── test_source/
│   │       └── sql_injection.py              ← known-vuln test fixture
│   └── e2e/
│       └── test_real_semgrep.py              ← skip if no docker
└── README.md                                 ← "the reference"
```

Three rules that keep `plugins/semgrep/` separable from `backend/`:

1. **Self-contained.** No imports from `backend/`. Its tests run via
   `pytest` from within `plugins/semgrep/` and pass.
2. **`backend/` ignorant.** No code in `backend/` mentions
   "semgrep" by name. The only consumer is the operator's
   `plugin.toml` + the supervisor starting the container.
3. **Migration-ready.** `git filter-repo --path plugins/semgrep`
   produces a valid new repo with its full history.

### Manifest

```toml
[plugin]
name           = "semgrep"
display_name   = "Semgrep (bundled)"
version        = "0.1.0"
api_version    = "vulture-plugin/1.0"
publisher      = "vulture-core"
description    = "Cross-language SAST via Semgrep. Reference bundled plugin demonstrating the vulture-plugin/1.0 contract. Maintainers: Vulture core team."
homepage       = "https://github.com/bobinson/vulture/tree/main/plugins/semgrep"
license        = "Apache-2.0"
documentation  = "https://github.com/bobinson/vulture/tree/main/plugins/semgrep/README.md"

[trust]
tier           = "in-tree"
# No signature — bundled, signed by the Vulture release pipeline as a whole.
required_ack   = []

[runtime]
type           = "container"
image          = "ghcr.io/bobinson/vulture-plugin-semgrep:0.1.0"
port           = 8080
health_endpoint = "/health"
info_endpoint  = "/info"
run_endpoint   = "/run"
restart        = "on-failure"
network        = "internal"
resources      = { cpu = "2", memory = "4Gi" }

[runtime.fs]
read           = ["/audit-inputs"]
write          = ["/tmp/semgrep-cache"]

[runtime.env]
required       = []
optional       = ["SEMGREP_APP_TOKEN"]

[[capabilities]]
phase          = "scan"
languages      = ["javascript", "typescript", "python", "go", "java", "ruby", "csharp", "php"]
emits          = ["finding", "progress", "thinking", "run_started", "run_finished", "result"]
timeout_s      = 1800

# Per BLOCKER #4: mapping_file field omitted from v1 — its load
# semantics (relative-to-host vs absolute-in-container vs /info
# endpoint) are unresolved in 0050. Inline maps only. Per MAJOR
# #12: only entries NOT in the orchestrator's base map appear here.
[normalization]
[normalization.prefix_to_cwe]
"python.django.security.unsafe-raw-sql" = "CWE-89"
"python.cryptography.fernet"            = "CWE-310"
"javascript.express.security.audit"     = "CWE-1004"
"java.spring.security.web.cors-csrf"    = "CWE-352"
# ~15 entries — Semgrep-specific patterns the orchestrator base
# map at internal/cwe/data/check_id_prefix_to_cwe.json doesn't
# already cover. The full Semgrep rule corpus (~2000 rules) is
# best resolved by 0050 v1.1's external mapping_file once the
# load semantics are pinned.
```

Note the deliberate tier=in-tree + runtime.type=container combination.
This requires the 0048 sanity-check relaxation described below.

### Vulture-core change required by 0053 (BLOCKER #3 fix)

`pkg/pluginregistry/loader.go::sanityCheckRuntime` currently has
two halves. The second half (`tier=in-tree requires runtime=in-tree`)
must be **scoped** to the discovery source, NOT removed wholesale:

```go
// sanityCheckRuntime now accepts the source label so the
// in-tree-tier + container-runtime combo is allowed ONLY when the
// manifest was discovered from the builtin directory. A rogue
// manifest at ~/.vulture/plugins/evil/plugin.toml claiming
// tier=in-tree with runtime=container is still rejected — the
// install path goes through pluginlifecycle.Install which itself
// rejects tier=in-tree, but the loader's discoverDir path bypasses
// that. This scoping closes the bypass.
func sanityCheckRuntime(m *Manifest, source string) error {
    if m.Runtime.Type == RuntimeInTree && m.Trust.Tier != TierInTree {
        return errInTreeRuntimeReserved
    }
    if m.Trust.Tier == TierInTree && m.Runtime.Type != RuntimeInTree {
        if source != "builtin" {
            return errInTreeTierNonInTreeRuntime
        }
    }
    return nil
}
```

`source == "builtin"` corresponds to manifests discovered via the
new `BuiltinDir` (env `VULTURE_BUILTIN_PLUGINS_DIR`). Manifests
under `LocalDir` (`~/.vulture/plugins/`) and `ExtraDirs`
(`VULTURE_PLUGIN_DIRS`) still enforce the original constraint:
they cannot claim `tier=in-tree` with a non-in-tree runtime.

Three tests must pin this:

1. `builtin` source + `tier=in-tree` + `runtime=container` → accept
2. `local` source + `tier=in-tree` + `runtime=container` → reject
   (security regression guard)
3. any source + `runtime=in-tree` + `tier=user-supplied` → reject
   (unchanged from 0048)

### Bundled discovery

The registry already supports operator-controlled load paths
(`LocalDir` + `ExtraDirs` from `VULTURE_PLUGIN_DIRS`). 0053 adds
one new path:

- `VULTURE_BUILTIN_PLUGINS_DIR` env var
- If set, registry scans the directory for `<name>/plugin.toml` files
- Defaults to empty (no bundled plugins loaded)
- Container deployments mount `./plugins:/vulture-plugins:ro` and
  set the env var to `/vulture-plugins`
- Dev workflow: `VULTURE_BUILTIN_PLUGINS_DIR=$REPO/plugins go run ./cmd/vulture/ serve`

This is opt-in by env var (operators who don't want bundled plugins
just don't set it). State.toml still tracks enable/disable as
normal; bundled plugins start `enabled=true` on first discovery
(consistent with all other plugins).

### Python wrapper

`src/wrapper.py`:

```python
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
import asyncio, json, os, subprocess, time
from .translate import translate_findings, normalise_source_path
from .sse import write_event

app = FastAPI()
AUDIT_INPUTS_ROOT = "/audit-inputs"

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/info")
def info():
    return {
        "name": "semgrep",
        "version": "0.1.0",
        "capabilities": [{"phase": "scan", "emits": ["finding", "result"]}],
    }

@app.post("/run")
async def run(req: Request):
    body = await req.json()
    # Contract: body shape is {envelope, run_id, stage, input{}, config{}}
    # per docs/spec/plugin-v1/contract.md. (MAJOR #11 fix.)
    if body.get("envelope") != "vulture-plugin/1.0":
        raise HTTPException(status_code=400, detail="unsupported envelope")
    run_id = body["run_id"]
    raw_source = body.get("input", {}).get("source_path")
    config = body.get("config", {}) or {}

    # MAJOR #9 fix: realpath + prefix check. Also rejects flag-style
    # source_path that starts with `-` (TM4).
    source_path = normalise_source_path(raw_source, root=AUDIT_INPUTS_ROOT)
    if source_path is None:
        raise HTTPException(status_code=400, detail="invalid source_path")

    async def stream():
        yield write_event("run_started", {"run_id": run_id})
        yield write_event("agent_start", {"agent_type": "semgrep"})

        rule_packs = config.get("rule_packs", ["p/auto"])
        args = ["semgrep", "--json", "--quiet"]
        for pack in rule_packs:
            args += ["--config", pack]
        args.append(source_path)

        # BLOCKER #2 fix: subprocess.run blocks the asyncio loop.
        # Wrap in run_in_executor so probe handlers + other audits
        # keep responding while Semgrep is scanning.
        started = time.time()
        loop = asyncio.get_event_loop()
        try:
            proc = await loop.run_in_executor(
                None,
                lambda: subprocess.run(args, capture_output=True, text=True, timeout=1500),
            )
        except subprocess.TimeoutExpired:
            yield write_event("result", {"error": "semgrep timeout (1500s)"})
            yield write_event("agent_end", {"agent_type": "semgrep"})
            yield write_event("run_finished", {"run_id": run_id})
            return

        # MINOR #16 fix: explicit exit-7 message for SEMGREP_APP_TOKEN.
        if proc.returncode == 7:
            yield write_event("result", {
                "error": "Semgrep requires authentication; set SEMGREP_APP_TOKEN via runtime.env.optional",
            })
            yield write_event("agent_end", {"agent_type": "semgrep"})
            yield write_event("run_finished", {"run_id": run_id})
            return
        if proc.returncode not in (0, 1):  # 0 = clean, 1 = findings present
            yield write_event("result", {"error": proc.stderr[:2000]})
            yield write_event("agent_end", {"agent_type": "semgrep"})
            yield write_event("run_finished", {"run_id": run_id})
            return

        semgrep_json = json.loads(proc.stdout)
        findings = translate_findings(semgrep_json, agent_type="semgrep")
        for f in findings:
            yield write_event("finding", f)
            await asyncio.sleep(0)  # cooperative yield

        yield write_event("result", {
            "findings_count": len(findings),
            "duration_s": time.time() - started,
        })
        yield write_event("agent_end", {"agent_type": "semgrep"})
        yield write_event("run_finished", {"run_id": run_id})

    return StreamingResponse(stream(), media_type="text/event-stream")
```

`normalise_source_path` (in `translate.py`):

```python
import os

def normalise_source_path(raw, root):
    """Reject flag-style args (`-foo`), `..` traversal, and
    symlinks escaping the audit-inputs mount. Returns the resolved
    absolute path on success or None."""
    if not raw or not isinstance(raw, str):
        return None
    if raw.startswith("-"):
        return None
    if ".." in raw.split(os.sep):
        return None
    resolved = os.path.realpath(raw)
    if not resolved.startswith(root + os.sep) and resolved != root:
        return None
    return resolved
```

`src/translate.py`:

```python
import re

# BLOCKER #5 fix: real Semgrep JSON emits
#   "cwe": ["CWE-89: Improper Neutralization of Special Elements …"]
# A list of human-readable strings with the CWE-NNN prefix. Strip
# to canonical form via the regex.
_CWE_RE = re.compile(r"^(CWE-\d{1,5})\b")

def extract_cwe(rule):
    """Return canonical CWE-NNN string from a Semgrep finding, or
    None if no parseable CWE in metadata."""
    cwes = rule.get("extra", {}).get("metadata", {}).get("cwe", [])
    if isinstance(cwes, str):  # tolerate scalar form
        cwes = [cwes]
    for entry in cwes:
        if not isinstance(entry, str):
            continue
        m = _CWE_RE.match(entry.strip())
        if m:
            return m.group(1)
    return None

# MINOR #14 fix: ERROR → high (not critical) so L2 rollup groups
# Semgrep findings with in-tree high-severity findings on the same
# (category, file_path). Vulture's L2 rollup key ignores severity,
# but UI dedup heuristics often consider it; matching the in-tree
# severity convention keeps cross-agent grouping consistent.
_SEMGREP_SEVERITY_MAP = {
    "ERROR":   "high",
    "WARNING": "medium",
    "INFO":    "info",
}

def map_severity(s):
    return _SEMGREP_SEVERITY_MAP.get(s, "info")

def translate_findings(semgrep_json, agent_type):
    out = []
    for r in semgrep_json.get("results", []):
        cwe = extract_cwe(r)
        out.append({
            "id": r["check_id"],
            "agent_type": agent_type,
            "title": r["extra"]["message"].split("\n")[0][:200],
            "description": r["extra"]["message"],
            "severity": map_severity(r["extra"].get("severity", "INFO")),
            # Prefer canonical CWE for category; fall back to
            # check_id so the 0050 prefix/rule maps can resolve.
            "category": cwe or r["check_id"],
            "check_id": r["check_id"],
            "file_path": r["path"],
            "line_start": r["start"]["line"],
            "line_end": r["end"]["line"],
            "code_snippet": r["extra"].get("lines", ""),
        })
    return out
```

Test fixture (`tests/fixtures/semgrep_output_sample.json`) uses
the **real Semgrep JSON shape**, including
`"cwe": ["CWE-89: SQL Injection Improper Neutralization…"]`, not
the idealised `["CWE-89"]` form. Asserted by AC #5 / #6.

### Dockerfile (single-stage; NIT #21 fix)

```dockerfile
FROM semgrep/semgrep:1.84.0
WORKDIR /app

# MINOR #15 fix: Semgrep's default rules cache is $HOME/.semgrep,
# which points at /root when this image's base sets HOME=/root.
# After USER nobody, nobody cannot read /root. Redirect the cache
# to /srv/semgrep-rules (writable by nobody after chown), pre-warm
# under that path, then drop to nobody.
ENV SEMGREP_RULES_CACHE=/srv/semgrep-rules
RUN mkdir -p /srv/semgrep-rules \
 && chown -R 65534:65534 /srv/semgrep-rules \
 && semgrep --config p/auto --quiet /tmp 2>/dev/null || true

COPY pyproject.toml /app/
COPY src/ /app/src/
COPY rules/ /app/rules/
RUN pip install --no-cache-dir fastapi uvicorn[standard]

EXPOSE 8080
USER 65534:65534                 # explicit numeric uid for `nobody`
                                  # avoids cross-distro variance (TM5 fix)
CMD ["uvicorn", "src.wrapper:app", "--host", "0.0.0.0", "--port", "8080"]
```

Pinned `semgrep/semgrep:1.84.0` — not `:latest`. Reproducibility.
Bump explicitly via the release process.

`SEMGREP_RULES_CACHE` is documented in the plugin README as the
location to mount as a docker volume if operators want rule cache
to persist across container restarts.

### Tests

#### Unit (Python, fast)

- `tests/unit/test_translate.py` — load
  `tests/fixtures/semgrep_output_sample.json`; assert mapping into
  `Finding` shape; assert CWE extraction from metadata.
- `tests/unit/test_wrapper.py` — FastAPI TestClient; mock
  `subprocess.run` to return a canned Semgrep JSON; assert SSE event
  sequence (`run_started`, `agent_start`, N `finding`, `result`,
  `agent_end`, `run_finished`).

#### Backend-side (Go)

- `backend/pkg/pluginregistry/loader_test.go` — new test:
  `TestSanityCheckRuntime_InTreeTierAllowsContainerRuntime_0053` —
  manifest with `tier=in-tree, runtime.type=container` parses
  successfully.
- `backend/pkg/pluginregistry/loader_test.go` — `TestLoad_FromBuiltinDir_0053`
  — set `VULTURE_BUILTIN_PLUGINS_DIR` to a temp dir containing the
  semgrep manifest; registry returns it as `Source: "builtin"`.

#### Integration (Python, needs docker)

- `tests/e2e/test_real_semgrep.py` — pytest fixture: `docker build`
  the image, `docker run` it on a random port, POST `/run` with a
  source path pointing at `tests/fixtures/test_source/`, assert
  ≥1 finding for `sql_injection.py`. Skipped if `docker` binary
  absent.

#### Vulture-wide E2E

A bash + Go script in `tests/e2e/0053_semgrep_end_to_end.sh`:

```
1. Build the semgrep plugin image: docker build plugins/semgrep -t vulture-plugin-semgrep:test
2. Start vulture backend with VULTURE_BUILTIN_PLUGINS_DIR=plugins
3. Wait for registry to pick up semgrep + supervisor to start container
4. Submit a source path (small Python file with SQLi pattern)
5. POST /api/audits with types=[semgrep]
6. Stream SSE; collect findings
7. Assert: ≥1 finding with category="CWE-89" (Semgrep's CWE metadata)
   OR check_id matching "python.django.security.injection" mapped via 0050
```

Skipped if docker unavailable.

### Migration path (when ready to extract)

When `plugins/semgrep/` is mature:

| Step | Change |
|---|---|
| Extract repo | `git filter-repo --path plugins/semgrep` → `vulture-plugin-semgrep` |
| Set up CI | `.github/workflows/release.yml`: build image, push to ghcr.io, cosign-sign the image AND the plugin.toml via Sigstore keyless OIDC |
| Change tier | `in-tree` → `community-signed` |
| Add signature | `cosign://sigstore/<publisher>/vulture-plugin-semgrep` |
| Change publisher | `vulture-core` → `<maintainer-org>` |
| Remove from monorepo | leave `plugins/semgrep/README.md` as a redirect |
| Update example manifest | `docs/spec/plugin-v1/examples/external-semgrep.toml` now references the real published cosign subject |

Vulture core doesn't change. The contract doesn't change. Just
labels move.

## Threat model

### TM1 — Semgrep image vulnerabilities

**Risk**: pinned `semgrep/semgrep:1.84.0` may have CVEs over time.
**Mitigation**: monthly bump policy + release of a new `0.1.x`
plugin version. Documented in plugin README. v1.1 may add a
scheduled vulnerability scan of the bundled image.

### TM2 — Semgrep rule download at runtime

**Risk**: `--config p/auto` fetches rule packs from `semgrep.dev`
on first run. If `runtime.network=internal`, this fails.
**Mitigation**: 0053 pre-warms rules at image build time:

```dockerfile
RUN semgrep --config p/auto --quiet /tmp 2>/dev/null || true
```

This caches the default ruleset in `/root/.semgrep/`. Plugin runs
with `network=internal`; rules served from cache. Custom packs
selected via config DO need network=host or a registry mirror;
documented.

### TM3 — Source-tree exposure

**Risk**: Semgrep reads everything under `/audit-inputs`. If the
mount included secrets, they're visible to the plugin.
**Mitigation**: `runtime.fs.read = ["/audit-inputs"]` is read-only
mounted. Vulture's audit-source service controls what lands there;
plugin can't write back. Standard for any SAST tool.

### TM4 — Wrapper subprocess injection

**Risk**: `source_path` from `POST /run` body passed to
`subprocess.run(["semgrep", ..., source_path])`. If source_path
contained shell metacharacters or argument-style strings (`--exec
…`), Semgrep might mis-interpret.
**Mitigation**: subprocess uses argv list (not shell), so
metacharacters are inert. But argument-style strings are still a
concern — a `source_path` starting with `-` becomes a flag. Wrapper
rejects any source_path matching `^-`. Tested.

### TM5 — Container running as root

**Risk**: docker default user is root.
**Mitigation**: Dockerfile sets `USER nobody`. Verified by
`docker inspect` test.

### TM6 — Findings exfiltration

**Risk**: a malicious wrapper could exfiltrate findings to an
external server.
**Mitigation**: not applicable to v1 — Vulture core team is the
maintainer of the bundled plugin. When extracted to a community
repo, this concern is addressed by cosign verification of the
publisher.

### TM7 — Resource exhaustion (huge codebases)

**Risk**: Semgrep on a multi-GB monorepo can OOM the container.
**Mitigation**: `runtime.resources.memory = "4Gi"` cap. If exceeded,
docker kills the container; supervisor restart policy applies.
Operator can override per-install by editing the manifest.

## Reliability + chaos engineering

| Failure mode | Behaviour |
|---|---|
| Semgrep crashes mid-scan | wrapper catches non-zero exit; emits `result` event with `error` field; SSE stream terminates cleanly |
| Source path doesn't exist | wrapper returns HTTP 400 to the proxy with a clear error |
| Source path starts with `-` (argv injection) | wrapper rejects HTTP 400 (TM4) |
| Container OOM-killed | supervisor restarts per policy; in-flight audit gets connection-refused, surfaces as agent error |
| Semgrep ruleset fetch fails (network unavailable, cache cold) | wrapper logs the failure; emits empty `result`; documented limitation |
| Wrapper Python deps incompatible at image build | image build fails at CI; never ships |
| Multiple concurrent audits hitting the same plugin | each `POST /run` is independent; Semgrep CLI per request; resource limits apply per container, not per request |

## Maintenance

- Plugin lives behind a clean contract — Vulture core can refactor
  internals without touching `plugins/semgrep/`.
- README explicitly positions the dir as the reference:
  > "This plugin is bundled with Vulture as the canonical reference
  > implementation of the `vulture-plugin/1.0` contract. To build
  > your own plugin, fork this directory, change the manifest's
  > `name` + `publisher`, replace the wrapper logic, and ship it
  > in your own repo with cosign keyless OIDC signing. See
  > `docs/spec/plugin-v1/contract.md` for the full contract."
- Rule maps are pure data; community contributions = PRs against
  the JSON files.
- Semgrep version bumps via the Dockerfile pin; CI verifies new
  bumps don't break the SSE event sequence against the fixture.

## Performance

- Wrapper overhead: FastAPI + uvicorn handles a single POST /run
  per audit; not a hot path. ~50ms framework overhead, dwarfed by
  Semgrep itself (seconds to minutes).
- Image size: `semgrep/semgrep:1.84.0` is ~400MB base + ~5MB
  wrapper. ~405MB total. Acceptable for a SAST tool image.
- Rule cache: ~30MB after pre-warm. Lives in the image, not on
  the host.
- Cold start: image pull is the dominant cost. After cache,
  container start is <2 seconds.

## Community satisfaction

Two explicit asks the LLD must satisfy:

1. **Forkability.** A community plugin author should be able to
   fork the directory, adapt the wrapper logic, and ship a working
   plugin. The README walks through this WITHOUT making
   time-promises — exact effort depends heavily on author
   familiarity with Docker, Sigstore, GitHub Actions, and the
   target scanner. (MINOR #18 fix: removed the "30 minutes" claim
   pending real measurement.)
   
   README "How to fork" section MUST include:
   - **Prerequisites checklist** (Docker, ghcr.io access, GitHub
     Actions enabled on the fork repo, a non-empty understanding
     of Sigstore keyless OIDC)
   - **The 7 manifest fields to change** (name, publisher,
     description, homepage, license if different, image tag,
     `signature` cosign URL)
   - **Concrete templates** (MINOR #20 fix): show
     `publisher = "your-github-org"`,
     `homepage = "https://github.com/your-org/vulture-plugin-yours"`,
     `signature = "cosign://sigstore/your-org/vulture-plugin-yours"`
     — explicitly NOT `vulture-core` / `bobinson/vulture` sentinel
     values an author might accidentally retain.
   - **Trust narrative**: explain WHY the manifest must reference
     the author's repo (cosign keyless OIDC ties signatures to a
     specific GitHub Actions identity)
   - **Language-agnostic note**: this plugin uses Python because
     it wraps Semgrep (Python tool). The contract is
     language-agnostic; Go / Node / Rust plugins are equally valid.
     Point at the contract spec for the language-neutral
     requirements.

2. **Trust narrative clarity.** README explains:
   > "This plugin lives in Vulture's repo because the Vulture core
   > team maintains it. Its tier is `in-tree` — meaning the Vulture
   > release pipeline vouches for it. Your plugin, in your own
   > repo, will be `community-signed` — cosign-verified with your
   > GitHub Actions OIDC identity. Both paths are first-class; the
   > only difference is who signs."

## DRY review

- **SSE event shape**: `src/sse.py` writes events in the
  vulture-plugin/1.0 format. This format is already documented in
  the contract spec; no duplication. Other plugins forking this
  copy `sse.py` verbatim — that's the intended pattern.
- **Finding shape**: the wrapper emits findings matching the Go
  `model.Finding` struct field names. We don't import Go types;
  the contract is JSON. Translator tests pin the shape.
- **CWE mappings (MAJOR #12 fix)**: orchestrator's
  `backend/internal/cwe/data/check_id_prefix_to_cwe.json` is the
  CANONICAL source for well-known Semgrep prefixes. The plugin's
  `prefix_to_cwe` in `plugin.toml` carries ONLY entries that the
  orchestrator base map doesn't already cover. CI test
  (`TestCWEMapsNoOverlap_0053`) walks both files and fails if a
  prefix appears in both. Prevents silent stale-data divergence.
- **JSON schema versioning (MAJOR #13 fix)**: any future
  `rules/*.json` file (loaded when 0050 v1.1 activates
  `mapping_file`) ships a top-level `"schema_version": "1"` field.
  The loader rejects files with an unknown schema_version. v1 of
  0053 ships only inline `prefix_to_cwe` (in TOML), so this
  concern is preventive — but the rule is set now.
- **Health endpoint pattern**: every plugin needs `/health` and
  `/info` per the contract. `wrapper.py` defines them in standard
  shape; community plugins copy.

## Files touched

| File | Action |
|---|---|
| `docs/features/0053_bundled_semgrep_plugin/{plan,status,rollback}.md` | NEW |
| `plugins/semgrep/plugin.toml` | NEW |
| `plugins/semgrep/Dockerfile` | NEW |
| `plugins/semgrep/pyproject.toml` | NEW |
| `plugins/semgrep/src/wrapper.py` | NEW |
| `plugins/semgrep/src/translate.py` | NEW |
| `plugins/semgrep/src/sse.py` | NEW |
| `plugins/semgrep/rules/rule_to_cwe.json` | NEW |
| `plugins/semgrep/rules/prefix_to_cwe.json` | NEW |
| `plugins/semgrep/tests/unit/*.py` | NEW (RED for Python side) |
| `plugins/semgrep/tests/fixtures/*` | NEW |
| `plugins/semgrep/tests/e2e/*.py` | NEW |
| `plugins/semgrep/README.md` | NEW |
| `backend/pkg/pluginregistry/loader.go` | MOD — relax sanity check (drop one half-condition) |
| `backend/pkg/pluginregistry/loader_test.go` | MOD — add 2 tests for new tier+runtime combo + builtin dir |
| `backend/pkg/pluginregistry/loader.go` | MOD — add `BuiltinDir` field to `LoadOptions`; discover from `VULTURE_BUILTIN_PLUGINS_DIR` |
| `docker-compose.yml` | MOD — mount `./plugins` into backend container; set `VULTURE_BUILTIN_PLUGINS_DIR=/vulture-plugins` |
| `Makefile` | MOD — add `make plugin-semgrep-build`, `make plugin-semgrep-test` |
| `.gitignore` | MOD — `plugins/*/dist/`, `plugins/*/__pycache__/` |

Estimated LoC: 250 (wrapper) + 200 (tests) + 200 (manifest + Docker + JSON + README) + 20 (Go-side changes) = ~670 net.

## Acceptance criteria

1. **Manifest validates** — `pluginregistry.ParseManifest` accepts
   `plugins/semgrep/plugin.toml` with no errors.
2. **Tier+runtime combo allowed** —
   `TestSanityCheckRuntime_InTreeTierAllowsContainerRuntime_0053`
   passes after the one-line loader relaxation.
3. **Builtin dir discovery** — `VULTURE_BUILTIN_PLUGINS_DIR=<path>`
   causes registry to enumerate manifests from that path with
   `Source: "builtin"`. Disabled by default (env unset).
4. **Wrapper SSE contract** — TestClient POSTs `/run`; assert event
   sequence `run_started, agent_start, finding*, result,
   agent_end, run_finished`.
5. **Translator handles missing CWE metadata** — Semgrep finding
   without `extra.metadata.cwe` produces a Finding whose `category`
   is the check_id (relying on 0050 prefix map for resolution).
6. **Translator handles `extra.metadata.cwe = ["CWE-89"]`** —
   produces Finding with `category = "CWE-89"` directly.
7. **Severity mapping** — Semgrep ERROR/WARNING/INFO → Vulture
   critical/medium/info; documented narrowing.
8. **Source-path argv injection rejected** — POST /run with
   `source_path = "-rm-rf"` returns HTTP 400.
9. **Source-path nonexistent** — POST /run with
   `source_path = "/nope"` returns HTTP 400 with clear message.
10. **`/health` returns 200** — for supervisor probe.
11. **`/info` returns capabilities** — matches manifest.
12. **Dockerfile USER nobody** — image inspect confirms
    non-root.
13. **CWE mapping ships ≥30 prefix entries** — `prefix_to_cwe.json`
    has at least 30 keys; loaded by 0050 layer.
14. **Manifest declares `mapping_file = "rules/rule_to_cwe.json"`** —
    consumed by 0050 v1.1 when that lands; today the field is
    parsed-and-ignored (consistent with 0050 v1).
15. **`docker-compose.yml` mounts `./plugins`** — bundled plugins
    available in the default deployment.
16. **README walks through forking** — section "How to build your
    own plugin" with concrete steps and trust-tier explanation.
17. **`make plugin-semgrep-build`** — produces a runnable image.
18. **E2E with real docker** — supervisor + bundled plugin produce
    ≥1 finding from `tests/fixtures/test_source/sql_injection.py`
    via a full audit flow. Skipped if docker unavailable.
19. **Vulture core unchanged for migration** — when the plugin
    moves to its own repo, the only Vulture-side changes are
    docs + example manifest. No code change required to switch
    `plugins/semgrep/` from `tier=in-tree` to `tier=community-signed`
    via the registry's existing logic.

## Build sequence

1. LLD review (cross-cutting subagent).
2. Backend-side changes first (one-line loader relaxation + new
   `BuiltinDir` field + 2 RED tests + GREEN).
3. Python wrapper RED (unit tests + fixtures only; wrapper.py absent).
4. Python wrapper GREEN.
5. Dockerfile + image build verification.
6. E2E with real docker.
7. README polished as the reference document.

## Rollback

| Failure | Recovery |
|---|---|
| Wrapper bug in production | `vulture plugin disable semgrep`; backend continues without it |
| Image build broken | `make plugin-semgrep-build` fails at CI; no image shipped |
| Semgrep upstream breakage | pin to previous version; new minor release of plugin |
| Full revert | `git revert <merge>`; `plugins/semgrep/` gone; backend loader relaxation reverted by same revert; no DB changes |
