# 0063 OWASP-over-CWE Pipeline — Rollback Plan

## Rollback triggers

Roll back if any of these appear after deployment:
- OWASP audits report drastically fewer findings than the pre-0063 scanner **and** the
  cause is not simply the CWE agent not being run (check the prerequisite notice first).
- The OWASP agent raises/500s on any `/run` payload (it must never fail — see Task 4).
- The pipeline deadlocks or loops because of the new `owasp → cwe` prerequisite edge.
- CWE-agent additions (CWE-799/703/1357) produce a false-positive flood that degrades
  overall audit quality.

## Rollback is staged — three independent layers

Because the feature is layered, you can roll back the risky part without losing the
detection improvements.

### Layer A — revert only the backend orchestration (lowest blast radius)

If the problem is orchestration (ordering/tap), revert Task 9 (and, if needed, Task 7):

```bash
git revert <task-9-commit-sha> <task-7-commit-sha>
cd backend && go build ./... && go test ./internal/service/ ./pkg/agentregistry/
```

Effect: `owasp` returns to the concurrent scan set (Task 7 revert) and the deferred phase
is gone (Task 9 revert). OWASP then runs concurrently again; with the mapper still in place
it emits a zero-coverage manifest (safe, no failure) rather than detecting. Detection gains
(Tasks 10–12) and the mapper (Tasks 1–6) remain. There is **no DB state to unwind** — the
revised design adds no schema. This is the primary, low-risk rollback.

### Layer B — restore the old OWASP scanner (feature-flag path, preferred)

Rather than a hard revert of the agent rewrite, keep the deleted skills recoverable and
gate behavior with an env var so rollback needs no redeploy of code:

- Before merging Task 4, tag the pre-rewrite tree: `git tag pre-0063-owasp-scanner`.
- Recovery: `git checkout pre-0063-owasp-scanner -- agents/owasp/owasp_agent/skills/ agents/owasp/owasp_agent/agent.py agents/owasp/owasp_agent/config.py`
- Add `VULTURE_OWASP_MODE=scan|map` (default `map`) if a runtime toggle is wanted; the
  scanner path is the restored files, the mapper path is 0063. (This toggle is optional
  and NOT built by the plan — add it only if operational risk warrants a hot switch.)

Effect: OWASP agent reverts to independent regex detection; CWE agent and mapping data
are untouched.

### Layer C — full revert

If the whole feature must go:

```bash
git revert --no-commit <task-15-sha>..<task-1-sha>
# resolve the deleted-skills restoration (Layer B checkout), then:
git commit -m "revert(0063): full rollback of OWASP-over-CWE pipeline"
```

There is **no migration to unwind** — the revised design adds no DB schema. The additive
`PriorFinding.LineStart/LineEnd` fields (Task 9) are in-memory/JSON only; reverting the
struct change is sufficient and touches no stored data.

## Data / schema considerations

- **No DB schema change.** The single-stream design adds no tables/columns and no migration.
- **Mapping data files** (`agents/shared/shared/owasp/editions/*.json`) are inert data;
  leaving them after a rollback is harmless.
- **Findings are not rewritten in place** — the mapper emits new OWASP-labeled findings
  alongside the CWE findings in the same audit; CWE findings are unchanged. Historical
  audits are unaffected in either direction.
- **`PriorFinding.LineStart/LineEnd`** are additive JSON fields; older agents ignore
  unknown fields, so the transport is backward/forward compatible.

## Verification after rollback

```bash
cd agents/owasp && PYTHONPATH=../shared:. python -m pytest tests/ -q
cd ../cwe && PYTHONPATH=../shared:. python -m pytest tests/unit/ -q
cd ../../backend && go vet ./... && go test ./internal/service/ ./pkg/agentregistry/
```
Confirm: OWASP `/run` returns 200 on an empty payload; an audit requesting `owasp`
either runs cwe-first then maps (feature on) or runs concurrently emitting a zero-coverage
manifest without error (feature off).
