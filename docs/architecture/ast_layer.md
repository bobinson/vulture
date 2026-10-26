# Vulture - Shared AST Layer

## Overview

`agents/shared/shared/ast/` (`shared.ast`, feature 0102) is a structural layer
any agent can use: tree-sitter parse tree → normalised file model → scopes and
def-use → origin-set data flow. It is language-neutral and framework-agnostic:
it knows **roles** (generic concept words and structural positions), never
libraries, packages or frameworks.

| | |
|---|---|
| Languages | JavaScript (`.js .jsx .mjs .cjs`), TypeScript (`.ts .mts .cts`; `.tsx` with the TSX grammar), Python, Go, Java, Rust, PHP, C (`.c .h`), C++ (`.cpp .cc .cxx .hpp`) |
| Families | `path` (CWE-22), `request` (CWE-918), `command` (CWE-78); C and C++ own `path` and `command` only |
| First consumers | the CWE agent: `cwe.input_validation.path_traversal`, `cwe.injection.ssrf`, `cwe.injection.command` (`OWNED_CHECK_IDS`) |
| Scope of one analysis | one file: same-file callees are followed, nothing across files |

What the layer adds over the regex tier is the within-file flow a line
pattern cannot see: a value carried across statements, a call result that
carries input (`JSON.parse(req.body.x).path`), a same-file helper that holds
the sink, a sanitiser applied to the wrong variable, a local function that
shadows a sink name. It does not add cross-file flow, and it does not replace
the regex tier: the regex bodies stay as the permanent per-file fallback.

The CWE agent's `SKILLS.md` documents, per owned check id, what the layer
decides, the named heuristics, and every known gap.

## Architecture

```
agent process (8 audit generators; each skill thread runs in a copy of its audit's context)
  skill thread ──► prefetch.advance(path) ──► issue the next files of its walk ahead (tickets)
               ──► owns_answer(path)  ──► prefetch.refill() (the collected ticket's slot reused)
                     ├─ declined earlier in this audit → None (no second parse, no second tally)
                     ├─ cache hit → FileAnswer (immutable, shared across audits)
                     └─ miss → single-flight → collect the key's ticket, or
                                               WorkerPool.parse(language, bytes, answer)   JSON frames over pipes
                     ┌───────────────────────────────────────────────────────────────────┐
                     │ worker: python -I -c BOOTSTRAP   cwd = private temp dir             │
                     │         env = {PATH, LANG}       rlimits (AS, CPU, NPROC, FSIZE)    │
                     │  parse → skeleton → model → analysis → ANSWER | {"error": reason}   │
                     └───────────────────────────────────────────────────────────────────┘
  skill thread ──► answer.analysis().candidates(family)   validated at the boundary
             ──► decide(flow, rule, audit context) → report | decline | none
             ──► finding (unchanged schema + validation.ast / validation.flow)
                 declines → `thinking` lines; tallies → result.ast_coverage
```

Only the spawned worker imports `tree_sitter`. The parent reads the file
through the scanner (its size cap, decode and path confinement apply
unchanged) and ships the bytes. The worker answers with the file's ANSWER:
its coverage facts and every owned family's candidate flows, built by the
same code the library path runs in the parent (`get_model`, which ships the
columnar skeleton and builds the `FileModel` and its analysis in the parent;
the bench, the goldens and the tests use it). The parent validates every
reply at the boundary, an answer field by field. `import shared.ast` is light:
it loads neither `tree_sitter`, the validate stage, the audit runner nor the
LLM client.

### Parse prefetch

A skill's file loop runs under a walk (`prefetch.walk`, through the CWE
agent's `ast_walk`): the files it analyses, in order, and the families its
rules ask about. Right before the head asks for a file's answer it calls
`prefetch.advance(path)`, which sends the walk's next files to idle workers
(`PREFETCH_AHEAD` positions ahead) when the consumer would ask for them and
nothing holds them yet. Each such request is a **ticket**: a request already
sent, its reply waiting in the worker's pipe. The key's flight leader (any
skill thread of the audit) claims it and reads the reply instead of sending
the request again, so a file reaches a worker once per audit in the common
case, and the second skill to ask finds the answer stored. Right after the
answer is in, `prefetch.refill()` lets the walk issue what its advance left
for want of a slot, into the slot that ticket freed.

* No thread and no future: everything runs on the consumer's own thread.
* Tickets sit below the cache. They read only whether a key is stored or in
  flight, store nothing and record nothing; what a ticket's request meets is
  recorded when it is collected, on the collecting audit. So the cache
  tallies, declines and coverage equal a synchronous run's, and prefetch
  never evicts anything.
* Tickets never take the last `PREFETCH_RESERVE` worker slot: a synchronous
  request always finds one, and a pool of one worker never issues.
* One request per key: a key is reserved in the audit's ticket index in the
  same step that finds nothing holds it, before the file is read, so two
  skills' walks never issue it twice; a flight leader that finds the key
  reserved waits for the ticket (the issue does not wait on the worker) and
  claims it.
* A walk discards the tickets it issued and nobody claimed when it ends; the
  audit's ticket index is closed (every ticket discarded, later issues
  refused) when the audit is left and in the runner's skill-phase `finally`,
  the cancel and deadline paths included.

## Ownership

`owns_answer(path)` returns the file's answer (`owns(path)`, on the library
path, its model), and the layer owns its families' check ids on that file,
when:

1. the file's language has a profile, and that profile owns the family;
2. the worker parsed it within the caps with **zero ERROR nodes**;
3. the audit's circuit breaker is closed.

That is the whole rule. There is no engine selector, no environment variable
and no configuration: ownership is decided per file by the parse outcome. On
an owned file only the AST head emits the check id; on any other file only
the regex body does. The two never both emit one check id on one file.

A cheap prefilter runs first, on the text the skill already holds: a file of a
supported language with no sink key of the family is owned with no rows and
is never sent to a worker.

## Fallback

A file the layer does not own is scanned by the regex body, for the whole
file, exactly as before 0102. The reason is counted once per file in the
result's `ast_coverage.files.fallback`:

| Reason | Meaning |
|---|---|
| `unsupported` | no profile for the language (Ruby, C#, …): the regex tier's own coverage, not a loss |
| `parse_error` | the tree has at least one ERROR node (whole-file fallback; a C/C++ file whose macros break the parse lands here) |
| `too_large`, `too_deep`, `ir_too_large` | over the size, nesting-depth or node / frame cap |
| `bad_model` | the worker's reply failed the parent's validation |
| `timeout`, `worker_crashed`, `worker_error`, `spawn_failed` | the worker did not answer, died, failed, or could not be started |
| `circuit_open` | the audit's breaker tripped after 20 worker timeouts or crashes: every later file falls back |

A refused or failed parse is remembered for the rest of the audit only; the
next audit retries the file.

## From parse tree to finding

* **File model.** A closed set of 41 node kinds; each profile maps its
  grammar's types onto them in one table, from which the worker's grammar
  check is generated. Indexes (per kind, children, enclosing function and
  block, line) are precomputed, so every query is O(1).
* **Scopes and def-use.** A forward pass per function, run on demand. Each
  branch and each switch/match arm runs from the state before it and its
  changes are joined back; unconditional reassignment overwrites; loops get
  one extra pass. No CFG, no SSA.
* **Origins.** Every value carries a set of origins: `external(role, via)`
  (role `request`, `network`, `upload`, `argv`, `stdin`, `env`, `error` or the
  `param_hint` heuristic; `via` the sanitiser roles it passed), `constant`, or
  `unknown(reason)` (`param`, `unresolved`, `external_call`, `recursion`, …).
  A call to an unknown callee passes its arguments' origins through. A call to
  a same-file function is summarised (at most 1 + 4 summaries per callee,
  nesting depth 2; re-entering a callee is `unknown(recursion)`).
* **Sinks, sanitisers, guards.** A sink is a call whose glued callee key (last
  identifier, lowercased, `_` and `$` removed) is in the family's sink lexicon
  or a profile builtin. Sanitiser and guard roles are matched on the generic
  concept words of an identifier; a few short ambiguous words reach a role
  only as an exact builtin key or inside a composition (`shell_quote`,
  `host_allow`). A few readings are structural: a generic HTTP verb is a
  request sink only with HTTP-client evidence and never on a collection
  receiver; a regex or data-store receiver runs no command; a container word
  (`params`, `body`, …) is a request source only in request context; a
  dominating validation call statement is a guard; and `<stem>sync` is a path
  sink when `<stem>` is. The lexicons live in `shared/ast/roles/`, one home
  each.
* **The decision.** `decide(flow, rule, ctx)` is the only place a flow is
  judged:
  * `report` when an external origin of a role the family accepts reaches the
    sink argument uncovered by a sanitiser and no covering guard precedes it;
  * `decline` when every such origin passed a covering sanitiser, or a guard
    covering the family protects the sink; the decline is recorded;
  * `none` when nothing external reaches it. A sink whose origins are all
    `unknown` is tallied (`unknown_only_sinks`), not reported, except where a
    rule's named heuristic reports it.
* **Named heuristics.** Two places use a name, not a flow, and say so on the
  row: the parameter-name hint (a parameter named like `filename` or
  `dest_path` is an external origin of role `param_hint`, shown as
  `external:param_hint`), and the CWE-78 command parameter heuristic (an
  UNKNOWN-only flow holding a function parameter reports when the sink shells
  the argument, the argument is built, or it is the whole command of a
  command builtin of the profile's own table (`new ProcessBuilder(cmd)`),
  unless a caller in the same file binds the parameter; the row carries
  `"heuristic": "command_param"`).

The row keeps the regex tier's `check_id`, category, title, severity and
recommendation, so finding identity is unchanged. It anchors at the **sink
line** (`line_start == line_end`), quotes that line as `evidence_quote`, and
carries the AST facts under the top-level `validation.ast` and
`validation.flow` keys, never in `checks[]`. The wire shapes are in
[agent_protocol.md](agent_protocol.md#ast-tier-fields-feature-0102-all-optional).

## Coverage

Every audit's `result` snapshot carries `ast_coverage`: files parsed and
fallen back (with the reason), the fallback files as an uncapped lossless key
list and as a capped display list, the grammar stamp per language, the
declines by label, the tallies (UNKNOWN-only sinks, cap hits, model-cache hits
and misses, node types a profile does not map) and the worker pool. A degraded
run is therefore visible, never silent: a file the layer could not read is
named, and scan-set coverage (`unsupported`) is kept apart from AST coverage.

## Declines

A decline is the layer's only suppression, and it is structural: a covering
sanitiser in the value's path or a covering guard before the sink. No
sanitiser, guard or allowlist recognised by name ever deletes a finding at the
validation layer. Each decline is recorded on the audit and streamed as one
`ast_decline` thinking line (`family`, `file`, `line`, `rule`, `origins`), at
most 50 per label in a bounded heap, followed by one `ast_decline_summary`
line per audit. A decline is never a `false_positive` label.

## Isolation

The audited repository is treated as adversarial.

* Workers are **spawned**, never forked from the agent: `python -I` (no
  `PYTHONPATH`, user site or current directory on the import path), a private
  empty working directory, an environment of `PATH` and `LANG` only (no keys),
  and resource limits where the platform enforces them (address space 256 MB
  on Linux, CPU, no child processes, no file writes).
* Frames are length-prefixed JSON in both directions, at most 8 MB. Every
  reply is validated against the request before it becomes a model: an
  identifier must look like an identifier, and a literal value may only be a
  boolean or a short number, besides the identifier-shaped subscript keys and
  command-flag and shell-interpreter text the analysis needs.
* No source literal value leaves the layer: a literal subscript key or command
  flag is kept for analysis but emitted only as `<index>` / `<flag>`, in hops,
  declines and findings. Every emitted path is rendered root-relative,
  printable ASCII, at most 200 characters.
* A worker that times out (10 s per file, the whole frame round trip) or
  crashes is killed and replaced, and its file falls back. A worker is also
  recycled at its file and resident bounds (Limits).

## Limits

Every cap is a named constant in `shared/ast/limits.py`; at a cap the layer
tallies and degrades in the conservative direction, never loops.

| Operation | Cap | At the cap |
|---|---|---|
| file sent to a worker | `MAX_FILE_SIZE` 512 KB, `MAX_NODES` 500,000, `MAX_DEPTH` 256 | `too_large` / `ir_too_large` / `too_deep` fallback |
| frame | `FRAME_CAP` 8 MB | `ir_too_large` |
| per-identifier words, chain segments | `MAX_WORDS` 16, `MAX_CHAIN` 8 | truncated, tallied |
| branch nesting per function | `MAX_BRANCH_DEPTH` 32 | `unknown(depth)`, tallied |
| origins per value | `MAX_ORIGINS` 16 | collapse to a reportable set, tallied |
| callee summaries | `MAX_SUMMARY_SIGNATURES` 4, `MAX_SUMMARY_DEPTH` 2 | `unknown(summary_cap)`, tallied |
| guard search | `MAX_ARG_NAMES` 16, `MAX_TEST_NODES` 64, `GUARD_WINDOW` 8 preceding `if`/`try` | an unexamined guard is no guard (reportable) |
| arguments per call | `MAX_ARGS` 16 | the rest unread, tallied |
| hops per flow | `MAX_HOPS` 8 | the first 8 kept, `truncated` |
| declines per label | `MAX_SUPPRESSIONS_PER_RULE` 50 | label named in `capped_rules` |
| display fallback paths | `MAX_FALLBACK_PATHS` 200 | `fallback_paths_truncated` (the key list stays whole) |
| worker faults per audit | `CIRCUIT_BREAK_AFTER` 20 | `circuit_open` for the rest of the audit |
| files a worker serves | `RECYCLE_AFTER` 2,000 | the worker is recycled, tallied `workers.recycled` |
| worker resident high-water (Linux `/proc`) | `MAX_WORKER_RSS_MB` 48 MB | the worker is recycled after the request, tallied `workers.recycled` |
| files a walk considers ahead of its cursor | `PREFETCH_AHEAD` 8 (2 × `MAX_WORKERS`) | the rest wait for the next advance |
| worker slots tickets never take | `PREFETCH_RESERVE` 1 | an issue past `W − 1` outstanding tickets is refused; the file goes synchronous |

Workers: `W = clamp(1, min(cpu_quota, (memory_limit − rss − caches) / 192 MB), 4)`,
so the compose shape (one CPU per agent) runs one worker, shared FIFO by the
agent's concurrent audits. The model cache is byte-budgeted (at most 128 MB
and a quarter of the deployment memory limit, an analysis charged to its
model), keyed by the file's real path, size, mtime, grammar pack, model
schema, language and grammar entry point (an answer's key adds the answer
schema), single-flight, and shared across audits: the key makes a stale
entry unreachable, so it is not cleared per audit. In production it holds
answers, which weigh about a fourteenth of their models.

## Determinism

Arrays are in document order; origin sets are sorted before they are emitted;
findings are sorted by `(file, line_start, check_id)` and declines by line;
the decline heap and the display fallback list keep the lexicographically
smallest entries; the `ast_coverage` snapshot is key-sorted at every level,
and its cache tallies count every request of a key after its first as a hit,
however the skill threads interleave. The contract: two runs of the same tree,
in different processes (different hash seeds) and thread interleavings,
produce byte-identical findings, decline lines and coverage (the CWE agent's
`tests/e2e/test_0102_determinism.py`). The grammar version is part of the
cache key and of every row's `validation.ast.grammar`.

## No flag; rollback; deploy order

There is **no environment variable** for the layer (`CLAUDE.md` rule 6). The
AST tier owns its check ids on every file it parses cleanly; the regex bodies
own them on every other file.

* **Rollback is a code revert** of the consumer heads (the CWE-22, CWE-918 and
  CWE-78 heads in the CWE skills) and a redeploy of the agent: an image
  rebuild, or a native reinstall. The regex bodies are never deleted, so the
  revert restores the pre-0102 behaviour exactly. No data migration and no
  frontend change are involved. A reverted agent stops writing
  `validation.ast`/`validation.flow` and the decline lines; rows both tiers
  produce move back from the sink line to the regex anchor line (lineage keys
  carry no line, so identity is kept).
* **Deploy order: backend before agents.** An AST-owned finding is
  deterministic-tier, so a later scan that does not re-report it would close
  it as fixed, and when its file falls back to regex (a new syntax error, a
  timeout, the breaker) the regex tier cannot reproduce an AST-only flow. The
  backend's lineage pass therefore reads the streamed `ast_coverage` and holds
  CWE-22/918/78 rows on fallback files `unconfirmed` instead
  ([agent_protocol.md](agent_protocol.md#ast-tier-fields-feature-0102-all-optional)).
  A backend carrying this guard must be running before agents that carry the
  layer; an agent with the layer against an older backend would let such rows
  close as fixed.
* **Line moves.** A row both tiers can produce may change `line_start` when its
  file moves between tiers (parse success ↔ fallback): the AST tier anchors at
  the sink, the regex tier where its pattern matched.

## Using the layer from an agent

The consumer surface (`shared.ast`, `shared.ast.consume`,
`shared.ast.context`):

```python
owns_answer(path) -> FileAnswer | None      # None: the regex body owns the file
owns(path) -> FileModel | None              # the same decision on the library path (parent-built model)
prefetch.walk(files, families)              # a skill's file loop: `with walk(...) as files:`
prefetch.advance(path)                      # right before owns_answer(path): send the next files ahead
prefetch.refill()                            # right after it: reuse the slot the collected ticket freed
profile.owns_family(path, family) -> bool | None   # by extension, no parse: the one ownership predicate
owns_lang(path) -> bool                      # a profile exists (no parse)
model_needed(text, family) -> bool           # the prefilter: False = no sink of the family can exist
roles.needed_families(text, families) -> frozenset[str]   # several families' prefilters, one glued view
FamilyRule(family, check_id, category, title, severity, recommendation, cwe_id,
           gate=None, heuristic=None)        # one per migrated check, shared by both tiers
rule_row(rule, description, *, file_path, line, lines, **extra) -> dict   # the row both tiers emit (D19)
family_spans(model, rule, ctx, path, *, server_ctx=True) -> dict[int, Flow]
emit_for_line(spans, line_num, rule, *, file_path, nl_lines, findings, enrich=identity) -> bool
flow_to_finding(flow, rule, *, file_path, nl_lines) -> dict
context.current() -> AuditContext            # the audit's coverage, decline ledger and breaker
```

A migrated check follows one shape:

1. Define the check's identity once as a `FamilyRule`; the regex body builds
   its rows from the same constant through `rule_row`, the row
   `flow_to_finding` extends, so both tiers emit one row shape.
2. Per file: if `model_needed(text, family)` is false (`needed_families` when
   one skill asks several families of one text) the file is owned with no rows
   when its profile owns the family (`owns_family`, by extension, no parse)
   and regex-owned otherwise; else, when the profile owns the family,
   `prefetch.advance(path)`, `owns_answer(path)` and `prefetch.refill()` decide, and an owned
   file's `family_spans` maps every line of each reported sink's span to its
   flow, recording the declines against that file. The skill's file loop runs
   under `prefetch.walk`. The cwe agent keeps this decision in one head
   (`cwe_agent/skills/_ast_head.py`: `ast_walk`, `ast_answers`), which every
   migrated check calls.
3. In the line loop, call `emit_for_line` first: True on a span line (the AST
   owns it, the regex siblings stay silent there), and the row appended once,
   at the sink line. When `spans` is `None`, run the regex body unchanged.

The rules every consumer keeps (`test_0102_consumer_contract.py` checks them
over `OWNED_CHECK_IDS`): one owner per check id per file; the finding schema
unchanged, with AST facts only under `validation.ast` / `validation.flow`; no
literal value emitted; corpus parity before ownership and a held-out sample
after the lexicons freeze; an `AST usage` bullet with known gaps in the agent's
`SKILLS.md`; new words in `shared/ast/roles/`, never a per-agent table; every
cap from `limits.py`.

## Adding a language

One file under `shared/ast/profiles/`: the grammar import, the node-kind
table, scope rules and the language's own builtins (a stdlib sink or
superglobal, never a library). Extensions come from `shared/language.py`. The
kind, scope-construct and golden-hash tests are parametrised over the
profiles, so a new profile gets them by existing.

Admission is decided on **correctness of the files that parse**, not on the
parse-error rate: because fallback is whole-file, a high parse-error rate costs
AST coverage, never correctness (those files are scanned as before). A
language is admitted when its corpus fixtures pass recall 1.0 and FP 0 on the
AST tier, and `ast_coverage` reports its measured parse-error rate. A profile
is held back (`disabled_until` a grammar version) only if its clean-parse
files give wrong corpus results or a systematic silent misparse is found (a
tree with no ERROR node but the wrong structure, the C/C++ macro risk).

## Known limits

The layer is intra-file by design. Its stated limits, each listed with
examples in the CWE agent's `SKILLS.md`:

* No cross-file flow; a request object reaching a sink only through a
  parameter with no role word is UNKNOWN-only and tallied, not reported (the
  CWE-78 command parameter heuristic is the one named exception).
* Calls to unknown callees pass origins through (the false-positive direction,
  filtered downstream); a sanitiser or guard whose name carries no concept
  word is not seen.
* No exhaustiveness analysis of switch/match arms; a switch is never a guard;
  C/C++ `case` fall-through is not followed.
* The C preprocessor is not expanded: a macro that breaks the parse sends the
  file to the regex fallback, and a sink behind a macro that parses cleanly is
  invisible. `.h` files parse with the C grammar.
* On macOS the address-space limit is not enforced; the size, node and depth
  caps, the wall timeout and crash containment bound a worker there.

## Not in this version

CFG or dominance analysis, cross-file flow, other agents' migrations (each a
feature of its own, built on the same API: error disclosure, logging,
accumulation, XSS, resilience patterns, endpoint discovery), the LLM's
`ast_parser` tool, persisting `ast_coverage` on the audit row, and languages
beyond the nine above.
