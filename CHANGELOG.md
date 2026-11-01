# Changelog

All notable changes to Vulture will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Security fixes** are recorded under a `### Security` heading naming the advisory
identifier (CVE / GHSA / PYSEC), the affected versions, and the remediation, and
are surfaced in the corresponding GitHub release notes — so every release that
fixes a vulnerability discloses it (OpenSSF Best Practices passing criterion).

## [Unreleased]

### Known limitations

- **Finding triage labels (thumbs FP/TP) are not yet functional.** The
  `audit_memories` table lacks the `fingerprint` column the label
  endpoint and the L4 memory-prior validation layer query, so labelling
  a finding logs a non-fatal error and the L4 layer is skipped. Audits,
  scanning, and all other validation layers are unaffected. Tracked for
  a follow-up release.

### Added

- **Feature 0102 — Shared AST layer (`shared.ast`).** A structural layer in the
  shared agent library: tree-sitter parse tree → normalised file model → scopes
  and def-use → data flow inside one file, for JavaScript, TypeScript, Python,
  Go, Java, Rust, PHP, C and C++. It knows roles (generic concept words and
  structural positions), never libraries or frameworks. Parsing runs in
  isolated, spawned worker processes (no keys in their environment, resource
  limits, length-prefixed JSON validated at the boundary, killed and replaced on
  a timeout or crash); a file the layer cannot parse is scanned by the regex
  tier exactly as before. The CWE agent is the first consumer, for CWE-22,
  CWE-918 and CWE-78. New wire fields, all optional, so either side may be
  older: `validation.ast` and `validation.flow` on an AST-tier finding (top-level
  keys, never `checks[]`; persisted with no backend change), `ast_coverage` on
  the `result` snapshot (files parsed and fallen back with the reason, the
  declines, the tallies), and the `ast_decline` / `ast_decline_summary`
  thinking lines. The backend's lineage pass reads `ast_coverage` and holds a
  CWE-22/918/78 row `unconfirmed`, never `fixed`, when its file fell back to the
  regex tier in that scan. Parsing runs ahead of the consuming skill: while a
  skill decides one file, the workers already analyse its next owned files, so
  in the common case each file is parsed once per audit, with rows, declines
  and `ast_coverage` equal to a synchronous run's. A worker whose resident
  memory high-water exceeds 48 MB after a request is replaced
  (`ast_coverage.workers.recycled`). Ten new dependencies: the tree-sitter core
  and nine grammars (MIT). See
  [docs/architecture/ast_layer.md](docs/architecture/ast_layer.md) and
  [docs/architecture/agent_protocol.md](docs/architecture/agent_protocol.md).

- **Feature 0074 — verify masked values; merge records masked.** A finding's
  masked snippet can be verified against the scanned file: `GET
  /api/audits/{id}/findings/{fid}/masked` locates every masked value (line,
  column, kind) and returns the values only to an authorised human (an admin;
  locally, the signed-in session) and only while the file still matches the
  scan. The UI shows a "Show unmasked" switch in the finding detail; the MCP
  tool `vulture_verify_masked_values` returns locations and a UI link, never
  values. Nothing raw is stored. The descriptions of LLM rows merged into
  another row now get the same secret masking as every finding's description,
  in the agent and again in the backend.

- **Feature 0099 — Anonymous, caller-addressed message sends (CWE-799).** A new
  `resource_check` rule, `cwe.resource.anonymous_message_send`, reports a handler
  that lets a caller with no authenticated principal make the server send an
  e-mail / SMS / OTP / magic link to an address the caller chose, with no
  human-verification step gating it. Language- and framework-independent: it
  reads identifier meaning, the recipient's data flow inside the handler (and
  one same-file helper), and whether a principal or CAPTCHA actually gates the
  send. High, or medium when a quota is in scope. No new environment flag; the
  CWE literal set and skill count are unchanged.

- **Feature 0044 — Native installer (Mode E):** `curl … install.sh | sh`
  produces a Docker-less single-user install under `~/.vulture/`. Ships
  a bundled python-build-standalone, SQLite-backed daemon, and the SPA
  served as embedded assets straight from the Go binary. Includes new
  `vulture {start, stop, status, logs, doctor, uninstall}` subcommands,
  cosign-signed release tarballs with SBOM + Trivy CVE gate, and a
  19-item security-invariant spec. See
  [docs/features/0044_native_installer](docs/features/0044_native_installer/).
- **Repo-hygiene & security primitives:** CODEOWNERS enforcement on
  security-critical paths; `.trivyignore` / `.pip-audit-ignore`
  90-day-expiry allowlist; install.sh re-validates `VULTURE_HOME` before
  extract (TOCTOU mitigation); subprocess env scrubber drops
  `LD_PRELOAD` / `PYTHONPATH` / `DYLD_INSERT_LIBRARIES` from agent env;
  field-name allow-list logger redactor; append-only audit log for
  security events; LLM endpoint URL validator rejects cleartext non-loopback.
- **CWE detector simplifications:** PATH_TRAVERSAL_PATTERNS collapsed
  from 9 regexes to 2 (hot-path win); 104 dual-contract lock-in tests
  added to guard against false-negative blunders.
- **Feature 0098 — Offline skills gate (`vulture-offline-skills`).** Runs the
  CWE agent's deterministic skills over a list of files with no backend, no
  database and no LLM, for a pre-commit hook or a CI job, and gives the verdict
  the full audit would give with the LLM off (same skill set, redaction,
  skill-vs-skill collapse and L1/L2 validate stage). Exit codes: `0` no blocking
  finding, `1` blocking findings at or above `--severity` (default `high`), `2`
  tool or usage error (the verdict is withheld), and `128 + signal` when stopped
  by SIGTERM/SIGHUP. `--format json` prints a schema `1` report (`findings`,
  `blocking`, `errors`, `scanned`, `not_scanned`, `outside_root`). It runs
  without installing anything first-party:
  `PYTHONPATH=vulture/agents/cwe:vulture/agents/shared python -m cwe_agent.offline FILE...`
  after installing the hashed lockfile into a dedicated virtualenv. See
  [docs/guides/offline_skills_gate.md](docs/guides/offline_skills_gate.md).
- **Feature 0097 — access-control guard-application checks (CWE-807 /
  CWE-290).** Three `access_control` checks report an authentication or
  authorisation guard that a client-controlled request attribute can skip:
  - `cwe.access_control.guard_skip_by_request_attr` (CWE-807): a branch on a
    header, cookie, query or body value that skips the guard (returns early or
    calls through) or grants access, ahead of the guard's deny;
  - `cwe.access_control.spoofable_identity_guard` (CWE-290): the same, keyed on
    a spoofable identity attribute (`X-Forwarded-For`, `Host`, `User-Agent`,
    `Referer`);
  - `cwe.access_control.guard_excluded_by_request_attr` (CWE-807): a framework
    hook or route matcher that excludes requests by a request attribute (for
    example a Next.js middleware `matcher` with a `missing` header condition, or
    a Rails `before_action ... unless:`).

  They do not fire when the attribute is compared with a value the client
  cannot know (a server-held secret, also one whose same-file literal is only a
  default overridden elsewhere, or a CSRF double-submit token), when a verifying
  call (not a CSRF validator) is conjoined with the read, on a feature or
  challenge gate answering 403, or on a route handler returning a DTO early. They reach Rails `before_action` `if:`/`unless:`, Spring
  `preHandle`, ASP.NET `_next`, Auth.js middleware re-exports, Go and Express
  identity accessors, Echo `ErrUnauthorized`, Koa cookies, Flask
  `"X" in request.headers`, principal providers (a FastAPI dependency, a
  Passport `validate()`) that return a principal, a comparison of one request
  read with another, and the
  `export const config = { matcher }` shorthand. The access_control section of
  the CWE agent's SKILLS.md lists what they do not reach.

### Changed

- **The bundled SAST plugin is now `opengrep` 0.2.0, replacing `semgrep` (feature 0102).** Vulture may
  not redistribute Semgrep's proprietary engine, which the official Semgrep image carries, nor use the
  Semgrep Registry's rules, whose licence allows internal use only. The plugin now:
  - runs [Opengrep](https://github.com/opengrep/opengrep) 1.33.1 (LGPL-2.1), which the image build on
    your machine downloads from Opengrep's release and checks against a pinned sha256 per architecture,
    on a digest-pinned `python:3.12-slim` base, with the wrapper's packages hash-locked;
  - scans with bundled rules only, offline: Vulture's own, plus GitLab `sast-rules` (MIT and
    Apache-2.0 folders), elttam and 0xdea (MIT), each file pinned by sha256 with its licence in
    `rules/RULESET_SNAPSHOT.json`. No `p/…` or `r/…` Registry pack can reach the engine;
    `config.rule_sets` (bundled set names) replaces `config.rule_packs`, which is ignored;
  - returns real code snippets (Semgrep CE without a login answered `requires login`), sends no usage
    metrics, and follows taint across functions within a file (`--taint-intrafile`). It still skips test
    code (`test/`, `tests/`, `*_test.go`), now as explicit excludes: `.semgrepignore` files are ignored,
    since the engine's default also matched a scan root's own ancestors.

  Findings carry `agent_type` and `provenance` `opengrep`; the results-page "tier not active" notice
  recognises both names.

- **CWE-22, CWE-918 and CWE-78 rows come from the AST layer on parsed files
  (feature 0102).** On a JavaScript, TypeScript, Go, Java, Rust, PHP or Python
  file that parses with no error, `cwe.input_validation.path_traversal`,
  `cwe.injection.ssrf` and `cwe.injection.command` are decided by data flow
  inside the file instead of line patterns; on C and C++ files only CWE-22 and
  CWE-78 are (CWE-918 stays regex there). What changes for consumers:
  - **Rows anchor at the sink line** (`line_start == line_end`), where the
    regex tier anchored at the line its pattern matched, so a row both tiers
    produce may move line on the first scan after the upgrade and whenever its
    file moves between tiers. The check id, category, title, severity and
    recommendation are unchanged, and lineage identity carries no line.
  - **Declines are visible.** A flow the layer does not report because a
    sanitiser or a guard covers it is streamed as an `ast_decline` thinking
    line, and every audit's skill phase ends with one `ast_decline_summary`
    line. A sink reached only by values of unknown origin is counted, not
    reported, except the CWE-78 command parameter heuristic (rows marked
    `validation.flow.heuristic = "command_param"`). That heuristic also reports
    a parameter that is the whole command of a command builtin of the
    language's own table (`new ProcessBuilder(cmd)`, Rust `Command::new(cmd)`,
    C `posix_spawn`).
  - **Shapes the regex tier flagged by pattern alone change on a parsed file.**
    A command sink reached only by a parameter no caller in the file binds
    (`Runtime.getRuntime().exec(cmd)`, PHP `passthru($cmd)`, `proc_open($cmd,
    …)`) is counted, not reported, unless the heuristic above names it; a
    command with a constant argument (`shell_exec("ls -la")`) is not reported,
    and no other check flags its presence (CWE-676 has not covered execution
    calls since feature 0060); a request value in a later argument after a
    literal program (`new ProcessBuilder("tar", "-C" + v)`) is no command
    injection. For SSRF a source is followed through the whole file, not a
    25-line window, and words near the sink (a `validate_url` call on another
    variable, an `allowed_hosts` list) no longer suppress a row — only a check
    of the sink's own argument does. Files that do not parse keep every regex
    behaviour.
  - **Precision rules.** The layer reads generic concept words structurally,
    never library names. A generic HTTP verb (`get`, `put`, `delete`,
    `request`, …) is an SSRF sink only with HTTP-client evidence (no receiver,
    a client or transport word on the receiver, or a URL-shaped argument), and
    never on a receiver bound to a collection, so a map read keyed by a request
    value (`users.get(req.cookies.token)`) does not report. A command key on a
    regex or data-store receiver (`re.exec(s)`, `db.exec(sql)`) runs no
    process, and a multi-word callee reaches a command key only through an
    exact leading key plus a process word on the callee, on its receiver or
    in the module its import names, so `cp.execFile(cmd)` after
    `const cp = require("child_process")` is a command sink. A container word
    (`params`, `payload`, `body`, `query`, `headers`, …) names a request
    source only on a request-rooted chain, in a function in handler context
    or through a framework's extractor type. A dominating call statement such
    as `assertInsideRoot(p)` (a validation verb plus a role word, taking the
    flowing value) guards its role, a call returning a containment-checked
    path is a sanitiser, and a same-file function that tests its parameter
    and exits early guards its callers. Such a check, or an early exit, before
    a sink guards it from any block enclosing the sink within its function,
    so a later `if` with no check of its own no longer hides it; neither
    reaches into a callback that holds the sink. A synchronous twin of a path
    API (`fs.mkdirSync`, `fs.existsSync`) is a CWE-22 sink, and a generic file
    verb (`open`, `copy`, `save`, …) is one only with file-system evidence: a
    file-system word on the callee or receiver chain or in the path of the
    module its import names, or a call to a language global such as Python's
    `open`. The parameter-name hint (`fileName`, `dest_path`) applies only to
    a function a caller in another file can reach: an exported one (a class
    exported by name contributes its methods, in TypeScript as in
    JavaScript), or a public top-level one nothing in the file calls. A
    program's own arguments (`process.argv`, `sys.argv`) are no external
    source, except the `argv` of a C/C++ `main`; elsewhere they report only
    through the command parameter heuristic, when shelled or built into a
    command. Measured skills-only against the previous release on two public
    codebases, rows on the three ids go from 9 to 12 on one (4 true positives
    added, 7 false positives removed, 6 false positives added) and from 149
    to 66 on the other (127 false positives removed, 44 added; every added
    row was read and none is a true positive, nor is any of the previous
    release's rows).
    The gaps that remain are listed in the CWE agent's `SKILLS.md`.
  - **Row sets change.** Multi-statement flows, call results and same-file
    helpers are now reported; regex rows the flow does not support are not.
    Under `VULTURE_LINEAGE_FIX_MODE=evidence` (the default) a deterministic row
    a scan no longer reports closes as FIXED, so the first scan of an existing
    target after upgrading marks such rows fixed; rows on files that fell back
    to the regex tier are held `unconfirmed`. On a parsed file CWE-36 and CWE-23
    still take a path line before CWE-22. The known gaps, including path APIs
    the layer has no sink key for, are listed in the CWE agent's `SKILLS.md`.
  - **No flag.** Ownership is decided per file by the parse outcome alone;
    rollback is a code revert of the CWE consumer heads and a redeploy. Deploy
    the backend before the agents, so its lineage guard is in place when an
    agent with the layer reports.

- **The CWE agent's GENERATE prompt states the computed coverage counts**
  (171 CWE-ID `category` literals across 24 dedicated skills, N=81
  corpus-verified) instead of the stale ~73 / N=10. These are prompt bytes for
  every model family: the `generate/cwe` manifest is at version 6, and a unit
  test pins the stated counts to the values the code computes.

- **The CWE agent's GENERATE prompt states N=83 corpus-verified CWE types
  (feature 0102).** The AST tier's corpus group makes CWE-22 and CWE-918
  VERIFIED (CWE-78 stays VERIFIED on more fixtures), and the prompt's computed
  count follows: `generate/cwe` manifest version 8, goldens re-captured.

- **Finding-text masking is precise, for every agent (feature 0098).** Every
  finding's `code_snippet` and `description` are masked for secret SHAPES
  before any egress. The shapes are now a high-confidence set: provider tokens
  (OpenAI/Anthropic `sk-` keys, whatever their random body holds, a hyphen
  among its first characters included, GitHub classic and
  fine-grained, Slack tokens and webhook URLs, AWS key ids and secret keys,
  Stripe, npm, GitLab, SendGrid, Hugging Face, Google), JWTs, `Bearer`/`Basic`
  followed by a credential-looking value on the same line (a header value
  after `Authorization` or in quotes included), URL userinfo in any scheme case
  (an empty user too, `redis://:<password>@`), a connection-string `Password=`
  or `AccountKey=`, private-key BODIES (not just the header, in a numbered
  window, below the BEGIN row, as a one-line escaped key or a concatenation,
  with LF or CRLF line ends), and a hex value only on a line that names a
  credential (`SECRET_KEY_BASE=<hex>`, `headers["X-Api-Key"] = "<hex>"`,
  `define("SECRET_KEY", "<hex>")`, `apiKey := ...`, `ENV API_KEY <hex>`).
  Commit SHAs, image digests, UUIDs, MD5/SHA constants, hashes named as such
  (`cache_key`, `password_hash`, `commit`), CSS class names, CamelCase
  identifiers and prose that mentions Bearer or basic authentication are no
  longer masked, and masking never joins two lines. Logs keep the broader set:
  everything the previous log pattern masked is still masked there. A row that
  a secret finding cites is masked in every other finding's window, whatever
  CWE the secret skill gave it (a password in a config file is CWE-260); a row
  the structured redactor cannot mask (a bare key-body or value row) is
  replaced whole; and a triple-quoted literal is masked as one value, with the
  code around it redacted as before, instead of garbling to
  `"***REDACTED***""***REDACTED***`. Live `finding` events carry only the
  finding's own cited rows, since a neighbour's secret row is masked only once
  the whole batch is known. The `result` snapshot, and the rows persisted from
  it, carry the full, masked window; a finding the backend keeps from the live
  events because its agent sent no snapshot (a stalled or timed-out agent)
  carries only its cited rows. Masking is linear in the input size.
- **Offline gate CLI contract (feature 0098), refined before release.**
  Compared with the gate as first merged:
  - a working directory inside a directory that an audit of the discovered root
    prunes (`<repo>/build/proj`), with every file passed under it, exits `2`
    with `errors[].stage == "root"` instead of passing with "Nothing to gate";
    `--root` gates such a project as its own root;
  - an empty directory argument is a usage error (exit `2`) unless it holds a
    `.git` entry or the enclosing repository's `.gitmodules` declares it in a
    `[submodule "..."]` section (read as git reads it: any key case, quoted
    values, trailing comments);
  - an empty `--root ""` (an unset variable) is a usage error (exit `2`), not
    root discovery;
  - a file over its read cap is staged as a stand-in of the cap plus one byte
    and never copied, so a name-only check still sees it: a served database
    over 16MB now blocks, as in the full audit;
  - the `not_scanned` reason names the scanner's own cause (`extension outside
    the scan set`, `minified or bundled artefact`, `ignored or pruned path
    (<dir>/)`, `exceeds the scanner's read size cap (not copied)`); a file a
    skill reads by name (`.env.*`, a key file) over the cap gives only the cap;
  - text output, the stderr notes and argparse's usage errors escape control
    and format characters (every bidi control, zero-width marks), line
    separators and undecodable characters;
  - a stdout closed at startup exits `2` before anything is scanned; stderr is
    advisory, so a stderr that cannot be written changes neither the exit code
    nor the stdout report;
  - once a signal has started the cleanup, a second SIGTERM, SIGHUP or Ctrl-C
    no longer interrupts the removal of the temporary copy, and a signal the
    caller ignores (`nohup`) stays ignored.
- **Feature 0096 — OWASP Top 10 categories are labels, not duplicate
  findings.** The OWASP agent no longer re-emits each CWE finding as a second
  `agent_type = owasp` row with its own lineage and `VLT-` ref. It returns its
  edition's CWE→category table (mapping v1), and the backend labels the final,
  deduplicated CWE-categorised findings of every scan agent. A weakness is now
  persisted, counted and triaged once. What changes for consumers, for audits
  run after the upgrade:
  - **Agent protocol**: the backend asks for a mapping with `accepts_mapping: 1`,
    a top-level field of the OWASP agent's `/run` body. It is never a config
    key: an older backend forwards user config to agents, so the agent ignores
    `config.accepts_mapping` and the backend strips it from every agent's
    config. The presence of a `mapping` member on the result marks mapping mode
    for the rest of the run; such a result persists none of its rows. See
    [docs/architecture/agent_protocol.md](docs/architecture/agent_protocol.md).
  - **REST** (`GET /api/audits/{id}`) and **CLI JSON** output no longer contain
    `agent_type = owasp` rows. Findings gain `compliance_labels`:
    `[{framework, edition, category_id, category_name, cwe}]`, where `cwe`
    names the CWE the label came from (a dedup survivor keeps the categories of
    the rows it absorbed; `CWE-089` is read as `CWE-89`). Lineage rows gain
    `compliance_labels` keyed `framework:edition` (e.g. `owasp:2025`). The CLI
    human summary adds per-category counts under an "OWASP Top 10:<edition>"
    heading.
  - **Counts drop by the removed copies.** The webhook payload is unchanged in
    shape, but its `findings_count` no longer includes OWASP copies; audit
    totals, severity counts and `vulture scan --exit-on` count each weakness
    once. On an OWASP audit the copies can be close to half of all rows.
    `--exit-on` now prints `Exit 1: <n> finding(s) at or above <severity>
    (--exit-on)` to stderr when it fails the build.
  - **Comparison**: `GET /api/audits/{id}/comparison` leaves the older audit's
    OWASP copy rows out of the diff when the newer audit is in mapping mode, and
    reports them as `excluded_legacy_copies`; the finding counts reconcile with
    the classification (previous = persistent + changed + fixed, current =
    persistent + changed + new).
  - **MCP**: `vulture_get_findings` and `vulture_search_findings` gain
    `framework`, `category` and `edition` filters (`framework="owasp"`,
    `category="A07"`). `agent_type` stays a literal agent filter, so
    `agent_type="owasp"` matches only audits run before this change. With
    `framework`, older OWASP rows match too, carrying one label marked
    `"legacy": true`.
  - **Target aggregate**: `GET /api/targets/{key}/aggregate` accepts
    `framework=owasp&category=A07&edition=2025`; the three go together, and a
    partial or malformed filter is rejected with 400. Every response carries
    `label_editions`, the editions and categories the target's lineage rows
    carry, which the target report offers as its filter. The filter returns
    only lineage rows that carry labels, and no row has any at upgrade (see
    Upgrade below), so an empty answer right after the upgrade does not mean
    "no OWASP findings".
  - **Coverage**: the `owasp_coverage` persisted on the audit (GET
    `/api/audits/{id}`, and the replay once the broadcast TTL has passed) is
    authoritative. It keeps the agent's `mapped_count`; `found_cwes` /
    `found_count` / `status` and `unmapped_cwes` / `unmapped_count` are
    recomputed from the persisted findings, so a CWE whose only finding was
    deduplicated away is no longer reported as found. Under a `categories`
    subset, each unselected category reports 0 found and carries
    `"selected": false`: not checked, not clean. If the backend rejects the
    mapping, or the manifest is for another edition, the found and unmapped
    values are cleared; an unreadable manifest is not stored. Only the OWASP
    agent's result can supply it. The copy on the streamed OWASP `result`
    event is provisional: the agent's own manifest, counted before dedup over
    every category, with no `selected` key. SSE consumers should re-read the
    audit once it is terminal.
  - **Coverage ignores false positives**: the served `owasp_coverage` leaves
    out findings whose own lineage row is marked `false_positive`, so a
    category found only through them reads `clean-or-undetected`, and an
    unmapped CWE is dropped once all its findings are marked. Each category
    gains `false_positive_count`. `accepted_risk` and `resolved` still count.
    It is worked out each time the audit is read and the stored manifest is
    not changed, so clearing the mark restores the count; audits run before
    labels, and reads where lineage or the findings cannot be loaded, are
    served as stored. The results page shows the count on each
    category and refreshes the card after a status change.
  - **Results page**: an OWASP chip per label and an OWASP category filter; a
    coverage category filters the table when some finding carries its label.
    Labels appear live during a run on provisional, pre-dedup rows that the
    persisted rows replace at the end. Audits run before the change still list
    their OWASP rows, but after the upgrade those rows show no VLT ref or triage
    status: migration 031 folded their lineage into the twin finding's row, or
    retired it. Use the twin's ref and timeline for their history.
  - **Audit cache**: a cached audit that still holds OWASP copy rows is a miss,
    so the request runs fresh instead of replaying the old shape. With an
    upgraded agent the fresh run produces labels.
  - **Plugins**: `matches_check_id_prefix` entries starting `owasp.` match only
    OWASP copy rows, which only an older OWASP agent still produces. Match the
    CWE ids with `matches_cwe` instead.
  - **Upgrade**: at first start, migration 031 (SQLite: a one-shot step) folds
    existing OWASP lineage rows into the lineage row of the finding each was
    copied from, with a `merged` event on both; rows with no twin are retired.
    Twins keep their status, notes and ticket. If a triaged OWASP row disagrees
    with its twin the migration aborts, naming every disagreeing pair, and the
    backend does not start until each pair's statuses match. To recover, start
    the previous release against the same database (it ignores the
    `compliance_labels` columns, the only change left behind), set the statuses
    through the UI or `PATCH /api/lineage/{id}` (the twin's, to keep the OWASP
    row's decision; the OWASP row's, to drop it), then start the new release
    again. To avoid the stop, check before upgrading for triaged
    (`false_positive`, `accepted_risk`, `resolved`) OWASP lineage rows whose
    twin (same target, same file, same title without the `[Axx] ` prefix) has a
    different status. Existing lineage rows get no OWASP labels: the new column
    starts empty, and the fold does not move a folded row's category onto its
    twin. A row gains labels only when an OWASP-enabled scan with an upgraded
    agent sights it again, so run one per target to populate the aggregate's
    `framework` filter; a row that is never sighted again (a fixed finding,
    say) stays unlabelled.
  - **Version skew**: an older backend with a newer agent keeps the previous
    copy-row behaviour (the agent's copy mode is retained for one release). A
    newer backend with an older agent still gets copy rows; they are persisted
    as findings but create, update and close no lineage rows, since the OWASP
    agent no longer owns lineage in any mode. Such audits carry no labels, count
    the copies, and are never served from the cache. Upgrade the OWASP agent
    together with the backend. See
    [docs/guides/owasp_agent.md](docs/guides/owasp_agent.md).
- **Removed a hardcoded admin backdoor password** that shipped in early
  commits (rejected by hash at startup; the literal was purged from git
  history in the 0036 Phase 4 release scrub). The seeded local
  dev user (`admin@vulture.local`) now uses
  `$VULTURE_LOCAL_DEV_PASSWORD` if set, or a CSPRNG-generated 16-byte
  hex password logged once at backend startup. The `/api/auth/local-session`
  endpoint uses a new password-less `IssueLocalAdminToken` helper.
- Unified all repo-URL references to `github.com/bobinson/vulture`.
- **Native install (Mode E) now auto-detects a system Python for agents.**
  `VULTURE_USE_SYSTEM_PYTHON` became a tri-state: **unset = AUTO** (the new
  default — when a hashed agent lockfile ships and a host Python ≥ 3.12 is
  present, the installer provisions the agent venv automatically so agents +
  skills run via `vulture start` out of the box); `1` = REQUIRE (loud-fail if
  either is absent); `0` = DISABLE (force CLI-only). `--require-hashes`
  dependency verification and the `>=3.12` gate stay enforced on every install
  path; a hashless lockfile under AUTO warns and degrades to CLI-only rather
  than aborting. See
  [docs/features/0055_native_installer_hardening](docs/features/0055_native_installer_hardening/).
- **Honest install messaging.** Rewrote the CLI-only note (removed the false
  "CLI + skills still work" — skills run inside the agents): it now states that
  agent/LLM scanning needs a local Python ≥ 3.12 or Docker, while the CLI and
  web UI are installed and work. The post-install summary and quickstart adapt
  to whether agents were actually installed.

### Removed

- **The Semgrep Registry tier of the bundled plugin (feature 0102):** the `p/security-audit` default, the
  `r/solidity` Solidity namespace with its `VULTURE_SEMGREP_DISABLE_SOLIDITY_REGISTRY` switch, the
  `SEMGREP_APP_TOKEN` / `--pro` path, `rules/rule_to_cwe.json` (Registry rule IDs; CWE now comes from each
  rule's own metadata) and the plugin's `VULTURE_SEMGREP_AUDIT_ROOT` / `VULTURE_SEMGREP_VENDORED_RULES`
  test hooks.

- **The `next_middleware_matcher` CWE skill and category (feature 0097).** Its
  Next.js matcher-bypass detection is one instance of the access_control
  route-matcher arm and is reported as
  `check_id: cwe.access_control.guard_excluded_by_request_attr` (CWE-807). A
  consumer filtering on the `next_middleware_matcher` category or on
  `cwe.next_middleware_matcher.bypass` must filter on that check id instead.

### Fixed

- **The bundled plugin's image is built on your machine and never published.** The briefly published
  `ghcr.io/bobinson/vulture-plugin-semgrep` images were built on Semgrep's own image, which carries
  Semgrep's engines, one of them proprietary; the package is deleted. The manifest names a local image
  (`vulture-plugin-opengrep:0.2.0`), and the backend never pulls a bundled plugin that ships a
  Dockerfile: it uses the local image or builds it from that Dockerfile. The native-install tarball now
  ships the plugin's build context (Dockerfile, `requirements.txt`, `pyproject.toml`, `src/`, bundled
  rules), never an image. The build runs the engine once (`opengrep --version`), so an image whose engine
  cannot start fails to build: unpinned, fastapi 0.162 had lifted `opentelemetry-api` past the Semgrep
  base's exporters and the 0.1.1 image's engine could not start while `/health` still answered.
- **Host-network plugins are reachable on macOS.** Docker on macOS runs in a Linux VM, so a plugin on
  `--network host` (the bundled semgrep plugin) listened on the VM's localhost while the backend dialled the
  Mac's, and `vulture.sh dev` started a plugin it could never reach. When the backend runs on darwin, a
  host-network plugin now runs on the default bridge with its port published on loopback only
  (`-p 127.0.0.1:<port>:<port>`), which keeps it off every other interface. Derived from the backend's OS, so
  there is no new setting; Linux keeps host networking unchanged, and the `host-network` trust ack is still
  required.
- **CWE-799 (`anonymous_message_send`): two false-positive classes (feature 0074).** A handler that
  verifies a shared secret against the REQUEST (an event trigger's or webhook's secret or hook token, e.g.
  `if (!requireValidHookSecret(req, res)) return;`, or a verification bound to a name a later branch exits on)
  is now treated as authenticated, as a signature check already was. Only a check OF the secret, given the
  request itself, counts: validating a submitted value (a secret-sharing or password-policy check, a body-bound
  DTO, `validateSecretMessage(req)`), a logged result, a verification after the send and an anti-forgery
  secret still gate nothing. A parameter whose type is a query RESULT — a compound `...Query` type that is
  indexed into (a generated GraphQL result), followed by `Result` / `Row`, or declared by a helper its own file
  calls without passing request input in that argument position — is no longer read as HTTP query input; an
  entry point's `...Query` parameter, query bindings and every parameter name still are. Measured on one
  evaluation target: 13 rows to 6, the 7 removed all false positives; no change on 20 other local trees, and
  no row lost on the 51 true-positive probe rows two adversarial review passes wrote.
- **CWE-778 (`cwe.insufficient_logging.*`) reports security-relevant failures, not every quiet handler
  (feature 0101).** The rule reported any `catch`/`except` that did not log. A non-empty handler is now excused
  when it hands the error on (returns it, stores it in a field or a name that outlives the try, collects or
  reports it, or passes it to a callback parameter of its routine) AND the operation it guards is not
  security-relevant. The guarded text runs from the try body up to the routine declaration and includes the
  exception type; it is matched against one security vocabulary of word roots (auth, session, token, crypt,
  signature, permission, …), which the opt-in `SECURITY_SCOPE` arm now shares. An unresolved try, an empty body,
  a conversion to a value without the error, a failure flag and a negating verb (`ignoreFailures()`) are never
  excused. `auth_decision` no longer fires on a keyword that NAMES an outcome (`export const UNAUTHORIZED = 401`,
  enum members, a literal `when` mapping, a regex alternation, a bare `case` label); `promise_swallow` excuses a
  teardown as the last call of a non-security chain, or a null-guarded fallback. Measured on the two
  adjudicated real targets at their adjudicated commits: 246 to 152 rows (false positives 211 to 117) and 82 to
  56 (70 to 45), with every adjudicated true positive kept; the self-scan 485 to 466. The aggregate row's
  `metric_version` is `0101.1`.
- **CWE-770 (`cwe.resource.unbounded_alloc`) reports input-driven, uncapped accumulation (feature 0101).** The
  rule reported a Python `.append` inside any loop; 86% of its self-scan rows were appends inside a loop over a
  finite in-memory collection. A row now needs a growing receiver (any language: growth verbs, self-growth
  operators, writes to an in-memory buffer), a lifetime beyond one iteration, a driver (a loop fed by a socket,
  stream, request, queue, stdin or a child process's output, or an input-event callback such as
  `req.on('data', …)`), and no cap on that receiver (a size comparison that exits or trims, a bounding guard, a
  bounded container, or a cap wrapper such as `islice`/`io.LimitReader` on the source). An unbound iteration
  source is classified by the last word of its name, a stated heuristic. `SIZE_LIMIT` now applies to the Go
  `make([]T, 0)` arm only, over code with comments stripped. Scope and known gaps are listed in the CWE agent's
  `SKILLS.md`. Measured: self-scan 343 rows to 5 (all 18 adjudicated false positives removed; 3 of the 5 are the
  unchanged Go arm); a large public multi-language codebase 9 to 25, every row reviewed (the 9 removed iterate
  in-memory data; the 25 accumulate a network stream, a partial line from a peer, a child process's output or
  stdin, with no cap).
- **CWE-209 (`cwe.info_exposure.error_disclosure`) reports the error value reaching a peer (feature 0101).**
  The Node pattern matched any identifier whose NAME started with `err`/`error`/`ex`, so a catalogue helper
  (`errorEnvelope(Catalog.X)`) or an `{ error: err.code }` field was reported. The rule now resolves which value
  reaches a response write: a caught error's message, stack, string form or raw object (through any call that
  does not project it, and back through assignments, destructuring and parameters in the routine) is reported;
  a code/status/name projection, a catalogue constant or a projection helper is not. Non-peer writes (stderr,
  files, loggers, builders, mail, queues), sinks inside comments or strings, and prose files are skipped. CWE-550
  still replaces 209 on its line. Measured on one adjudicated real target at its adjudicated commit: 100 rows to
  13, false positives 86 to 1. Seven of its file-level true-positive rows are no longer reported on the carrier
  line they were filed against; in five of the six files the leak line their verdict cites is itself reported,
  and the sixth cites a result-object `.error` field, which is deliberately not treated as raw error text. On
  the second adjudicated target (2 rows to 5) its one true-positive row is likewise not reported on its filed
  line, while the leak lines its verdict cites are. A public reference application goes from 9 rows to 13; the
  4 new rows are genuine.
- **Consequences of the three CWE rule changes above (feature 0101).** No `check_id`, category, severity, finding
  field or environment variable changed. Under `VULTURE_LINEAGE_FIX_MODE=evidence` (the default) a deterministic
  row closes as FIXED when a scan no longer reports it, so the first scan of an existing target after upgrading
  marks the removed rows fixed; rows triaged `false_positive` keep that status. With `VULTURE_LLM_TIER3` off
  (the default) the LLM sweep covers files a skill finding flags, so files flagged only by these rules leave
  the sweep: on the latest archived scans, 96 of 307 CWE-flagged files of the self-scan and 56 of 179 of one
  real target. The CWE GENERATE prompt's CWE-778/770/209 definitions now state the same concepts, so the model
  does not re-emit the removed class (`generate/cwe` manifest version 7).

- **Plugin audits no longer fail with "requested agents did not run" because the staging root is root-owned.**
  The plugin staging root (`VULTURE_SUPERVISOR_AUDITS_DIR`, default `/tmp/vulture-audit-inputs`) is a bind-mount
  source for plugin containers, and Docker creates a missing mount source as root. A non-root dev backend could
  then never stage into it, so every plugin (e.g. semgrep) was skipped with `mkdir …: permission denied`. In local
  mode the backend now creates the root itself, as its own user, before the supervisor starts any container, and
  logs a clear startup message naming the directory and the remedy when an existing root is not writable.

- **"Copy All as Issues" copies what the table shows.** The export now follows
  every active filter — hidden false positives, severity, agent, tier, OWASP
  category, hidden suspicious — across all pages and in table order, instead of
  the audit's unfiltered finding list. The button shows how many findings it
  will copy.
- **Install-mode UI/URL reporting.** Added a `localdev.UIPort` helper so the
  CLI reports the correct UI address — in install mode the backend serves both
  the API and the embedded SPA on one port (the phantom `23000` is gone).
  `vulture start`, `vulture scan` ("View results"), `vulture status`, and the
  launcher banner now print the backend port as the UI, with no bogus separate
  "frontend" row/line in install mode and an Agents line only when agents are
  actually started.
- **`vulture scan` agent-health guard.** Before relying on results, `scan` now
  probes each configured agent `/health`; if none are reachable it prints a
  loud, actionable warning (the scan will produce no findings — install Python
  3.12+ and reinstall, or use Docker) and continues, so submissions to a
  remote/centralized server still work.
- **`vulture doctor`.** In install mode a missing bundled-Python path is now a
  WARN (exit 2), not a hard FAIL — a CLI-only install is a documented-valid
  state; the fix hint points to installing Python 3.12+ or using Docker.

### Security

Seven fixes ship together in this release (feature 0102). Three are security
advisories, whose identifiers are added here when the advisories are published;
the other four are hardening. Only the latest release receives security fixes
([SECURITY.md](SECURITY.md)), so the remediation for every entry is to upgrade.
Several defaults now refuse what an earlier release allowed: read the upgrade
notes before upgrading a centralized (Mode B or C) server or a `docker compose`
stack, which runs centralized with its shipped defaults (`VULTURE_LOCAL_MODE=false`).

- **Plugin `/run` accepted unauthenticated requests, and every plugin received the
  shared agent token (CWE-306, CWE-862).**
  - **Advisory:** GHSA pending.
  - **Affected:** v0.0.1 through v0.0.21, wherever a container plugin runs: the
    bundled semgrep plugin 0.1.0 once enabled through `VULTURE_PLUGINS`, mainly on
    local and native installs (the stock compose backend image has no Docker CLI
    and starts no plugins). The plugin's `POST /run` answered any caller that could
    reach its port. On Linux the plugin uses host networking, so any local process,
    or a web page open in a local browser through DNS rebinding, could run Semgrep
    over the audit inputs staged at that moment and read the findings; in v0.0.1
    through v0.0.11 the plugin listened on every interface, not only loopback.
    Separately, the backend sent its shared `VULTURE_AGENT_TOKEN` to every `/run`
    target, plugins included, so code running in any plugin container held the
    token that opens the in-tree agents' `/run`, which can scan any path the agents
    can read.
  - **Fix:** the shared token now goes only to the backend's own in-tree agents. Each
    plugin receives a token derived for it alone,
    `hex(HMAC-SHA256(key, "vulture-plugin-run-token/v1:<name>"))`, where the key is
    the shared token or, when none is configured, a random key drawn at each start.
    A plugin that reuses an in-tree agent's name or claims the in-tree tier gets a
    derived token too. The token reaches the container through its environment,
    never a command line, and the Docker CLI that starts plugins no longer inherits
    backend credentials or dynamic-linker and interpreter injection variables. The
    semgrep plugin 0.1.1 requires the token on `/run` (403 without it), refuses a
    non-loopback `Host` on a loopback connection (403), answers 415 to a body not
    declared as JSON and 400 to invalid JSON. The in-tree agents compare their token
    over bytes, so a malformed header is a 403, never a 500. The plugin contract
    documents the rules; checking the token is a SHOULD for a plugin, so
    `api_version` (1.0), the manifest schema and the conformance checks are
    unchanged.
  - **Upgrade notes:** the bundled plugin is now `opengrep` 0.2.0 (see Changed), whose
    image the backend builds on your machine as `vulture-plugin-opengrep:0.2.0`; the
    backend no longer starts the `semgrep` plugin. Enable it as `opengrep`
    (`VULTURE_PLUGINS=opengrep`, `--plugins opengrep`, or the UI): a list still naming
    `semgrep` matches nothing and the backend's warning names the rename, and a
    `semgrep` enablement stored in `state.toml` does not carry over. This plugin's
    findings get new fingerprints (they include the agent type), so its lineage
    restarts once. A plugin started by hand behind a backend with a shared token
    needs the derived value (the contract shows how to compute it); with no token
    set, its `/run` is open and logs a warning. A third-party plugin should check
    `X-Vulture-Agent-Token` against its own `VULTURE_AGENT_TOKEN`, and one that used
    the token to call in-tree agents is now refused. In local mode a Linux
    host-network plugin still shares the machine's loopback and has the trust of a
    local process; the plugin contract's `host-network` acknowledgement row says so.
    A `docker compose` stack takes the in-tree agents' shared code from the
    `vulture-agent-base` image, which `docker compose up --build` does not rebuild:
    to pick up the new token comparison, rebuild it first:
    `docker build -t vulture-agent-base:latest -f agents/Dockerfile.base agents/`.

- **Local-path source ingest revealed which server paths exist, and a symlink
  spelling escaped the source root (CWE-22, CWE-203, CWE-59).**
  - **Advisory:** GHSA pending.
  - **Affected:** v0.0.1 through v0.0.21 in centralized mode. `POST /api/sources`
    with `type=local` examined the requested path before applying the local-path
    policy, so a principal allowed to create sources learned whether any server path
    existed and whether it was a readable directory, even where local ingest was
    refused. In v0.0.15 through v0.0.21, with `VULTURE_SOURCE_ROOT` set, a path that
    used `..` after a symlink inside the root could be accepted although it resolved
    outside the root, and the server then scanned that directory. Stored local
    sources were never re-checked when an audit ran. Releases before v0.0.15 did not
    confine local ingest in centralized mode at all.
  - **Fix:** one local-path policy now governs ingest, the folder browser and the
    dispatch of every audit. In centralized mode without a root, ingest is refused
    before the path is looked at (400 `local paths are disabled on this server: …`).
    With a root, a path must be absolute, contain no `..`, be at most 4096 bytes and
    be spelled under the root; it is then resolved and confined, and every path that
    is outside, missing, unreadable or unresolvable gets the same 400
    `path not permitted: must be an existing directory inside the source root`.
    Only a path inside the root gets an error that names it. Resolving a very long
    path no longer costs quadratic time.
  - **Upgrade notes:** every audit now re-checks its stored local source against the
    policy before any agent runs. An audit of a source the policy refuses fails with
    `source refused by the local-path policy`, and nothing is scanned. Such sources
    exist when a database used in local mode is served centralized, when the root is
    narrowed, or when a source was stored through a spelling an earlier release
    accepted. Before upgrading, list them with the query in
    [docs/guides/central_server_deployment.md](docs/guides/central_server_deployment.md),
    "Stored local sources" (SQLite and Postgres, with a dry-run script for what the
    query cannot see), and re-ingest them under their canonical path. In centralized
    mode `VULTURE_SOURCE_ROOT` is required for local ingest (as since v0.0.15), and
    now also for the folder browser and for audits of stored local sources; a
    read-only server refuses all three whatever its value. Point the root at a
    dedicated directory. A path spelled through an outside symlink that points into
    the root is refused: submit the canonical path. The backend now opens the root
    to confine a path, so its user needs read and search permission on the root, not
    only search: a root it can only traverse, which earlier releases accepted, is
    refused. A root it cannot use (missing or unmounted, not a directory, or not
    openable) is the server's fault, not the caller's: local ingest and the folder
    browser answer 500, an audit of a stored local source fails with
    `source root unavailable` before any agent runs, and a root that is already
    unusable at startup is named, by its setting, in an ERROR log line
    (`source_root_unavailable`).

- **The folder browser listed server directories to any signed-in user in
  centralized mode (CWE-22, CWE-548).**
  - **Advisory:** GHSA pending.
  - **Affected:** v0.0.1 through v0.0.21. In centralized mode with
    `VULTURE_SOURCE_ROOT` unset, `GET /api/filesystem/browse` listed the names and
    sizes of entries in any directory the backend could read outside a small system
    denylist, to any authenticated principal, viewers and API keys included, and on
    a read-only (Mode C) viewer. That covered the temporary clones of other users'
    private git sources. With a root set, viewers and API keys could still browse
    inside it.
  - **Fix:** browse follows the local-path policy above. It is refused (403) in
    centralized mode without a root, and on a read-only server whatever the root.
    With a root, it is confined to it, and every outside path gets the same refusal
    (`access denied: path outside source root`), including one that resolves into a
    denylisted tree. Browse requires a member or admin; viewers and API keys get 403
    `requires member or admin role`. Local mode is unchanged.
  - **Upgrade notes:** a centralized server, or a `docker compose` stack with its
    shipped defaults, that used the folder browser without `VULTURE_SOURCE_ROOT` now
    gets a 403 there; set the root to a dedicated directory. Do not place it under a
    denylisted tree (`/var`, `/usr`, `/etc`, …), which browse refuses even inside the
    root, nor at the checkout (it holds `.env`) or the clone temp directory. Under
    `docker compose` the backend sees host files only at `/mnt/source`, the mount of
    `VULTURE_SOURCE_DIR` (by default the checkout): set
    `VULTURE_SOURCE_ROOT=/mnt/source` and point `VULTURE_SOURCE_DIR` at a dedicated
    host directory, since a host path as the root refuses every path.

- **Browser sessions moved out of `localStorage` into an HttpOnly cookie
  (CWE-922).**
  - **Advisory:** none (hardening).
  - **Affected:** v0.0.1 through v0.0.21. The web UI kept its 24-hour session JWT
    in `localStorage`, where any script running in the page could read it and use
    it from anywhere; the Settings page also saved the API key typed there.
  - **Fix:** a sign-in that sends `X-Vulture-CSRF: 1` receives an HttpOnly,
    SameSite=Strict cookie (`__Host-vulture_session` with `Secure` over HTTPS,
    `vulture_session` over plain HTTP) and no token in the body. The UI stores no
    credential (it deletes the old `vulture_token` key, and strips a saved API key
    from its settings, on load) and sends `X-Vulture-CSRF: 1` on every request; a
    cookie-authenticated unsafe request without that header is refused (403). The
    cookie is ignored on a request whose `Sec-Fetch-Site` is `same-site` or
    `cross-site`, and `X-Vulture-CSRF` is not an allowed CORS header. New
    `POST /api/auth/logout` deletes the cookie (204); the JWT itself is not revoked
    and expires with the session. `/api/api-keys` and `/api/admin/users` accept only
    a Bearer credential, so a browser session cannot mint an API key or an account.
    `GET /api/auth/me` answers 401 unless the request presented a credential, which
    changes only local mode's implicit user. Bearer clients (CLI, CI, scripts) are
    unaffected: a sign-in without the header returns the token in the body as before.
    This stops a script from carrying the session off the machine; it does not stop
    a script injected into the page from using the session while the page is open.
  - **Upgrade notes:** reload open browser tabs after upgrading. A tab loaded
    before the upgrade may be refused with
    `cookie-authenticated requests must send X-Vulture-CSRF; reload the page`, and
    users sign in once more (local mode signs in again by itself). Behind a TLS
    proxy, forward `X-Forwarded-Proto`, or the cookie is issued without `Secure`.
    Serve Vulture on a hostname no other service uses, on any port: cookies are not
    isolated by port. Cookies are host-only, so users sign in separately on a
    read-only viewer's hostname. Browser sessions are same-origin only: a UI build
    whose `VITE_API_URL` names another origin is unsupported, and every API request
    from it now fails the CORS preflight; the dev proxy, the nginx `/api/` route
    and the embedded UI are all same-origin. The rate limits on `/api/audits` and
    `/api/findings/` now key on the authenticated principal instead of the
    `Authorization` header, so all sessions and tokens of one user share one bucket.

- **The SSH host-key store left the shared temp directory (CWE-379, CWE-252).**
  - **Advisory:** none (hardening).
  - **Affected:** v0.0.15 through v0.0.21. Key-based git clones pinned host keys
    in `/tmp/vulture-ssh/known_hosts`, which another local account could create or
    pre-seed first, and a failure to create the directory was ignored, in which
    case host keys were never pinned. Releases before v0.0.15 did not verify SSH
    host keys at all.
  - **Fix:** the default store is `<directory of VULTURE_DB_PATH>/ssh/known_hosts`
    (`/data/ssh/known_hosts` in the container, also when the database is Postgres).
    Before every key clone, and before the private key is written, the backend
    checks that the `ssh` directory is a real directory it owns (one open to group or
    others is tightened to `0700`), that the data directory is not
    world-writable without the sticky bit, that `known_hosts` is absent or a
    single-link regular file it owns, and that the path holds no character ssh would
    interpret. Anything else fails the clone closed with a 500; the backend log line
    for its request id names the cause and the remedy. A file named by
    `VULTURE_GIT_SSH_KNOWN_HOSTS` is used as given, unchecked.
  - **Upgrade notes:** pins kept in `/tmp/vulture-ssh/known_hosts` are not imported,
    so under the default `accept-new` each git host is accepted once more on its
    first key clone. With `VULTURE_GIT_SSH_STRICT=yes`, which the backend also forces
    when the installed OpenSSH is older than 7.6, every key clone fails until the new
    store is seeded with each git host's key: follow "Seeding the store" in
    [docs/guides/central_server_deployment.md](docs/guides/central_server_deployment.md),
    "SSH host-key store". In the container `/data` is not a volume, so the store
    starts empty whenever the backend container is recreated; to keep pins, or on a
    container with an arbitrary UID or a read-only filesystem, mount an
    operator-managed file and set `VULTURE_GIT_SSH_KNOWN_HOSTS` to it. The store
    no longer follows `VULTURE_DATA_DIR`: an install that set it, and so kept its
    pins in `$VULTURE_DATA_DIR/ssh/known_hosts`, now uses the directory of
    `VULTURE_DB_PATH` (the same file only when the two directories agree); set
    `VULTURE_GIT_SSH_KNOWN_HOSTS` to the old file to keep its pins.

- **Internal error text no longer reaches API responses (CWE-209).**
  - **Advisory:** none (hardening).
  - **Affected:** v0.0.1 through v0.0.21. 500 responses, and some 400 and 409
    responses, echoed internal error chains: database engine and query fragments,
    server paths, git output, and the resolved addresses of refused git and webhook
    hosts.
  - **Fix:** every 500 body is `{"error":"internal error","request_id":"<id>"}`,
    and the cause is logged once (`http_internal_error`) under that id. A 4xx body
    no longer echoes an internal error chain: it carries caller input or a fixed
    message. A refused git or webhook host and a failed clone get fixed 400
    messages that read the same for an internal host as for one that does not
    resolve (`clone: git host is not permitted or cannot be
    resolved`, `invalid webhook_url: host is not permitted or cannot be resolved`,
    `clone: git clone failed: the repository is unreachable or the credentials were
    rejected`), with the `request_id` as well. The id is also the `X-Request-ID`
    response header; a client's own `X-Request-ID` is adopted only when it is 1-64
    characters of `A-Z a-z 0-9 . _ -`.
  - **Upgrade notes:** a client that read the cause from an error body now gets the
    generic text; to trace one, grep the backend log for its `request_id` (see
    "Tracing an error to its cause" in
    [docs/guides/central_server_deployment.md](docs/guides/central_server_deployment.md)).
    Some statuses change class. An invalid `webhook_url` on `POST /api/audits` is
    a 400 (was 500). A server-side fault while ingesting a source
    (`POST /api/sources`: the database, the work directory, the SSH key or
    host-key store, or a git clone that could not start git or was stopped because
    the request was cancelled or ran past the 10-minute ingest limit) is a 500 with
    a `request_id` (was 400); a clone that git itself fails keeps its fixed 400.
    On register and on an
    admin's account creation, only a duplicate email is a 409; a failure to store
    the account is a 500 (was 409). The CLI reports any 4xx or 5xx as an error, as
    before; only the status it prints changes.

- **Release pipeline: least privilege and a real CVE gate (CWE-829).**
  - **Advisory:** none (hardening). No compromised release is known.
  - **Affected:** the release workflow that built v0.0.1 through v0.0.21. It piped
    Trivy's install script, fetched without a checksum, into a shell inside a
    workflow whose every job held the signing (OIDC) token and write permissions;
    ran an unpinned `npx audit-ci` after building the web UI and before uploading
    it for embedding in the signed binary; and persisted checkout credentials. Its
    Trivy step scanned the compressed tarballs, which Trivy does not look inside, so
    the `*.vulns.json` reports attached to those releases inspected nothing.
  - **Fix:** Trivy is installed by `scripts/install-trivy.sh` from the upstream
    release tarball, verified against a committed SHA-256. The workflow grants
    nothing by default and each job declares its own permissions: the OIDC token
    exists only in `sign`, which checks out no code and signs only bytes whose
    digests the build legs recorded; write access exists only in `release`; no
    checkout keeps its credentials; the unused `attestations: write` is gone.
    `audit-ci` and `pip-audit` are pinned, and `audit-ci` runs in the read-only
    `scan` job, after the web UI is embedded and its digest recorded. Every
    third-party action in every workflow is pinned to a commit SHA. The `scan` job
    first runs a blocking CVE gate (`scripts/release-cve-gate.sh`): Trivy, run in
    the gate's own work directory with no inherited environment or configuration
    (so no file in the checkout but the dated waivers applies), scans each
    extracted tarball for HIGH and CRITICAL vulnerabilities and secrets, plus each
    bundled wheel's own SBOM, and nothing is signed unless every tarball passes.
    `*.vulns.json` is now that gate's report.
  - **Release notes for maintainers:** a finding with no fix needs a dated waiver
    in `.trivyignore`, one `<ID> exp:YYYY-MM-DD # <reason>` line, at most 90 days
    ahead, approved by the security code owner; CI and the gate refuse any other
    shape, and Trivy stops honouring an entry on its date, which turns the gate red
    again. Waived findings are not listed in `*.vulns.json`, so read `.trivyignore`
    beside it. This release carries nine such waivers; the two for the darwin-only
    `cryptography` pin expire on 2026-11-21, so a tag after 2026-11-20 needs them
    renewed or the pin replaced. A tarball without the bundled Python runtime now
    fails the gate. Dry-run the gate before every tag ("Dry-run the release CVE
    gate" in [docs/guides/release_process.md](docs/guides/release_process.md)).

### Planned

- Mode-B (centralized server) hardening pass — see
  [docs/features/0036_public_release_hardening](docs/features/0036_public_release_hardening/)
  Phase 3 (or follow-up feature 0037).
- Frontend agent auto-discovery: replace hardcoded UI lists in
  `frontend/src/components/results/FindingsTable.tsx` with config
  derived from `GET /api/agents`.
- Continuous-integration gates: `actionlint`, `govulncheck`,
  `pip-audit`, `npm audit`.
- SBOM publication as a GitHub release artifact (gating released in
  feature 0044's `release.yml`; pending first tag-push to validate).

## [0.1.0] - 2026-06-05

> Date and tag pinned at release time. See feature 0036 Phase 4.

### Added

- Initial public release.
- Go backend (orchestrator, JWT/API-key auth, PostgreSQL/SQLite
  persistence, Server-Sent Events streaming).
- Ten Python audit agents:
  - `chaos_engineering` — retry, circuit-breaker, timeout, fallback,
    blast-radius patterns.
  - `owasp` — OWASP Top 10 (injection, auth, crypto, misconfig,
    access control, etc.).
  - `soc2` — SOC 2 CC6/CC7/CC8 clauses, configurable per-clause.
  - `cwe` — full CWE 4.19.1 catalog (1,400+ weakness types) with
    taxonomic rollup and `path_equivalence` skill.
  - `prove` — formal provenance/finding verification.
  - `xss` — cross-site scripting scanner.
  - `ssdf` — NIST SP 800-218 SSDF v1.1 practice groups.
  - `discover` — endpoint discovery and attack-surface mapping.
  - `do178c` — DO-178C avionics safety checks.
  - `asvs` — OWASP ASVS v5.0.0 (345 requirements across 17 chapters
    and 3 verification levels).
- React SPA frontend (Vite + Tailwind v4) with native EventSource
  SSE streaming and i18n support for `en`, `es`, `de`, `fr`, `ja`,
  `pt`.
- CLI binary (`vulture scan / login / list / watch`) for headless
  audit execution.
- Memory system with cross-audit intelligence via pgvector
  embeddings (OpenAI `text-embedding-3-small` or Ollama
  `nomic-embed-text`).
- Four documented deployment modes:
  - Mode A — developer laptop (`make docker-up`).
  - Mode B — centralized server.
  - Mode C — read-only viewer.
  - Mode D — CI client.
- Two-phase audit pipeline: deterministic skill-based pattern
  matching across the entire codebase, followed by optional
  LLM-driven deep analysis with automatic deduplication against
  prior findings.
- Configurable LLM provider via LiteLLM (OpenAI, Anthropic, Gemini,
  local models via Ollama / LM Studio / vLLM).

### Documented

- Apache-2.0 license throughout (repository, all 10 agent
  pyproject.toml manifests, frontend package.json).
- `NOTICE`, `THIRD_PARTY_LICENSES.md`, and per-data-directory
  `LICENSE.md` files for redistributed third-party content
  (MITRE CWE, OWASP ASVS, NIST SSDF).
- `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, PR
  template, bug-report and feature-request issue templates,
  security-advisory contact link.

[Unreleased]: https://github.com/bobinson/vulture/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bobinson/vulture/releases/tag/v0.1.0
