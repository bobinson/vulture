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

- **The CWE agent's GENERATE prompt states the computed coverage counts**
  (171 CWE-ID `category` literals across 24 dedicated skills, N=81
  corpus-verified) instead of the stale ~73 / N=10. These are prompt bytes for
  every model family: the `generate/cwe` manifest is at version 6, and a unit
  test pins the stated counts to the values the code computes.

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

- **The `next_middleware_matcher` CWE skill and category (feature 0097).** Its
  Next.js matcher-bypass detection is one instance of the access_control
  route-matcher arm and is reported as
  `check_id: cwe.access_control.guard_excluded_by_request_attr` (CWE-807). A
  consumer filtering on the `next_middleware_matcher` category or on
  `cwe.next_middleware_matcher.bypass` must filter on that check id instead.

### Fixed

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
