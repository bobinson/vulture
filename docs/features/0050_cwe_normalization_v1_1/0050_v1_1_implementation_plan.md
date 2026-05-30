# 0050 v1.1 — `mapping_file` External Loader (LLD + plan)

**Author**: tbd
**Status**: PLAN — cross-cutting review applied (11 findings; 3 BLOCKER, 5 MAJOR, 3 MINOR/NIT)
**Created**: 2026-05-29
**Depends on**: 0048 (registry parses `mapping_file` field), 0050 v1 (Layer + system base maps), 0052 (`internal/pathutil.RejectTraversal`), 0053 (bundled Semgrep plugin's `rules/rule_to_cwe.json` placeholder)
**Closes**: 0050's deferred residual; 0053's note that ~2000 Semgrep rules need this to be usable

## Review changelog (applied below)

| # | Sev | Axis | Finding | Resolution |
|---|---|---|---|---|
| 1 | BLOCKER | correctness | `strings.HasPrefix(cleaned, manifestDir)` traversal bypass via sibling dir (`/tmp/plug` matches `/tmp/plugin-evil`) | use `manifestDir + string(filepath.Separator)` as the prefix; also use `filepath.Rel` cross-check |
| 2 | BLOCKER | correctness | `os.ReadFile` + `io.LimitReader` are incompatible APIs | pinned: `os.ReadFile` then post-read `len(data) > 16 MiB` length check |
| 3 | BLOCKER | reliability | AC #9 all-or-nothing on 1 bad entry destroys 9999 valid ones | per-entry log-and-skip; aggregate count reported once |
| 4 | MAJOR | correctness | intermediate symlinks in `manifestDir` bypass `os.Lstat` on the final path | add `filepath.EvalSymlinks(cleaned)` step; reject if differs from cleaned |
| 5 | MAJOR | maintenance | `MaxNormalisationEntries` duplication via comment-only sync | export `pluginregistry.MaxNormalisationEntries`; loader imports it (the `internal/cwe → pluginregistry` import already exists, no cycle) |
| 6 | MAJOR | maintenance | `loadMappingFile` returns only `map`; tests can't distinguish failure modes | signature changes to `(entries map[string]string, err error)`; sentinel errors per failure class |
| 7 | MAJOR | community | `mapping_file = ""` and whitespace semantics undefined | empty / whitespace-only → no external file (no warning); `validateNormalizationBlock` may add a length cap in a follow-up |
| 8 | MAJOR | community | no documented Semgrep YAML → JSON conversion workflow | added "Plugin author workflow" section; v1 accepts only `{schema_version, entries}` JSON; conversion-script note |
| 9 | MINOR | DRY | LLD's cycle direction reversed; export of `cweRE` is fine | export `pluginregistry.CWERe`; loader imports + uses it |
| 10 | MINOR | correctness | redundant traversal checks not differentiated | clarified: `RejectTraversal` blocks `..`; prefix check is a belt-and-suspenders assertion on `filepath.Clean` output (catches non-`..` exotic paths) |
| 11 | NIT | reliability | `defer recover` requires named return | dropped; `encoding/json` doesn't panic on input — recovery not needed |

## Problem

0050 v1 reads `[normalization].rule_to_cwe` and `[normalization].prefix_to_cwe`
inline from each plugin's manifest TOML. 0048's
`maxNormalisationEntries = 10000` caps each map. For most plugins this
is plenty. Semgrep is the exception — the corpus is ~2000 rules and
the manifest would balloon to a megabyte if we inlined them.

The schema's `[normalization].mapping_file` field has existed since
0047 (referenced by manifest validation in 0048, ignored by Layer in
0050 v1). The 0053 bundled Semgrep plugin already ships a placeholder
`plugins/semgrep/rules/rule_to_cwe.json`:

```json
{ "schema_version": "1", "entries": {} }
```

0050 v1.1 wires the existing field to actually load that file.

## Goal

Load external `<plugin_dir>/<mapping_file>.json` at registry build
time; merge its entries into the per-plugin maps consumed by
`cwe.Layer.Normalize`. Inline TOML wins on conflict.

## Non-goals (deferred)

- **Hot reload** — same as 0048/0050 v1; restart picks up changes.
- **Multi-file mapping** — only one `mapping_file` per plugin. If a
  plugin needs both rule + prefix maps via file, it ships both
  inline OR uses one big file (entries can be either rule-exact or
  prefix; v1.1 treats every entry as exact-rule-id match; prefix
  entries still go in the manifest TOML's `prefix_to_cwe` block).
- **Remote fetching** — `mapping_file` must be a relative path to a
  local file in the plugin's own dir. No `https://…` URLs.
- **Per-language sub-files** (`mapping_file = "rules/*.json"`) — v1
  takes one filename, not a glob.
- **Schema versions beyond `"1"`** — unknown versions are rejected
  with a clear log line. v1.2 may add `"2"`.

## Design

### Resolution path

1. After 0050 v1's per-plugin map extraction (inline `rule_to_cwe` +
   `prefix_to_cwe`), the Layer constructor iterates the registry
   one more time looking for non-empty
   `strings.TrimSpace(Manifest.Normalization.MappingFile)`. Empty
   or whitespace-only → no external file (no warning; this is the
   normal default for plugins without external mappings).

2. For each such plugin, resolve the file path:
   - `Plugin.Path` is the absolute path to the plugin.toml (set by
     0048's loader; empty for virtual plugins).
   - Reject early if `Plugin.Path == ""` (virtual plugin — can't
     have a `mapping_file` because there's no on-disk manifest to
     be relative to).
   - `manifestDir := filepath.Dir(Plugin.Path)`.
   - **First-line traversal check (review #10)**: call
     `pathutil.RejectTraversal(rawMappingFile)`. This blocks any
     `..` segment in the raw input before path joining.
   - `cleaned := filepath.Clean(filepath.Join(manifestDir, rawMappingFile))`.

3. Containment check (BLOCKER #1 fix):
   - Use `manifestDir + string(filepath.Separator)` as the prefix —
     NOT bare `manifestDir`, which would let `/tmp/plug` match
     `/tmp/plugin-evil`:
     ```go
     prefix := manifestDir + string(filepath.Separator)
     if !strings.HasPrefix(cleaned, prefix) && cleaned != manifestDir {
         return errOutsideManifestDir
     }
     ```
   - Cross-check with `filepath.Rel(manifestDir, cleaned)`: the
     result must not be `..` or start with `.."+string(filepath.Separator)`.
     Both checks are belt-and-suspenders; either failing rejects.

4. Symlink-aware containment (MAJOR #4 fix):
   - `evaluated, err := filepath.EvalSymlinks(cleaned)` — resolves
     every symlink in the path (including intermediate dirs).
   - If `evaluated != cleaned`, reject with logged warning.
   - This catches both final-component symlinks AND intermediate-
     dir symlinks (e.g., `manifestDir/rules` itself being a symlink).
   - If `EvalSymlinks` errors (file doesn't exist), propagate as
     "missing file" — same behaviour as before.

5. Load + decode (BLOCKER #2 fix):
   - `data, err := os.ReadFile(evaluated)`. On error, return
     typed `ErrMappingFileMissing` (or `ErrMappingFileUnreadable`).
   - **Length check is post-read, not via `io.LimitReader`**: if
     `len(data) > maxMappingFileBytes` (16 MiB), reject with
     `ErrMappingFileTooLarge`.
   - JSON-decode into:
     ```go
     type mappingFile struct {
         SchemaVersion string            `json:"schema_version"`
         Entries       map[string]string `json:"entries"`
     }
     ```
   - Reject `SchemaVersion != "1"` with `ErrMappingFileSchemaVersion`.
   - Reject `len(entries) > pluginregistry.MaxNormalisationEntries`
     (MAJOR #5 fix: exported, not duplicated) with
     `ErrMappingFileTooManyEntries`.

6. Per-entry validation (BLOCKER #3 fix — was "all-or-nothing"):
   - For each `(rule_id, cwe)`:
     - If `cwe` matches `pluginregistry.CWERe` (MINOR #9 fix:
       exported), keep it.
     - Else log a single warning naming the bad rule_id; skip
       just that entry.
   - At end of file processing, log a summary line:
     `[cwe] loaded N/T external rule mappings for plugin <name> (S skipped)`
     where T = entries in file, N = valid kept, S = invalid skipped.

7. Merge:
   - For each `(rule_id, cwe)` in the kept entries, add to the
     plugin's `rule_to_cwe` map ONLY if not already present (inline
     wins; documented "manifest is authoritative" precedence).
   - The plugin's `prefix_to_cwe` is untouched — external file
     contributes only to `rule_to_cwe` (exact-rule-id matches).

### Public API impact

The Layer's `New(registry)` constructor signature is unchanged.
External-loading behaviour is automatic when a plugin's manifest
sets `mapping_file`. Tests can still use `NewFromMaps` to construct
a layer without any registry.

A new internal helper (MAJOR #6 fix — testable error path):

```go
// in backend/internal/cwe/

// Sentinel errors for mapping-file failure modes; tests use errors.Is.
var (
    ErrMappingFileVirtualPlugin   = errors.New("virtual plugin cannot have mapping_file")
    ErrMappingFileOutsideDir      = errors.New("mapping_file resolves outside plugin dir")
    ErrMappingFileSymlinkUnsafe   = errors.New("mapping_file contains symlink components")
    ErrMappingFileMissing         = errors.New("mapping_file not found")
    ErrMappingFileUnreadable      = errors.New("mapping_file unreadable")
    ErrMappingFileTooLarge        = errors.New("mapping_file exceeds 16 MiB")
    ErrMappingFileBadJSON         = errors.New("mapping_file malformed JSON")
    ErrMappingFileSchemaVersion   = errors.New("mapping_file schema_version unsupported")
    ErrMappingFileTooManyEntries  = errors.New("mapping_file exceeds entry cap")
)

// loadMappingFile resolves and decodes a plugin's external
// mapping_file. Returns the valid rule_to_cwe entries (per-entry
// invalid CWEs are skipped, NOT all-or-nothing). Returns an error
// for any file-level failure (missing, malformed, traversal, etc.).
// The Layer constructor logs the error and continues with inline-
// only entries for that plugin.
func loadMappingFile(plugin pluginregistry.Plugin) (map[string]string, error)
```

### File format

```json
{
  "schema_version": "1",
  "entries": {
    "python.django.security.unsafe-raw-sql": "CWE-89",
    "python.cryptography.fernet": "CWE-310",
    "javascript.express.audit.xss": "CWE-79"
  }
}
```

`entries` is `map[ruleID → CWE-NNN]` for exact-match lookup. Same
shape that 0053 already prepared via `rules/rule_to_cwe.json` placeholder.

### Logging

- `[cwe] loaded N external rule mappings for plugin <name>` — info
- `[cwe] skip mapping_file for <name>: <reason>` — warning, used for
  every failure mode (missing, malformed, schema mismatch, traversal,
  cardinality, symlink)

### Concurrency

External-file load happens once at Layer construction. Thereafter
the maps are read-only. No locking needed; same posture as v1.

## Threat model

| Threat | Mitigation |
|---|---|
| Path traversal via `mapping_file = "../../../etc/passwd"` | `pathutil.RejectTraversal` on the raw value + post-join prefix check against `manifestDir` |
| Symlink escape: file inside the dir is a symlink to /etc/* | `os.Lstat` + `ModeSymlink` reject (same as 0048 plugin.toml check) |
| 10 GB mapping file as DoS | `os.ReadFile` limited via `io.LimitReader` to 16 MB before json decode (cap chosen as 16× the inline manifest cap to allow ~10K-entry files with reasonable key/value sizes) |
| Malformed JSON | json.Decode error → logged warning + skip |
| Forge a non-CWE value: `"rule": "evil-payload"` | per-value validation via `cweRE` |
| Schema version drift | strict `"1"` match; unknown versions rejected |
| Cardinality | 10K entries cap (same as inline) |
| Virtual (in-tree) plugin claims mapping_file | Plugin.Path empty → skip with logged warning. No on-disk file to load. |

## Reliability + chaos engineering

| Failure mode | Behaviour |
|---|---|
| File missing | log warning, plugin loads without external entries |
| File present but unreadable (perms) | log warning, skip |
| File present but malformed JSON | log warning, skip |
| Schema version != "1" | log warning + version mismatch detail, skip |
| Cardinality exceeded | log warning + counts, skip |
| Path traversal in `mapping_file` value | log warning, skip |
| Symlinked file | log warning, skip |
| Inline + external have same rule_id with different CWE | inline wins, external entry silently dropped (consistent with "manifest authoritative" principle) |
| Plugin enables mapping_file but Plugin.Path empty (virtual) | log warning, skip |

## Plugin author workflow (MAJOR #8 fix)

External `mapping_file` accepts only the
`{"schema_version": "1", "entries": {...}}` JSON shape. Upstream
scanners often ship their rule metadata in different formats:

- **Semgrep** ships rules as YAML with `metadata.cwe = ["CWE-89: ..."]`.
  Plugin authors must convert YAML → JSON. A reference converter
  lives at `plugins/semgrep/tools/semgrep_rules_to_cwe.py` (ships
  with 0053 v1.1 — or, if not present, plugin authors write their
  own from the 10-line template in the README).
- **ZAP / Trivy / others** — same pattern: convert upstream metadata
  to the JSON format. Conversion is data-only; one PR per scanner.

The JSON format is intentionally minimal — `schema_version` and a
flat `entries` map. No nested metadata, no version pinning per
entry, no rule descriptions. Plugin authors who need richer
metadata layer it in the plugin's own UI / docs; the loader cares
only about `rule_id → CWE-NNN`.

## DRY review

- **Path-traversal check**: reuse `pathutil.RejectTraversal` from
  0052. No re-implementation.
- **Symlink check**: pluginregistry's `RejectSymlink` operates on
  plugin.toml; 0050 v1.1 does its own `os.Lstat` because the
  pluginregistry helper is keyed to .toml files. Considered extracting
  a generic helper — but the call sites have different error semantics
  (skip-with-warning vs reject-entire-plugin), so keep them separate.
- **CWE regex (MINOR #9 fix)**: the original 0050 LLD claimed the
  import direction would be a cycle inversion; the reviewer is
  correct that `internal/cwe` already imports `pluginregistry`
  today, so the import direction is consistent. **Export
  `pluginregistry.CWERe`** (capitalise the existing `cweRE`); the
  loader imports it. Single source of truth, no duplication.
- **Cardinality cap (MAJOR #5 fix)**: **Export
  `pluginregistry.MaxNormalisationEntries`** (capitalise existing
  `maxNormalisationEntries`); the loader imports it. Both inline-
  and external-file caps stay synchronised by design, not by
  comment.

## Files touched

| File | Action |
|---|---|
| `docs/features/0050_cwe_normalization_v1_1/{plan,status,rollback}.md` | NEW |
| `backend/internal/cwe/loader.go` | NEW — `loadMappingFile`, JSON shape, validation |
| `backend/internal/cwe/loader_test.go` | NEW (RED) |
| `backend/internal/cwe/layer.go` | MOD — `New(registry)` calls `loadMappingFile` per plugin; merges results into per-plugin map |
| `backend/internal/cwe/layer_test.go` | MOD — add integration test for inline-wins-over-external |
| `plugins/semgrep/rules/rule_to_cwe.json` | MOD — add ~30 real Semgrep rule mappings (no longer empty) |
| `plugins/semgrep/plugin.toml` | MOD — declare `mapping_file = "rules/rule_to_cwe.json"` |

Estimated LoC: ~250 (loader + tests + sample data inflation).

## Acceptance criteria

1. **External file loaded for bundled plugin** — a plugin with
   `Path = /tmp/plug/plugin.toml` and `mapping_file = "rules/foo.json"`
   reads `/tmp/plug/rules/foo.json`. Sample test asserts entries
   merged into per-plugin `rule_to_cwe`.
2. **Inline wins** — plugin manifest TOML has `rule_to_cwe = {"foo":
   "CWE-89"}`; external file has `entries: {"foo": "CWE-79"}`.
   Layer.Normalize for that rule_id returns `CWE-89`.
3. **Schema version != "1" rejected** — file with `"schema_version":
   "2"` → external entries dropped, logged warning, plugin still
   loads with inline-only.
4. **Cardinality cap** — file with 10001 entries → rejected; plugin
   loads with inline-only.
5. **Path traversal rejected** — `mapping_file = "../../etc/passwd"`
   → rejected (containment check).
6. **Symlink rejected** — `mapping_file` points at file that is a
   symlink → rejected via `os.Lstat`.
7. **Missing file graceful** — `mapping_file` references nonexistent
   path → logged warning + plugin loads with inline-only.
8. **Malformed JSON graceful** — file has bad JSON → same.
9. **Per-entry skip on invalid CWE** (BLOCKER #3 fix) — file with
   9999 valid entries + 1 entry whose value is `"NOT-CWE"` loads
   exactly 9999 entries; the single bad entry is logged once with
   its rule_id; no file-level rejection.
9b. **Containment via sibling-dir attack rejected** (BLOCKER #1) —
    `manifestDir = "/tmp/plug"`, `mapping_file = "../plug-evil/x.json"`
    → containment check rejects with `ErrMappingFileOutsideDir`
    even though `strings.HasPrefix("/tmp/plug-evil/x.json", "/tmp/plug")`
    would be `true`.
9c. **Intermediate-symlink rejected** (MAJOR #4) — `manifestDir/rules`
    is a symlink to `/etc`. `filepath.EvalSymlinks` detects the
    divergence; rejected with `ErrMappingFileSymlinkUnsafe`.
9d. **Oversize file rejected** (BLOCKER #2) — 17 MiB file → rejected
    with `ErrMappingFileTooLarge` without JSON parse.
9e. **Empty `mapping_file = ""` silent no-op** (MAJOR #7) — plugin
    with `mapping_file = ""` (or `"   "` whitespace) loads with
    inline-only, no warning logged.
10. **Virtual plugin with mapping_file ignored** — `Plugin.Path = ""`
    (in-tree synthesised plugin) AND non-empty mapping_file → logged
    warning + skip.
11. **Vulture-on-vulture E2E** — inflate
    `plugins/semgrep/rules/rule_to_cwe.json` with real Semgrep rule
    mappings; build live `cwe.New(registry)` with the bundled
    Semgrep manifest discovered via `VULTURE_BUILTIN_PLUGINS_DIR=plugins`;
    assert `Normalize("semgrep", "<some-category>", "<real-semgrep-rule-id>")`
    returns the expected CWE from the file.

## Build sequence (TDD via RED → GREEN subagents)

1. LLD doc (this file)
2. Cross-cutting review (correctness / reliability / maintenance /
   chaos engineering / security / DRY)
3. RED phase via subagent — `loader_test.go` covering ACs 1–10
4. RED verification — `go build ./...` clean; `internal/cwe` test
   package fails at `loadMappingFile` symbol
5. GREEN phase via subagent — `loader.go` implementation + wire into
   `layer.go::New`
6. Verify all `go test -race ./...` clean
7. AC 11 E2E: inflate the bundled Semgrep rule_to_cwe.json with
   ~30 real entries; assert Layer resolves them
8. Status doc update

## Rollback

| Failure | Recovery |
|---|---|
| External loader panics | `defer recover` at the loadMappingFile boundary; on panic, log + return empty map |
| Bad data in `plugins/semgrep/rules/rule_to_cwe.json` | data-only fix (PR against the JSON) |
| Layer construction slowness on N plugins × N entries | already O(N+M) maps + map ops; not a hot path |
| Full revert | `git revert`; `mapping_file` reverts to "parsed-and-ignored" as in 0050 v1; semgrep manifest revert removes the `mapping_file` line |
