# 0051 — Plugin Lifecycle CLI + Cosign Verification (LLD + plan)

**Author**: tbd
**Status**: PLAN — LLD reviewed (16 findings, 3 BLOCKERs, 8 MAJORs), all incorporated
**Created**: 2026-05-28
**Depends on**: 0047 (contract), 0048 (registry), 0050 (normalisation; for state.toml schema reuse)
**Unblocks**: 0053 (Semgrep plugin gets a real install path); future network-source installs (v1.1)

## Reviewer-fix changelog (applied in this revision)

| # | Sev | Finding | Resolution |
|---|---|---|---|
| 1 | BLOCKER | `cosign verify` wrong subcommand | Pinned `cosign verify-blob` with explicit argv (see "Cosign argv contract" below) |
| 2 | BLOCKER | `cosign://` semantics never defined | Pinned: the value after `cosign://` is the `--certificate-identity` claim; signature lives in `<plugin.toml>.sigstore` bundle by convention |
| 3 | BLOCKER | ack prompt has no `io.Reader` seam | `PromptAcks(acks []string, in io.Reader, out io.Writer) error` signature pinned |
| 4 | MAJOR | install disk-write ordering undefined | Pinned 3-step order: plugin dir → marker → state.toml; partial-install repair documented |
| 5 | MAJOR | `--force` ambiguous | **Dropped `--force` from v1**; operators use `remove` then `install` |
| 6 | MAJOR | lockfile vs dir-creation race | `MkdirAll` runs before lock open; `O_CREATE\|O_RDWR` (not `O_EXCL`) on the lock file |
| 7 | MAJOR | partial install state machine | "absence of marker = unverified" convention pinned; `plugin verify` is the recovery path |
| 8 | MAJOR | `--yes` 1-second delay is theatre | Removed; `--yes` proceeds immediately |
| 9 | MAJOR | symlink rejection would be duplicated | New shared helper `pluginregistry.RejectSymlink(path)`; both loader + install call it |
| 10 | MAJOR | permission constants location | All in `pkg/pluginregistry/permissions.go`; lifecycle imports |
| 11 | MAJOR | `--force` test gap | Moot — feature dropped |
| 12 | MINOR | `cosign_version` source | Pinned: `cosign version --short`; `unknown` on failure |
| 13 | MINOR | re-verify trust note | Documented: `plugin verify` runs cosign on current file bytes |
| 14 | MINOR | help-text hierarchy | Pinned: `plugin --help` lists subcommands; each subcommand has its own `flag.PrintDefaults()` |
| 15 | MINOR | plugin dir mode | Per-plugin dir is 0700, not 0755 |
| 16 | NIT | rename vs copy wording | "rename" → "copy"; source untouched |

## Problem

After 0050, the plugin platform is fully functional in code but
unusable from an operator's perspective:

- To install a community plugin: `mkdir + cp + edit state.toml` by hand
- `community-signed` tier is a documentation-only label — nothing
  verifies the cosign signature
- `required_ack` array on user-supplied plugins is stored in state.toml
  but never *asked* — silent auto-acceptance of dangerous capabilities
  (`runs-real-exploits`, `host-fs-write`, `privileged`, etc.)
- No way to list installed plugins, enable/disable from the CLI, or
  inspect their verification status

0051 ships the operator surface that closes these gaps:

```
vulture plugin list
vulture plugin install <path>          # local manifest, with cosign verify
vulture plugin enable  <name>
vulture plugin disable <name>
vulture plugin remove  <name>
vulture plugin verify  <name>          # re-run cosign on installed plugin
vulture plugin info    <name>          # full manifest + verification status
```

Plus actual Sigstore/cosign verification at install time, and an
interactive ack flow for `tier = "user-supplied"`.

## Goal

Make plugins installable and operable from `vulture plugin …`. Enforce
the threat-model promises of 0047's tier system: community-signed
plugins must pass `cosign verify`; user-supplied plugins must obtain
explicit operator acknowledgement of each declared `required_ack`.

## Non-goals (deferred)

- **Network installs** (git URL / OCI ref / HTTPS URL). v1 takes
  only local paths. Network installs add supply-chain attack surface
  that deserves its own threat model + cert pinning + TUF metadata
  conversation — out of scope.
- **Plugin upgrade** (`vulture plugin upgrade <name>`). v1 is
  install / remove / replace-by-reinstalling. Semver-aware upgrade
  flow is a v1.1 follow-up.
- **Plugin search / discovery** (`vulture plugin search`). Requires
  a hosted index; no such index exists. v1 takes locally-resolved
  paths only.
- **Pure-Go cosign**. v1 shells out to the `cosign` CLI via
  `os/exec`. v1.1 may switch to `github.com/sigstore/sigstore-go`
  when the library matures further. Choice deliberate (see Design
  decisions below).
- **Backend hot reload**. CLI mutates `~/.vulture/plugins/` and
  `state.toml`; operator must restart the backend to pick up the
  change. Consistent with 0048 behaviour.
- **`mapping_file` external loader**. Separate v1.1 of 0050.

## Design decisions

### Cosign argv contract (resolves BLOCKERs 1, 2)

The `cosign://...` value in a community-signed manifest's
`[trust].signature` field is interpreted as a **Sigstore certificate
identity claim**, NOT an OCI ref. The path after `cosign://` is
passed verbatim as the `--certificate-identity` argument to
`cosign verify-blob`.

The signature is shipped as a **Sigstore bundle file alongside the
manifest** by convention: `<plugin.toml>.sigstore`. (E.g. for an
operator who downloads `semgrep/plugin.toml`, they also download
`semgrep/plugin.toml.sigstore`.) If the bundle file is missing,
install aborts with `"signature bundle not found at <path>.sigstore"`.

Exact argv:

```
cosign verify-blob \
  --certificate-identity <path-after-cosign-prefix> \
  --certificate-oidc-issuer <fixed-set; see below> \
  --bundle <plugin.toml>.sigstore \
  <plugin.toml>
```

`--certificate-oidc-issuer` is fixed to the GitHub Actions OIDC
issuer URL `https://token.actions.githubusercontent.com` for v1 —
the only issuer Vulture community plugins are expected to use. A
manifest signed via a different issuer (Google, custom) is out of
scope for v1; the operator can verify manually and use
`tier = "user-supplied"` instead.

`cosign verify-blob` reads bytes from the named file path (not
stdin) for the blob argument. The temp-file → rename pattern
(TM8) writes the verified bytes to the destination after cosign
exits 0.

### D1: Cosign integration via `os/exec`

Three options surveyed:

| Approach | Pros | Cons |
|---|---|---|
| Shell out to `cosign` CLI | tiny code surface; zero new Go deps; defers to operator's cosign install (which sigstore-best-practices recommend keeping current) | operator must have `cosign` in PATH |
| `github.com/sigstore/sigstore-go` (pure Go) | no external binary; tighter integration | ~30 transitive deps; library still evolving |
| `github.com/sigstore/cosign/v2` (full cosign Go) | "official" path | bloats binary by ~30MB; brings cobra/viper |

**Choice: `os/exec`**. Reasons:

1. Project's stated constraint is to minimise dependencies (CLAUDE.md
   lists current deps as `lib/pq, x/crypto, modernc.org/sqlite`,
   `BurntSushi/toml` from 0048).
2. Operators serious about sigstore already have cosign installed.
3. Missing-cosign error path gives a clear message + install link;
   not silent failure.
4. Verification logic is a single command: `cosign verify --certificate-identity-regexp '…' <ref>`.
5. Mocking is trivial: `VULTURE_COSIGN_BINARY=/path/to/script` env
   var lets tests inject a stub binary without sigstore credentials.

### D2: Source forms accepted by `install`

v1 accepts:
- Local file path: `./my-plugin/plugin.toml`
- Local directory containing `plugin.toml`: `./my-plugin/`

Both forms parsed by `pluginregistry.ParseManifest` (already exists).
Network sources rejected with `"network installs not supported in
v1; download the manifest manually and pass the local path"`.

### D3: State changes vs schema changes

No new schema. The `state.toml` schema (0048) already has:

```go
type PluginState struct {
    Enabled     bool      `toml:"enabled"`
    TrustAcks   []string  `toml:"trust_acks"`
    InstalledAt time.Time `toml:"installed_at"`
}
```

0051 just *populates* `TrustAcks` (currently always empty) and sets
`InstalledAt` to actual install timestamp (currently set to first-
discovery time).

New per-plugin file: `~/.vulture/plugins/<name>/.cosign-verified`
— a tiny TOML marker recording:

```toml
verified_at = "2026-05-28T…"
subject     = "https://github.com/foo/bar/…"
signature   = "cosign://sigstore/foo/bar@sha256:abc…"
cosign_version = "v2.4.1"
```

The marker lets `plugin list` and `plugin info` report verification
status without re-running cosign every call. `plugin verify` re-runs
cosign and rewrites the marker.

### D4: Concurrency

Two `vulture plugin install` invocations racing would corrupt
state.toml. Lock file at `~/.vulture/plugins/.install.lock` via
`syscall.Flock`. Second invocation waits with a 30s timeout, then
errors. The locked region is small (parse → cosign → write); never
held across network I/O.

### D5: Disk-write ordering (resolves MAJOR 4, 7)

Install commits in three stages, in order:

1. **Plugin dir + plugin.toml** — `MkdirAll ~/.vulture/plugins/<name>/`
   mode 0700, then write plugin.toml mode 0644 via temp-file +
   `os.Rename` (atomic on POSIX).
2. **`.cosign-verified` marker** — only when tier=community-signed,
   after cosign success. Same temp-file + rename pattern, mode 0600.
3. **state.toml entry** — append/update the plugin's
   `PluginState{Enabled: true, TrustAcks: …, InstalledAt: now}` via
   `pluginregistry.SaveState` (already atomic + 0600).

Failure between (1) and (3) leaves an untracked plugin dir.
Recovery: `vulture plugin list` performs a reconcile pass on startup
that detects plugin.toml files without a state.toml entry and
adds a default entry (`Enabled: true`, `TrustAcks: []`, `InstalledAt:
mtime of dir`). Operators can then `vulture plugin verify` to
rebuild the marker.

Convention: **absence of `.cosign-verified` marker = unverified**;
its presence with a successful re-verify timestamp = verified.

### D6: Interactive prompt seam (resolves BLOCKER 3)

Ack prompt is implemented as:

```go
// PromptAcks prints the ack list to `out`, reads operator input
// from `in`, and returns nil iff the operator confirmed by typing
// the literal token "YES" on its own line. Any other input → an
// error of type *DeclinedError; reads up to 1KiB to avoid
// unbounded buffering on a hostile stdin.
func PromptAcks(acks []string, in io.Reader, out io.Writer) error
```

CLI layer passes `os.Stdin`, `os.Stderr`. Tests pass
`bytes.NewBufferString("YES\n")` etc. No package reads `os.Stdin`
directly.

### D7: --yes flag semantics (resolves MAJOR 8)

`--yes` proceeds with no delay and no interactive read. It still
prints the ack list to stderr so the operator sees what was
recorded. There is no Ctrl-C window — operators who want one use
the interactive mode.

### D5 (renumbered): User confirmation UX

For user-supplied plugins with non-empty `required_ack`, the install
flow is interactive by default:

```
$ vulture plugin install ./semgrep/plugin.toml
Manifest:
  name:      semgrep
  version:   0.1.0
  publisher: r2c
  tier:      user-supplied

This plugin requires the following acknowledgements:
  ● runs-real-exploits  — the plugin may execute attack payloads
  ● network-egress      — the plugin may make outbound network calls

Type YES (uppercase) to install:
> YES
Installed: ~/.vulture/plugins/semgrep/plugin.toml
Restart the backend to activate.
```

`--yes` / `-y` flag skips the prompt for CI workflows. `--yes`
records the acks just like the interactive path — it's not a bypass,
it's a non-interactive confirmation. (The operator still chose to
pass `--yes`.)

For community-signed plugins: no ack prompt; cosign verify is the
verification mechanism. If the manifest also declares `required_ack`,
those are still presented (just as informational; operator
acknowledges them).

For in-tree tier: `vulture plugin install` rejects outright —
in-tree plugins are synthesised by the backend at startup; operators
can't install them.

## Architecture

```
                ┌──────────────────────────┐
                │ cmd/vulture/plugin*.go    │  CLI dispatch (list/install/…)
                └────────────┬──────────────┘
                             │
                ┌────────────▼──────────────┐
                │ internal/pluginlifecycle/ │  business logic, no I/O
                │   install.go               │  - parse manifest
                │   verify.go                │  - cosign verify
                │   marker.go                │  - .cosign-verified TOML
                │   acks.go                  │  - interactive prompt
                │   lockfile.go              │  - flock concurrency
                └────────────┬──────────────┘
                             │
                ┌────────────▼──────────────┐
                │ internal/cosign/           │  exec.Command wrapper
                │   verify.go                │
                └────────────────────────────┘
                             │
                ┌────────────▼──────────────┐
                │ pkg/pluginregistry/        │  (existing) ParseManifest, SaveState
                └────────────────────────────┘
```

Reasoning for two layers (`pluginlifecycle` + `cosign`): the cosign
wrapper is a stateless utility that just wraps `exec.Command`. The
lifecycle layer owns the orchestration (read source → validate →
cosign → marker → state.toml → unlock). Splitting keeps the cosign
wrapper independently testable and easy to mock for the rest of the
suite.

## Threat model

### TM1 — Cosign binary missing

**Risk**: `os/exec` returns `exec.ErrNotFound`.
**Mitigation**: detection runs eagerly at the start of `install` and
`verify`; clear error `"cosign binary not found; install via https://docs.sigstore.dev/cosign/installation"`.
v1 does not auto-download cosign.

### TM2 — Manifest claims community-signed but `signature` field has a malicious cosign:// URL pointing at a forged transparency-log entry

**Risk**: signature URL like `cosign://attacker.com/foo` — cosign
verifies that subject + sig pair, but only if the attacker controls
both. They can sign their own plugin under their own subject.
**Mitigation**: v1 records the verified subject in `.cosign-verified`
and surfaces it in `plugin list`. Operators must check the subject
against their trust expectations. A future `--trusted-subjects
"github.com/foo/*"` flag would enforce subject-allow-listing —
deferred to v1.1.

### TM3 — Plugin manifest claims `tier = "user-supplied"` to bypass cosign

**Risk**: legitimate downgrade; community-signed plugins might switch
to user-supplied to avoid sigstore.
**Mitigation**: user-supplied with `required_ack` forces the
interactive prompt. The plugin can't bypass acknowledgement —
schema already requires non-empty `required_ack` for user-supplied
(enforced in 0048's `validateTrustBlock`).

### TM4 — Concurrent installs corrupt state.toml

**Risk**: two `vulture plugin install` racing; both read state.toml,
mutate it independently, last-write wins → one install silently lost.
**Mitigation**: D4 lockfile.

### TM5 — TOCTOU on the source manifest

**Risk**: an attacker mutates `./plugin.toml` between parse and copy.
**Mitigation**: parse + validate via `ParseManifestBytes` on the
exact bytes that will be copied to the destination. Validate the
copied bytes after writing.

### TM6 — Filesystem permissions

**Risk**: `~/.vulture/plugins/state.toml` written with 0644 leaks
ack confirmations to other users on a shared machine.
**Mitigation**: 0048's `SaveState` already enforces 0600. 0051
preserves this; new `.cosign-verified` markers ALSO use 0600
(verification metadata could include subject URLs an operator
considers sensitive).

### TM7 — Plugin dir is a symlink

**Risk**: operator passes `./plugin` which is a symlink to
`/etc/passwd`. The install logic reads it; remove operation later
might delete the target.
**Mitigation**: `os.Lstat` at install + remove time; reject if
plugin path or any of its files is a symlink targeting outside
its own dir. (0048 already has this protection for `plugin.toml`;
0051 extends it to the install path.)

### TM8 — Manifest changed by community-signed plugin between cosign verify and disk write

**Risk**: race window between `cosign verify` and `cp plugin.toml ~/.vulture/...`.
**Mitigation**: read manifest bytes once; pass those bytes to
cosign via stdin (or to a temp file that is then renamed). cosign
verify operates on the same bytes that get written. The temp
file → rename pattern is atomic on POSIX.

### TM9 — Operator pastes a poisoned `--yes` flag from a malicious tutorial

**Risk**: `vulture plugin install --yes ./evil/plugin.toml` skips
the interactive prompt; operator never sees the ack list.
**Mitigation**: `--yes` still PRINTS the ack list before installing
and waits for stdin EOF / SIGINT — but doesn't require typing YES.
The 1-second delay between print and install gives a Ctrl-C
window. Documented in `--help`.

## Reliability + chaos engineering

| Failure mode | Behaviour |
|---|---|
| `~/.vulture/plugins` doesn't exist | created (mode 0755) |
| `~/.vulture/plugins` is read-only | clear error, abort install |
| Cosign verify fails (exit non-zero) | install aborts; no files written; non-zero CLI exit |
| `state.toml` is malformed | install aborts; existing state.toml preserved (atomic rename pattern from 0050 still applies) |
| Plugin name on disk doesn't match manifest's `plugin.name` | install **copies** the manifest to the canonical `~/.vulture/plugins/<manifest.name>/plugin.toml` (mode 0644 via temp-file + `os.Rename`); the operator's source directory is left untouched. Cross-device copies are explicit `io.Copy` + `os.Rename` within the destination dir (so the final rename is same-FS) |
| Plugin already installed (same name) | install errors with `"already installed; remove first"`; no `--force` in v1 (dropped per LLD review MAJOR 5) |
| Stdin not a TTY (e.g., CI without `--yes`) | `install` errors: "interactive prompt needed; pass --yes to confirm non-interactively" |
| Backend running while CLI mutates state.toml | mutation succeeds; backend continues with its in-memory snapshot; restart required |
| Cosign succeeds but disk write fails | marker not written; verify reported as "not verified" on next list; operator can `vulture plugin verify` |

### Chaos test catalogue (must exist in tests)

1. Cosign binary returns exit 1 → install aborts, no files written
2. Cosign binary missing → clear error before any disk write
3. Source manifest is malformed TOML → rejected before cosign call
4. Source manifest claims `tier = "in-tree"` → rejected with "in-tree plugins are bundled with the backend, not installable"
5. Source manifest claims `tier = "community-signed"` without `signature` → rejected by `ValidateManifest` (already in 0048)
6. Source manifest is a symlink → rejected (TM7)
7. `state.toml` is held by another process via flock → install retries 30s then errors
8. Install completes, then user removes — state.toml entry gone, dir gone, marker gone
9. Install completes, restart backend, `vulture plugin list` shows the new plugin
10. Install with `--yes` records acks in state.toml (not skipped)
11. Two parallel `install` invocations: one succeeds, other reports lock contention

## Maintenance

CLI surface is intentionally small (7 commands) so help text + usage
fits in one screen. Each command's logic lives in its own file
(`plugin_list.go`, `plugin_install.go`, …) under
`backend/cmd/vulture/`; `plugin.go` is just the dispatcher.

Business logic is in `internal/pluginlifecycle/` so it's unit-
testable without CLI scaffolding. CLI files do only:

1. Parse argv
2. Resolve env (cosign binary path, plugins dir)
3. Call lifecycle function
4. Print result + exit code

This keeps the CLI files cyclo-complexity-low and the testable
surface large.

## DRY review

- **Manifest parsing**: reuse `pluginregistry.ParseManifest` /
  `ParseManifestBytes`. Don't duplicate.
- **State.toml read/write**: reuse `pluginregistry.LoadState` /
  `SaveState` (atomic + 0600 already proven in 0048).
- **Lockfile**: standard `syscall.Flock` pattern; no new dep needed.
- **TOML marker**: reuse `BurntSushi/toml` (already in go.mod from
  0048).
- **Tier / runtime constant strings**: reuse `pluginregistry.TierInTree`
  etc. — don't duplicate enum membership.
- **Symlink rejection (resolves MAJOR 9)**: extract a shared
  helper `pluginregistry.RejectSymlink(path string) error` from
  the existing inline check at `loader.go::loadOne` (the `os.Lstat`
  + `ModeSymlink` check). Both `loader.go` and the new
  `pluginlifecycle/install.go` call it.
- **Permission constants (resolves MAJOR 10)**: all in
  `pkg/pluginregistry/permissions.go` as exported `const`s
  (`PluginDirMode = 0o700`, `ManifestMode = 0o644`,
  `StateFileMode = 0o600`, `MarkerMode = 0o600`). 0048's
  `SaveState` switches from its hard-coded `0o600` to
  `StateFileMode`. Lifecycle imports from there. No duplicate.

## Files touched

| File | Action |
|---|---|
| `docs/features/0051_plugin_cli/{plan,status,rollback}.md` | NEW |
| `backend/cmd/vulture/main.go` | MOD — add `plugin` to dispatch switch |
| `backend/cmd/vulture/plugin.go` | NEW — `vulture plugin` dispatcher |
| `backend/cmd/vulture/plugin_list.go` | NEW |
| `backend/cmd/vulture/plugin_install.go` | NEW |
| `backend/cmd/vulture/plugin_state.go` | NEW — enable/disable/remove |
| `backend/cmd/vulture/plugin_verify.go` | NEW — verify/info |
| `backend/internal/pluginlifecycle/install.go` | NEW |
| `backend/internal/pluginlifecycle/marker.go` | NEW |
| `backend/internal/pluginlifecycle/acks.go` | NEW (interactive prompt) |
| `backend/internal/pluginlifecycle/lockfile.go` | NEW |
| `backend/internal/pluginlifecycle/permissions.go` | NEW — file mode constants |
| `backend/internal/pluginlifecycle/*_test.go` | NEW (RED) |
| `backend/internal/cosign/verify.go` | NEW |
| `backend/internal/cosign/verify_test.go` | NEW (RED) |

Estimated LoC: ~1000 net.

## Help text hierarchy (resolves MINOR 14)

```
vulture plugin --help            → list 7 subcommands + one-liner each
vulture plugin install --help    → flags for install only (--yes, --cosign)
vulture plugin <other> --help    → flags for that subcommand
```

Each subcommand parses its own `flag.FlagSet`. No third-party flag
library added. `main.go::printUsage` gains a single line:
`"plugin       Manage plugins (install/list/enable/disable/remove/verify/info)"`.

## Acceptance criteria

Each AC names the relevant reviewer fix #s in parentheses.

1. **List installed** — `vulture plugin list` on a fresh
   `~/.vulture/plugins/` shows only the 10 in-tree synthesised
   plugins (existing 0048 behaviour preserved).
2. **Install user-supplied with acks (interactive)** — Given an
   `io.Reader` containing `"YES\n"` and a user-supplied manifest with
   `required_ack = ["network-egress"]`, `pluginlifecycle.Install`
   prints the ack list to the writer, reads `YES`, and writes
   plugin.toml + state.toml entry with `trust_acks = ["network-egress"]`.
   (BLOCKER 3)
3. **Install user-supplied with `--yes` non-interactive** — Same
   flow without consuming stdin; ack still recorded; no `time.Sleep`
   in code path. (MAJOR 8)
4. **Install community-signed: cosign success** — Mock cosign binary
   prints `"verified"` on stdout, exits 0. Install succeeds; marker
   written with subject (the path after `cosign://`), signature URL,
   `cosign_version = "v9.9.9-mock"` from `cosign version --short`.
   (BLOCKER 1, 2; MINOR 12)
5. **Install community-signed: cosign failure** — Mock cosign exits 1.
   Install aborts non-zero; **no plugin dir created**, no marker,
   state.toml unchanged. (MAJOR 4, 7)
6. **Cosign binary missing** — `VULTURE_COSIGN_BINARY=/nonexistent`
   on a community-signed install produces a clear error mentioning
   "cosign binary not found"; aborts without disk writes.
7. **Bundle file missing** — Community-signed install with no
   `<plugin.toml>.sigstore` file in source dir aborts with
   `"signature bundle not found"`; no disk writes. (BLOCKER 2)
8. **Reject in-tree install** — `tier = "in-tree"` manifests reject
   with "in-tree plugins are bundled".
9. **Reject malformed manifest** — Broken TOML aborts via
   `ParseManifest` error.
10. **Disable / enable round-trip** — flips state.toml `enabled`
    field; `list` shows the new state.
11. **Remove deletes everything** — `remove foo` deletes plugin dir
    + state.toml entry + marker; `list` no longer shows it.
12. **Verify re-runs cosign on current bytes** — `verify foo`
    invokes cosign against `~/.vulture/plugins/foo/plugin.toml`,
    updates marker `verified_at`. (MINOR 13)
13. **Concurrent installs lock-protected** — Two simultaneous
    `Install` calls; one wins, the other reports lock contention.
    State.toml is consistent. (MAJOR 6)
14. **Permissions enforced** — state.toml 0600; plugin.toml 0644;
    `.cosign-verified` 0600; per-plugin dir 0700. All values read
    from `pluginregistry.PluginDirMode` etc. — no magic numbers in
    lifecycle code. (MAJOR 10, MINOR 15)
15. **Symlinked install source rejected** — Source `plugin.toml`
    being a symlink → reject via shared
    `pluginregistry.RejectSymlink`; same error wording as 0048
    loader. (MAJOR 9)
16. **Partial install reconcile** — Plugin dir exists with valid
    plugin.toml but no state.toml entry → next registry build
    creates an entry (`Enabled: true`, `TrustAcks: []`, `InstalledAt:
    mtime`). Existing 0048 behaviour confirmed unchanged for
    safety. (MAJOR 4)
17. **Help-text hierarchy** — `vulture plugin --help` lists 7
    subcommands; `vulture plugin install --help` shows only install
    flags. (MINOR 14)
18. **Install copies, does not move** — A source dir at `/tmp/foo/`
    containing `plugin.toml` is installed to
    `~/.vulture/plugins/<manifest.name>/plugin.toml`; the source
    `/tmp/foo/plugin.toml` still exists afterward. (NIT 16)
19. **E2E using vulture's own example manifests** — A self-
    contained Go program installs
    `docs/spec/plugin-v1/examples/external-semgrep.toml` using a
    mock cosign binary (`VULTURE_COSIGN_BINARY` pointing at a
    script that exits 0). Then: `plugin list` shows it; `plugin
    disable semgrep`; `plugin enable semgrep`; `plugin info semgrep`;
    `plugin verify semgrep`; `plugin remove semgrep`; `plugin list`
    no longer shows it.

## Build sequence (RED → GREEN, TDD)

1. **LLD doc** (this file).
2. **LLD review** (code-reviewer subagent; correctness, reliability,
   maintenance, chaos engineering, security, DRY).
3. **Incorporate review findings** — update LLD if BLOCKER/MAJOR
   issues surface.
4. **RED phase** (subagent) — write test files only:
   - `internal/cosign/verify_test.go`
   - `internal/pluginlifecycle/*_test.go` (install, marker, acks,
     lockfile)
   - `cmd/vulture/plugin_*_test.go` (CLI argv parsing + dispatch)
5. **Verify RED state** — `go build ./...` clean (no production code
   changes); `go test ./internal/cosign/ ./internal/pluginlifecycle/
   ./cmd/vulture/` fails at expected seams.
6. **GREEN phase** (subagent) — minimal implementation; no test
   edits.
7. **Verify GREEN** — `go test -race ./... -count=1` clean.
8. **E2E** — install/list/disable/enable/remove the vulture-repo
   example manifest using a mock cosign script.

## Rollback

| Failure | Recovery |
|---|---|
| CLI panics during install | atomic-rename semantics mean state.toml is never half-written; plugin dir cleanup is best-effort |
| Cosign verify produces wrong result | re-run `vulture plugin verify <name>` after fixing cosign |
| Operator removed wrong plugin | re-install — manifests are local files; idempotent install rewrites the dir |
| Whole feature rolled back | `git revert <merge>`; CLI commands gone; registry continues to work read-only as in 0048-0050 |

No database migration to undo. Marker files left behind by a revert
are harmless; the registry doesn't read them.
