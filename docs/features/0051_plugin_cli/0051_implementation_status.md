# 0051 — Implementation status

**Last updated**: 2026-05-28
**State**: COMPLETE — LLD reviewed (16 findings, 3 BLOCKER, 8 MAJOR, 4 MINOR, 1 NIT, all incorporated); RED→GREEN TDD via subagents; live E2E against vulture's own example manifest: 26/26 PASS.

## Checklist

- [x] LLD doc (plan/status/rollback)
- [x] LLD review (code-reviewer subagent, 16 findings)
- [x] LLD findings incorporated (revision changelog at top of plan)
- [x] RED phase via subagent: 8 test files, production unchanged
- [x] RED state verified — `go build ./...` clean; 4 target packages fail at expected seams
- [x] GREEN phase via subagent: production code minimal, no test edits
- [x] All 19 acceptance criteria pass independently
- [x] `go test -race ./... -count=1` clean across 20 packages
- [x] cyclomatic complexity < 10 (gocyclo `>9` introduced 0 violations)
- [x] no magic permission literals outside `pkg/pluginregistry/permissions.go`
- [x] E2E: install/list/info/verify/disable/enable/remove the
      `docs/spec/plugin-v1/examples/external-semgrep.toml` manifest
      against a mock cosign binary; 26/26 assertions pass

## LLD-review fix map

| # | Sev | Issue | Resolution |
|---|---|---|---|
| 1 | BLOCKER | `cosign verify` wrong subcommand | Pinned `cosign verify-blob ...` — verified by T4 argv-contract check |
| 2 | BLOCKER | `cosign://` semantics never defined | Pinned: value after prefix is `--certificate-identity`; `<plugin.toml>.sigstore` is the bundle |
| 3 | BLOCKER | ack prompt has no `io.Reader` seam | `PromptAcks(acks, in, out)` signature pinned + tested |
| 4 | MAJOR | install disk-write ordering undefined | 3-step order pinned: plugin dir → marker → state |
| 5 | MAJOR | `--force` ambiguous | Dropped from v1 scope |
| 6 | MAJOR | lockfile vs dir-creation race | `MkdirAll` precedes lock open; `O_CREATE\|O_RDWR` |
| 7 | MAJOR | partial install state machine | "absence of marker = unverified"; `plugin verify` is recovery |
| 8 | MAJOR | `--yes` 1-second delay theatre | Removed; `--yes` proceeds immediately |
| 9 | MAJOR | symlink rejection would duplicate | `pluginregistry.RejectSymlink` shared by loader + installer |
| 10 | MAJOR | permission constants duplicated | All in `pluginregistry/permissions.go` |
| 11 | MAJOR | `--force` test gap | Moot — feature dropped |
| 12 | MINOR | `cosign_version` source unspecified | `cosign version --short`; `"unknown"` on failure |
| 13 | MINOR | re-verify trust note | `plugin verify` runs cosign on current file bytes |
| 14 | MINOR | help-text hierarchy | `plugin --help` + per-subcommand `flag.PrintDefaults()` |
| 15 | MINOR | plugin dir mode | Per-plugin dir is 0700; verified by T3 |
| 16 | NIT | rename vs copy wording | "rename" → "copy"; source preserved (T2 confirms) |

## Test summary

```
internal/cosign           4 tests  (cosign argv contract, missing binary, version capture)
internal/pluginlifecycle  ~20 tests (install/marker/acks/lockfile, all 19 ACs covered)
pkg/pluginregistry        +2 tests (RejectSymlink + cardinality from 0050)
cmd/vulture               2 tests  (dispatch + help)
... full backend          20 packages PASS under -race
```

## E2E against vulture's own example manifests

```
$ /tmp/0051-e2e.sh

T1 help mentions install / verify           PASS / PASS
T2 install reports verified                 PASS
T2 plugin.toml installed                    PASS
T2 marker written                           PASS
T2 source preserved (NIT 16)                PASS
T2 state.toml updated                       PASS
T3 dir mode 0700 / manifest 0644 / marker 0600 / state 0600   PASS x4
T4 cosign verify-blob argv                  PASS
T4 --certificate-identity (BLOCKER 1, 2)    PASS
T4 --certificate-oidc-issuer                PASS
T4 --bundle pointing at .sigstore           PASS
T5 plugin list shows semgrep                PASS
T6 info shows version 1.0.0                 PASS
T6 info shows verified                      PASS
T7 disable confirmed (row shows 'no')       PASS
T7 enable confirmed (row shows 'yes')       PASS
T8 verify re-ran cosign                     PASS
T9 plugin dir removed                       PASS
T9 list no longer shows semgrep             PASS
T10 failing cosign produces error           PASS
T10 no plugin dir created on failure        PASS

26 / 26 PASS
```

## Files shipped

```
backend/internal/cosign/verify.go                              NEW
backend/internal/cosign/verify_test.go                         NEW (RED)
backend/internal/pluginlifecycle/install.go                    NEW
backend/internal/pluginlifecycle/marker.go                     NEW
backend/internal/pluginlifecycle/acks.go                       NEW
backend/internal/pluginlifecycle/lockfile.go                   NEW
backend/internal/pluginlifecycle/atomicwrite.go                NEW
backend/internal/pluginlifecycle/*_test.go                     NEW (RED)
backend/internal/pluginlifecycle/permissions_test.go           NEW (RED)
backend/pkg/pluginregistry/permissions.go                      NEW
backend/pkg/pluginregistry/symlink_helper.go                   NEW
backend/pkg/pluginregistry/symlink_helper_test.go              NEW (RED)
backend/pkg/pluginregistry/state.go                            MOD (use StateFileMode)
backend/pkg/pluginregistry/loader.go                           MOD (call RejectSymlink)
backend/cmd/vulture/plugin.go                                  NEW (dispatcher)
backend/cmd/vulture/plugin_install.go                          NEW
backend/cmd/vulture/plugin_list.go                             NEW
backend/cmd/vulture/plugin_state.go                            NEW (enable/disable/remove)
backend/cmd/vulture/plugin_verify.go                           NEW (verify/info)
backend/cmd/vulture/plugin_dispatch_test.go                    NEW (RED)
backend/cmd/vulture/main.go                                    MOD (plugin case + help line)
docs/features/0051_plugin_cli/*.md                             NEW (plan / status / rollback)
```

## Open residuals (deliberate)

- **Network installs (git / OCI / HTTPS sources)** → v1.1 follow-up; requires its own supply-chain threat model.
- **`vulture plugin upgrade`** → v1.1.
- **`vulture plugin search` / hosted index** → no upstream index exists yet.
- **Pure-Go cosign integration** → v1 shells out; v1.1 may switch to `sigstore-go` when the library matures.
- **In-process hot reload** → intentionally not in 0051; restart picks up changes.
