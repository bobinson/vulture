# 0036 — Public Open-Source Release Hardening: Rollback Plan

## Scope

This feature has four phases with very different rollback profiles:

| Phase | Reversibility | Rollback method |
|---|---|---|
| 1 (docs/attribution/metadata) | Trivially reversible | `git revert <commit-range>` |
| 2 (untrack bloat) | Trivially reversible | `git revert` + restore files from history |
| 3 (Mode-B hardening) | Reversible per-task | `git revert <commit>`; tests catch regressions |
| 4 (history rewrite + push) | **Irreversible after public push** | Restore from `pre-filter-repo-backup` tag or bare-clone (only if discovered before any third party clones) |

The defining risk is **Phase 4**: once `git push -u origin main` has executed against the public remote and any third party has cloned, the rewrite cannot be undone — the new history is the canonical history forever. Rollback up to that point is mechanical; after that point, "rollback" means "fix forward in a new commit".

## Rollback triggers

Initiate rollback if any of:

- A test regression surfaces post-merge that did not appear pre-merge (Phase 1/2/3 commit suspect → `git revert`).
- The Phase 4 `filter-repo` produces a corrupt tree (HEAD doesn't build, file count surprising, etc.) — restore from backup before pushing.
- Third-party data attribution turns out to be wrong (e.g., MITRE/OWASP responds clarifying additional obligations) — fix forward in a v0.1.1 commit; do not rewrite history again.
- `vulture.dev` domain is squatted before T16 completes — pull SECURITY.md/CODE_OF_CONDUCT.md addresses immediately, replace with GitHub-native flows in a fast-follow commit.
- The frontend hardcoded-agent-list deferral (T3 Step 9 option b) blocks an external contributor PR — accept the tech-debt and prioritize the auto-discovery follow-up.

## Per-phase rollback procedure

### Phase 1 (Tasks T1–T5) — docs / attribution / metadata

Each task lands as a single commit. To revert one:

```bash
git revert <commit-sha>
git push
```

To revert the whole phase:

```bash
git revert --no-commit <T1-sha>..<T5-sha>
git commit -m "revert: feature 0036 Phase 1 (docs/attribution/metadata)"
git push
```

**Side effects:** none. Documentation reverts to the pre-feature state. Audit findings are restored as open and the README/NOTICE/THIRD_PARTY_LICENSES.md files vanish (or revert to their previous content if they existed). License-metadata mismatch returns. The known-broken state is recoverable.

### Phase 2 (Task T6) — untrack binaries + bloat

```bash
git revert <T6-sha>
git push
```

**Side effects:** the binaries and large vendored data files are *re-tracked* in HEAD. Repo size at HEAD goes back up to ~90 MB. `.gitignore` reverts. **The historic blobs were never deleted from `.git/`** (Phase 4 hadn't run yet), so nothing is lost — `git checkout <T6-sha>~1 -- backend/vulture` restores the binary instantly.

### Phase 3 (Tasks T7–T16) — code-security hardening

Each fix-task (T8, T10, T12, T14) lands as a single GREEN commit paired with a RED test commit. To revert one fix:

```bash
git revert <GREEN-sha>
# the RED test commit can stay — it now fails again, which is correct
# OR revert both:
git revert <RED-sha> <GREEN-sha>
```

If reverting **after** the fix has been depended on by later code (e.g., T8's `cfg.CORSAllowedOrigins` field is consumed elsewhere), `git revert` may produce conflicts; resolve by keeping the *later* code's expectations and reintroducing a stub — typically not worth it; fix forward.

**Side effects of reverting Phase 3:**
- C1, C3, H7, H9 (T8): default `docker compose up` becomes unsafe again. Mode B operators must set every defensive env var manually.
- C2 (T10): SQLite users may be created with `role=admin` again.
- H1, H8 (T12): webhook URLs accept SSRF targets; agents accept unauthenticated requests.
- H2, H3 (T14): `/api/filesystem/browse` exposes the host filesystem.

If reverting Phase 3 **after** it has been merged to public `main`, also: update README §Deployment Modes to re-state "Mode B is not hardened".

### Phase 4 (Tasks T17–T20) — history rewrite + push

#### Before T20 (push) has executed

Recovery is full and clean:

```bash
# Discard the rewritten state
cd /home/user/src/vulture
cd ..
rm -rf vulture
# Restore from bare-clone backup
git clone vulture-pre-filter-repo.git vulture
cd vulture
git remote remove origin  # if the bare-clone had origin set
# Now you're back to the pre-rewrite state with all original SHAs intact.
```

Or, if the working repo still has the `pre-filter-repo-backup` tag and the original branches/tags are still in the reflog:

```bash
cd /home/user/src/vulture
git reflog | head -20  # find the pre-rewrite HEAD
git reset --hard <pre-rewrite-sha>
# verify branch refs
for ref in $(git for-each-ref refs/heads/ --format='%(refname)'); do
  echo "$ref"
done
```

`git filter-repo` writes a backup of `refs/original/...` in `.git/` if `--force` was not used; with `--force` it overwrites in place but preserves `.git/filter-repo/` tooling files. The bare clone is the safest restore path.

#### After T20 (public push) has executed and a third party has cloned

**Rollback is no longer feasible.** The public remote is now the canonical history. Options:

1. **Fix forward.** Add a new commit on top of the public history that addresses whatever surfaced. This is the only correct path for any post-push problem except an active credential leak.
2. **Take the repo private temporarily.** GitHub allows re-privatizing a repo. This does not unclone copies anyone has already pulled; it only stops new clones. Useful only if you must stop further distribution of an actively-leaking secret while you respond.
3. **Force-push a corrected history.** Possible mechanically, useless practically — anyone who already cloned has the bad history; collaborators see angry "your branch has diverged" messages; this approach is destructive and almost never the right call.

#### If a credential leak is discovered post-push

Treat the credential as compromised regardless. **Rotate immediately.** Forking and pull-cache services (GitHub, GHArchive, archive.org's GitHub mirror, dependabot scanners) will have copies. The fix is rotation, not history rewrite.

## Backup retention

After a successful Phase 4 push:

- Keep the `pre-filter-repo-backup` git tag in the local working repo for at least **30 days**.
- Keep the bare-clone backup at `/home/user/src/vulture-pre-filter-repo.git/` for at least **30 days** with the retention note from T20 Step 4.
- After 30 days, if no rollback was needed, delete both.

If the Phase 4 push is delayed (e.g., decisions are pending), the backup may be stale by the time Phase 4 actually runs; if the working repo has had any commits since the backup, refresh the bare clone immediately before T17.

## Verification after rollback

- For Phase 1/2/3 reverts: `make test` passes; `git log --oneline -10` shows the revert commits with clear messages.
- For Phase 4 pre-push restore: `git log --all --format='%h' | sort -u` matches the backup's commit list; `git ls-files | wc -l` matches; backups still readable.
- For post-push fix-forward: the new commit explicitly references the problem in its message and the audit/CHANGELOG records the issue and resolution.

## Roles and approvals

- **Phase 1/2/3 revert**: maintainer's discretion.
- **Phase 4 pre-push restore**: maintainer's discretion; ideally announce in the project chat/issue tracker if any collaborators are watching.
- **Phase 4 post-push fix-forward**: maintainer's discretion; if a credential leak, follow SECURITY.md disclosure timeline (acknowledge within 48h).
