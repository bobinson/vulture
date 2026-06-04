# 0036 Phase 4 (T17–T18) — git history scrub runbook

**Status**: READY TO EXECUTE — destructive; the rewrite + push steps
require explicit operator authorization. Prep (de-literalize) landed in
commit `03a9260`.

**Verified topology (2026-06-04, HEAD `03a9260`)**:
- No git remote configured → pre-publication, no force-push-over-
  published-history risk.
- One worktree (`/home/user/src/vulture`).
- `.git` = 135 MB; HEAD-tracked ≈ 7 MB → history bloat from binaries.
- 118 commits.
- `git-filter-repo` NOT installed.

## What gets scrubbed

### Secrets (`--replace-text`)

All four are real historical default credentials. Three are history-
only; `REDACTED-DEV-PW` was de-literalized from HEAD in `03a9260` (guard now
compares by SHA-256) so it can be redacted everywhere.

```
# replacements.txt
REDACTED-DEV-PW==>REDACTED-DEV-PW
REDACTED-DEV-PW==>REDACTED-DEV-PW
REDACTED-PG-PW==>REDACTED-PG-PW
REDACTED-JWT-DEFAULT==>REDACTED-JWT-DEFAULT
```

**Deliberately NOT redacted** (not secrets — would corrupt the secret-
scanner's own test corpus, i18n placeholders, detector patterns):
`sk-*`, `AKIA*` (Amazon's documented `AKIAIOSFODNN7EXAMPLE`), `ghp_*`
(synthetic `ghp_secret123` in askpass_test), `xoxb-*`, and the
`nvapi-...` literal in `scripts/start.sh` help text. The pasted live
NVIDIA key was **never committed** (verified).

### Bloat (`--invert-paths`) — all confirmed not-at-HEAD

```
backend/vulture                                   (17 MB ×2)
cli/vulture                                       (9 MB ×2)
verification/bin/simulated-target                 (7 MB)
docs/features/0014_cwe_version_4.19.1/cwe_latest.pdf   (37 MB)
docs/features/0010_cwe_audit/cwec_v4.19.1.xml          (16 MB)
```

**Excluded** (tracked at HEAD, needed): `agents/cwe/cwe_agent/data/cwe_catalog.json`.
Expected `.git`: 135 MB → < 10 MB.

## Procedure

### 0. Install the tool
```bash
pipx install git-filter-repo            # preferred (PEP-668 safe)
# or: sudo apt install git-filter-repo
# or: curl the single script onto PATH from github.com/newren/git-filter-repo
git filter-repo --version               # confirm
```

### 1. Backup (restore point — do not skip)
```bash
git clone --mirror /home/user/src/vulture /home/user/src/vulture-backup.git
```

### 2. Rewrite a fresh CLONE, not the original
The original `/home/user/src/vulture` stays pristine until verified.
```bash
git clone /home/user/src/vulture /home/user/src/vulture-clean
cd /home/user/src/vulture-clean
printf '%s\n' \
  'REDACTED-DEV-PW==>REDACTED-DEV-PW' \
  'REDACTED-DEV-PW==>REDACTED-DEV-PW' \
  'REDACTED-PG-PW==>REDACTED-PG-PW' \
  'REDACTED-JWT-DEFAULT==>REDACTED-JWT-DEFAULT' \
  > /tmp/replacements.txt

# Pass 1 — secrets
git filter-repo --replace-text /tmp/replacements.txt

# Pass 2 — bloat eviction
git filter-repo --invert-paths \
  --path backend/vulture \
  --path cli/vulture \
  --path verification/bin/simulated-target \
  --path docs/features/0014_cwe_version_4.19.1/cwe_latest.pdf \
  --path docs/features/0010_cwe_audit/cwec_v4.19.1.xml
```

### 3. Verify (all must pass before any push)
```bash
# (a) zero secret hits across ALL history
for s in REDACTED-DEV-PW REDACTED-DEV-PW REDACTED-PG-PW \
         REDACTED-JWT-DEFAULT; do
  echo -n "$s: "; git log --all -S "$s" --oneline | wc -l    # must be 0
done
git grep -F REDACTED-DEV-PW $(git rev-list --all) ; echo "exit=$?"  # must be empty / exit 1

# (b) size dropped
du -sh .git                                                     # expect < 10 MB

# (c) commit count preserved (no commits dropped)
git rev-list --all --count                                     # expect 118

# (d) tree integrity — build + test the rewritten clone
cd backend && go build ./... && go vet ./... && go test ./... -short
cd ../agents/shared && /path/to/.venv/bin/python -m pytest tests/unit/ -q
cd ../../frontend && npx tsc --noEmit && npx vitest run
```

### 4. Adopt + push (T19–T20 — SEPARATE authorization)
Only after step 3 is fully green:
```bash
# tag the release
git tag -a v0.1.0 -m "Vulture v0.1.0"
# point at the fresh PUBLIC repo (slug TBD — bobinson/vulture)
git remote add origin git@github.com:<slug>/vulture.git
git push origin master --tags          # first publication: normal push, no force
```
Then make `vulture-clean` the canonical working copy (or re-clone from
the new remote). Retain `vulture-backup.git` until the public repo is
confirmed good.

## Rotation
The four scrubbed values are dev/local defaults; HEAD already fail-closes
on an unset JWT secret and rejects the weak dev password by hash. Rotate
any real deployment that ever used them (likely none in production).

## Rollback
Any verification failure → discard `vulture-clean`; the original repo is
untouched. Full restore if ever needed: re-clone from
`vulture-backup.git`.

## Residual risk
`--replace-text` redacts the secret bytes but the surrounding commit
messages/diffs remain (now showing `REDACTED-*`). The four values are
low-value local defaults, so this is acceptable. The only irreversible
step is the public `git push` (step 4) — gated on explicit authorization.
