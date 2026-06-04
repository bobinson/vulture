# 0036 Phase 4 (T17–T18) — git history scrub runbook

**Status**: READY TO EXECUTE — destructive; the rewrite + push steps
require explicit operator authorization. Prep (de-literalize) landed in
commit `03a9260`. **Security-reviewed 2026-06-04** — the review caught
that the first draft would have leaked secrets via commit messages
(`--replace-text` is blob-only) and via 3 unscrubbed side branches; both
fixed below (`--replace-message`, `--single-branch master`), plus the
current `REDACTED-SMOKE-PW` credential added and message/scanner
verification gates.

**Verified topology (2026-06-04, HEAD `03a9260`)**:
- No git remote configured → pre-publication, no force-push-over-
  published-history risk.
- One worktree (`/home/user/src/vulture`).
- `.git` = 135 MB; HEAD-tracked ≈ 7 MB → history bloat from binaries.
- 118 commits.
- `git-filter-repo` NOT installed.

## What gets scrubbed

### Secrets (`--replace-text` AND `--replace-message`)

**CRITICAL:** `--replace-text` rewrites file blobs ONLY. Commit/tag
messages need `--replace-message` with the SAME file. Verified: commits
`154f957` ("...(REDACTED-DEV-PW)") and `612b4b2` ("rotate local-dev password
REDACTED-DEV-PW -> REDACTED-DEV-PW") carry secrets in their messages — a
blob-only scrub leaves them public.

```
# replacements.txt  (used for BOTH --replace-text and --replace-message)
REDACTED-DEV-PW==>REDACTED-DEV-PW
REDACTED-DEV-PW==>REDACTED-DEV-PW
REDACTED-PG-PW==>REDACTED-PG-PW
REDACTED-JWT-DEFAULT==>REDACTED-JWT-DEFAULT
REDACTED-SMOKE-PW==>REDACTED-SMOKE-PW
REDACTED-SMOKE-PW==>REDACTED-SMOKE-PW
```

All are historical/ephemeral default credentials. `REDACTED-DEV-PW` was
de-literalized from HEAD in `03a9260` (guard now compares by SHA-256).
`REDACTED-SMOKE-PW` is a current ephemeral smoke-test pg password
(`scripts/mode-b-smoke.sh:102`); the script sets and uses it
symmetrically, so redacting the literal keeps it self-consistent. (TODO
follow-up: parameterize that script to read the password from env.)

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

### 2. Rewrite a fresh, master-ONLY clone — not the original
`--single-branch --branch master --no-local` so the scrub repo contains
ONLY master (the 3 other branches — feat/0031, feat/0039, perf/fix —
carry the same secrets, including in messages, and must never be
published). `--no-local` fully isolates the object store from the
original.
```bash
git clone --single-branch --branch master --no-local \
  /home/user/src/vulture /home/user/src/vulture-clean
cd /home/user/src/vulture-clean
git branch -a    # MUST show only master, no remotes/* — abort if not

printf '%s\n' \
  'REDACTED-DEV-PW==>REDACTED-DEV-PW' \
  'REDACTED-DEV-PW==>REDACTED-DEV-PW' \
  'REDACTED-PG-PW==>REDACTED-PG-PW' \
  'REDACTED-JWT-DEFAULT==>REDACTED-JWT-DEFAULT' \
  'REDACTED-SMOKE-PW==>REDACTED-SMOKE-PW' \
  'REDACTED-SMOKE-PW==>REDACTED-SMOKE-PW' \
  > /tmp/replacements.txt

# SINGLE pass — text (blobs) + message (commit/tag) + path eviction.
# Combined to avoid filter-repo's "already ran" refusal on a 2nd pass.
git filter-repo \
  --replace-text    /tmp/replacements.txt \
  --replace-message /tmp/replacements.txt \
  --invert-paths \
  --path backend/vulture \
  --path cli/vulture \
  --path verification/bin/simulated-target \
  --path docs/features/0014_cwe_version_4.19.1/cwe_latest.pdf \
  --path docs/features/0010_cwe_audit/cwec_v4.19.1.xml

# Drop the stale internal tag (points at a pre-rewrite commit; do NOT
# publish it) and force-prune residual objects.
git tag -d pre-0031-merge 2>/dev/null || true
git reflog expire --expire=now --all && git gc --prune=now --aggressive
```

### 3. Verify (ALL must pass before any push)
```bash
SECRETS='REDACTED-DEV-PW REDACTED-DEV-PW REDACTED-PG-PW REDACTED-JWT-DEFAULT REDACTED-SMOKE-PW REDACTED-SMOKE-PW'

# (a) zero hits in blob DIFFS across all history
for s in $SECRETS; do echo -n "$s diff: "; git log --all -S "$s" --oneline | wc -l; done   # all 0

# (b) zero hits in reachable blob TREES (catches content -S might miss)
for s in $SECRETS; do echo -n "$s tree: "; git grep -F "$s" $(git rev-list --all) 2>/dev/null | wc -l; done   # all 0

# (c) zero hits in COMMIT + TAG MESSAGES (the D1 gap — must check explicitly)
for s in $SECRETS; do echo -n "$s msg: "; git log --all --format='%H%n%s%n%b' | grep -cF "$s"; done   # all 0

# (d) independent scanner as the final gate (install gitleaks first)
gitleaks detect --source . --config .gitleaks.toml --log-opts="--all" --no-banner    # exit 0 / no leaks

# (e) only master, no stray refs, stale tag gone
git branch -a            # master only
git tag                  # empty (v0.1.0 added later, in step 4)

# (f) size dropped + bloat blobs gone
du -sh .git                                                    # < 10 MB
git rev-list --all --objects | grep -E 'backend/vulture|cli/vulture|simulated-target|cwe_latest.pdf|cwec_v4.19.1.xml'   # empty

# (g) commit count: invert-paths may prune now-empty (binary/data-only)
#     commits, so a SMALL drop from 118 is expected — enumerate + sanity-check,
#     don't assert equality.
echo "commits: $(git rev-list --all --count) (was 118; a few pruned binary/data-only commits are OK)"

# (h) tree integrity — the rewritten clone must build + test green
cd backend && go build ./... && go vet ./... && go test ./... -short
cd ../agents/shared && /home/user/src/vulture/agents/.venv/bin/python -m pytest tests/unit/ -q
cd ../../frontend && npx tsc --noEmit && npx vitest run
```

### 4. Adopt + push (T19–T20 — SEPARATE authorization)
Only after EVERY check in step 3 is green. Push ONLY from
`vulture-clean` — never from `/home/user/src/vulture` (still dirty).
```bash
cd /home/user/src/vulture-clean        # confirm you are in the CLEAN clone
pwd                                     # MUST end in /vulture-clean

# Pre-push secret re-scan as a hard gate (belt-and-suspenders).
gitleaks detect --source . --config .gitleaks.toml --log-opts="--all" --no-banner || { echo "ABORT: leak"; exit 1; }

git tag -a v0.1.0 -m "Vulture v0.1.0"
git remote add origin git@github.com:<slug>/vulture.git   # slug: resolve AUTHORS.md first
git push origin master                  # NOT --tags blindly
git push origin v0.1.0                  # publish only the release tag

# Quarantine the dirty original so it can never be pushed by mistake.
mv /home/user/src/vulture /home/user/src/vulture-DIRTY-DO-NOT-PUSH
# Adopt the clean repo as canonical (or re-clone from the new remote).
```
Retain `vulture-backup.git` (PRIVATE — contains every secret; never
push or share it) until the public repo is confirmed good, then delete.

## Rotation
The four scrubbed values are dev/local defaults; HEAD already fail-closes
on an unset JWT secret and rejects the weak dev password by hash. Rotate
any real deployment that ever used them (likely none in production).

## Rollback
Any verification failure → discard `vulture-clean`; the original repo is
untouched. Full restore if ever needed: re-clone from
`vulture-backup.git`.

## Residual risk
- Commit/tag messages ARE scrubbed (`--replace-message`), and verified
  explicitly in step 3(c). Diffs/messages now show `REDACTED-*`.
- The six scrubbed values are low-value local/ephemeral defaults; HEAD
  already fail-closes on an unset JWT secret and rejects the weak dev
  password by hash. Rotate any real deployment that used them.
- The only irreversible step is the public `git push` (step 4), gated on
  explicit authorization. The original repo is quarantined post-push so
  it can't be pushed by mistake, and `gitleaks` runs as a hard pre-push
  gate.
- If `gitleaks` surfaces any secret class not in `replacements.txt`
  (e.g. a value this review didn't enumerate), STOP, add it, and re-run
  the rewrite from the backup — do not push.
