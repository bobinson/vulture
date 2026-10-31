# Offline Skills Gate (`vulture-offline-skills`)

`vulture-offline-skills` runs Vulture's deterministic CWE skills over a list of
files on the local machine, with **no backend, no database and no LLM**. It is
meant for a pre-commit hook or a CI job that should fail when a change
introduces a security issue at or above a chosen severity.

It is not a replacement for a full audit. It scans only the files you pass it,
runs only the CWE agent's skills, and never runs the LLM tier or the L5 judge.
Within that scope it gives the verdict the full audit would give with the LLM
off: the same skill set (`SKILL_MAP`), the same secret redaction, the same
collapse of duplicate rows on one line, and the same deterministic validate
stage (L1/L2). For example, a `# nosec` waiver marks a finding `likely_fp` and
it does not block.

---

## Install

The command is the `cwe_agent.offline` module of the CWE agent, which needs the
`shared` library next to it. Neither first-party package is published to any
package index, so both load from a Vulture checkout. Do not let pip resolve
`vulture-shared` from an index: nothing there is ours, and whatever claims the
name would run inside your hook.

The recommended install fetches nothing first-party from an index and builds
nothing. It pins the checkout to a release, installs only the third-party
dependencies from the hashed lockfile into a dedicated virtualenv (the lockfile
pins the union of every agent's dependencies, so keep it out of a shared
environment), and loads the two packages through `PYTHONPATH`, as the lockfile's
header describes:

```bash
git clone --branch <release-tag> https://github.com/bobinson/vulture.git
python3.12 -m venv ~/.venvs/vulture-gate
~/.venvs/vulture-gate/bin/python -m pip install --require-hashes -r vulture/agents/requirements-frozen.txt
PYTHONPATH=vulture/agents/cwe:vulture/agents/shared ~/.venvs/vulture-gate/bin/python -m cwe_agent.offline --help
```

`<release-tag>` is the first release that contains this command (feature
0098); until one is tagged, clone without `--branch` and run `git checkout <commit-sha>`
inside the clone. Use absolute paths in
`PYTHONPATH` when the hook runs from another directory.

For a `vulture-offline-skills` console script on the virtualenv's `PATH`,
install the two packages as well, after the lockfile and without their
dependencies:

```bash
~/.venvs/vulture-gate/bin/python -m pip install --require-hashes -r vulture/agents/requirements-frozen.txt
~/.venvs/vulture-gate/bin/python -m pip install --no-deps -e vulture/agents/shared -e vulture/agents/cwe
~/.venvs/vulture-gate/bin/vulture-offline-skills --help
```

This form builds the packages, so pip fetches their build backend (`hatchling`)
from the index, unpinned, even with `--no-deps`. Use the `PYTHONPATH` form where
that matters.

In a Vulture development checkout, the agents virtualenv already holds both
packages. An environment created before this command existed has no console
script until it reinstalls the CWE package
(`cd agents && python -m pip install --no-deps -e cwe/`, or
`make build-agents-force`). The module form needs no console script:

```bash
python -m cwe_agent.offline --help
```

The Docker images and the native installer (Mode E) do not put the command on
the host `PATH`. Use one of the installs above for a host-side hook.

---

## Usage

```
vulture-offline-skills [--root DIR] [--severity LEVEL] [--format text|json] FILE...
```

| Option | Default | Meaning |
|--------|---------|---------|
| `FILE...` | (required) | Files to scan, usually the staged or changed files. A directory is a usage error, except a submodule (see below). |
| `--root DIR` | nearest directory above the cwd that holds `.git`, else the cwd | Repository root. Files under it keep their root-relative paths. |
| `--severity LEVEL` | `high` | Lowest severity that blocks: `info`, `low`, `medium`, `high` or `critical` (any case). Any other value is a usage error. |
| `--format` | `text` | `text` prints the blocking findings. `json` prints the full report described below. |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No finding is at or above `--severity`, or every such finding was dismissed by validation (`likely_fp`). Also `0` when none of the files is one the scanner reads (only images, a lock file, a submodule): stdout then says `Nothing to gate: 0 of N file(s) scanned` instead of `No blocking findings.` |
| `1` | At least one blocking finding. |
| `2` | Tool or usage error. A skill or the validate stage failed, a `FILE` does not exist or is a directory (an empty directory counts, unless `.gitmodules` declares it a submodule), `--root` is not a directory, a file could not be read, the report could not be written (stdout closed; a stdout already closed at startup is found before anything is scanned), no neutral temporary directory was available, or the working directory is inside a directory an audit of the discovered root prunes and every file passed is under it (see below). The verdict is withheld. Treat this as a failure, not a pass. |

A run stopped by SIGTERM or SIGHUP, for example by a hook timeout or a
cancelled CI job, removes its temporary copy and exits `128 + signal`. Once that
removal has started, a second SIGTERM, SIGHUP or Ctrl-C cannot interrupt it. A
signal the caller ignores (`nohup`) stays ignored.

### Output

In text mode, stdout lists each blocking finding (severity, `path:line`, title
and check id), then a verdict line. In both formats stderr shows the resolved
root, any skill failures (`Skill <name> failed: <message>`), each file outside
the root, how many files were scanned, and each file that was not scanned, with
the reason. stderr is advisory: if it cannot be written (a full disk, a closed
pipe), the notes are dropped and the exit code and stdout are unchanged.

Text that reaches a terminal is escaped. A control character (C0, DEL, C1), a
format character (every bidi control, zero-width and joiner marks, the soft
hyphen), a line or paragraph separator, or an undecodable byte in a file name, a title or an
error message is printed as its escape (`\x1b`, `\u202e`, `\udcff`), in stdout,
in the stderr notes and in argparse's own usage errors, so a file name cannot
rewrite the line it is printed on. The JSON report escapes them too.

`--format json` prints one object to stdout, with the same stderr notes.

```json
{
  "schema": 1,
  "root": "/home/me/project",
  "severity": "high",
  "findings": [ { "check_id": "cwe.injection.command", "severity": "critical", "file_path": "/home/me/project/src/run.py", "line_start": 5, "validation_status": "suspicious", "...": "..." } ],
  "blocking": [ "the subset of findings that decided the exit code" ],
  "errors": [ { "skill": "injection", "error": "message" } ],
  "scanned": [ "/home/me/project/src/run.py" ],
  "not_scanned": [ { "path": "/home/me/project/web/app.min.js", "reason": "minified or bundled artefact" } ],
  "outside_root": [ "/home/me/elsewhere/helper.py" ]
}
```

- `findings` are in the audit's finding shape: `id`, `check_id`, `category`,
  `severity`, `file_path`, `line_start`, `code_snippet`, `provenance`,
  `validation_status` and `validation`. They cite the real paths you passed,
  never the temporary copy. They include the L2 rollup parents
  (`is_rollup: true`) the full audit reports.
- `blocking` holds the findings at or above `severity` whose
  `validation_status` is not `likely_fp`, leaving out rollup parents: a parent
  only groups member rows that are listed themselves.
- `errors` lists each failed skill (`{"skill", "error"}`) or failed stage
  (`{"stage": "validate", "error"}`). A non-empty list means exit code `2`.
  When the validate stage fails, `findings` is empty: those rows never
  finished post-processing. `{"stage": "root", "error"}` means the discovered
  root prunes the directory you work in (see "A project inside a pruned
  directory" below).
- `outside_root` lists the files that lie outside the root (see below).

**Secrets in the report.** The masking is the full audit's, applied to every
row: a secret finding masks the values on its own lines, every other row's
`code_snippet` masks the lines a secret finding cites (a cited row the
structured redactor cannot mask, such as a bare key-body row, is replaced
whole), and every row's `code_snippet` and `description` mask secret-shaped
values: provider tokens, JWTs, `Bearer`/`Basic` credentials, credentials in a
URL, private-key bodies, and a hex value after a credential-named key. Commit
SHAs, image digests, UUIDs, hashes and prose are evidence and are not masked.
A free-form password on a line no
secret finding cites cannot be recognised by its shape, so treat the JSON
report as sensitive and do not publish it as a public artifact.

---

## What is scanned, and what is not

The skills walk a directory, not a list of files. The command therefore copies
the files into a private temporary directory and scans that:

- **Files under the root** keep their root-relative path. Path-aware rules
  still see their directories: the editor-autorun skill reads
  `.claude/settings.json` only under `.claude/`, and test detection reads
  `tests/` and `e2e/`. The root's own `.gitignore` and `.vultureignore` (the
  working-tree copies, whether staged or not) are copied alongside, so ignored
  paths are skipped exactly as in a full audit. An ignore file anywhere else,
  such as a nested one or one outside the root, has no effect. This is also
  the full audit's behaviour.
- **Files outside the root** go into a separate tree, one numbered directory
  per source directory, so they can never collide with a repository path. They
  lose the directories above them, so test detection and ignore files do not
  apply to them, and stderr names each one. An editor autorun file
  (`.vscode/tasks.json`, `.claude/settings.json`, ...) keeps the directories
  its pattern names and is scanned as one.
- **Submodules.** `git diff --name-only` lists a submodule bump as the
  submodule's path. A directory argument that holds a `.git` entry (an
  initialised submodule), or that the nearest enclosing repository's
  `.gitmodules` declares with a `path` entry in a `[submodule "..."]` section
  (an uninitialised one; read as git reads it: the key in any case, a quoted
  value unquoted, a trailing `;` or `#` comment dropped), is
  reported as not scanned rather than refused. Both are read from the files,
  so `git` need not be on `PATH`. Any other directory, an empty one included,
  is a usage error. Scan a submodule's own changes in its own repository.

A file is reported as **not scanned** when the scanner never reads it:

| Reason | Example |
|--------|---------|
| submodule (git link) | `lib` in a commit that bumps the `lib` submodule. |
| symlink (not followed) | `settings.py -> ~/.aws/credentials`. The full audit's walker skips every symlink, and git commits only the link. The target is never read. |
| ignored or pruned path (`<dir>/`) | a file under a pruned directory (`vendor/`, `build/`, `data/`, ...) or under a directory the root's `.gitignore` / `.vultureignore` ignores. |
| extension outside the scan set | `logo.png`, `blob.bin`. |
| minified or bundled artefact | `app.min.js`, or a hash-named chunk whose lines are bundle-length. |
| exceeds the scanner's read size cap (not copied) | a source file over `VULTURE_MAX_FILE_SIZE` (512KB), or a dependency manifest over `VULTURE_MAX_MANIFEST_SIZE` (16MB). |
| not read by any skill | anything else no skill opened, such as a file the root's ignore files match by name. |

A file can have more than one reason (`extension outside the scan set; exceeds
the scanner's read size cap (not copied)`); they are listed in that order.

"Not scanned" comes from the scanner itself: the command records which files
the skills actually read, and the reason comes from the walker's own
predicates. It does not re-implement the scanner's rules.

**Content no reader takes is never copied.** A file over its read cap (the
manifest cap for a dependency manifest, the source cap for anything else) is
staged as a sparse stand-in of exactly that cap plus one byte, holding none of
its content. Every reader refuses it by its size, as it would refuse the
original, while a check that needs only the NAME still sees it: a database
under `public/` (`public/app.sqlite`) is flagged as a served sensitive file
however large it is, as in the full audit. A file within its read cap is
copied as is, even when its extension is outside the scan set: a skill with a
narrower or wider set of its own may still read it.

The verdict does not depend on where the temporary directory lives. Skills
classify test, fixture, generated, documentation and vendored files by the
absolute path, and some suppress findings by a path glob (`*/docs/*`,
`*/example*`). The command therefore uses a temporary directory under `$TMPDIR`
only when its whole path is classified by none of them (`tests`, `e2e`,
`fixtures`, `docs`, `example...`, `vendor`, ...). Otherwise it falls back to
`/tmp` or `/var/tmp`, and it exits `2` if none of them qualifies.

### Limitation: the root's own location still counts

The skills see only root-relative paths, but the validate stage classifies
each finding by its real, absolute path, as the full audit does. A repository
checked out under a directory named like a test, docs, data or build directory
(`~/tests/project`, `/data/project`) therefore has its findings demoted, and
some may become `likely_fp` and stop blocking. The full audit of the same
checkout demotes them too, and its skills also skip more files there. Keep the
checkout the gate runs on under a plainly named directory.

### A project inside a pruned directory

Pruning is relative to the root, as in a full audit of that root. A project
checked out at `<repo>/build/proj` (or under `vendor/`, `data/`, ...) is
therefore never scanned when the root is `<repo>`, and a full audit of `<repo>`
skips it too. When the root was DISCOVERED (no `--root`), the working directory
is inside such a directory, and every file you pass under the root is under it,
the command does not report "Nothing to gate". It exits `2` with
`errors[].stage == "root"`, naming the directory. Pass `--root` (for example
`--root .`) to gate the project as its own root. When only some of the files
are under the pruned directory, those are listed as not scanned
(`ignored or pruned path (build/)`) and the rest decide the verdict.

### Limitation: per-CWE caps in the catalog tier

The catalog tier (`check_catalog_generic`: the keyword rows `cwe.catalog.cwe_<N>`,
the signature rows `cwe.sig.*`, and the Class/Pillar rollups
`cwe.catalog.cwe_<N>.rollup`) reports each CWE in at most
8 files per CWE per scanned tree, in path order, as the full audit does for the
same set of files.
Files outside the root, and each editor autorun tree, are scanned and counted
separately. A file's catalog rows can therefore depend on which other files are
passed with it: in a large change, a ninth file matching the same CWE gets no
catalog row for it. The dedicated skills (injection, secrets, access control,
...) have no such cap. Gate on them, and run a full audit for catalog coverage
of a large change.

### Limitation: it reads the working tree

The command reads files from disk, not from the git index. When a file is only
partially staged, the working-tree copy is scanned. A vulnerable hunk can then
be committed while a clean edit stays unstaged, and the reverse also happens.

- With **lefthook**, keep the hook on the staged content. Recent lefthook
  versions hide the unstaged changes of partially staged files while
  `pre-commit` runs. Check that your version does. Otherwise stash them
  yourself (`git stash push --keep-index --include-untracked`) around the
  command.
- For an exact check of the index regardless of hook manager, scan a checkout
  of the index:

  ```bash
  #!/usr/bin/env bash
  tmp=$(mktemp -d)
  git diff --cached --name-only --diff-filter=ACMR -z > "$tmp/.files"
  mapfile -d '' files < "$tmp/.files"
  [ "${#files[@]}" -eq 0 ] && { rm -rf "$tmp"; exit 0; }
  git checkout-index --prefix="$tmp/tree/" -z --stdin < "$tmp/.files"
  git checkout-index --prefix="$tmp/tree/" -- .gitignore .vultureignore 2>/dev/null
  (cd "$tmp/tree" && vulture-offline-skills --root . "${files[@]}"); rc=$?
  rm -rf "$tmp"; exit $rc
  ```

  Findings then cite paths under the temporary checkout. Pass the file list as
  arguments, not through `xargs`: `xargs` turns every non-zero exit into `123`
  and loses the distinction between `1` and `2`.

CI scans a checkout, where the working tree is the commit, so this limitation
does not apply there.

---

## Pre-commit hook (lefthook)

```yaml
# lefthook.yml (the recommended PYTHONPATH install; use absolute paths)
pre-commit:
  commands:
    vulture-offline-skills:
      run: PYTHONPATH=/opt/vulture/agents/cwe:/opt/vulture/agents/shared ~/.venvs/vulture-gate/bin/python -m cwe_agent.offline {staged_files}
```

`/opt/vulture` stands for wherever you cloned the checkout. With the
console-script install, `run: vulture-offline-skills {staged_files}` does the
same.

A path that does not exist is exit code `2`, so a deleted file must not be
passed. A submodule path is fine: it is reported as not scanned. If your hook manager lists deleted files among the staged ones, build
the list with `git diff --cached --name-only --diff-filter=ACMR` instead. Root
discovery finds the
repository from the hook's working directory, so a `root:` subdirectory works
unchanged. `git` itself is not needed on `PATH`.

## CI (GitHub Actions)

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: actions/setup-python@v5
  with:
    python-version: "3.12"
- name: Install the offline gate
  run: |
    git clone --depth 1 --branch <release-tag> https://github.com/bobinson/vulture.git "$RUNNER_TEMP/vulture"
    python -m venv "$RUNNER_TEMP/gate-venv"
    "$RUNNER_TEMP/gate-venv/bin/python" -m pip install --require-hashes -r "$RUNNER_TEMP/vulture/agents/requirements-frozen.txt"
- name: Gate on changed files
  shell: bash
  env:
    PYTHONPATH: ${{ runner.temp }}/vulture/agents/cwe:${{ runner.temp }}/vulture/agents/shared
  run: |
    mapfile -d '' files < <(git diff --name-only -z --diff-filter=ACMR "origin/${{ github.base_ref }}...HEAD")
    [ "${#files[@]}" -eq 0 ] && exit 0
    "$RUNNER_TEMP/gate-venv/bin/python" -m cwe_agent.offline --format json "${files[@]}" > offline-gate.json
```

The clone is pinned to a release (`--branch <release-tag>`, see Install) for
reproducible verdicts, and nothing first-party is resolved from an index. Exit code
`2` fails the job just like `1`. Inspect `errors` in the JSON report to tell a
broken gate from a blocked change. For a whole-repository audit with the LLM
tier, history and lineage, use the server-backed `vulture scan` flow in
[ci_integration.md](ci_integration.md).
