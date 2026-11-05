# VULTUREIGNORE(5)

## NAME

`.vultureignore`, `default.vultureignore`: what a Vulture audit skips.

## SYNOPSIS

```
<scan root>/.vultureignore     your project's rules (read at the scan root only)
<any directory>/.gitignore     git's rules, read as git reads them
default.vultureignore          Vulture's defaults (root of the Vulture repository)
```

## DESCRIPTION

Vulture walks the scan root once and drops the paths these files exclude.
Everything that looks at the tree uses that one walk: every agent skill,
the model's file tools (`read_file`, `list_files`, `search_pattern`), the
L5 judge, discover's source plugins, and the copy of the source a
container plugin scans. A skipped path gets no findings and is never sent
to a model.

Use `.vultureignore` for files git tracks that an audit should not read:
recorded fixtures, vendored data, generated code. Use a `!` line in it to
bring back a folder Vulture skips by default.

Edits take effect on the next audit; nothing needs a restart.

## RULES

A path is skipped when any of these rules skips it:

```
1. ALWAYS   a symlink; a version-control store (.git .svn .hg .bzr);
            a Python virtualenv (any directory holding pyvenv.cfg)
2. PROJECT  the root .vultureignore; else the nearest .gitignore with a
            matching line. Within a file, the last matching line wins.
3. DEFAULT  a directory named in default.vultureignore
```

- A `!` line in the root `.vultureignore` overrides rules 2 and 3, never 1.
- A `!` line in a `.gitignore` overrides only `.gitignore` lines.
- A skipped directory is never entered, so nothing beneath it comes back.

## PATTERN FORMAT

The syntax is gitignore(5). In `.vultureignore`, paths are relative to the
scan root; in a `.gitignore`, to that file's directory.

| Pattern | Matches |
|---|---|
| `# text` | A comment. Blank lines are ignored too. |
| `name` | A file or directory called `name`, at any depth. |
| `name/` | A directory called `name`, at any depth. |
| `dir/name` | That path only. A `/` inside a pattern anchors it. |
| `/name` | `name` at the top level only. |
| `*.ext` | `*` and `?` match within one path segment; `[a-z]` matches one character. |
| `**/name`, `dir/**` | `**` matches any number of directories. |
| `!pattern` | Re-includes what an earlier line excluded. |
| `\#name`, `\!name` | A name that starts with `#` or `!`. |

## DEFAULTS

`default.vultureignore` lists the folders that are skipped when no project
file says otherwise:

- dependencies (`node_modules`, `vendor`, `.venv`);
- build output (`dist`, `build`, `target`, `.next`);
- caches (`__pycache__`, `.cache`);
- coverage and test reports (`coverage`, `test-results`);
- infrastructure state (`.terraform`);
- editor folders (`.vscode`, `.idea`, `.claude`);
- test data (`fixtures`, `testdata`, `snapshots`);
- backup copies (`*-backup`, `*_old`).

Read the file itself for the full list.

Words that projects use for their own code are not on the list: `data`,
`bin`, `env`, `mocks`, `out`, `lib`.

In the editor folders, the files that run when a folder is opened
(`.vscode/tasks.json`, `.idea/workspace.xml`, `.claude/settings.json`, ...)
are still read. They are not read if your own `.gitignore` or `.vultureignore`
skips the folder.

## EXAMPLES

Skip a generated folder, wherever it appears:

```gitignore
generated/
```

Skip one folder only:

```gitignore
web/public/legacy/
```

Skip a folder at the top level only:

```gitignore
/scripts/
```

Skip files by extension:

```gitignore
*.snap
```

Skip a folder's contents but keep one file. Skip the contents, not the
folder: `recordings/` would never be entered, and the `!` line could not
reach the file.

```gitignore
recordings/*
!recordings/keep.json
```

Scan a folder that Vulture skips by default:

```gitignore
!build/           # every directory named build
!web/build/       # this one only
!*-backup/        # backup copies too
```

Read all of an editor folder, not only its autorun files:

```gitignore
!.vscode/
```

Audit a file that git ignores (here, the `.gitignore` lists
`config/local.yml`):

```gitignore
!config/local.yml
```

Audit everything git ignores: set `VULTURE_IGNORE_GITIGNORE=true`.

## CHECKING

From a Vulture checkout, list the folders a scan skips:

```sh
cd agents
PYTHONPATH=shared .venv/bin/python - ~/src/myapp <<'EOF'
import sys
from shared.tools.file_scanner import pruned_dirs, scan_all_files
scan_all_files(sys.argv[1])
print("\n".join(pruned_dirs(sys.argv[1])))
EOF
```

Ask about one path. `True` means the audit reads it, provided its extension
is in the scan set.

```sh
PYTHONPATH=shared .venv/bin/python -c 'import sys
from shared.tools.file_scanner import walk_reaches
print(walk_reaches(*sys.argv[1:]))' ~/src/myapp ~/src/myapp/web/build/main.js
```

## ENVIRONMENT

- **`VULTURE_IGNORE_GITIGNORE=true`**: read no `.gitignore`, nested ones
  included. `.vultureignore` and `default.vultureignore` still apply.

## FILES

- **`<scan root>/.vultureignore`**: read at the scan root only. If you scan
  a sub-folder, that sub-folder's `.vultureignore` is read, not the
  repository's.
- **`<directory>/.gitignore`**: every one at or below the scan root is read.
  None is read from inside a skipped directory or through a symlink.
- **`default.vultureignore`**: Vulture's defaults, at the root of the
  Vulture repository. Each line is one directory-name glob ending in `/`,
  with no `!` and no `/` inside the name.

  The scanner, the backend and the opengrep plugin each build from their
  own directory, so each carries a byte-identical copy:
  `agents/shared/shared/tools/`, `backend/pkg/scanignore/` and
  `plugins/opengrep/src/`. Their tests fail if a copy differs from the root
  file. After editing the root file, copy it to all three:

  ```sh
  for d in agents/shared/shared/tools backend/pkg/scanignore plugins/opengrep/src; do
    cp default.vultureignore "$d/"
  done
  ```

## NOTES

- When a model asks for a skipped path, the tools answer "excluded ... do not
  treat this as evidence of absence", whether or not the file exists.
- Findings under a skipped directory stay open, because the scan reports
  that directory as not looked at. A finding in a skipped file is simply no
  longer reported, and lineage may close it as fixed. To hide a file without
  closing its findings, skip its directory.
- `.env`, `.env.*` and `.envrc` are scanned for secrets but never sent to a
  model, whatever the ignore files say.
- Lock files (`package-lock.json`, `poetry.lock`, ...) are walked but not
  scanned as code. The dependency checks still read them.
- Ignore files decide which paths are walked. Of the walked files, only
  those whose extension is in the scan set are scanned; add extensions with
  `VULTURE_EXTRA_EXTENSIONS`.

## CAVEATS

- In local mode, a container plugin scans a copy of the source that the
  backend stages. That copy understands every pattern above except a
  leading `/` and `**`. For rules that must also hold there, write
  `build/` or `web/build/`, not `/build/` or `**/build/`.
- Outside local mode, the opengrep plugin scans the source itself. It then
  applies only the defaults and the `!` lines of the root `.vultureignore`;
  any `!` line that names a folder brings back every folder of that name.

## SEE ALSO

gitignore(5), [offline_skills_gate.md](offline_skills_gate.md) (the
pre-commit gate applies the same rules), `CLAUDE.md` ("Scan-time
exclusion").
