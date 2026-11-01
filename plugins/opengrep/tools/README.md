# `vendor_rules.py`: bundling third-party rules

The plugin bundles Opengrep rules from two places, all listed with their sha256
and licence in `rules/RULESET_SNAPSHOT.json` (schema 2):

| Set | Folder (under `rules/`) | Licence |
|---|---|---|
| `vulture` | `vulture/` | Apache-2.0, Vulture-authored |
| `gitlab` | `third_party/gitlab/` | MIT, and Apache-2.0 for the gosec-derived `go/` files |
| `0xdea` | `third_party/0xdea/` | MIT |

elttam/semgrep-rules is not bundled although it is MIT: its LICENSE names
Semgrep as the copyright holder, and the plugin redistributes nothing of
Semgrep's.

Each third-party set holds its rule files at their upstream paths, its licence
text(s) and a `SOURCE.md` (upstream URL, commit, notes, and every file left out
with the reason). `tests/unit/test_ruleset_snapshot.py` fails the build if a
file drifts from its hash, if a rule file is not listed, or if anything but
MIT/Apache-2.0 content appears.

## The policy

Only rules whose licence is **MIT or Apache-2.0** are bundled. Never vendor:

- the Semgrep Registry (`p/...`, `r/...`, `semgrep.dev/r/...`) or semgrep-rules,
  in any form, nor a fork of it such as opengrep-rules (LGPL with the Commons
  Clause, or the Semgrep Rules License);
- copyleft rules (GPL, LGPL, AGPL), non-commercial or source-available terms, or
  anything whose provenance you cannot show;
- sample code, test targets, docs or CI files: rule files only.

If a set you want is not MIT or Apache-2.0, it does not go in. Do not edit a
vendored file to make it pass: the hashes pin the upstream bytes.

## What the tool does

`vendor_rules.py` is network-free and deterministic. It never fetches and never
executes anything from the clone; it reads `.git/HEAD` as a file to check the
commit.

`vendor` takes every `*.yml`/`*.yaml` under the `--include` folders of a local
clone, screens each one, copies the survivors byte for byte to
`rules/third_party/<set>/<path in the clone>`, copies the `--license-file`
texts, writes `SOURCE.md` and rewrites that set's entry in the snapshot. It
prints every exclusion. The screen, first reason wins:

1. `--exclude REL=REASON` (e.g. a rule the engine rejects);
2. a symlink;
3. no non-empty top-level `rules:` list (samples, manifests, CI files);
4. a forbidden marker anywhere in the file: Commons Clause, Semgrep Rules
   License, semgrep-rules, returntocorp, r2c, `semgrep.dev/r/` or `/p/`, GPL
   family, non-commercial;
5. a licence claim (`# License:` header or `license:` metadata) that is not MIT
   or Apache-2.0, or two claims that disagree (a file with no claim takes
   `--license`);
6. with `--lineage-corpus DIR` (a local clone of semgrep-rules or a fork, read as
   data only): a rule whose pattern clauses, at least three, all appear in one
   corpus rule after whitespace and metavariable names are normalised.

It refuses, writing nothing, when the clone's HEAD is not `--commit`, a folder
or set name is bad, an `--exclude` names no candidate, nothing survives, or a
licence used by the vendored files has no licence text.

`pin` hashes the in-tree `vulture` set under the same screen (failing instead
of excluding). Run it after editing a Vulture-authored rule:

```sh
python3 plugins/opengrep/tools/vendor_rules.py pin --set vulture --path vulture \
    --source Vulture-authored --license Apache-2.0
```

## Bumping a third-party set

1. **Clone it yourself, at the commit you want, outside the repo**:

   ```sh
   git clone https://gitlab.com/gitlab-org/security-products/sast-rules "$WORK/gitlab"
   git -C "$WORK/gitlab" checkout --detach <full-sha>
   ```

   Read its `LICENSE` and check it is still MIT (or Apache-2.0). For the
   lineage check, also clone semgrep-rules or opengrep-rules to `$WORK/lineage`.

2. **Run the tool** with the set's current flags, below. Carry the existing
   `--exclude` and `--note` lines over from the set's `SOURCE.md`; drop an
   exclusion whose file is gone (the tool refuses a stale one).

3. **Validate with Opengrep, offline.** `opengrep scan --validate` fetches
   `p/semgrep-rule-lints` from semgrep.dev, so do not use it. Load the set in a
   real scan inside a container with no network instead, and read the JSON
   `errors`:

   ```sh
   docker run --rm --network none -v "$OPENGREP_BIN:/usr/local/bin/opengrep:ro" \
       -v "$PWD/plugins/opengrep/rules:/rules:ro" -v "$EMPTY_DIR:/target:ro" debian:12-slim \
       sh -c 'HOME=/tmp opengrep scan --config /rules/third_party/<set>/<file> --json /target'
   ```

   A set-wide `--config` also reports rule parse errors, keyed by rule id; one
   run per file names each rejected file directly. For each rule Opengrep
   rejects, add an
   `--exclude <path>=Opengrep <version> rejects it: <error>` and run step 2 again.

4. **Review the diff**: `git diff --stat plugins/opengrep/rules`, the set's
   `SOURCE.md` exclusions, and every newly added rule file. Then run the tests:

   ```sh
   cd plugins/opengrep && python -m pytest tests/unit tools/tests -q
   ```

### Current flags per set

`$WORK/<set>` is your clone; run from `plugins/opengrep/`.

```sh
python3 tools/vendor_rules.py vendor --set gitlab --clone "$WORK/gitlab" \
    --commit 9c375dc49a7cd431e2b95c2620af651ef1d096a4 \
    --source https://gitlab.com/gitlab-org/security-products/sast-rules \
    --include csharp --include go --include java --include javascript \
    --include python --include scala --license MIT \
    --license-file "$WORK/gitlab/LICENSE:LICENSE" \
    --license-file rules/third_party/gitlab/LICENSE-APACHE-2.0:LICENSE-APACHE-2.0 \
    --lineage-corpus "$WORK/lineage" \
    --exclude "csharp/crypto/rule-CertificateValidationDisabled.yml=Opengrep 1.33.1 rejects it: rule parse error (invalid C# pattern)" \
    --note "..."   # the four Notes lines of third_party/gitlab/SOURCE.md

python3 tools/vendor_rules.py vendor --set 0xdea --clone "$WORK/0xdea" \
    --commit 60d33a2ab635e529fc7aad9328005c9ba8ac99d3 \
    --source https://github.com/0xdea/semgrep-rules \
    --include rules/c --license MIT --license-file "$WORK/0xdea/LICENSE:LICENSE" \
    --lineage-corpus "$WORK/lineage" \
    --note "..."   # the two Notes lines of third_party/0xdea/SOURCE.md
```

`LICENSE-APACHE-2.0` (gitlab) is the Apache License 2.0 text with a preamble
attributing the gosec-derived `go/` files; passing the in-tree file as its own
source keeps it as is.

When a set's upstream, commit or licence changes, update the third-party
attribution in the repository's `NOTICE` and `THIRD_PARTY_LICENSES.md` in the
same change.

## Testing

```sh
cd plugins/opengrep && python -m pytest tools/tests -q
```
