# `semgrep_rules_to_cwe.py` — YAML → `rule_to_cwe.json` converter

Closes the documented residual in 0050 v1.1 status doc: plugin
authors shouldn't have to hand-curate `rules/rule_to_cwe.json` from
upstream Semgrep packs. This script walks one or more directories
(or individual `.yaml` / `.yml` files), extracts every rule's
`metadata.cwe`, and emits the canonical mapping-file shape that
Vulture's 0050 v1.1 loader consumes.

## Usage

```sh
# Convert all rules under a Semgrep pack directory:
python3 plugins/semgrep/tools/semgrep_rules_to_cwe.py \
    /path/to/semgrep-rules/python > rules/rule_to_cwe.json

# Convert multiple packs at once (deterministic; first-seen wins on
# duplicate rule_id):
python3 plugins/semgrep/tools/semgrep_rules_to_cwe.py \
    /path/to/semgrep-rules/python \
    /path/to/semgrep-rules/javascript \
    /path/to/semgrep-rules/go \
    > rules/rule_to_cwe.json
```

## What it does

For each YAML rule file it finds, it walks the `rules:` array and
extracts pairs of:

- `id` — the Semgrep rule ID (e.g. `python.django.security.unsafe-raw-sql`)
- `metadata.cwe` — Semgrep ships this as a list of descriptive
  strings (`["CWE-89: Improper Neutralization of Special Elements…"]`).
  The script extracts just `CWE-89` via the regex `^(CWE-\d{1,5})\b`.

Rules without an extractable CWE are silently skipped. Output is
deterministic — entries sorted by rule ID.

## Output shape

The canonical `{schema_version, entries}` JSON the 0050 v1.1 loader
expects:

```json
{
  "schema_version": "1",
  "entries": {
    "python.django.security.unsafe-raw-sql": "CWE-89",
    "python.lang.security.audit.dangerous-system-call": "CWE-78"
  }
}
```

The 0050 v1.1 loader (`backend/internal/cwe/loader.go`) handles
schema-version validation, cardinality cap (10000 entries),
path-traversal safety, and per-entry CWE format checks.

## Plugin author workflow

To re-generate the bundled Semgrep plugin's mapping file from a fresh
upstream Semgrep release:

```sh
# 1. Pull the upstream rule packs (whatever languages you care about)
git clone https://github.com/semgrep/semgrep-rules /tmp/semgrep-rules

# 2. Run the converter for the languages your plugin supports
python3 plugins/semgrep/tools/semgrep_rules_to_cwe.py \
    /tmp/semgrep-rules/python \
    /tmp/semgrep-rules/javascript \
    /tmp/semgrep-rules/go \
    /tmp/semgrep-rules/java \
    > plugins/semgrep/rules/rule_to_cwe.json

# 3. Restart Vulture; new mappings load on next backend start
```

## Testing

```sh
python3 -m pytest plugins/semgrep/tools/tests/ -q
```

16 tests cover every documented input shape (list of strings,
scalar, missing, unparseable, malformed YAML, directory walk,
deterministic output, JSON round-trip).
