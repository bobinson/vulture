"""Feature 0070 P8 — secrets group: CWE-260 and CWE-526.

Both ids ride on the *name-shape* arm of ``secret_scan/config_files.py`` —
the arm that fires when a key NAME implies a credential and the value is a
non-placeholder literal. Before this change every such row was reported as
CWE-798 regardless of what carried it. That is one label for three
materially different findings:

* a password sitting in an application config file — CWE-260;
* any secret bound into a process ENVIRONMENT VARIABLE (Dockerfile
  ``ENV``/``ARG``, a YAML ``env:``/``environment:`` block) — CWE-526,
  where the extra exposure is the image layer / CI log / ``ps`` output,
  not the file;
* everything else — CWE-798, unchanged.

The three arms are a PARTITION: ``_classify`` returns exactly one rule per
(key, value) pair, so no line can ever carry two of these sibling rows.
That one-row invariant is asserted here, not assumed.

The other thing pinned here is the shell-expansion guard. The compose idiom

    - OPENAI_API_KEY=${AGENT_OPENAI_API_KEY-${OPENAI_API_KEY}}

is an indirection, not a literal, but the shared ``is_variable_reference``
helper only understands a FLAT ``${VAR}`` / ``${VAR:-default}`` — a nested or
``:?``-guarded expansion fell through it and was reported as a hardcoded
secret. On one real tree that single shape is 30 rows, all wrong, and every
one of them arrives with the env-block arm. ``_EXPANSION`` is what stops it,
so it is tested with the exact nested shapes rather than a toy ``$VAR``.
"""

from __future__ import annotations

from pathlib import Path

from cwe_agent.skills.secret_scan import config_files


def _scan(content: str, path: str) -> list[dict]:
    return config_files.find_config_secrets(Path(path), content)


def _cats(findings: list[dict]) -> list[str]:
    return [f["category"] for f in findings]


# ── CWE-260: password in a configuration file ────────────────────────────
class TestPasswordInConfigFile:
    def test_json_password_key_is_cwe_260(self):
        content = '{"database": {"user": "svc", "password": "Zt4qL9pR2sX7"}}'
        findings = _scan(content, "settings.json")
        assert _cats(findings) == ["CWE-260"]
        assert findings[0]["check_id"] == "cwe.secret_scan.config.password_in_config_file"

    def test_yaml_passwd_alias_is_cwe_260(self):
        findings = _scan("mail:\n  passwd: Hh38kQm2Vp01\n", "settings.yaml")
        assert _cats(findings) == ["CWE-260"]

    def test_dotenv_password_is_cwe_260(self):
        findings = _scan("SERVICE_DB_PASSWORD=Wq83nZr5Td61\n", ".env")
        assert _cats(findings) == ["CWE-260"]

    def test_non_password_secret_key_stays_cwe_798(self):
        # The 260 arm must claim ONLY password-family keys; a generic
        # api_key keeps the shipped CWE-798 row.
        content = '{"my_internal_secret": "internal-system-9f8e7d6c5b4a3210"}'
        findings = _scan(content, "settings.json")
        assert _cats(findings) == ["CWE-798"]

    def test_password_hash_key_is_not_a_password(self):
        # `password_hash` stores a digest, not a password. Keying on
        # "contains the word password" would claim it; the tail match must not.
        content = '{"password_hash": "a3f9c1d4b7e2058613ac9f2b4d6e8f10"}'
        findings = _scan(content, "settings.json")
        assert "CWE-260" not in _cats(findings)


# ── CWE-526: cleartext secret in an environment variable ─────────────────
class TestEnvVarCleartextSecret:
    def test_yaml_env_block_mapping(self):
        content = (
            "job:\n"
            "  env:\n"
            "    SERVICE_API_TOKEN: 7f3a91c4e85b2d60a1\n"
        )
        findings = _scan(content, "pipeline.yml")
        assert _cats(findings) == ["CWE-526"]
        assert findings[0]["check_id"] == (
            "cwe.secret_scan.config.env_var_cleartext_secret"
        )

    def test_compose_environment_list_item(self):
        content = (
            "services:\n"
            "  api:\n"
            "    environment:\n"
            "      - DATABASE_PASSWORD=9f2c7b41ad83e5\n"
        )
        findings = _scan(content, "compose.yml")
        assert _cats(findings) == ["CWE-526"]

    def test_dockerfile_env_directive(self):
        content = "FROM scratch\nENV REGISTRY_API_TOKEN=8b31fd94ac27e0\n"
        findings = _scan(content, "Dockerfile")
        assert _cats(findings) == ["CWE-526"]

    def test_dockerfile_arg_directive(self):
        content = "FROM scratch\nARG BUILD_SIGNING_SECRET=5c02de91bf74a3\n"
        findings = _scan(content, "Containerfile")
        assert _cats(findings) == ["CWE-526"]

    def test_env_carrier_wins_over_password_key(self):
        # A password key inside an env carrier is BOTH 260 and 526. The
        # partition gives it to 526 (the carrier is the sharper statement)
        # and emits exactly one row — never both.
        content = "job:\n  env:\n    DB_PASSWORD: Kd72maQ4rZ19\n"
        findings = _scan(content, "pipeline.yml")
        assert _cats(findings) == ["CWE-526"]

    def test_block_closes_on_dedent(self):
        # A key at or below the `env:` indent is outside the block again;
        # a password there is a config-file password (260), not an env var.
        content = (
            "job:\n"
            "  env:\n"
            "    SERVICE_API_TOKEN: 7f3a91c4e85b2d60a1\n"
            "  password: Kd72maQ4rZ19\n"
        )
        findings = _scan(content, "pipeline.yml")
        assert _cats(findings) == ["CWE-526", "CWE-260"]

    def test_non_secret_env_name_not_flagged(self):
        content = "job:\n  env:\n    LOG_LEVEL: verbose-structured\n"
        assert _scan(content, "pipeline.yml") == []

    def test_dotenv_file_is_config_not_env_carrier(self):
        # A `.env` file is a config file the scanner reads; the CWE-526 arm
        # is about a value bound into a live process environment. Keeping
        # `.env` on the config path is what stops this change from silently
        # relabelling every already-shipped dotenv row.
        findings = _scan("SERVICE_API_TOKEN=7f3a91c4e85b2d60a1\n", ".env")
        assert _cats(findings) == ["CWE-798"]


# ── shell / template expansion is an indirection, not a literal ──────────
class TestExpansionGuard:
    NESTED = (
        "services:\n"
        "  agent:\n"
        "    environment:\n"
        "      - OPENAI_API_KEY=${AGENT_OPENAI_API_KEY-${OPENAI_API_KEY}}\n"
    )
    REQUIRED = (
        "services:\n"
        "  db:\n"
        "    environment:\n"
        "      - POSTGRES_PASSWORD=${DB_PASSWORD:?DB_PASSWORD must be set}\n"
    )

    def test_nested_expansion_is_not_a_secret(self):
        assert _scan(self.NESTED, "compose.yml") == []

    def test_required_expansion_is_not_a_secret(self):
        assert _scan(self.REQUIRED, "compose.yml") == []

    def test_command_substitution_is_not_a_secret(self):
        # `$(...)` is already understood by the shared reference guard, so
        # this lands on the benign "verify the indirection" info row rather
        # than on a CWE-526 finding. Pin that it is NOT the secret arm.
        content = "job:\n  env:\n    API_TOKEN: $(vault read -field=token kv/api)\n"
        findings = _scan(content, "pipeline.yml")
        assert [f["check_id"] for f in findings] == [
            "cwe.secret_scan.config.variable_reference"
        ]

    def test_new_carriers_do_not_mint_advisory_rows(self):
        # Compose env lists and Dockerfile ENV/ARG are surface this module
        # did not read before. Letting them reach the emitter's `info`
        # "confirm this indirection resolves" fallback costs six rows on one
        # real compose file for code that is already correct. Only the
        # literal comes out of these two carriers.
        compose = (
            "services:\n"
            "  agent:\n"
            "    environment:\n"
            "      - OPENAI_API_KEY=${OPENAI_API_KEY}\n"
            "      - AGENT_TOKEN=${AGENT_TOKEN}\n"
        )
        assert _scan(compose, "compose.yml") == []
        assert _scan("FROM scratch\nARG NPM_TOKEN=${NPM_TOKEN}\n", "Dockerfile") == []

    def test_env_mapping_indirection_keeps_its_advisory_row(self):
        # The `env:` MAPPING shape was already parsed before this change, so
        # its shipped info row must survive — suppressing it would delete
        # existing coverage under cover of a noise fix.
        content = "job:\n  env:\n    API_TOKEN: ${{ secrets.API_TOKEN }}\n"
        findings = _scan(content, "pipeline.yml")
        assert [f["check_id"] for f in findings] == [
            "cwe.secret_scan.config.variable_reference"
        ]

    def test_literal_containing_a_dollar_still_fires(self):
        # The guard keys on expansion SYNTAX, not on the dollar character —
        # a password may legitimately contain one.
        findings = _scan("app:\n  password: pW7$q2Lm9Rx4\n", "settings.yaml")
        assert _cats(findings) == ["CWE-260"]


# ── one row per line: the sibling ids never stack ────────────────────────
class TestNoRowStacking:
    def test_cloud_pattern_keeps_the_line(self):
        # A provider-shaped value is already claimed by the cloud rule
        # (CWE-798). The 526/260 arms must stand down rather than add a
        # second row for the same line.
        content = "FROM scratch\nENV GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789\n"
        findings = _scan(content, "Dockerfile")
        assert _cats(findings) == ["CWE-798"]
        assert findings[0]["check_id"] == "cwe.secret_scan.config.github_pat"

    def test_one_row_per_pair_across_every_arm(self):
        content = (
            '{"password": "Zt4qL9pR2sX7", '
            '"api_key": "internal-system-9f8e7d6c5b4a3210"}'
        )
        findings = _scan(content, "settings.json")
        lines = [(f["file_path"], f["line_start"], f["category"]) for f in findings]
        assert len(lines) == len(set(lines))
        assert sorted(_cats(findings)) == ["CWE-260", "CWE-798"]


# ── placeholder / short-value guards still hold on the new arms ──────────
class TestGuardsCarryOver:
    def test_placeholder_password_skipped(self):
        assert _scan('{"password": "changeme"}', "settings.json") == []

    def test_short_env_value_skipped(self):
        assert _scan("job:\n  env:\n    API_TOKEN: ab12\n", "pipeline.yml") == []

    def test_dockerfile_placeholder_arg_skipped(self):
        content = "FROM scratch\nARG BUILD_TOKEN=changeme-before-release\n"
        assert _scan(content, "Dockerfile") == []
