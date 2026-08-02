"""The config-file secret scanner uses the single shared variable-reference guard.

`config_files.py` used to carry its own narrower copy of the `$VAR` / `${VAR}`
regex. It did not know `$(command substitution)`, whitespace-trimmed templates
(`{{- .Values.x -}}`), dotted/hyphenated template paths (`{{ .Values.apiKey }}`),
configparser conversions other than `%(VAR)s`, or the docker-compose `$$VAR`
escape. Every one of those is an indirection — the literal value is a pointer to
something injected at runtime — but the narrow copy classified them as literal
credentials and emitted a `medium` "Suspicious config key with literal value".

The copy is gone; `config_files` imports `is_variable_reference` from
`cwe_agent.skills._var_reference`. These tests pin both halves of that:

1. the shapes the narrow copy missed are now suppressed to an `info`
   variable-reference finding, and
2. a genuine hardcoded credential still produces a `medium`-or-worse finding —
   the suppression must not become a blanket amnesty.
"""

import tempfile
from pathlib import Path

from cwe_agent.skills import _var_reference
from cwe_agent.skills.secret_scan import config_files

# Shapes the deleted local copy could not recognise. Each is a pointer to a
# runtime-injected value, not a credential.
INDIRECTIONS_THE_NARROW_COPY_MISSED = [
    "$(op read op://vault/db/password)",       # 1Password CLI substitution
    "$(vault kv get -field=key secret/app)",   # Vault CLI substitution
    "$(cat /run/secrets/api_key)",             # file-mounted secret
    "{{ .Values.registryToken }}",             # Helm value (leading dot)
    "{{ .Values.api-key }}",                   # Helm value (hyphenated path)
    "{{- .Values.clientSecret -}}",            # whitespace-trimmed Helm
    "%(mail_password)d",                       # configparser, non-`s` conversion
    "%(token)x",                               # configparser, hex conversion
    "$$SERVICE_TOKEN",                         # docker-compose `$$` escape
]

# Shapes both implementations already agreed on — they must not regress.
INDIRECTIONS_ALREADY_COVERED = [
    "${{ secrets.API_TOKEN }}",
    "${SESSION_SECRET}",
    "${SESSION_SECRET:-fallback}",
    "$WEBHOOK_SECRET",
    "%(api_key)s",
    "<%= api_key %>",
    "{{ api_key }}",
]

# Literal credentials. These must never be excused. Deliberately free of
# placeholder words (`example`, `changeme`, `dummy`, …) — the scanner has a
# separate, legitimate safe-context filter for those, and mixing the two would
# make this test measure the wrong thing.
LITERAL_CREDENTIALS = [
    "8f14e45fceea167a5a36dedd4bea2543",
    "prod-consumer-secret-9931-do-not-share",
    "hunter2-hunter2-hunter2",
    "qWv3Zt7Lp0Rn5Xc8Bd2Kj4Hf6Ms1Ya9U",
]


class TestGuardIsSingleSourced:
    def test_config_files_uses_the_shared_function_object(self):
        assert config_files.is_variable_reference is _var_reference.is_variable_reference

    def test_no_second_regex_survives_in_config_files(self):
        assert not hasattr(config_files, "_VAR_REF_RE"), \
            "a second variable-reference regex reappeared in config_files"
        assert not hasattr(config_files, "_is_variable_reference"), \
            "a second variable-reference guard reappeared in config_files"


class TestShapesNowRecognised:
    def test_previously_missed_indirections_are_recognised(self):
        for value in INDIRECTIONS_THE_NARROW_COPY_MISSED:
            assert config_files.is_variable_reference(value), \
                f"{value!r} is an indirection, not a literal credential"

    def test_already_covered_indirections_did_not_regress(self):
        for value in INDIRECTIONS_ALREADY_COVERED:
            assert config_files.is_variable_reference(value), f"{value!r} regressed"

    def test_literals_are_not_indirections(self):
        for value in LITERAL_CREDENTIALS:
            assert not config_files.is_variable_reference(value), \
                f"{value!r} is a literal and must not be suppressed"

    def test_composed_values_are_not_a_free_pass(self):
        """A value that merely *contains* an indirection is still composed."""
        for value in ("$(vault read x)-suffix", "prefix-{{ .Values.token }}",
                      "$$TOKEN and more", ""):
            assert not config_files.is_variable_reference(value), \
                f"{value!r} is not a clean indirection"


SERIOUS = ("medium", "high", "critical")


def _scan(body: str, filename: str = "settings.yaml") -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / filename).write_text(body)
        from cwe_agent.skills import SKILL_MAP
        return SKILL_MAP["secrets"](str(d))["findings"]


def _serious(findings: list[dict]) -> list[tuple[int, str, str]]:
    """(line, severity, title) for every finding at medium or worse."""
    return [(f["line_start"], f["severity"], f["title"])
            for f in findings if f["severity"] in SERIOUS]


def _yaml_body(prefix: str, values: list[str]) -> str:
    return "".join(f"{prefix}_{i}: {v}\n" for i, v in enumerate(values))


def _with_check_id(findings: list[dict], check_id: str) -> list[dict]:
    return [f for f in findings if f["check_id"] == check_id]


class TestEndToEndSeverity:
    def test_indirection_values_yield_no_medium_or_worse(self):
        body = _yaml_body("secret_key", INDIRECTIONS_THE_NARROW_COPY_MISSED
                          + INDIRECTIONS_ALREADY_COVERED)
        bad = _serious(_scan(body))
        assert not bad, \
            f"variable references must not be reported as hardcoded secrets; got {bad}"

    def test_indirection_values_are_still_surfaced_as_info(self):
        """Suppression means downgrade-and-explain, not silence."""
        body = "api_key: $(op read op://vault/app/api_key)\n"
        infos = _with_check_id(_scan(body),
                               "cwe.secret_scan.config.variable_reference")
        assert len(infos) == 1, f"expected one info-level reference finding, got {infos}"
        assert (infos[0]["severity"], infos[0]["category"]) == ("info", "CWE-798")

    def test_hardcoded_credential_still_fires(self):
        bad = _serious(_scan(_yaml_body("client_secret", LITERAL_CREDENTIALS)))
        assert len(bad) == len(LITERAL_CREDENTIALS), (
            f"every literal credential must still be reported; got {len(bad)} "
            f"of {len(LITERAL_CREDENTIALS)}: {bad}"
        )

    def test_env_file_literal_still_fires_and_reference_does_not(self):
        body = (
            "DATABASE_PASSWORD=$(op read op://vault/db/password)\n"
            "STRIPE_WEBHOOK_SECRET=whsec-literal-value-2f4b9a17\n"
        )
        by_line = {f["line_start"]: f["severity"] for f in _scan(body, ".env")}
        assert by_line[1] == "info", \
            "the command-substitution value must not be reported as a literal"
        assert by_line[2] in SERIOUS, "the literal webhook secret must still be reported"
