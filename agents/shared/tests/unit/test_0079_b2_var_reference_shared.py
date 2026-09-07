"""Feature 0079 B2: variable-indirection detection lives in shared.

`password = $DB_PASS` is a REFERENCE, not a secret. The detector was CWE-local
while ASVS and SSDF ran their own credential scans without it.

The guard ORDER matters and is tested here. Benchmarked on the real regexes,
200k iterations:

    os.getenv().strip().lower() alone   0.550 us/line
    _RHS_CAPTURE.search alone           0.332 us/line
    env-first  (env and regex)          0.873 us/line
    regex-first (regex and env)         0.339 us/line

The guard runs per LINE, not per finding: on a 5M-line tree env-first cost
+4.36s for SSDF alone, 2.75s of it pure getenv, and x8 GIL-serialised
generators made it ~35s of wall clock. Regex-first is 2.6x cheaper because the
env read only happens on the rare line that already looks like a match.
"""

from __future__ import annotations

import pathlib

import pytest

from shared.tools.var_reference import is_variable_reference, line_value_is_variable_ref

AGENTS = pathlib.Path(__file__).resolve().parents[3]


@pytest.mark.parametrize(
    "value",
    [
        "$DB_PASSWORD",
        "${DB_PASSWORD}",
        "${{ secrets.API_KEY }}",
        "{{ .Values.apiKey }}",
        "%(DB_PASS)s",
    ],
)
def test_indirection_forms_are_recognised(value):
    assert is_variable_reference(value), f"{value!r} is a reference, not a secret"


@pytest.mark.parametrize(
    "value",
    ["hunter2realsecret", "AKIAIOSFODNN7EXAMPLE", "sk-live-abcdef0123456789"],
)
def test_real_looking_secrets_are_not_suppressed(value):
    """The recall side. A detector that suppresses real secrets is worse than
    no detector, and this project has shipped exactly that mistake before."""
    assert not is_variable_reference(value)


def test_line_form_matches_the_value_form():
    assert line_value_is_variable_ref('password = "$DB_PASS"')
    assert not line_value_is_variable_ref('password = "hunter2realsecret"')


def test_the_cwe_shim_re_exports_the_same_objects():
    """The move must be behaviour-preserving for CWE, and identity is the
    strongest available proof: the shim must expose the SAME function objects,
    not lookalikes."""
    import sys

    sys.path.insert(0, str(AGENTS / "cwe"))
    from cwe_agent.skills import _var_reference as shim

    assert shim.is_variable_reference is is_variable_reference
    assert shim.line_value_is_variable_ref is line_value_is_variable_ref


def test_guard_is_regex_first_not_env_first():
    """Pin the ORDER, by reading the source of each consumer guard.

    An `env and regex` guard pays an os.getenv on EVERY line; `regex and env`
    pays it only on the rare line that already matched. Measured 2.6x. This is
    a per-line cost on a multi-million-line tree, so the ordering is a
    correctness-of-cost property worth pinning, not a micro-optimisation.
    """
    for rel in ("ssdf/ssdf_agent/skills", "asvs/asvs_agent/skills"):
        d = AGENTS / rel
        if not d.exists():
            continue
        for py in d.glob("*.py"):
            src = py.read_text()
            for line in src.splitlines():
                if "VAR_REF_GUARD" not in line or " and " not in line:
                    continue
                before = line.split(" and ")[0]
                assert "getenv" not in before and "environ" not in before, (
                    f"{py.name}: env read comes FIRST in `{line.strip()}` — put the "
                    f"regex first so the env read only happens on a matching line"
                )
