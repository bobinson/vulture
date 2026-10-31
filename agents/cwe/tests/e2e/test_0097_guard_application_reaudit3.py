"""E2E business-logic contract, part four: the comparand model and the
principal outcome after the third re-audit (feature 0097).

Precision (negatives in ``fixtures/guard_application/neg``, so the part-one
glob asserts them silent too):

  * a server-held secret whose same-file literal is only a DEFAULT, reassigned
    anywhere in the file (a conditional or one-line override, a promise
    callback, a Go ``init``, a second statement on a line), is a value the
    client cannot know: the comparison is authentication, not a bypass;
  * an early return of an ordinary object (a DTO, a summary, a preview) is not
    a principal grant, even when its class name contains ``User``; and a route
    handler returning a ``User`` is not a principal PROVIDER.

Reach (positives in ``fixtures/guard_application/pos_reaudit3``), each a real
bypass the rule must keep reporting:

  * a literal comparand followed by a block comment, an enum member's
    ``.value``, a PHP ``define()`` constant, a literal narrowed by ``as <Type>``;
  * a CSRF validator conjoined with the read (CSRF is not authentication);
  * a comparand that is itself a request read (a cookie, a query parameter):
    the client sets both sides, so it is not a shared secret;
  * a principal provider (a Passport ``validate()``) returning a user entity
    built from a request header.

Every positive is exactly ONE ``high`` row through the skill AND through the
offline runner. These tests are the business contract. Do NOT weaken them.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from cwe_agent.offline import main, scan_files
from cwe_agent.skills.access_control_check import check_access_control
from shared.tools.file_scanner import clear_caches

FIXTURES = Path(__file__).parent / "fixtures" / "guard_application"

SKIP = "cwe.access_control.guard_skip_by_request_attr"
SPOOF = "cwe.access_control.spoofable_identity_guard"
EXCLUDED = "cwe.access_control.guard_excluded_by_request_attr"
GUARD_IDS = {SKIP, SPOOF, EXCLUDED}

# fixture -> (check_id, category, line_start). Exactly ONE guard row each.
POSITIVES: dict[str, tuple[str, str, int]] = {
    "s01_js_literal_block_comment.js": (SKIP, "CWE-807", 2),
    "s02_py_enum_member_value.py": (SKIP, "CWE-807", 14),
    "s03_php_define_literal.php": (SKIP, "CWE-807", 5),
    "s04_ts_literal_as_type.ts": (SKIP, "CWE-807", 3),
    "s05_csrf_validator_conjunct.js": (SKIP, "CWE-807", 2),
    "s06_header_vs_cookie.js": (SKIP, "CWE-807", 2),
    "s07_header_vs_query_403.js": (SKIP, "CWE-807", 2),
    "s08_flask_header_vs_args.py": (SKIP, "CWE-807", 9),
    # a Passport strategy's validate() building the principal from a header
    "s09_nest_passport_validate_header_identity.ts": (SKIP, "CWE-807", 5),
}

NEGATIVES = (
    "n105_secret_default_conditional_override.js",
    "n106_go_secret_default_init_override.go",
    "n107_secret_default_then_override.js",
    "n108_py_secret_default_oneline_override.py",
    "n109_secret_default_second_statement.js",
    "n110_nest_dto_early_return.ts",
    "n111_fastapi_summary_early_return.py",
    "n112_nest_public_dto_early_return.ts",
    "n113_spring_summary_early_return.java",
    "n114_fastapi_route_returns_demo_user.py",
)


@pytest.fixture(autouse=True)
def _clean_caches():
    clear_caches()
    yield
    clear_caches()


def _stage(tmp_path: Path, name: str, sub: str) -> Path:
    """Copy one fixture into its own tree (fixtures live under tests/, which
    the scanner skips as test code)."""
    dst = tmp_path / "src" / name
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FIXTURES / sub / name, dst)
    return dst


def _guard_rows(findings: list[dict]) -> list[tuple]:
    return [(f["check_id"], f["category"], f["severity"], f["line_start"])
            for f in findings if f.get("check_id") in GUARD_IDS]


def test_every_fixture_is_in_the_contract() -> None:
    assert {p.name for p in (FIXTURES / "pos_reaudit3").iterdir()} == set(POSITIVES)
    assert set(NEGATIVES) <= {p.name for p in (FIXTURES / "neg").iterdir()}


@pytest.mark.parametrize("name", sorted(POSITIVES))
def test_positive_fires_exactly_once(tmp_path: Path, name: str) -> None:
    f = _stage(tmp_path, name, "pos_reaudit3")
    check_id, category, line = POSITIVES[name]
    expected = [(check_id, category, "high", line)]

    assert _guard_rows(check_access_control(str(tmp_path / "src"))["findings"]) == expected
    assert _guard_rows(scan_files([str(f)], root=str(tmp_path))) == expected


@pytest.mark.parametrize("name", NEGATIVES)
def test_negative_is_silent(tmp_path: Path, name: str) -> None:
    f = _stage(tmp_path, name, "neg")

    assert _guard_rows(check_access_control(str(tmp_path / "src"))["findings"]) == []
    assert _guard_rows(scan_files([str(f)], root=str(tmp_path))) == []


@pytest.mark.parametrize("name", [
    "n105_secret_default_conditional_override.js",
    "n113_spring_summary_early_return.java",
])
def test_negative_does_not_block_the_offline_gate(tmp_path: Path, name: str) -> None:
    f = _stage(tmp_path, name, "neg")

    assert main(["--root", str(tmp_path), "--severity", "high", str(f)]) == 0


def test_returned_principal_from_a_provider_still_fires(tmp_path: Path) -> None:
    """The principal outcome is narrowed, not removed: a dependency named as a
    principal provider that returns a ``User`` built from a header still fires."""
    _stage(tmp_path, "r13_fastapi_dependency_principal.py", "pos_reaudit")

    rows = _guard_rows(check_access_control(str(tmp_path / "src"))["findings"])
    assert rows == [(SKIP, "CWE-807", "high", 8)]
