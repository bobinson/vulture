"""E2E business-logic contract: two gates the anonymous-message-send rule
(CWE-799, feature 0099) must recognise — feature 0074, measured on a real
target where they made 7 of 13 rows false positives.

1. A SHARED SECRET VERIFIED AGAINST THE REQUEST authenticates the caller. A
   handler that passes the request (its context, its headers) to a check named
   for verifying a secret or a hook token (the secret is what is verified,
   not a secret message or note), and exits when it fails, is not
   anonymous, exactly like one that verifies a signature. A check of a VALUE
   (a secret the caller submits to be stored or shared, a policy check) is
   content validation and gates nothing; nor does a secret that is only read,
   one verified after the send, or an anti-forgery (CSRF) secret, which any
   anonymous caller can obtain.
2. A QUERY RESULT IS NOT REQUEST INPUT. A parameter whose TYPE is a compound
   name ending in ``Query`` holds a stored row when the type is indexed into
   (``GetOrderByIdQuery["order"]``, a generated GraphQL result) or when the
   function is a helper the same file calls (declared once), and no call
   passes it request input, directly or through the caller's locals and
   parameters (a row LOOKED UP by request input is a result, a converted copy
   of it is not): its argument comes from that caller, not a framework binding. An entry point's ``...Query``
   parameter, a ``Query`` annotation, a ``FromQuery`` binding, and any parameter
   NAMED like a query keep declaring request input.

Positives (``fixtures/message_send_0074/pos``) are exactly ONE row each, through
the skill AND the offline runner; negatives are silent. The rule still names
no framework, library or platform.

These tests are the business contract. Do NOT weaken them.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from cwe_agent.offline import scan_files
from cwe_agent.skills.resource_check import check_resource_management
from shared.tools.file_scanner import clear_caches

FIXTURES = Path(__file__).parent / "fixtures" / "message_send_0074"
CHECK_ID = "cwe.resource.anonymous_message_send"

# fixture -> (severity, line_start, line_end), as in the 0099 contract.
POSITIVES: dict[str, tuple[str, int, int]] = {
    # a secret that is read and checked for presence is not a verification
    "p01_ts_secret_read_not_verified.ts": ("high", 8, 9),
    # a `Query` annotation still declares request input beside a `...Query` type
    "p02_ts_query_decorator_with_query_type.ts": ("high", 5, 6),
    # a verification after the send gates nothing
    "p03_py_secret_verified_after_send.py": ("high", 8, 9),
    # validating a secret the caller submits is content validation, not authentication
    "p04_ts_secret_share_validates_value.ts": ("high", 9, 10),
    # an entry point's `...Query` parameter is a request binding
    "p05_java_entry_query_dto.java": ("high", 7, 8),
    # a parameter NAMED like a query is request input, in a helper too
    "p06_ts_helper_param_named_query.ts": ("high", 4, 5),
    # an anti-forgery secret is free to an anonymous caller
    "p07_ts_csrf_secret_is_not_a_principal.ts": ("high", 7, 8),
    # a helper the file calls WITH request input keeps its `...Query` parameter as input
    "p08_ts_helper_fed_request_query.ts": ("high", 5, 6),
    # ... also through a local or a parameter the caller binds from the request
    "p09_ts_helper_fed_by_local.ts": ("high", 5, 5),
    "p10_py_entry_dto_forwarded_to_helper.py": ("high", 10, 10),
    # a check named for a secret MESSAGE validates content, even given the request
    "p11_py_secret_message_check_of_request.py": ("high", 9, 10),
    # a body-bound parameter named like the request is a submitted value
    "p12_java_body_dto_is_not_the_request.java": ("high", 8, 8),
    # a verification that is logged, not branched on, gates nothing
    "p13_ts_verification_logged_not_gated.ts": ("high", 6, 7),
    # an identifier that merely contains `request` is not the request
    "p14_ts_request_id_is_not_the_request.ts": ("high", 9, 9),
    # an entry point does not become a helper because an overload shares its name
    "p15_java_overloaded_entry_point.java": ("high", 5, 5),
    # an entry point's `...QueryData` parameter is a request binding
    "p16_cs_entry_query_data.cs": ("high", 6, 6),
    # a copy of request input through a conversion is still the request's input
    "p17_ts_helper_fed_a_converted_copy.ts": ("high", 5, 5),
    # accessors called ON the request (`r.URL.Query().Get(...)`) read it; they look nothing up
    "p18_go_helper_fed_request_accessors.go": ("high", 11, 11),
}


@pytest.fixture(autouse=True)
def _clean_caches():
    clear_caches()
    yield
    clear_caches()


def _stage(tmp_path: Path, name: str, sub: str) -> Path:
    dst = tmp_path / "src" / name
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FIXTURES / sub / name, dst)
    return dst


def _rows(findings: list[dict]) -> list[tuple]:
    return [(f["category"], f["severity"], f["line_start"], f["line_end"])
            for f in findings if f.get("check_id") == CHECK_ID]


def test_every_fixture_is_in_the_contract() -> None:
    assert {p.name for p in (FIXTURES / "pos").iterdir()} == set(POSITIVES)


@pytest.mark.parametrize("name", sorted(POSITIVES))
def test_positive_fires_exactly_once(tmp_path: Path, name: str) -> None:
    f = _stage(tmp_path, name, "pos")
    severity, start, end = POSITIVES[name]
    expected = [("CWE-799", severity, start, end)]

    assert _rows(check_resource_management(str(tmp_path / "src"))["findings"]) == expected
    assert _rows(scan_files([str(f)], root=str(tmp_path))) == expected


@pytest.mark.parametrize("name", sorted(p.name for p in (FIXTURES / "neg").iterdir()))
def test_negative_is_silent(tmp_path: Path, name: str) -> None:
    f = _stage(tmp_path, name, "neg")

    assert _rows(check_resource_management(str(tmp_path / "src"))["findings"]) == []
    assert _rows(scan_files([str(f)], root=str(tmp_path))) == []
