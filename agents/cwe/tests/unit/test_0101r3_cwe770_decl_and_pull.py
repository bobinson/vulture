"""Feature 0101 revision 3 -- CWE-770 predicates: typed body declarations, sized pulls.

Unit contract behind ``tests/e2e/test_0101r3_cwe770_decl_and_pull.py``: each
predicate is asked on its own so a regression names the concept that broke.
"""
from __future__ import annotations

import pytest

from cwe_agent.skills import resource_check as rc


def _body(row: str) -> list[str]:
    return ["while (true) {", row, "  parts.add(x);"]


@pytest.mark.parametrize("row", [
    "  List<String> parts = new ArrayList<>();",
    "  final java.util.List<String> parts = new java.util.ArrayList<>();",
    "  std::vector<char> parts = std::vector<char>();",
    "  Map<String, List<Integer>> parts = new HashMap<>();",
    "  char *parts = malloc(n);",
    "  String[] parts = line.split(\",\");",
    "  StringBuilder parts = new StringBuilder();",
])
def test_a_typed_local_in_the_body_is_declared_there(row: str) -> None:
    assert rc._declared_inside("parts", _body(row))


@pytest.mark.parametrize("row", [
    "  parts = new ArrayList<>();",           # a plain rebinding is the reset's business
    "  else parts = grow(parts);",            # a control word is not a type
    "  return parts = grow(parts);",
    "  parts == other;",
    "  other.parts = new ArrayList<>();",
    "  List<String> other = parts;",          # declares another name
    "  if (a < b) parts = c;",
])
def test_a_row_that_is_not_a_typed_declaration_of_the_name_declares_nothing(row: str) -> None:
    assert not rc._declared_inside("parts", _body(row))


@pytest.mark.parametrize("code", [
    "data = os.read(fd, 4096)",
    "$chunk = socket_read($sock, 2048);",
    "$got = socket_recv($sock, $data, 2048, 0);",
    "$n = stream_socket_recvfrom($server, 1500);",
])
def test_a_sized_or_prefixed_read_or_receive_is_a_pull(code: str) -> None:
    assert rc._pulls(code)


@pytest.mark.parametrize("code", [
    "item = self._read()",
    "cfg = config_read()",
    "x = file_read(path)",
    "parser.read(paths)",
    "thread_reader(x, 2)",
])
def test_a_private_or_unsized_read_helper_is_not_a_pull(code: str) -> None:
    assert not rc._pulls(code)
