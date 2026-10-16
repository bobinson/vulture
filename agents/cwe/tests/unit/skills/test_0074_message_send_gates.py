"""Unit contract for the two CWE-799 gates added in feature 0074: a shared secret
verified against the REQUEST gates the send, and a query RESULT is not request
input. Read from identifier meaning and data flow, never a name list."""

from __future__ import annotations

import pytest

from cwe_agent.skills._guard_application import code_lines
from cwe_agent.skills._message_send import is_principal, role_params, secret_gated, verifies_secret


@pytest.mark.parametrize("ident", [
    "requireValidHookSecret", "validateHookSecret", "verify_webhook_secret", "isValidClientSecret",
    "checkActionSecret", "verifyHookToken", "validate_shared_key", "webhookTokenMatches", "isSecretValid",
])
def test_names_a_verification_of_a_shared_secret(ident: str) -> None:
    assert verifies_secret(ident)


@pytest.mark.parametrize("ident", [
    "secret", "clientSecret", "WEBHOOK_SECRET", "getSecret", "generateSecret", "verifyToken",
    "skipSecretVerification", "validateCsrfSecret", "verify_xsrf_secret", "mustGetSecret",
    "validateSecretMessage", "check_secret_message", "checkSecretSize", "validateSecretRequest",
])
def test_names_no_verification_of_a_shared_secret(ident: str) -> None:
    assert not verifies_secret(ident)


def test_a_secret_check_is_not_a_principal_by_name_alone() -> None:
    assert not is_principal("requireValidHookSecret")


def _codes(src: str) -> tuple[str, ...]:
    return code_lines(src.splitlines())


@pytest.mark.parametrize("src, handles", [
    ("  if (!requireValidHookSecret(req, res)) return;\n  send(x);\n", set()),
    ("  await verifyHookToken(ctx);\n  send(x);\n", set()),
    ("    ok = verify_webhook_secret(request.headers)\n    if not ok:\n        abort(403)\n    send(x)\n", set()),
    ("\tif !validSharedSecret(r) {\n\t\treturn\n\t}\n\tsend(x)\n", {"r"}),
    ("  if (!this.hooks.verifyWebhookSecret(req)) return;\n  send(x);\n", set()),
    ("  const ok = verifyWebhookSecret(\n    req,\n  );\n  if (!ok) return;\n  send(x);\n", set()),
])
def test_a_secret_verified_against_the_request_gates(src: str, handles: set[str]) -> None:
    codes = _codes(src)
    assert secret_gated(codes, 0, len(codes) - 1, handles)


@pytest.mark.parametrize("src", [
    "  if (!validateSecret(secret)) return res.status(400).end();\n  send(x);\n",
    "  if (!isValidSecret(req.body.secret)) return;\n  send(x);\n",
    "  if (!checkSecret(reqBody)) return;\n  send(x);\n",
    "  if (!validateCsrfSecret(req)) return;\n  send(x);\n",
    "  send(x);\n  if (!requireValidHookSecret(req, res)) return;\n",
    "  const ok = verifyHookToken(req);\n  send(x);\n",
    "  const ok = verifyHookToken(req);\n  console.log(ok);\n  send(x);\n",
    "  log(verifyHookToken(req));\n  send(x);\n",
    "  if (!validateHookSecret(secret, requestId)) return;\n  send(x);\n",
])
def test_a_value_check_or_an_ungated_one_does_not(src: str) -> None:
    codes = _codes(src)
    assert not secret_gated(codes, 0, len(codes) - 1, set())


@pytest.mark.parametrize("header", [
    'async function notify(order: GetOrderByIdQuery["order"]) {',
    "def handle(q: ListOrdersQueryResult):",
])
def test_a_query_result_type_is_not_request_input(header: str) -> None:
    assert role_params(_codes(header), 0) == set()


def test_a_result_word_other_than_result_or_row_needs_a_helper() -> None:
    header = "public IActionResult Invite(InviteQueryData data) {"
    assert role_params(_codes(header), 0) != set()
    assert role_params(_codes(header), 0, internal=True) == set()


@pytest.mark.parametrize("header", [
    "async function notifyFirstOrder(orders: GetOrdersByCustomerQuery) {",
    "private void remind(FindOverdueQuery overdue) {",
])
def test_a_helpers_query_type_is_not_request_input(header: str) -> None:
    assert role_params(_codes(header), 0, internal=True) == set()
    assert role_params(_codes(header), 0) != set(), "an entry point's ...Query parameter is a binding"


@pytest.mark.parametrize("header, name", [
    ("async start(@Query() dto: StartLinkQuery) {", "dto"),
    ("public Response find([FromQuery] SearchQuery q) {", "q"),
    ("function list(req: Request<{}, {}, {}, ReqQuery>, reqQuery: ReqQuery) {", "reqQuery"),
    ("export async function list(query: ListQuery) {", "query"),
    ("async function startLink(linkQuery) {", "linkQuery"),
    ("def lookup(search_query):", "search_query"),
    ("def start(email: str = Form()):", "email"),
    ("public Response start(@RequestBody OtpStart req) {", "req"),
])
def test_request_input_is_still_declared_in_a_helper_too(header: str, name: str) -> None:
    assert name in role_params(_codes(header), 0, internal=True)


def test_a_lookup_named_like_a_query_does_not_feed_its_result_as_input() -> None:
    """`const [rows] = await queryRowsByOwner({...})` then `helper(rows)`: the
    callee's name is not a submitted value, so `rows` stays a stored row."""
    from cwe_agent.skills._message_send import _submits_value

    assert not _submits_value("await queryRowsByOwner({", set())
    assert _submits_value("{ email: String(req.query.email) }", set())
    assert _submits_value("query", set())
