"""Unit contract for the anonymous-message-send rule (feature 0099): the
lexicons are read from identifier MEANING (camel/snake segments), never from a
framework or library name."""

from __future__ import annotations

import pytest

from cwe_agent.skills._guard_application import code_lines
from cwe_agent.skills._message_send import (
    INPUT_READ,
    body_end,
    function_header,
    gated,
    is_human_check,
    is_principal,
    is_send_call,
    recipient,
    role_params,
    segments,
)


def test_segments_split_camel_and_snake() -> None:
    assert segments("sendPasswordlessEmail") == ["send", "passwordless", "email"]
    assert segments("deliver_reset_link") == ["deliver", "reset", "link"]
    assert segments("SendConfirmationEmailAsync") == ["send", "confirmation", "email", "async"]


@pytest.mark.parametrize("recv, name", [
    (None, "sendPasswordlessEmail"), (None, "send_sms_code"), (None, "deliver_reset_link"),
    ("mailer", "send"), ("smtp", "sendmail"), ("_notifier", "SendConfirmationEmailAsync"),
    (None, "sendInvitation"), (None, "dispatchVerificationCode"),
])
def test_a_delivery_verb_naming_a_message_is_a_send(recv: str | None, name: str) -> None:
    assert is_send_call(recv, name)


@pytest.mark.parametrize("recv, name", [
    ("res", "send"), (None, "sendStatus"), ("socket", "send"), (None, "sendFile"),
    (None, "sendRateLimitExceeded"), (None, "notifyOwner"), (None, "senderName"),
])
def test_a_send_that_names_no_message_is_not_one(recv: str | None, name: str) -> None:
    assert not is_send_call(recv, name)


@pytest.mark.parametrize("args, expected", [
    ("{ to: email, code }", "email"),
    ("to=email, token=token", "email"),
    ("email, rawToken, mode", "email"),
    ("{ recipient: emailAddress, subject: 's' }", "emailAddress"),
    ("$phone, $code", "$phone"),
    ("subject, body, from_email, [email]", "[email]"),
    ("{ emailAddress: input.email, verifyUrl }", "input.email"),
])
def test_the_recipient_is_found_by_key_or_contact_shape(args: str, expected: str) -> None:
    assert recipient(args) == expected


@pytest.mark.parametrize("args", [
    "{ from: fromEmail, text: msg }",
    "{ replyTo: { email: body.email }, text: msg }",
    "res, payload",
    "chatId, text",
])
def test_no_recipient_when_only_sender_side_or_non_contact(args: str) -> None:
    assert recipient(args) is None


@pytest.mark.parametrize("text", [
    "req.body", "body.email", "request.form.get('email')", "params[:email]", "$_POST['phone']",
    "r.FormValue('email')", "request.POST.get('email')", "req.query.email",
])
def test_request_input_reads(text: str) -> None:
    assert INPUT_READ.search(text)


@pytest.mark.parametrize("text", [
    "params", "args.email", "payload.email", "input.email", "dto.email", "jsonify(x)",
])
def test_ordinary_parameter_names_are_not_request_input(text: str) -> None:
    assert not INPUT_READ.search(text)


@pytest.mark.parametrize("ident", [
    "getServerSession", "authenticateAndAuthorize", "requireAuth", "currentUser",
    "login_required", "verifySignature", "isAuthenticated", "bearerToken",
])
def test_principal_identifiers(ident: str) -> None:
    assert is_principal(ident)


@pytest.mark.parametrize("ident", [
    "optionalAuth", "skipAuth", "allowAnonymous", "unauthenticated", "authorizationUrl",
    "identityProvider", "getIdentifierWithUid", "author", "oauthState",
])
def test_negated_or_unrelated_identifiers_are_not_principals(ident: str) -> None:
    assert not is_principal(ident)


@pytest.mark.parametrize("ident, expected", [
    ("verifyCaptcha", True), ("recaptchaClient", True), ("siteverify", True),
    ("proof_of_work", True), ("captchaToken", True), ("challenge", False),
])
def test_human_check_identifiers(ident: str, expected: bool) -> None:
    assert is_human_check(ident) is expected


def _codes(src: str) -> tuple[str, ...]:
    return code_lines(src.splitlines())


def test_the_enclosing_function_skips_callbacks_and_control_blocks() -> None:
    codes = _codes(
        "export default async function handler(req, res) {\n"
        "  items.forEach((x) => {\n"
        "    if (x) {\n"
        "      sendCodeEmail(x.email);\n"
        "    }\n"
        "  });\n"
        "}\n"
    )
    assert function_header(codes, 3) == 0
    assert body_end(codes, 0) == 7


def test_a_multi_line_signature_and_allman_brace() -> None:
    codes = _codes(
        "async function handler(\n"
        "  req,\n"
        "  res,\n"
        ") {\n"
        "  send(req.body.email);\n"
        "}\n"
        "function next() {}\n"
    )
    assert function_header(codes, 4) == 0
    assert body_end(codes, 0) == 6
    cs = _codes(
        "    public async Task<IResult> Subscribe(SubscribeRequest body)\n"
        "    {\n"
        "        await _n.SendConfirmationEmailAsync(body.Email);\n"
        "    }\n"
    )
    assert function_header(cs, 2) == 0


def test_a_member_access_named_sub_is_not_a_header() -> None:
    codes = _codes(
        "function handler(req) {\n"
        "  const id = claims.sub(1);\n"
        "  if (id) {\n"
        "    send(x);\n"
        "  }\n"
        "}\n"
    )
    assert function_header(codes, 3) == 0


def test_a_principal_that_exits_gates_and_one_that_is_only_read_does_not() -> None:
    gate = _codes(
        "  const session = await getSession(req);\n"
        "  const uid = session?.user?.id;\n"
        "  if (!uid) {\n"
        "    return res.status(401).end();\n"
        "  }\n"
        "  send(x);\n"
    )
    read = _codes(
        "  const session = await getSession(req);\n"
        "  if (session) {\n"
        "    console.log(session.id);\n"
        "  }\n"
        "  send(x);\n"
    )
    assert gated(gate, 0, 5, is_principal)
    assert not gated(read, 0, 4, is_principal)


def test_an_asserting_call_gates() -> None:
    codes = _codes("  await requireUser(req);\n  send(x);\n")
    assert gated(codes, 0, 1, is_principal)


def test_parameters_declared_as_request_input() -> None:
    assert role_params(_codes("public Response start(@RequestBody OtpStart req) {"), 0) == {
        "RequestBody", "OtpStart", "req"}
    assert role_params(_codes("def start(email: str = Form()):"), 0) >= {"email"}
    assert role_params(_codes("export async function send(params: EmailParams) {"), 0) == set()
