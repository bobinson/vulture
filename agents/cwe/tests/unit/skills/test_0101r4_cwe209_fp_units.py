"""Feature 0101 revision 4 -- units of the CWE-209 false-positive corrections.

The E2E contract is tests/e2e/test_0101r4_cwe209_fp.py; these pin the pieces it rests on.
"""
from __future__ import annotations

import pytest

from cwe_agent.skills import info_exposure_check as iec

# ---- a sanitising qualifier makes a detail-named callee a projection ----

@pytest.mark.parametrize("callee, extractor", [
    ("toPublicMessage", False),
    ("get_redacted_message", False),
    ("scrubbedMessage", False),
    ("sanitizeErrorMessage", False),
    ("maskedMessage", False),
    ("genericMessage", False),
    ("friendlyMessage", False),
    # no sanitising qualifier: still a raw-detail getter
    ("getErrorMessage", True),
    ("errorMessage", True),
    ("formatErrorMessage", True),   # `format` renders, it does not sanitise
    ("getUserMessage", True),       # `user` names whose message, not a projection
    ("readMessage", True),
    # `safe` also means null-safe / non-throwing: a getter that will not throw still
    # returns the raw message, so it is not a sanitising qualifier
    ("safeGetMessage", True),
    ("safeStackTrace", True),
    ("safe_str", False),            # no detail word at all: unchanged
])
def test_a_sanitising_qualifier_is_not_an_extractor(callee: str, extractor: bool) -> None:
    assert iec._is_extractor(callee) is extractor


def test_a_sanitising_qualifier_is_a_projection_call() -> None:
    for callee in ("toPublicMessage", "get_redacted_message", "scrubbedMessage", "maskedMessage"):
        assert iec._is_opaque_call(callee, iec._last_segment(callee), "err"), callee


# ---- a caller-facing error class ----

@pytest.mark.parametrize("name, facing", [
    ("InputError", True),
    ("ValidationError", True),
    ("ToolAuthorizationError", True),
    ("InputValidationException", True),
    # a bare HTTP status word names an OUTBOUND call's status far more often than the
    # caller's (an HTTP client's `Forbidden` / `Unauthorized`, whose message carries the
    # upstream response), so it is not a caller-facing role on its own
    ("UnauthorizedError", False),
    ("ForbiddenError", False),
    ("Forbidden", False),
    ("ForbiddenException", False),
    # any qualifier naming an outbound or internal role makes the class internal
    ("HttpClientErrorException.Forbidden", False),
    ("BillingClient.ValidationException", False),
    ("UpstreamApi.InputError", False),
    ("RemoteValidationError", False),
    ("errors.ValidationError", True),
    ("SQLException", False),
    ("DatabaseError", False),
    ("InputOutputError", False),
    ("InputStreamException", False),
    ("PermissionError", False),
    ("IllegalArgumentException", False),
    ("HttpError", False),
    ("Exception", False),
    ("ArgumentShapeError", False),
    # an authorization word paired with an access / path target is the runtime's
    # resource error, whose message names the path
    ("UnauthorizedAccessException", False),
    ("UnauthorizedAccess", False),
    ("InvalidPathAuthorizationError", False),
])
def test_caller_facing_error_class(name: str, facing: bool) -> None:
    assert iec._caller_facing_type(name) is facing


def _guarded(src: str, line_num: int) -> bool:
    return iec._type_guarded(src.splitlines(), line_num)


def test_a_positive_instanceof_branch_of_the_caught_error_is_guarded() -> None:
    src = ("try {\n  run();\n} catch (e) {\n  if (e instanceof InputError) {\n"
           "    res.json({ m: e.message });\n  }\n}\n")
    assert _guarded(src, 5)


@pytest.mark.parametrize("cond", [
    "!(e instanceof InputError)",
    "e instanceof InputError || e instanceof StorageError",
    "e instanceof DatabaseError",
    "other instanceof InputError",
    "e instanceof InputError || retry",
])
def test_a_negated_mixed_internal_or_foreign_guard_is_not(cond: str) -> None:
    src = f"try {{\n  run();\n}} catch (e) {{\n  if ({cond}) {{\n    res.json({{ m: e.message }});\n  }}\n}}\n"
    assert not _guarded(src, 5)


def test_a_sink_after_the_branch_is_not_guarded() -> None:
    src = ("try {\n  run();\n} catch (e) {\n  if (e instanceof InputError) {\n    note();\n  }\n"
           "  res.json({ m: e.message });\n}\n")
    assert not _guarded(src, 7)


@pytest.mark.parametrize("header, guarded", [
    ("    } catch (InputValidationException e) {", True),
    ("    } catch (InputValidationException | SQLException e) {", False),
    ("    } catch (SQLException e) {", False),
    ("    } catch (e: ValidationException) {", True),
    ("    } catch (e) {", False),
])
def test_a_typed_handler_names_the_class(header: str, guarded: bool) -> None:
    src = f"void f() {{\n    try {{\n      run();\n{header}\n      w.write(e.getMessage());\n    }}\n}}\n"
    assert _guarded(src, 5) is guarded


@pytest.mark.parametrize("clause, guarded", [
    ("except ValidationError as exc:", True),
    ("except (ValidationError, AuthorizationError) as exc:", True),
    ("except (ValidationError, DatabaseError) as exc:", False),
    ("except DatabaseError as exc:", False),
])
def test_a_python_typed_except(clause: str, guarded: bool) -> None:
    src = f"def f(self):\n    try:\n        run()\n    {clause}\n        self.write(str(exc))\n"
    assert _guarded(src, 5) is guarded


def test_a_python_isinstance_branch() -> None:
    src = ("def f(self):\n    try:\n        run()\n    except Exception as exc:\n"
           "        if isinstance(exc, ValidationError):\n            self.write(str(exc))\n")
    assert _guarded(src, 6)


def test_go_errors_is_does_not_guard() -> None:
    src = ("func h(c *gin.Context) {\n\tif err := run(); err != nil {\n\t\tif errors.Is(err, ErrInvalidInput) {\n"
           "\t\t\tc.JSON(400, gin.H{\"error\": err.Error()})\n\t\t}\n\t}\n}\n")
    assert not _guarded(src, 4)


def test_a_stack_is_never_excused() -> None:
    src = ("try {\n  run();\n} catch (e) {\n  if (e instanceof InputError) {\n"
           "    res.json({ trace: e.stack });\n  }\n}\n")
    assert not _guarded(src, 5)


_CLASSIFIER = (
    "function classify(err) {\n"
    "  if (err instanceof InputError) {\n"
    "    return 400;\n"
    "  }\n"
    "  {refusal}\n"
    "}\n"
    "try {\n  run();\n} catch (err) {\n"
    "  const status = classify(err);\n"
    "  if (status !== null) {\n"
    "    send(res, status, getErrorMessage(err));\n"
    "  }\n"
    "}\n"
)


@pytest.mark.parametrize("refusal, guarded", [
    ("return null;", True),
    ("return 500;", False),
])
def test_a_same_file_classifier_must_refuse_other_errors(refusal: str, guarded: bool) -> None:
    assert _guarded(_CLASSIFIER.replace("{refusal}", refusal), 12) is guarded


def test_a_classifier_naming_an_internal_class_does_not_guard() -> None:
    src = _CLASSIFIER.replace("InputError", "StorageError").replace("{refusal}", "return null;")
    assert not _guarded(src, 12)


# ---- child stdin and request parameters ----

@pytest.mark.parametrize("before, local", [
    ("stdin", True),
    ("proc.stdin", True),
    ("res", False),
])
def test_child_stdin_is_not_a_peer(before: str, local: bool) -> None:
    assert iec._receiver_is_local(before) is local


@pytest.mark.parametrize("rhs, peer_input", [
    ('callbackUrl.searchParams.get("error")', True),
    ('self.request.args.get("error")', True),
    ('r.URL.Query().Get("error")', True),
    ('request.getParameter("error")', True),
    ("db.query(sql)", False),
    ('store.get("error")', False),
    ("String(err)", False),
])
def test_a_request_parameter_read(rhs: str, peer_input: bool) -> None:
    assert iec._reads_request_parameter(rhs) is peer_input


def test_the_else_arm_of_a_caller_facing_guard_is_not_guarded() -> None:
    """Plain brace balance reads `} else {` as net zero and hands the else arm the `if` header."""
    src = ("try {\n  run();\n} catch (e) {\n  if (e instanceof InputError) {\n    note();\n  } else {\n"
           "    res.json({ m: e.message });\n  }\n}\n")
    assert not _guarded(src, 7)


def test_a_typed_catch_after_a_try_block_is_the_header() -> None:
    src = "try {\n  run();\n} catch (InputValidationException e) {\n  w.write(e.getMessage());\n}\n"
    assert _guarded(src, 4)


def test_sanitising_words_do_not_widen_the_field_arms() -> None:
    """The qualifier set reads CALLEES; the field arms keep their pre-revision word set, so a
    field named `maskedValue` or `scrubbedText` keeps its verdict."""
    added = iec._SANITISING_WORDS - iec._PROJECTION_WORDS
    assert {"masked", "redacted", "scrub", "scrubbed"} <= added
    assert iec._FIELD_NOT_TEXT.isdisjoint(added)
    assert "safe" not in iec._SANITISING_WORDS


# ---- R209FP-1: the excuse covers only the caught error's OWN text ----

_GUARD = "try {{\n  run();\n}} catch (err) {{\n  if (err instanceof InputError) {{\n{body}  }}\n}}\n"


@pytest.mark.parametrize("body, row, guarded", [
    ("    res.json({ m: err.message });\n", 5, True),
    ("    res.json({ m: getErrorMessage(err) });\n", 5, True),
    ("    res.json({ m: String(err.cause) });\n", 5, False),
    ("    res.json({ m: `bad: ${err.cause}` });\n", 5, False),
    ("    res.json({ m: err.original.message });\n", 5, False),
    ("    const inner = err.cause as Error;\n    res.json({ m: inner.message });\n", 6, False),
    ("    const inner = err.cause;\n    res.json({ m: String(inner) });\n", 6, False),
    ("    const detail = err.message;\n    res.json({ m: detail });\n", 6, True),
    ("    const dbErr = await db.lastError();\n    res.json({ m: dbErr.message });\n", 6, False),
    ("    res.json({ m: lastFailure.getMessage() });\n", 5, False),
    ("    res.json({ m: err.message, d: other.stackTrace });\n", 5, False),
])
def test_the_excuse_covers_only_the_caught_errors_own_text(body: str, row: int, guarded: bool) -> None:
    assert _guarded(_GUARD.format(body=body), row) is guarded


@pytest.mark.parametrize("sink, guarded", [
    ("w.write(e.getMessage());", True),
    ("w.write(e.getCause().getMessage());", False),
    ("w.write(e.toString() + e.getCause());", False),
    ("w.write(ex.InnerException.Message);", False),
    ("w.write($e->getPrevious()->getMessage());", False),
])
def test_a_typed_handler_disclosing_a_wrapped_error(sink: str, guarded: bool) -> None:
    src = f"void f() {{\n    try {{\n      run();\n    }} catch (InputValidationException e) {{\n      {sink}\n    }}\n}}\n"
    assert _guarded(src, 5) is guarded


@pytest.mark.parametrize("expr, guarded", [
    ("str(exc)", True),
    ("str(exc.__cause__)", False),
    ("repr(exc.__context__)", False),
])
def test_a_python_typed_except_disclosing_a_wrapped_error(expr: str, guarded: bool) -> None:
    src = f"def f(self):\n    try:\n        run()\n    except ValidationError as exc:\n        self.write({expr})\n"
    assert _guarded(src, 5) is guarded


def test_a_multi_row_sink_is_read_whole() -> None:
    src = ("try {\n  run();\n} catch (err) {\n  if (err instanceof InputError) {\n"
           "    send(res, 400, {\n      m: err.message,\n      c: String(err.cause),\n    });\n  }\n}\n")
    assert not _guarded(src, 5)


# ---- R209FP-2: a classifier admits only through a caller-facing class ----

def _classifier(body: str) -> str:
    return ("function classify(err) {\n" + body + "}\n"
            "try {\n  run();\n} catch (err) {\n  const status = classify(err);\n"
            "  if (status !== null) {\n    send(res, status, getErrorMessage(err));\n  }\n}\n")


def _classifier_sink(src: str) -> int:
    return src.splitlines().index("    send(res, status, getErrorMessage(err));") + 1


@pytest.mark.parametrize("body, guarded", [
    # positive caller-facing test answers, the fall-through refuses
    ("  if (err instanceof InputError) {\n    return 400;\n  }\n  return null;\n", True),
    ("  if (err instanceof InputError) return 400;\n  return null;\n", True),
    # a screen refuses every other class first, then anything may answer
    ("  if (!(err instanceof InputError) && !(err instanceof AuthorizationError)) {\n    return null;\n  }\n"
     "  return err instanceof AuthorizationError ? 403 : 400;\n", True),
    ("  const name = err.name;\n  if (name !== \"InputError\" && name !== \"AuthorizationError\") {\n"
     "    return null;\n  }\n  if (typeof err.status === \"number\") {\n    return err.status;\n  }\n  return 400;\n", True),
    # the fall-through answers
    ("  if (!err) {\n    return null;\n  }\n  if (err instanceof InputError) {\n    return 400;\n  }\n  return 500;\n",
     False),
    # a code compare answers
    ("  if (err instanceof InputError) {\n    return 400;\n  }\n  if (err.code === \"ENOENT\") {\n    return 404;\n  }\n"
     "  return null;\n", False),
    # the else arm of a caller-facing test answers
    ("  if (err instanceof InputError) {\n    return 400;\n  } else {\n    return 500;\n  }\n", False),
    # a screen that is not a conjunction of negative caller-facing tests
    ("  if (!(err instanceof InputError) || retry) {\n    return null;\n  }\n  return 400;\n", False),
    ("  if (!(err instanceof StorageError)) {\n    return null;\n  }\n  return 400;\n", False),
    # a screen nested inside a branch does not screen the routine
    ("  if (strict) {\n    if (!(err instanceof InputError)) {\n      return null;\n    }\n  }\n  return 400;\n", False),
])
def test_a_classifier_answers_only_through_a_caller_facing_class(body: str, guarded: bool) -> None:
    src = _classifier(body)
    assert _guarded(src, _classifier_sink(src)) is guarded


@pytest.mark.parametrize("body, guarded", [
    ("    if not isinstance(exc, (ValidationError, AuthorizationError)):\n        return None\n    return 400\n", True),
    ("    if isinstance(exc, ValidationError):\n        return 400\n    return None\n", True),
    ("    if isinstance(exc, ValidationError):\n        return 400\n    if exc.errno == 2:\n        return 404\n"
     "    return None\n", False),
])
def test_a_python_classifier(body: str, guarded: bool) -> None:
    src = ("def status_for(exc):\n" + body + "\n\ndef post(self):\n    try:\n        run()\n"
           "    except Exception as exc:\n        status = status_for(exc)\n        if status is not None:\n"
           "            self.write(str(exc))\n")
    assert _guarded(src, len(src.splitlines())) is guarded


# ---- round 2: the caught error's OWN text is an allowlist ----

@pytest.mark.parametrize("body, guarded", [
    ("    res.json({ m: err.message });\n", True),
    ("    res.json({ m: `${err.name}: ${err.message.trim()}` });\n", True),
    ("    res.json({ m: `bad: ${err}` });\n", True),
    ("    res.json({ m: \"bad: \" + err });\n", True),
    ("    res.json({ m: String(err) });\n", True),
    # any other member of the caught error is not its own text
    ("    res.json({ m: err.dbError.message });\n", False),
    ("    res.json({ m: err.error.message });\n", False),
    ("    res.json({ m: err.parent.message });\n", False),
    ("    res.json({ m: err.query });\n", False),
    ("    res.json({ m: err.response.data });\n", False),
    # the whole error object handed to a serialiser carries every enumerable field
    ("    res.status(400).json(err);\n", False),
    ("    res.json({ e: err });\n", False),
])
def test_only_the_caught_errors_own_text_is_excused(body: str, guarded: bool) -> None:
    assert _guarded(_GUARD.format(body=body), 5) is guarded


@pytest.mark.parametrize("sink, guarded", [
    ("w.write(e.getLocalizedMessage());", True),
    ("w.write(e.sqlError.getMessage());", False),
    ("w.write(e.getErrorCode() + e.getSQLState());", False),
    ("w.write($e->dbError->getMessage());", False),
])
def test_a_typed_handler_reading_another_member(sink: str, guarded: bool) -> None:
    src = f"void f() {{\n    try {{\n      run();\n    }} catch (InputValidationException e) {{\n      {sink}\n    }}\n}}\n"
    assert _guarded(src, 5) is guarded


@pytest.mark.parametrize("expr, guarded", [
    ("str(exc)", True),
    ("f\"bad: {exc}\"", True),
    ("str(exc.orig)", False),
    ("str(exc.error)", False),
    ("exc", False),
])
def test_a_python_typed_except_reading_another_member(expr: str, guarded: bool) -> None:
    src = f"def f(self):\n    try:\n        run()\n    except ValidationError as exc:\n        self.write({expr})\n"
    assert _guarded(src, 5) is guarded


def test_go_error_call_is_own_text_but_an_error_field_is_not() -> None:
    assert iec._own_member_chain(".Error()")
    assert not iec._own_member_chain(".error")
    assert iec._own_member_chain(".message.trim()")
    assert not iec._own_member_chain(".parent.message")


# ---- round 2: a classifier must test ITS OWN parameter ----

@pytest.mark.parametrize("body, guarded", [
    ("  if (!(other instanceof InputError)) {\n    return null;\n  }\n  return 400;\n", False),
    ("  if (other instanceof InputError) {\n    return 400;\n  }\n  return null;\n", False),
    ("  const kind = other.name;\n  if (kind !== \"InputError\") {\n    return null;\n  }\n  return 400;\n", False),
    ("  const kind = err.name;\n  if (kind !== \"InputError\") {\n    return null;\n  }\n  return 400;\n", True),
])
def test_a_classifier_tests_its_first_parameter(body: str, guarded: bool) -> None:
    src = _classifier(body)
    assert _guarded(src, _classifier_sink(src)) is guarded


def test_a_python_classifier_testing_another_parameter() -> None:
    src = ("def status_for(exc, previous=None):\n    if not isinstance(previous, ValidationError):\n"
           "        return None\n    return 400\n\n\ndef post(self):\n    try:\n        run()\n"
           "    except Exception as exc:\n        status = status_for(exc)\n        if status is not None:\n"
           "            self.write(str(exc))\n")
    assert not _guarded(src, len(src.splitlines()))


# ---- round 2: a negated qualifier does not sanitise ----

@pytest.mark.parametrize("callee, extractor", [
    ("getNonPublicMessage", True),
    ("unsafePublicMessage", True),
    ("rawPublicMessage", True),
    ("notRedactedMessage", True),
    ("toPublicMessage", False),
])
def test_a_negated_sanitising_qualifier(callee: str, extractor: bool) -> None:
    assert iec._is_extractor(callee) is extractor
