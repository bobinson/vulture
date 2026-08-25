"""CWE-778 must not fire when the handler DELEGATES to an error routine.

Measured on a real target: 95 of 168 CWE-778 rows were
``catch (error) { handleApiError(error, response); }`` — and handleApiError
logs (``console.log("AppError", payload)``) one hop away. The rule only
recognised DIRECT log calls, so a single hop of indirection defeated it.

The predicate requires BOTH an error-handling NAME SHAPE and an
error-shaped ARGUMENT, so ``cleanup(e)`` or ``swallow(e)`` are not excused.
"""

from cwe_agent.skills.insufficient_logging_check import _handler_is_excused


class TestDelegationIsExcused:
    def test_handle_api_error(self):
        assert _handler_is_excused(["    handleApiError(error, response);"])

    def test_capture_exception(self):
        assert _handler_is_excused(["    Sentry.captureException(err);"])

    def test_report_error(self):
        assert _handler_is_excused(["    reportError(e);"])

    def test_log_error(self):
        assert _handler_is_excused(["    logError(error);"])

    def test_error_handler_suffix(self):
        assert _handler_is_excused(["    apiErrorHandler(error, res);"])


class TestNonDelegationStillReports:
    def test_cleanup_is_not_delegation(self):
        assert not _handler_is_excused(["    cleanup(e);"])

    def test_swallow_is_not_delegation(self):
        assert not _handler_is_excused(["    swallow(e);"])

    def test_name_without_error_arg_is_not_delegation(self):
        assert not _handler_is_excused(["    handleApiError(requestId, response);"])

    def test_bare_comment_is_not_delegation(self):
        assert not _handler_is_excused(["    // handleApiError(error) would go here"])

    def test_return_null_still_reports(self):
        assert not _handler_is_excused(["    return null;"])
