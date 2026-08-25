"""P4.11 — CWE-778 must not fire on handlers that PROPAGATE the error.

Re-raising / forwarding an error is not a logging defect: the caller
still gets the evidence. Only SWALLOWED errors (and empty handlers) are
CWE-778. An EMPTY body is not propagating and must still report.
"""


def _findings(tmp_path):
    from cwe_agent.skills.insufficient_logging_check import check_insufficient_logging
    return check_insufficient_logging(str(tmp_path))["findings"]


def _handler_findings(tmp_path):
    """Only the exception-handler rows (not the auth-decision rows)."""
    return [
        f for f in _findings(tmp_path)
        if f["check_id"] == "cwe.insufficient_logging.cwe_778"
    ]


def test_no_fire_on_propagating_handlers(tmp_path):
    """The measured 3-false-row fixture: next(err), throw e, bare raise."""
    (tmp_path / "route.js").write_text(
        "function handler(req, res, next) {\n"
        "  try {\n"
        "    doWork(req);\n"
        "  } catch (err) { next(err) }\n"
        "}\n"
        "function rethrow(x) {\n"
        "  try {\n"
        "    x();\n"
        "  } catch (e) { throw e }\n"
        "}\n"
    )
    (tmp_path / "svc.py").write_text(
        "def run(x):\n"
        "    try:\n"
        "        x()\n"
        "    except ValueError:\n"
        "        raise\n"
    )
    assert _handler_findings(tmp_path) == []


def test_no_fire_on_multiline_propagation_forms(tmp_path):
    """raise <name>, reject(, return err, callback(err) are propagation."""
    (tmp_path / "a.py").write_text(
        "def run(x):\n"
        "    try:\n"
        "        x()\n"
        "    except ValueError as exc:\n"
        "        raise RuntimeError('wrapped') from exc\n"
    )
    (tmp_path / "b.js").write_text(
        "function p(x) {\n"
        "  return new Promise((resolve, reject) => {\n"
        "    try {\n"
        "      resolve(x());\n"
        "    } catch (e) {\n"
        "      reject(e);\n"
        "    }\n"
        "  });\n"
        "}\n"
    )
    (tmp_path / "c.js").write_text(
        "function q(x, callback) {\n"
        "  try {\n"
        "    callback(null, x());\n"
        "  } catch (err) {\n"
        "    callback(err);\n"
        "  }\n"
        "}\n"
    )
    (tmp_path / "d.go").write_text(
        "package main\n"
        "func run() error {\n"
        "  v, err := do()\n"
        "  try {\n"
        "    use(v)\n"
        "  } catch (err) {\n"
        "    return nil, err\n"
        "  }\n"
        "}\n"
    )
    assert _handler_findings(tmp_path) == []


def test_still_fires_on_empty_handler_bodies(tmp_path):
    """Regression guard: EMPTY bodies are not propagating and still report."""
    (tmp_path / "e.py").write_text(
        "def run(x):\n"
        "    try:\n"
        "        x()\n"
        "    except ValueError:\n"
        "        pass\n"
    )
    (tmp_path / "E.java").write_text(
        "public class E {\n"
        "    public void run() {\n"
        "        try { foo(); } catch (Exception e) {}\n"
        "    }\n"
        "}\n"
    )
    assert len(_handler_findings(tmp_path)) == 2


def test_still_fires_on_swallowing_handlers(tmp_path):
    """A handler that neither logs nor propagates is still CWE-778."""
    (tmp_path / "s.py").write_text(
        "def run(x):\n"
        "    try:\n"
        "        x()\n"
        "    except ValueError:\n"
        "        self.failed = True\n"
        "        return None\n"
    )
    (tmp_path / "s.js").write_text(
        "function s(x) {\n"
        "  try {\n"
        "    x();\n"
        "  } catch (e) {\n"
        "    fallback();\n"
        "  }\n"
        "}\n"
    )
    assert len(_handler_findings(tmp_path)) == 2


def test_comment_mentioning_throw_does_not_suppress(tmp_path):
    """Precision guard: prose mentioning raise/throw is not propagation."""
    (tmp_path / "cmt.js").write_text(
        "function s(x) {\n"
        "  try {\n"
        "    x();\n"
        "  } catch (e) {\n"
        "    // we deliberately do not throw here\n"
        "    fallback();\n"
        "  }\n"
        "}\n"
    )
    assert len(_handler_findings(tmp_path)) == 1


def test_bare_next_without_error_is_not_propagation(tmp_path):
    """`next()` continues the chain without an error - still a swallow."""
    (tmp_path / "n.js").write_text(
        "function h(req, res, next) {\n"
        "  try {\n"
        "    work();\n"
        "  } catch (err) {\n"
        "    next();\n"
        "  }\n"
        "}\n"
    )
    assert len(_handler_findings(tmp_path)) == 1
