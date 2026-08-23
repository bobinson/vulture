"""CWE-209 must detect Node/Express error disclosure, not only Python/Java/Go.

ERROR_DISCLOSURE_PATTERNS covered `traceback.print_exc`, `traceback.format_exc`,
`.printStackTrace` (Java), `debug.PrintStack` (Go) and a `return ...traceback`
shape. Every one is foreign to Node, so CWE-209 scored zero on a TypeScript
target that leaks stack traces to unauthenticated clients by design:

    server.ts:682   app.use(errorhandler())

The `errorhandler` package exists to send the full stack trace and surrounding
source context in the HTTP response. A measured app mounted it unconditionally — no
`NODE_ENV` guard — and declares it as a *production* dependency
(package.json:108, not devDependencies), so the leak ships.

This matters beyond one finding: OWASP A10 was carried solely by CWE-754, whose
rows are unguarded `fs` calls in build scripts. CWE-209 gives A10 a second
mapped CWE and its first security-relevant row.

Precision is deliberately favoured over recall here. A generic literal
(`res.send('Internal Server Error')`) is not a disclosure, `errorhandler()`
behind a development guard is its documented safe usage, and logging an error
server-side is CWE-532's business, not this rule's.
"""

import tempfile
from pathlib import Path

from cwe_agent.skills.info_exposure_check import check_information_exposure


def _run(files: dict[str, str]) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return check_information_exposure(str(root))["findings"]


def _disclosure(findings: list[dict]) -> list[dict]:
    return [f for f in findings if f.get("category") == "CWE-209"]


class TestLeakyErrorMiddleware:
    def test_errorhandler_shape(self):
        """server.ts:682 — the exact instance the scan missed."""
        body = (
            "const errorhandler = require('errorhandler')\n"
            "function start () {\n"
            "  app.use(verify.errorHandlingChallenge())\n"
            "  app.use(errorhandler())\n"
            "}\n"
        )
        hits = _disclosure(_run({"server.ts": body}))
        assert hits, "an unguarded errorhandler() mount must be reported as CWE-209"
        assert hits[0]["line_start"] == 4, f"must point at the mount line, got {hits[0]['line_start']}"

    def test_other_leaky_middleware(self):
        for mw in ("errorhandler()", "expressErrorHandler()", "errorHandler({ debug: true })"):
            body = f"app.use({mw})\n"
            assert _disclosure(_run({"a.js": body})), f"{mw} not reported"

    def test_development_guard_suppresses(self):
        """Gating on the environment is errorhandler's documented safe usage."""
        body = (
            "if (process.env.NODE_ENV === 'development') {\n"
            "  app.use(errorhandler())\n"
            "}\n"
        )
        assert not _disclosure(_run({"dev.js": body})), \
            "an environment-guarded errorhandler() must not be reported"

    def test_express_env_guard_suppresses(self):
        body = (
            "if (app.get('env') !== 'production') {\n"
            "  app.use(errorhandler())\n"
            "}\n"
        )
        assert not _disclosure(_run({"dev2.js": body})), \
            "app.get('env') guards are equivalent to a NODE_ENV guard"


class TestErrorEchoedInResponse:
    def test_error_object_sent_directly(self):
        body = (
            "async function handler (req, res) {\n"
            "  try { await work() } catch (err) { res.status(500).send(err) }\n"
            "}\n"
        )
        assert _disclosure(_run({"h.ts": body})), "res.send(err) leaks internals"

    def test_stack_property_in_response(self):
        body = "app.use((err, req, res, next) => { res.status(500).json({ stack: err.stack }) })\n"
        assert _disclosure(_run({"m.js": body})), "err.stack in a response body must be reported"

    def test_stack_sent_via_end(self):
        body = "function h (e, req, res) {\n  res.end(e.stack)\n}\n"
        assert _disclosure(_run({"e.ts": body})), "res.end(e.stack) must be reported"

    def test_error_message_json(self):
        body = "catch (error) { res.json({ error: error.message }) }\n"
        assert _disclosure(_run({"j.ts": body})), "echoing error.message must be reported"


class TestPrecision:
    def test_generic_literal_is_not_a_disclosure(self):
        body = (
            "try { work() } catch (err) {\n"
            "  res.status(500).send('Internal Server Error')\n"
            "  res.status(500).json({ error: 'Something went wrong' })\n"
            "}\n"
        )
        assert not _disclosure(_run({"safe.ts": body})), \
            "a generic literal response is the correct behaviour, not a finding"

    def test_server_side_logging_is_not_this_rule(self):
        body = (
            "catch (err) {\n"
            "  console.error(err)\n"
            "  logger.error(err.stack)\n"
            "  res.status(500).send('error')\n"
            "}\n"
        )
        assert not _disclosure(_run({"log.ts": body})), \
            "logging an error server-side is CWE-532's concern, not error disclosure"

    def test_error_named_variable_holding_a_literal(self):
        """routes/recycles.ts:25 — an `errMsg` local holding a fixed message.

        The identifier is error-shaped but its value is a hardcoded string, so
        nothing internal escapes. Naming is not evidence.
        """
        body = (
            "function handler (req, res) {\n"
            "  const errMsg = { err: 'Sorry, this endpoint is not supported.' }\n"
            "  return res.send(utils.queryResultToJson(errMsg))\n"
            "}\n"
        )
        assert not _disclosure(_run({"recycles.ts": body})), \
            "an error-named variable assigned a literal must not be reported"

    def test_error_variable_holding_a_real_error_still_fires(self):
        """The mirror case: same shape, but the value is a caught error."""
        body = (
            "try { work() } catch (e) {\n"
            "  const errMsg = e.message\n"
            "  res.send(utils.toJson(errMsg))\n"
            "}\n"
        )
        assert _disclosure(_run({"real.ts": body})), \
            "an error-named variable holding a caught error's message is a disclosure"

    def test_comments_are_ignored(self):
        body = "// app.use(errorhandler())\n/* res.send(err) */\n"
        assert not _disclosure(_run({"c.js": body})), "commented-out code must not fire"

    def test_existing_python_patterns_still_fire(self):
        """The Node additions must not regress the original coverage."""
        body = (
            "import traceback\n"
            "def handler():\n"
            "    try:\n"
            "        work()\n"
            "    except Exception:\n"
            "        return traceback.format_exc()\n"
        )
        assert _disclosure(_run({"h.py": body})), "the pre-existing Python pattern must still fire"
