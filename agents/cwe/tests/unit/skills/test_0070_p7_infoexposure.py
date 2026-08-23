"""Feature 0070 P7 — info-exposure group: CWE-359 / 550 / 313 / 215 / 201.

Every rule here was written against an adversarial review of a measured
baseline, so the tests encode the *revised* predicate, not the proposed one.
The load-bearing cases:

* **CWE-359** must stay disjoint from the shipped CWE-598: 598 owns credentials
  in a query string, 359 owns personal data. A parameter can never produce both
  rows, and the ``[?&]…=`` anchor is mandatory (a bare ``dob`` word match is a
  different, much noisier rule).
* **CWE-550** is only claimed for sinks that are unambiguously an HTTP response
  carrying a *server-generated* error value. The loose JS bare-identifier and
  ``.stack`` shapes stay on CWE-209 — three existing contract tests pin them
  there — so this file asserts the 209 rows are UNCHANGED.
* **CWE-313** keys on the credential being in the sink's *content* position.
  A credential in the PATH argument is the file's name, not its contents.
* **CWE-215** shape (b) must not restate CWE-532: when the debug body line is
  itself a log call with a credential, 532 owns that row and 215 must stay out.
* **CWE-201** must not fire on inbound multipart parsers
  (``busboy({ headers: req.headers })`` is a designated CWE-434 must-fire line
  in this agent's own no-blunders test) nor inside declared proxy machinery.

Row stacking (P5): skill findings are not deduplicated against each other, so
each child specialisation actively suppresses its parent on the same line and
the one-row invariant is asserted, not assumed.
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


def _cats(findings: list[dict]) -> list[str]:
    return [f.get("category") for f in findings]


def _of(findings: list[dict], cwe: str) -> list[dict]:
    return [f for f in findings if f.get("category") == cwe]


# ---------------------------------------------------------------------------
# Item 39 — CWE-359: private personal information in a URL query string
# ---------------------------------------------------------------------------


class TestPiiInQueryString:
    def test_ssn_in_query_string(self):
        body = 'const url = `https://api.example.com/v1/lookup?ssn=${ssn}`\n'
        hits = _of(_run({"client.ts": body}), "CWE-359")
        assert len(hits) == 1, "an SSN in a query string is CWE-359"
        assert "ssn" in hits[0]["title"]

    def test_dob_in_python_request_url(self):
        body = 'resp = requests.get(f"https://svc/records?dob={dob}")\n'
        assert _of(_run({"c.py": body}), "CWE-359")

    def test_card_number_in_go_url(self):
        body = 'url := "https://pay.example.com/charge?card_number=" + pan\n'
        assert _of(_run({"pay.go": body}), "CWE-359")

    def test_delimited_suffix_is_matched(self):
        """Recall: `?medical_record_id=` is the same weakness as `?mrn=`."""
        body = 'const u = `/api/patients?medical_record_id=${id}`\n'
        assert _of(_run({"a.ts": body}), "CWE-359")

    # ── clean twins: minimal difference ──
    def test_pii_in_a_post_body_is_clean(self):
        body = (
            'const url = `https://api.example.com/v1/lookup`\n'
            'await fetch(url, { method: "POST", body: JSON.stringify({ ssn }) })\n'
        )
        assert not _of(_run({"clean.ts": body}), "CWE-359")

    def test_word_prefix_is_not_a_parameter(self):
        """`?dobro=` shares a prefix with `dob` and is not PII."""
        body = 'const url = "https://svc.example.com/i18n?dobro=true"\n'
        assert not _of(_run({"i.ts": body}), "CWE-359")

    def test_non_http_scheme_is_excluded(self):
        body = "const uri = `otpauth://totp/App?secret=${seed}&dob=${dob}`\n"
        assert not _of(_run({"otp.ts": body}), "CWE-359")

    def test_prose_mention_is_not_a_finding(self):
        body = "Never build a URL such as `/lookup?ssn=123456789` — it is logged.\n"
        assert not _of(_run({"SECURITY.md": body}), "CWE-359")

    # ── disjointness with the shipped CWE-598 ──
    def test_credential_parameter_stays_on_598(self):
        body = 'const url = `https://svc/api?access_token=${t}`\n'
        cats = _cats(_run({"t.ts": body}))
        assert "CWE-598" in cats
        assert "CWE-359" not in cats, "598 owns credentials; 359 must not double-fire"

    def test_pii_parameter_does_not_produce_598(self):
        body = 'const url = `https://svc/api?iban=${iban}`\n'
        cats = _cats(_run({"i.ts": body}))
        assert cats.count("CWE-359") == 1
        assert "CWE-598" not in cats


# ---------------------------------------------------------------------------
# Item 40 — CWE-550: server-generated error message in a response
# ---------------------------------------------------------------------------


class TestServerGeneratedErrorMessage:
    def test_go_http_error_with_err(self):
        body = 'func h(w http.ResponseWriter) {\n\thttp.Error(w, err.Error(), 500)\n}\n'
        findings = _run({"h.go": body})
        assert _of(findings, "CWE-550")
        assert not _of(findings, "CWE-209"), "550 replaces the 209 row (P5)"
        assert len(findings) == 1

    def test_go_response_writer_write_err(self):
        body = 'func h(w http.ResponseWriter) {\n\tw.Write([]byte(err.Error()))\n}\n'
        findings = _run({"w.go": body})
        assert _of(findings, "CWE-550")
        assert len(findings) == 1, "one row per line, not 550 + 209"

    def test_java_send_error_with_message(self):
        body = "void h() {\n  response.sendError(500, e.getMessage());\n}\n"
        assert _of(_run({"S.java": body}), "CWE-550")

    def test_aspnet_response_write_exception(self):
        body = "void H() {\n  Response.Write(ex.Message);\n}\n"
        findings = _run({"H.cs": body})
        assert _of(findings, "CWE-550")
        assert not _of(findings, "CWE-209")

    def test_python_explicit_response_sink(self):
        body = 'def h():\n    return jsonify({"error": str(e)}), 500\n'
        assert _of(_run({"v.py": body}), "CWE-550")

    # ── clean twins ──
    def test_go_generic_message_is_clean(self):
        body = 'func h(w http.ResponseWriter) {\n\thttp.Error(w, "internal error", 500)\n}\n'
        assert not _of(_run({"c.go": body}), "CWE-550")

    def test_java_generic_message_is_clean(self):
        body = 'void h() {\n  response.sendError(500, "Request failed");\n}\n'
        assert not _of(_run({"C.java": body}), "CWE-550")

    def test_bare_return_str_is_not_a_response(self):
        body = "def label(e):\n    return str(e)\n"
        assert not _of(_run({"lbl.py": body}), "CWE-550")

    def test_prose_mention_is_not_a_finding(self):
        body = "Do not call `http.Error(w, err.Error(), 500)` in production.\n"
        assert not _of(_run({"NOTES.md": body}), "CWE-550")

    # ── the existing CWE-209 contract is untouched ──
    def test_js_stack_in_response_stays_on_209(self):
        body = "app.use((err, req, res, next) => { res.status(500).json({ stack: err.stack }) })\n"
        cats = _cats(_run({"m.js": body}))
        assert cats == ["CWE-209"], f"the JS shapes stay on 209, got {cats}"

    def test_js_error_message_stays_on_209(self):
        body = "catch (error) { res.json({ error: error.message }) }\n"
        cats = _cats(_run({"j.ts": body}))
        assert cats == ["CWE-209"], f"the JS shapes stay on 209, got {cats}"


# ---------------------------------------------------------------------------
# Item 41 — CWE-313: cleartext storage in a file
# ---------------------------------------------------------------------------


class TestCleartextFileStorage:
    def test_node_write_file_with_password(self):
        body = "fs.writeFileSync(cfgPath, JSON.stringify({ password: pw }))\n"
        findings = _run({"w.js": body})
        assert _of(findings, "CWE-313")
        assert len(findings) == 1, "313 suppresses the 312 row on the same line (P5)"

    def test_go_write_file_with_api_key(self):
        body = 'func s() {\n\tos.WriteFile(p, []byte(apiKey), 0600)\n}\n'
        assert _of(_run({"s.go": body}), "CWE-313")

    def test_python_open_write_password(self):
        body = "def s(pw):\n    open('/var/tmp/c', 'w').write(f\"password={pw}\")\n"
        assert _of(_run({"s.py": body}), "CWE-313")

    def test_dotnet_write_all_text(self):
        body = "void S() {\n  File.WriteAllText(path, secretValue);\n}\n"
        assert _of(_run({"S.cs": body}), "CWE-313")

    # ── clean twins ──
    def test_non_credential_content_is_clean(self):
        body = "fs.writeFileSync(cfgPath, JSON.stringify({ theme: 'dark' }))\n"
        assert not _of(_run({"c.js": body}), "CWE-313")

    def test_credential_in_the_path_position_is_clean(self):
        """The file is NAMED for a credential; its contents are not one."""
        body = "fs.writeFileSync('secrets/password.txt', renderedTemplate)\n"
        assert not _of(_run({"p.js": body}), "CWE-313")

    def test_encrypted_content_is_clean(self):
        body = "fs.writeFileSync(cfgPath, encrypt(JSON.stringify({ password: pw })))\n"
        assert not _of(_run({"e.js": body}), "CWE-313")

    def test_python_open_writing_a_profile_is_clean(self):
        body = "def s(profile):\n    open('/var/tmp/c', 'w').write(json.dumps(profile))\n"
        assert not _of(_run({"cp.py": body}), "CWE-313")

    def test_prose_mention_is_not_a_finding(self):
        body = "Avoid `fs.writeFileSync(cfgPath, JSON.stringify({ password: pw }))`.\n"
        assert not _of(_run({"GUIDE.md": body}), "CWE-313")

    def test_shell_echo_redirect_is_not_this_rule(self):
        """The shell arm was dropped: 9 of 10 measured hits were diagnostics."""
        body = 'echo "ERROR: set OPENAI_API_KEY first" >&2\n'
        assert not _of(_run({"run.sh": body}), "CWE-313")


# ---------------------------------------------------------------------------
# Item 42 — CWE-215: sensitive information in debugging code
# ---------------------------------------------------------------------------


class TestDebugInformationExposure:
    def test_php_var_dump_of_session(self):
        body = "<?php\nvar_dump($_SESSION);\n"
        assert _of(_run({"d.php": body}), "CWE-215")

    def test_php_dd_helper_requires_sigil_argument(self):
        body = "<?php\ndd($_POST);\n"
        assert _of(_run({"dd.php": body}), "CWE-215")

    def test_node_console_dir_of_environment(self):
        body = "function boot() {\n  console.dir(process.env)\n}\n"
        assert _of(_run({"b.js": body}), "CWE-215")

    def test_python_pprint_of_environ(self):
        body = "def boot():\n    pprint(os.environ)\n"
        assert _of(_run({"b.py": body}), "CWE-215")

    def test_debug_gate_writing_a_secret_to_a_response(self):
        body = (
            "function h (req, res) {\n"
            "  if (debugMode) {\n"
            "    res.send('pwd=' + password)\n"
            "  }\n"
            "}\n"
        )
        assert _of(_run({"g.js": body}), "CWE-215")

    # ── clean twins ──
    def test_dump_of_a_domain_object_is_clean(self):
        body = "<?php\nvar_dump($user->id);\n"
        assert not _of(_run({"c.php": body}), "CWE-215")

    def test_dump_of_config_is_clean(self):
        """`config` carries no evidence of sensitivity — arm dropped."""
        body = "function boot() {\n  console.dir(config)\n}\n"
        assert not _of(_run({"cc.js": body}), "CWE-215")

    def test_single_env_lookup_is_clean(self):
        body = "function boot() {\n  console.dir(process.env.NODE_ENV)\n}\n"
        assert not _of(_run({"one.js": body}), "CWE-215")

    def test_debug_gate_without_a_secret_is_clean(self):
        body = (
            "function h (req, res) {\n"
            "  if (debugMode) {\n"
            "    res.send('ok')\n"
            "  }\n"
            "}\n"
        )
        assert not _of(_run({"cg.js": body}), "CWE-215")

    def test_debug_gate_logging_a_secret_belongs_to_532(self):
        """Anti-duplication: the body line is CWE-532's row, not a second one."""
        body = (
            "function h () {\n"
            "  if (debugMode) {\n"
            "    console.log('pw=' + password)\n"
            "  }\n"
            "}\n"
        )
        findings = _run({"l.js": body})
        assert _of(findings, "CWE-532")
        assert not _of(findings, "CWE-215"), "532 already reports that line"

    def test_prose_mention_is_not_a_finding(self):
        body = "Never ship `var_dump($_SESSION);` to production.\n"
        assert not _of(_run({"D.md": body}), "CWE-215")


# ---------------------------------------------------------------------------
# Item 43 — CWE-201: inbound request headers forwarded to an outbound client
# ---------------------------------------------------------------------------


class TestHeaderForwarding:
    def test_node_fetch_forwards_request_headers(self):
        body = (
            "async function h (req, res) {\n"
            "  const up = await fetch(target, { headers: req.headers })\n"
            "  res.json(await up.json())\n"
            "}\n"
        )
        hits = _of(_run({"f.js": body}), "CWE-201")
        assert hits
        assert hits[0]["severity"] == "medium"

    def test_node_spread_of_request_headers(self):
        body = (
            "async function h (req) {\n"
            "  const opts = { headers: { ...req.headers } }\n"
            "  return await fetch(target, opts)\n"
            "}\n"
        )
        assert _of(_run({"sp.js": body}), "CWE-201")

    def test_python_requests_forwards_request_headers(self):
        body = "def h(request):\n    return requests.get(url, headers=request.headers)\n"
        assert _of(_run({"p.py": body}), "CWE-201")

    def test_go_header_assignment_then_client_do(self):
        body = (
            "func h(r *http.Request) {\n"
            "\toutReq.Header = r.Header\n"
            "\tresp, err := client.Do(outReq)\n"
            "\t_ = resp\n"
            "}\n"
        )
        assert _of(_run({"g.go": body}), "CWE-201")

    # ── clean twins ──
    def test_explicit_headers_are_clean(self):
        body = (
            "async function h (req, res) {\n"
            "  const up = await fetch(target, { headers: safeHeaders })\n"
            "}\n"
        )
        assert not _of(_run({"c.js": body}), "CWE-201")

    def test_inbound_multipart_parser_is_clean(self):
        """`busboy({ headers: req.headers })` parses the inbound body."""
        body = (
            "function upload (req, res) {\n"
            "  const bb = busboy({ headers: req.headers })\n"
            "  bb.on('file', () => fetch(hook))\n"
            "}\n"
        )
        assert not _of(_run({"u.js": body}), "CWE-201")

    def test_declared_proxy_machinery_is_clean(self):
        body = (
            "const { createProxyMiddleware } = require('http-proxy-middleware')\n"
            "async function h (req) {\n"
            "  await fetch(target, { headers: req.headers })\n"
            "}\n"
        )
        assert not _of(_run({"px.js": body}), "CWE-201")

    def test_no_outbound_client_is_clean(self):
        body = "function h (req) {\n  const opts = { headers: req.headers }\n  return opts\n}\n"
        assert not _of(_run({"n.js": body}), "CWE-201")

    def test_credential_stripping_is_clean(self):
        body = (
            "async function h (req) {\n"
            "  const opts = { headers: req.headers }\n"
            "  delete opts.headers.authorization\n"
            "  return await fetch(target, opts)\n"
            "}\n"
        )
        assert not _of(_run({"st.js": body}), "CWE-201")

    def test_prose_mention_is_not_a_finding(self):
        body = "Do not write `fetch(target, { headers: req.headers })` in a handler.\n"
        assert not _of(_run({"P.md": body}), "CWE-201")


# ---------------------------------------------------------------------------
# Attestation: every new id must carry a LITERAL category (rule 8 / P0)
# ---------------------------------------------------------------------------


class TestAttestationLiterals:
    def test_literal_category_strings_are_present_in_source(self):
        src = Path(
            check_information_exposure.__code__.co_filename
        ).read_text()
        for cwe in ("359", "550", "313", "215", "201"):
            assert f'"category": "CWE-{cwe}"' in src, (
                f"CWE-{cwe} must be a literal, or the coverage extractor "
                "cannot see it"
            )
