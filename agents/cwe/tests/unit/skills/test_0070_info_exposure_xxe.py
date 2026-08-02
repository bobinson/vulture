"""Feature 0070 — info-exposure precision + Node XXE / config / token detectors.

Three separate defects, each measured on a real application tree:

1. CWE-611 (input_validation_check) scored ZERO on a target that is XXE-vulnerable
   by its own admission.
   `XXE_PATTERNS` held eight Python/Java parser APIs and no Node entry at all,
   so `lib/xml.ts:35` — which ORs `XML_PARSE_NOENT | XML_PARSE_DTDLOAD` into the
   libxml2 parse options and is reached from `routes/fileUpload.ts:76` — was
   invisible.

2. CWE-532 (info_exposure_check) emitted 6 rows in one sweep, all 6 false. The
   `log`-prefixed alternation `(?:log(?:ger)?|print|fmt\\.Print)\\w*\\(` matched
   `oauthLogin(`, `.login(` and `await login(`, and the remaining rows were log
   messages whose *literal text* merely mentions a token
   ("ORG_ADMIN_TOKEN secret not configured", "BEE tokens extracted
   successfully"). Both fixes are required together: pattern 3
   (`console\\.log\\(.*(?:password|secret|token|apiKey)`) independently re-fires
   on 4 of the 6 rows if only the receiver guard is added, so the literal strip
   has to run before ALL FOUR entries of LOG_SENSITIVE_PATTERNS.

   Detection of a genuinely logged secret must survive — including through an
   interpolation, which is why the strip keeps `${...}` / `{...}` expressions.

3. Two common exposures the skill had no rule for:
   - CWE-497 a config route serialises the WHOLE node-config
     object (`config.util.toObject(config)`) into an HTTP response.
   - CWE-598 `frontend/src/app/Services/user.service.ts:68` puts an OAuth
     access token in the query string of a GET URL.
"""

import tempfile
from pathlib import Path

from cwe_agent.skills.info_exposure_check import check_information_exposure
from cwe_agent.skills.input_validation_check import check_input_validation


def _run(files: dict[str, str], skill=check_information_exposure) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return skill(str(root))["findings"]


def _of(findings: list[dict], cwe: str) -> list[dict]:
    return [f for f in findings if f.get("category") == cwe]


# --------------------------------------------------------------------------
# 1. CWE-611 — Node XXE
# --------------------------------------------------------------------------


class TestNodeXXE:
    def test_libxml2_parse_options_flags(self):
        """lib/xml.ts:35 — the exact instance the scan missed."""
        body = (
            "import * as vm from 'node:vm'\n"
            "export async function parseXmlString (data: string) {\n"
            "  const libxml2 = await loadLibxml2()\n"
            "  const option = libxml2.ParseOption.XML_PARSE_NOENT | "
            "libxml2.ParseOption.XML_PARSE_DTDLOAD | libxml2.ParseOption.XML_PARSE_NOBLANKS\n"
            "  const sandbox = { libxml2, data, option }\n"
            "  return xmlDoc.toString()\n"
            "}\n"
        )
        hits = _of(_run({"xmlutil.ts": body}, check_input_validation), "CWE-611")
        assert hits, "XML_PARSE_NOENT | XML_PARSE_DTDLOAD must be reported as XXE"
        assert hits[0]["line_start"] == 4

    def test_libxmljs_parse_with_noent_option(self):
        body = (
            "function parse (xml) {\n"
            "  return libxmljs.parseXmlString(xml, { noent: true, dtdload: true })\n"
            "}\n"
        )
        assert _of(_run({"parser.ts": body}, check_input_validation), "CWE-611")

    def test_libxmljs_parsexml_call(self):
        body = "const doc = libxmljs2.parseXml(payload)\n"
        assert _of(_run({"doc.js": body}, check_input_validation), "CWE-611")

    def test_xml2js_parsestring(self):
        body = (
            "function handle (body) {\n"
            "  xml2js.parseString(body, (err, result) => { send(result) })\n"
            "}\n"
        )
        assert _of(_run({"soap.js": body}, check_input_validation), "CWE-611")

    def test_domparser_parsefromstring(self):
        body = "const doc = new DOMParser().parseFromString(raw, 'text/xml')\n"
        assert _of(_run({"render.ts": body}, check_input_validation), "CWE-611")

    def test_sax_with_entity_expansion(self):
        body = "const parser = sax.parser(true, { strictEntities: false })\n"
        assert _of(_run({"stream.js": body}, check_input_validation), "CWE-611")

    def test_entities_disabled_not_flagged(self):
        """`noent: false` is the hardened configuration, not a finding."""
        body = "const doc = libxmljs.parseXmlString(xml, { noent: false, dtdload: false })\n"
        assert not _of(_run({"safe.ts": body}, check_input_validation), "CWE-611")

    def test_json_parsing_not_flagged(self):
        body = "const doc = JSON.parse(raw)\nconst other = parseInt(raw, 10)\n"
        assert not _of(_run({"json.ts": body}, check_input_validation), "CWE-611")

    def test_parse_options_ored_into_a_variable_is_reached(self):
        """The real-world shape: the unsafe flags are OR-ed into a local that is
        passed to the parser, so no single line contains both the API and the
        flag."""
        body = (
            "const options = xmljs.ParserOptions.XML_PARSE_NOENT |\n"
            "  xmljs.ParserOptions.XML_PARSE_DTDLOAD\n"
            "export const parse = (xml: string) =>\n"
            "  libxmljs.parseXml(xml, { option: options })\n"
        )
        assert _of(_run({"xml.ts": body}, check_input_validation), "CWE-611")


# --------------------------------------------------------------------------
# 2. CWE-532 — precision
# --------------------------------------------------------------------------


class TestLogSensitivePrecision:
    def test_literal_message_mentioning_token_not_flagged(self):
        """.github/workflows/pr-compliance.yml:463 and faucet.component.ts:238."""
        body = (
            "function report () {\n"
            "  console.log('ORG_ADMIN_TOKEN secret not configured, skipping user block.')\n"
            "  console.log('BEE tokens extracted successfully')\n"
            "  console.log('Role from token could not be accessed.')\n"
            "}\n"
        )
        assert _of(_run({"report.ts": body}), "CWE-532") == []

    def test_oauth_login_receiver_not_flagged(self):
        """oauth.component.ts:28 — `oauthLogin(` is not a log sink."""
        body = (
            "ngOnInit (): void {\n"
            "  this.userService.oauthLogin(this.parseRedirectUrlParams().access_token).subscribe()\n"
            "}\n"
        )
        assert _of(_run({"oauth.component.ts": body}), "CWE-532") == []

    def test_dotted_login_not_flagged(self):
        """oauth.component.ts:46 — `.login({ ... password: ... })`."""
        body = (
            "login (profile: any) {\n"
            "  this.userService.login({ email: profile.email, password: btoa(profile.email), oauth: true })\n"
            "}\n"
        )
        assert _of(_run({"session.ts": body}), "CWE-532") == []

    def test_bare_login_call_not_flagged(self):
        """auth.ts:59 — `await login(app, { email, password })`."""
        body = (
            "async function setup (app) {\n"
            "  const { token } = await login(app, { email, password })\n"
            "  return token\n"
            "}\n"
        )
        assert _of(_run({"authhelper.ts": body}), "CWE-532") == []

    def test_genuine_console_log_password_still_flagged(self):
        body = "function boom (password) {\n  console.log(password)\n}\n"
        hits = _of(_run({"leak.ts": body}), "CWE-532")
        assert hits, "console.log(password) must still be reported"
        assert hits[0]["line_start"] == 2

    def test_genuine_logger_interpolated_token_still_flagged(self):
        body = "function boom (authToken) {\n  logger.warn(`session token: ${authToken}`)\n}\n"
        assert _of(_run({"audit.ts": body}), "CWE-532")

    def test_python_fstring_password_still_flagged(self):
        body = 'def go(password):\n    logging.info(f"password={password}")\n'
        assert _of(_run({"handler.py": body}), "CWE-532")

    def test_go_style_secret_log_still_flagged(self):
        body = 'func go() {\n\tlog.Printf("%s", apiKey)\n}\n'
        assert _of(_run({"main.go": body}), "CWE-532")

    def test_all_known_false_positive_shapes_together_score_zero(self):
        """Aggregate precision: every FP shape this rule ever produced, in one
        tree, must yield nothing. Kept as one test because the property that
        matters is the total, not any single shape."""
        files = {
            "oauth.ts": "const t = await oauthLogin(credentials)\n",
            "dotted.ts": "await this.userService.login(payload)\n",
            "bare.ts": "const session = await login(email, password)\n",
            "msg1.ts": 'logger.warn("ORG_ADMIN_TOKEN secret not configured")\n',
            "msg2.ts": 'console.log("BEE tokens extracted successfully")\n',
        }
        hits = _of(_run(files), "CWE-532")
        assert hits == [], [(h["file_path"], h["line_start"]) for h in hits]


# --------------------------------------------------------------------------
# 3a. CWE-497 — whole application config in a response
# --------------------------------------------------------------------------


class TestConfigExposure:
    def test_app_configuration_route(self):
        """A config route: full node-config dump in res.json()."""
        body = (
            "export function getAppConfig () {\n"
            "  return (_req: Request, res: Response) => {\n"
            "    const safeConfig = structuredClone(config.util.toObject(config))\n"
            "    delete safeConfig.application.chatBot.llmApiUrl\n"
            "    res.json({ config: safeConfig })\n"
            "  }\n"
            "}\n"
        )
        hits = _of(_run({"appconfig.ts": body}), "CWE-497")
        assert hits, "a whole-config dump reaching res.json() must be CWE-497"
        assert hits[0]["line_start"] == 5

    def test_direct_env_dump_flagged(self):
        body = "app.get('/debug', (req, res) => { res.json(process.env) })\n"
        assert _of(_run({"debugroute.js": body}), "CWE-497")

    def test_python_environ_dump_flagged(self):
        body = "def debug():\n    return jsonify(dict(os.environ))\n"
        assert _of(_run({"views.py": body}), "CWE-497")

    def test_single_config_value_not_flagged(self):
        body = (
            "router.get('/version', (req, res) => {\n"
            "  res.json({ version: config.get('application.version') })\n"
            "})\n"
        )
        assert _of(_run({"version.ts": body}), "CWE-497") == []

    def test_config_used_without_response_not_flagged(self):
        body = "const all = config.util.toObject(config)\nsetupThings(all)\n"
        assert _of(_run({"boot.ts": body}), "CWE-497") == []

    # The real-world route shape is already covered hermetically by
    # `test_app_configuration_route` above (a node-config dump reaching
    # `res.json`), so the former corpus-path test added no distinct coverage.


# --------------------------------------------------------------------------
# 3b. CWE-598 — sensitive token in a query string
# --------------------------------------------------------------------------


class TestTokenInQueryString:
    def test_access_token_in_get_url(self):
        """user.service.ts:68 — access_token appended to a GET URL."""
        body = (
            "googleAuth (accessToken: string) {\n"
            "  return this.http.get('https://www.googleapis.com/oauth2/v1/userinfo"
            "?alt=json&access_token=' + accessToken)\n"
            "}\n"
        )
        hits = _of(_run({"user.service.ts": body}), "CWE-598")
        assert hits, "a token in a GET query string must be reported as CWE-598"
        assert hits[0]["line_start"] == 2

    def test_password_in_query_string_flagged(self):
        body = "const url = `/api/login?user=${u}&password=${p}`\nfetch(url)\n"
        assert _of(_run({"login.ts": body}), "CWE-598")

    def test_apikey_in_query_string_flagged(self):
        body = "requests.get('https://api.example.com/v1/items?apiKey=' + key)\n"
        assert _of(_run({"client.py": body}), "CWE-598")

    def test_benign_query_params_not_flagged(self):
        body = "fetch('/rest/products?alt=json&limit=10&sort=name')\n"
        assert _of(_run({"list.ts": body}), "CWE-598") == []

    def test_token_in_post_body_not_flagged(self):
        body = "await http.post('/rest/user/login', { email, password })\n"
        assert _of(_run({"post.ts": body}), "CWE-598") == []

    def test_otpauth_provisioning_uri_not_flagged(self):
        """two-factor-auth.component.ts:77 — not a GET, and unavoidable by spec."""
        body = "this.totpUrl = `otpauth://totp/${app}:${email}?secret=${secret}&issuer=${app}`\n"
        assert _of(_run({"twofactor.ts": body}), "CWE-598") == []

    def test_token_in_a_get_query_string_is_reached(self):
        body = (
            "this.http.get(`${environment.hostServer}/rest/user/reset-password"
            "?token=${this.token}`)\n"
        )
        assert _of(_run({"reset.ts": body}), "CWE-598")
