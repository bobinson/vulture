"""Feature 0070 — resource_check precision + new detectors.

Two items:

1. CWE-404 (improper resource shutdown) was matching a bare ``open(``
   with no receiver guard, so every Angular ``snackBarHelperService.open()``
   / ``dialog.open()`` / ``window.open()`` call read as an unclosed
   resource. Narrowing must be receiver-aware (as the CWE-754 fix in
   error_handling_check.py already is) AND must add a real-resource
   namespace branch so the ``fs.createWriteStream`` / ``fs.createReadStream``
   family is still caught.

2. CWE-799 (Broken Anti Automation) was structurally unreachable on
   Express codebases because the endpoint pattern only matched Python
   ``def`` / Go ``func``. Plus a new CWE-807 rule for a rate limiter whose
   identity key is a client-controlled header (spoofable).
"""

from cwe_agent.skills.resource_check import check_resource_management


def _findings(path) -> list[dict]:
    return check_resource_management(str(path))["findings"]


def _cwes(path) -> set[str]:
    return {f["category"] for f in _findings(path)}


def _of(path, category: str) -> list[dict]:
    return [f for f in _findings(path) if f["category"] == category]


# --------------------------------------------------------------------------
# (1) CWE-404 — receiver-aware narrowing
# --------------------------------------------------------------------------

class TestCwe404Narrowing:
    """A method named ``open`` on an unrelated receiver is not a resource."""

    def test_angular_snackbar_open_not_flagged(self, tmp_path):
        (tmp_path / "accounting.component.ts").write_text(
            "  ngOnInit () {\n"
            "    this.snackBarHelperService.open(`Quantity updated`, 'confirmBar')\n"
            "  }\n"
        )
        assert "CWE-404" not in _cwes(tmp_path)

    def test_material_dialog_open_not_flagged(self, tmp_path):
        (tmp_path / "administration.component.ts").write_text(
            "  showUserDetail (id: number) {\n"
            "    this.dialog.open(UserDetailsComponent, { data: { id } })\n"
            "  }\n"
        )
        assert "CWE-404" not in _cwes(tmp_path)

    def test_window_open_not_flagged(self, tmp_path):
        (tmp_path / "order-history.component.ts").write_text(
            "  openConfirmationPDF (orderId: string) {\n"
            "    window.open(redirectUrl, '_blank')\n"
            "  }\n"
        )
        assert "CWE-404" not in _cwes(tmp_path)

    def test_method_declaration_named_open_not_flagged(self, tmp_path):
        """A bare ``open (`` at the start of a line is a DECLARATION."""
        (tmp_path / "mat-search-bar.component.ts").write_text(
            "export class Bar {\n"
            "  public open (): void {\n"
            "    this.searchVisible = true\n"
            "  }\n"
            "}\n"
        )
        assert "CWE-404" not in _cwes(tmp_path)

    def test_snack_bar_helper_declaration_not_flagged(self, tmp_path):
        (tmp_path / "snack-bar-helper.service.ts").write_text(
            "export class H {\n"
            "  open (message: string, cssClass?: string) {\n"
            "    this.doThing(message)\n"
            "  }\n"
            "}\n"
        )
        assert "CWE-404" not in _cwes(tmp_path)

    def test_html_template_open_handler_not_flagged(self, tmp_path):
        (tmp_path / "mat-search-bar.component.html").write_text(
            '<button mat-icon-button (click)="open()" aria-label="Search">\n'
        )
        assert "CWE-404" not in _cwes(tmp_path)

    # --- still detected (no over-correction) ------------------------------

    def test_python_builtin_open_still_flagged(self, tmp_path):
        (tmp_path / "encrypt.py").write_text(
            "confidential_document = open('announcement.md', 'r')\n"
            "data = confidential_document.read()\n"
        )
        rows = _of(tmp_path, "CWE-404")
        assert len(rows) == 1
        assert rows[0]["line_start"] == 1

    def test_c_fopen_still_flagged(self, tmp_path):
        (tmp_path / "reader.c").write_text(
            "int main(void) {\n"
            "  FILE *f = fopen(\"a.txt\", \"r\");\n"
            "  return 0;\n"
            "}\n"
        )
        assert "CWE-404" in _cwes(tmp_path)

    def test_fs_create_write_stream_flagged(self, tmp_path):
        """RECOVERY case: the bare-open form misses the fs stream family."""
        (tmp_path / "fileUpload.ts").write_text(
            "async function handle (entry) {\n"
            "  await pipeline(entry.stream(), fs.createWriteStream('uploads/' + name))\n"
            "}\n"
        )
        rows = _of(tmp_path, "CWE-404")
        assert len(rows) == 1
        assert rows[0]["line_start"] == 2

    def test_fs_create_read_stream_flagged(self, tmp_path):
        (tmp_path / "videoHandler.ts").write_text(
            "function stream (path, start, end) {\n"
            "  const file = fs.createReadStream(path, { start, end })\n"
            "  return file\n"
            "}\n"
        )
        assert "CWE-404" in _cwes(tmp_path)

    def test_go_os_open_still_flagged(self, tmp_path):
        (tmp_path / "reader.go").write_text(
            "func read() {\n"
            "\tf, err := os.Open(name)\n"
            "\t_ = f\n"
            "}\n"
        )
        assert "CWE-404" in _cwes(tmp_path)

    def test_sql_open_still_flagged(self, tmp_path):
        (tmp_path / "db.go").write_text(
            "func conn() {\n"
            "\tdb, err := sql.Open(\"postgres\", dsn)\n"
            "\t_ = db\n"
            "}\n"
        )
        assert "CWE-404" in _cwes(tmp_path)

    def test_net_dial_still_flagged(self, tmp_path):
        (tmp_path / "dialer.go").write_text(
            "func dial() {\n"
            "\tc, err := net.Dial(\"tcp\", addr)\n"
            "\t_ = c\n"
            "}\n"
        )
        assert "CWE-404" in _cwes(tmp_path)

    def test_with_open_still_suppressed(self, tmp_path):
        (tmp_path / "loader.py").write_text(
            "def load(p):\n"
            "    with open(p) as fh:\n"
            "        return fh.read()\n"
        )
        assert "CWE-404" not in _cwes(tmp_path)


# --------------------------------------------------------------------------
# (2a) CWE-799 — Express route registration form
# --------------------------------------------------------------------------

class TestCwe799Express:
    """``app.post('/rest/user/login', login())`` must be reachable."""

    def test_express_login_route_without_limiter_flagged(self, tmp_path):
        (tmp_path / "server.ts").write_text(
            "  /* Custom Restful API */\n"
            "  app.post('/rest/user/login', login())\n"
        )
        rows = _of(tmp_path, "CWE-799")
        assert len(rows) == 1
        assert rows[0]["line_start"] == 2

    def test_express_route_covered_by_limiter_path_not_flagged(self, tmp_path):
        (tmp_path / "server.ts").write_text(
            "  app.use('/rest/user/reset-password', rateLimit({\n"
            "    windowMs: 5 * 60 * 1000,\n"
            "    max: 100\n"
            "  }))\n"
            "  app.post('/rest/user/reset-password', asyncHandler(resetPassword()))\n"
        )
        assert "CWE-799" not in _cwes(tmp_path)

    def test_limiter_on_other_path_does_not_cover_login(self, tmp_path):
        """juice-shop server.ts shape: reset-password limited, login is not."""
        (tmp_path / "server.ts").write_text(
            "  app.use('/rest/user/reset-password', rateLimit({\n"
            "    max: 100\n"
            "  }))\n"
            "  app.post('/rest/user/login', login())\n"
            "  app.post('/rest/user/reset-password', asyncHandler(resetPassword()))\n"
        )
        rows = _of(tmp_path, "CWE-799")
        assert [r["line_start"] for r in rows] == [4]

    def test_inline_limiter_middleware_not_flagged(self, tmp_path):
        (tmp_path / "routes.ts").write_text(
            "  app.post('/api/login', loginLimiter, login())\n"
        )
        assert "CWE-799" not in _cwes(tmp_path)

    def test_non_auth_express_route_not_flagged(self, tmp_path):
        (tmp_path / "routes.ts").write_text(
            "  app.post('/api/Products', createProduct())\n"
            "  app.get('/api/Feedbacks', listFeedback())\n"
        )
        assert "CWE-799" not in _cwes(tmp_path)

    def test_express_signup_and_change_password_flagged(self, tmp_path):
        (tmp_path / "routes.ts").write_text(
            "  app.post('/api/Users/signup', signup())\n"
            "  app.get('/rest/user/change-password', changePassword())\n"
        )
        rows = _of(tmp_path, "CWE-799")
        assert [r["line_start"] for r in rows] == [1, 2]

    def test_auth_keyword_must_be_a_path_segment(self, tmp_path):
        """`/rest/saveLoginIp` is not a credential endpoint.

        Substring matching flagged it because "Login" appears mid-segment;
        the keyword has to be delimited to count.
        """
        (tmp_path / "server.ts").write_text(
            "  app.get('/rest/saveLoginIp', asyncHandler(saveLoginIp()))\n"
        )
        assert "CWE-799" not in _cwes(tmp_path)

    def test_express_check_id_is_distinct(self, tmp_path):
        (tmp_path / "server.ts").write_text(
            "  app.post('/rest/user/login', login())\n"
        )
        rows = _of(tmp_path, "CWE-799")
        assert rows[0]["check_id"] == "cwe.resource.express_rate_limit"

    def test_python_def_form_still_flagged(self, tmp_path):
        """Regression: the existing def/func form must keep working."""
        (tmp_path / "auth.py").write_text(
            "def login(request):\n    return authenticate(request)\n"
        )
        rows = _of(tmp_path, "CWE-799")
        assert len(rows) == 1
        assert rows[0]["check_id"] == "cwe.resource.rate_limit"


# --------------------------------------------------------------------------
# (2b) CWE-807 — spoofable rate-limit identity
# --------------------------------------------------------------------------

class TestCwe807SpoofableLimiterIdentity:

    def test_keygenerator_returning_forwarded_for_flagged(self, tmp_path):
        (tmp_path / "server.ts").write_text(
            "  app.use('/rest/user/reset-password', rateLimit({\n"
            "    windowMs: 5 * 60 * 1000,\n"
            "    max: 100,\n"
            "    keyGenerator ({ headers, ip }: { headers: any, ip: any }) "
            "{ return headers['X-Forwarded-For'] ?? ip }\n"
            "  }))\n"
        )
        rows = _of(tmp_path, "CWE-807")
        assert len(rows) == 1
        assert rows[0]["line_start"] == 4
        assert rows[0]["check_id"] == "cwe.resource.spoofable_rate_limit_key"

    def test_keygenerator_multiline_body_flagged(self, tmp_path):
        (tmp_path / "limiter.ts").write_text(
            "const l = rateLimit({\n"
            "  keyGenerator: (req) => {\n"
            "    return req.headers['x-real-ip']\n"
            "  }\n"
            "})\n"
        )
        assert "CWE-807" in _cwes(tmp_path)

    def test_keygenerator_using_ip_not_flagged(self, tmp_path):
        (tmp_path / "limiter.ts").write_text(
            "const l = rateLimit({\n"
            "  keyGenerator: (req) => req.ip\n"
            "})\n"
        )
        assert "CWE-807" not in _cwes(tmp_path)

    def test_default_limiter_without_keygenerator_not_flagged(self, tmp_path):
        (tmp_path / "limiter.ts").write_text(
            "const l = rateLimit({ windowMs: 60000, max: 10 })\n"
        )
        assert "CWE-807" not in _cwes(tmp_path)

    def test_plain_forwarded_for_read_without_keygenerator_not_flagged(self, tmp_path):
        """Only the rate-limit identity is in scope for CWE-807 here."""
        (tmp_path / "log.ts").write_text(
            "function clientIp (req) {\n"
            "  return req.headers['x-forwarded-for']\n"
            "}\n"
        )
        assert "CWE-807" not in _cwes(tmp_path)

    def test_807_and_799_are_distinct_rows(self, tmp_path):
        (tmp_path / "server.ts").write_text(
            "  app.use('/rest/user/reset-password', rateLimit({\n"
            "    keyGenerator ({ headers, ip }) { return headers['X-Forwarded-For'] ?? ip }\n"
            "  }))\n"
            "  app.post('/rest/user/login', login())\n"
        )
        cats = _cwes(tmp_path)
        assert {"CWE-799", "CWE-807"} <= cats
