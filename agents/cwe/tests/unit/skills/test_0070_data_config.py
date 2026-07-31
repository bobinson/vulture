"""Feature 0070 — data_handling / configuration detectors.

Three rules land here, all measured on a real application tree:

  CWE-915 mass assignment      request body spread wholesale into render
                               locals or a model create, plus auto-generated
                               CRUD resources that bind every model attribute
                               to request input (an auto-generated REST resource
                               loop — the registerAdminChallenge vector).
  CWE-922 insecure storage     auth/session/payment material persisted in
                               browser localStorage/sessionStorage. A
                               template-heavy Angular app writes to web
                               storage constantly, so the rule requires a
                               SENSITIVE KEY NAME and never looks at the
                               value expression (`setItem('bid',
                               authentication.bid)` contains "auth" in the
                               value and is not a credential store).
  CWE-942 permissive CORS      cors() with no origin restriction, or an
                               explicit Access-Control-Allow-Origin: *.
                               One finding per file, not one per line.
  CWE-348 less-trusted source  unconditional `trust proxy`, which makes
                               X-Forwarded-For client-controlled.
"""

import tempfile
from pathlib import Path

from cwe_agent.skills.configuration_check import check_configuration
from cwe_agent.skills.data_handling_check import check_data_handling


def _run(fn, files: dict[str, str]) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return fn(str(root))["findings"]


def _cats(findings: list[dict], category: str) -> list[dict]:
    return [f for f in findings if f["category"] == category]


# ---------------------------------------------------------------- CWE-915


def test_body_spread_into_render_locals_is_mass_assignment() -> None:
    """routes/dataErasure.ts:108 and :124."""
    findings = _run(check_data_handling, {"routes/dataErasure.ts": """
export function erasureRequest (req, res, next) {
  const themeVars = { theme: 'bluegrey' }
  res.render('dataErasureResult', {
    ...req.body,
    ...themeVars
  })
}
"""})
    rows = _cats(findings, "CWE-915")
    assert len(rows) == 1, rows
    assert rows[0]["line_start"] == 5
    assert rows[0]["check_id"] == "cwe.data_handling.mass_assignment"
    assert rows[0]["code_snippet"]


def test_body_spread_into_model_create_same_line() -> None:
    findings = _run(check_data_handling, {"routes/save.ts": """
export function save (req, res) {
  return UserModel.create({ ...req.body })
}
"""})
    rows = _cats(findings, "CWE-915")
    assert len(rows) == 1, rows
    assert rows[0]["line_start"] == 3


def test_auto_generated_crud_resource_is_mass_assignment() -> None:
    """server.ts:501 — finale.resource binds every attribute."""
    findings = _run(check_data_handling, {"server.ts": """
const autoModels = [
  { name: 'User', exclude: ['password'], model: UserModel },
  { name: 'Product', exclude: [], model: ProductModel }
]
for (const { name, exclude, model, include } of autoModels) {
  const resource = finale.resource({
    model,
    endpoints: [`/api/${name}s`],
    excludeAttributes: exclude,
    pagination: false,
    include
  })
}
"""})
    rows = _cats(findings, "CWE-915")
    assert len(rows) == 1, rows
    assert rows[0]["line_start"] == 7


def test_spread_of_non_request_object_is_not_flagged() -> None:
    findings = _run(check_data_handling, {"routes/ok.ts": """
export function render (req, res) {
  const themeVars = { theme: 'bluegrey' }
  res.render('page', {
    ...themeVars,
    ...defaults
  })
}
"""})
    assert _cats(findings, "CWE-915") == []


def test_validated_body_spread_is_not_flagged() -> None:
    """A schema-validated payload is no longer attacker-shaped."""
    findings = _run(check_data_handling, {"routes/validated.ts": """
export function save (req, res) {
  const value = schema.validate(req.body)
  return UserModel.create({
    ...value
  })
}
"""})
    assert _cats(findings, "CWE-915") == []


def test_body_spread_without_a_sink_is_not_flagged() -> None:
    """A spread into a plain local is not by itself mass assignment."""
    findings = _run(check_data_handling, {"routes/plain.ts": """
export function handler (req, res) {
  const copy = {
    ...req.body
  }
  console.log(Object.keys(copy).length)
}
"""})
    assert _cats(findings, "CWE-915") == []


def test_mass_assignment_does_not_double_report_as_prototype_pollution() -> None:
    findings = _run(check_data_handling, {"routes/one.ts": """
export function save (req, res) {
  return UserModel.create({ ...req.body })
}
"""})
    assert len(findings) == 1, findings
    assert findings[0]["category"] == "CWE-915"


# ---------------------------------------------------------------- CWE-922


def test_auth_token_in_localstorage_is_flagged() -> None:
    """Login / oauth / payment / two-factor components."""
    findings = _run(check_data_handling, {"app/login.component.ts": """
export class LoginComponent {
  login () {
    this.userService.login(this.user).subscribe((authentication) => {
      localStorage.setItem('token', authentication.token)
    }, (error) => {
      localStorage.setItem('totp_tmp_token', error.data.tmpToken)
    })
  }
}
"""})
    rows = _cats(findings, "CWE-922")
    assert len(rows) == 2, rows
    assert [r["line_start"] for r in rows] == [5, 7]
    assert rows[0]["check_id"] == "cwe.data_handling.web_storage"
    assert rows[0]["severity"] == "high"


def test_sensitive_key_variants_in_web_storage_are_flagged() -> None:
    findings = _run(check_data_handling, {"app/store.ts": """
function persist (a, b, c, d) {
  sessionStorage.setItem('sessionId', a)
  localStorage.setItem("creditCard", b)
  window.localStorage.setItem('jwt', c)
  localStorage['authToken'] = d
}
"""})
    rows = _cats(findings, "CWE-922")
    assert len(rows) == 4, rows


def test_non_sensitive_web_storage_keys_are_not_flagged() -> None:
    """A value expression mentioning `authentication` is not a key name."""
    findings = _run(check_data_handling, {"app/basket.component.ts": """
function persist (total, authentication, all) {
  sessionStorage.setItem('itemTotal', total[0].toString())
  sessionStorage.setItem('bid', authentication.bid?.toString())
  sessionStorage.setItem('walletTotal', this.balanceControl.value)
  sessionStorage.setItem('deliveryMethodId', this.deliveryMethodId.toString())
  localStorage.setItem(STORAGE_KEY, JSON.stringify(all))
}
"""})
    assert _cats(findings, "CWE-922") == []


def test_web_storage_read_is_not_flagged() -> None:
    findings = _run(check_data_handling, {"app/read.ts": """
function whoami () {
  return localStorage.getItem('token')
}
"""})
    assert _cats(findings, "CWE-922") == []


# ---------------------------------------------------------------- CWE-942


def test_unrestricted_cors_middleware_is_one_finding_per_file() -> None:
    """server.ts:182-183 — two lines, one row."""
    findings = _run(check_configuration, {"server.ts": """
export function start () {
  app.options('*', cors())
  app.use(cors())
}
"""})
    rows = _cats(findings, "CWE-942")
    assert len(rows) == 1, rows
    assert rows[0]["line_start"] == 3
    assert rows[0]["line_end"] == 4
    assert rows[0]["check_id"] == "cwe.configuration.permissive_cors"


def test_wildcard_cors_header_is_flagged() -> None:
    findings = _run(check_configuration, {"middleware.js": """
function headers (req, res, next) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  next()
}
"""})
    assert len(_cats(findings, "CWE-942")) == 1, findings


def test_origin_restricted_cors_is_not_flagged() -> None:
    """lib/startup/registerWebsocketEvents.ts is restricted."""
    findings = _run(check_configuration, {"ws.ts": """
export function register (server) {
  const io = new Server(server, { cors: { origin: 'http://localhost:4200' } })
  app.use(cors({ origin: 'https://example.com', credentials: true }))
}
"""})
    assert _cats(findings, "CWE-942") == []


# ---------------------------------------------------------------- CWE-348


def test_unconditional_trust_proxy_is_flagged() -> None:
    """server.ts:342 — app.enable('trust proxy')."""
    findings = _run(check_configuration, {"server.ts": """
export function start () {
  app.enable('trust proxy')
}
"""})
    rows = _cats(findings, "CWE-348")
    assert len(rows) == 1, rows
    assert rows[0]["line_start"] == 3
    assert rows[0]["check_id"] == "cwe.configuration.trust_proxy"
    # CWE-348 has no OWASP 2025 category; the finding must say so rather
    # than imply a mapping it does not have.
    assert "OWASP" in rows[0]["description"]


def test_trust_proxy_set_true_is_flagged() -> None:
    findings = _run(check_configuration, {"app.js": """
function boot (app) {
  app.set('trust proxy', true)
}
"""})
    assert len(_cats(findings, "CWE-348")) == 1, findings


def test_bounded_trust_proxy_hop_count_is_not_flagged() -> None:
    """`trust proxy: 1` is the recommended bounded config, not a weakness."""
    findings = _run(check_configuration, {"app.js": """
function boot (app) {
  app.set('trust proxy', 1)
}
"""})
    assert _cats(findings, "CWE-348") == []
