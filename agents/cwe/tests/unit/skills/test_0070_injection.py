"""Feature 0070 — injection_check precision + new detectors.

Four items, all measured on a real application tree:

1. CWE-89: the "clause bigram" template-literal branch matched prose under
   ``re.IGNORECASE`` ("how to *set* up", "the bonus points *from* this
   order"). 3 CRITICAL false positives, 0 true positives. Replaced by a
   bounded DML bigram (``SELECT ... FROM``, ``UPDATE ... SET``, ...).
2. CWE-918: the Go ``http.Get`` branch ran with ``re.IGNORECASE``, so it
   matched Angular's ``this.http.get(``; plus a bare ``\\+`` alternative
   treated any string concatenation as taint. 29 rows, 29 false.
3. CWE-918: one-hop taint recovers the real SSRF shape
   (``const url = req.body.imageUrl`` -> ``await fetch(url)``).
4. CWE-79: Angular sinks (``bypassSecurityTrust*``, ``[innerHTML]=``) were
   entirely unmodelled.
"""

import re
import time

import pytest

from cwe_agent.skills.injection_check import (
    SQL_INJECTION_PATTERNS,
    XSS_PATTERNS,
    check_injection,
)

# --- measured fixture lines (verbatim) -------------------------------------

JS_LOGIN_SQLI = (
    "    models.sequelize.query(`SELECT * FROM Users WHERE email = "
    "'${req.body.email || ''}' AND password = "
    "'${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, "
    "{ model: UserModel, plain: true })\n"
)
JS_SEARCH_SQLI = (
    "    models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE "
    "'%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS "
    "NULL) ORDER BY name`)\n"
)
PROSE_SET_UP = (
    "    logger.info(`Check ${colors.bold('https://howto.example.com')}"
    " for instructions on how to set up and configure the Alchemy API`)\n"
)
PROSE_FROM_THIS_ORDER = (
    "          doc.font('Times-Roman').fontSize(15).text(`(${req.__('The bonus "
    "points from this order will be added 1:1 to your wallet fund for future "
    "purchases!')}`)\n"
)


def _cats(result: dict, cat: str) -> list[dict]:
    return [f for f in result["findings"] if f["category"] == cat]


# === Item 1: CWE-89 prose false positives =================================


class TestSqlProseFalsePositives:
    def test_prose_set_up_is_not_sqli(self, tmp_path):
        (tmp_path / "validatePreconditions.ts").write_text(PROSE_SET_UP)
        assert _cats(check_injection(str(tmp_path)), "CWE-89") == []

    def test_prose_from_this_order_is_not_sqli(self, tmp_path):
        (tmp_path / "order.ts").write_text(PROSE_FROM_THIS_ORDER)
        assert _cats(check_injection(str(tmp_path)), "CWE-89") == []

    def test_real_sqli_sites_still_detected(self, tmp_path):
        (tmp_path / "login.ts").write_text(JS_LOGIN_SQLI)
        (tmp_path / "search.ts").write_text(JS_SEARCH_SQLI)
        hits = _cats(check_injection(str(tmp_path)), "CWE-89")
        assert len(hits) == 2, hits
        assert {h["severity"] for h in hits} == {"critical"}

    def test_update_set_bigram_still_matched(self):
        line = "db.query(`UPDATE Users SET email = '${req.body.email}'`)"
        assert any(p.search(line) for p in SQL_INJECTION_PATTERNS)

    def test_no_clause_only_prose_pattern_remains(self):
        """No surviving pattern may fire on a template literal whose only
        SQL-looking token is an English word."""
        prose = "logger.info(`${x} instructions on how to set up the API`)"
        assert not any(p.search(prose) for p in SQL_INJECTION_PATTERNS)

    def test_dml_bigram_is_redos_safe(self):
        evil = "`" + "SELECT " * 200 + "a" * 2000
        start = time.perf_counter()
        for p in SQL_INJECTION_PATTERNS:
            p.search(evil)
        assert time.perf_counter() - start < 1.0


# === Item 2: CWE-918 narrowing ============================================

ANGULAR_SERVICE = """import { HttpClient } from '@angular/common/http'

@Injectable()
export class ProductService {
  constructor (private readonly http: HttpClient) {}

  find (params: any) {
    return this.http.get(this.host + '/', { params }).pipe(map((r: any) => r.data))
  }
}
"""

GO_SERVER_SSRF = """package main

import "net/http"

func handler(w http.ResponseWriter, req *http.Request) {
    resp, _ := http.Get(req.URL.Query().Get("target"))
    _ = resp
}
"""

CONCAT_ONLY = """package main

func build() {
    http.Get("https://api.example.com/" + version)
}
"""


class TestSsrfNarrowing:
    def test_angular_http_get_is_not_ssrf(self, tmp_path):
        (tmp_path / "product.service.ts").write_text(ANGULAR_SERVICE)
        assert _cats(check_injection(str(tmp_path)), "CWE-918") == []

    def test_go_server_http_get_still_ssrf(self, tmp_path):
        (tmp_path / "main.go").write_text(GO_SERVER_SSRF)
        assert len(_cats(check_injection(str(tmp_path)), "CWE-918")) == 1

    def test_bare_concatenation_is_not_taint(self, tmp_path):
        (tmp_path / "client.go").write_text(CONCAT_ONLY)
        assert _cats(check_injection(str(tmp_path)), "CWE-918") == []

    def test_python_requests_ssrf_ungated(self, tmp_path):
        """Regression guard for the pre-existing contract in
        tests/unit/test_skills.py::TestCheckSSRF — server-side-only HTTP
        client libraries must not need a framework marker."""
        (tmp_path / "api.py").write_text(
            "import requests\ndef fetch(url):\n    return requests.get(user_input)\n"
        )
        assert len(_cats(check_injection(str(tmp_path)), "CWE-918")) == 1

    def test_browser_fetch_without_server_context_is_not_ssrf(self, tmp_path):
        (tmp_path / "widget.ts").write_text(
            "export function load (query: string) {\n"
            "  return fetch('/api/search?q=' + query)\n"
            "}\n"
        )
        assert _cats(check_injection(str(tmp_path)), "CWE-918") == []


# === Item 3: CWE-918 one-hop taint ========================================

PROFILE_IMAGE_UPLOAD = """import { type Request, type Response, type NextFunction } from 'express'

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await fetch(url)
          if (!response.ok) {
            throw new Error('bad status')
          }
        } catch (error) {
          next(error)
        }
      }
    }
  }
}
"""

WEBHOOK_ENV = """import config from 'config'

export const notify = async (challenge: any, webhook = process.env.SOLUTIONS_WEBHOOK) => {
  if (!webhook) {
    return
  }
  const res = await fetch(webhook, { method: 'POST' })
  return res
}
"""

REACHABLE_PARAM = """export const checkIfDomainReachable = async (domain: string) => {
  try {
    await fetch(domain, { signal: AbortSignal.timeout(5000) })
    return true
  } catch {
    return false
  }
}
"""


class TestSsrfOneHopTaint:
    def test_req_body_assigned_identifier_reaches_fetch(self, tmp_path):
        (tmp_path / "profileImageUrlUpload.ts").write_text(PROFILE_IMAGE_UPLOAD)
        hits = _cats(check_injection(str(tmp_path)), "CWE-918")
        assert len(hits) == 1, hits
        assert hits[0]["line_start"] == 10

    def test_env_var_identifier_is_not_taint(self, tmp_path):
        (tmp_path / "webhook.ts").write_text(WEBHOOK_ENV)
        assert _cats(check_injection(str(tmp_path)), "CWE-918") == []

    def test_function_parameter_identifier_is_not_taint(self, tmp_path):
        (tmp_path / "validate.ts").write_text(REACHABLE_PARAM)
        assert _cats(check_injection(str(tmp_path)), "CWE-918") == []

    def test_taint_does_not_reach_beyond_window(self, tmp_path):
        body = ["import express from 'express'", "const url = req.query.u"]
        body += ["  // filler"] * 25
        body += ["await fetch(url)"]
        (tmp_path / "far.ts").write_text("\n".join(body) + "\n")
        assert _cats(check_injection(str(tmp_path)), "CWE-918") == []

    def test_axios_get_sink_supported(self, tmp_path):
        (tmp_path / "proxy.ts").write_text(
            "import express from 'express'\n"
            "app.get('/p', async (req, res) => {\n"
            "  const target = req.query.url\n"
            "  const r = await axios.get(target)\n"
            "  res.send(r.data)\n"
            "})\n"
        )
        assert len(_cats(check_injection(str(tmp_path)), "CWE-918")) == 1


# === Item 4: CWE-79 Angular sinks =========================================

BYPASS_PLAIN = """import { DomSanitizer } from '@angular/platform-browser'

export class ScoreBoardComponent {
  populate () {
    this.challenges = data.map(challenge => ({
      description: this.sanitizer.bypassSecurityTrustHtml(challenge.description as string)
    }))
  }
}
"""

BYPASS_ROUTE_TAINT = """export class SearchResultComponent {
  filterTable () {
    let queryParam: string = this.route.snapshot.queryParams.q
    if (queryParam) {
      queryParam = queryParam.trim()
      this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)
    }
  }
}
"""


class TestAngularXssSinks:
    def test_bypass_security_trust_is_detected(self, tmp_path):
        (tmp_path / "score-board.component.ts").write_text(BYPASS_PLAIN)
        hits = _cats(check_injection(str(tmp_path)), "CWE-79")
        assert len(hits) == 1, hits
        assert hits[0]["severity"] == "high"

    @pytest.mark.parametrize(
        "variant",
        ["Html", "Script", "Style", "Url", "ResourceUrl"],
    )
    def test_all_bypass_variants_matched(self, variant):
        line = f"this.x = this.sanitizer.bypassSecurityTrust{variant}(v)"
        assert any(p.search(line) for p in XSS_PATTERNS)

    def test_route_snapshot_taint_escalates_to_critical(self, tmp_path):
        (tmp_path / "search-result.component.ts").write_text(BYPASS_ROUTE_TAINT)
        hits = _cats(check_injection(str(tmp_path)), "CWE-79")
        assert len(hits) == 1, hits
        assert hits[0]["severity"] == "critical"

    def test_inner_html_binding_detected(self, tmp_path):
        (tmp_path / "administration.component.html").write_text(
            '<mat-cell *matCellDef="let user" [innerHTML]="user.email"></mat-cell>\n'
        )
        hits = _cats(check_injection(str(tmp_path)), "CWE-79")
        assert len(hits) == 1, hits

    def test_translate_pipe_binding_suppressed(self, tmp_path):
        (tmp_path / "nft-unlock.component.html").write_text(
            "<p class=\"box-text\" [innerHTML]=\"'NFT_SBT_BOX_TEXT' | translate: i18nParams\"></p>\n"
        )
        assert _cats(check_injection(str(tmp_path)), "CWE-79") == []

    def test_translate_pipe_binding_suppressed_with_object_arg(self, tmp_path):
        (tmp_path / "warning.component.html").write_text(
            "<span warning-text [innerHTML]=\"'INFO_DISABLED_CHALLENGES' | translate: "
            "{num: numberOfDisabledChallenges(), env: disabledBecauseOfEnv()}\"></span>\n"
        )
        assert _cats(check_injection(str(tmp_path)), "CWE-79") == []

    def test_description_documents_whitelist_dependency(self, tmp_path):
        (tmp_path / "about.component.html").write_text(
            '<figure class="feedback" [innerHTML]="item?.args"></figure>\n'
        )
        hits = _cats(check_injection(str(tmp_path)), "CWE-79")
        assert len(hits) == 1
        assert "VULTURE_DISABLE_EXTENSION_WHITELIST" in hits[0]["description"]


# The former single-tree measurement class was removed: it asserted one
# repository's exact file paths and row counts for CWE-89/918/79. The predicates
# and their false-positive shapes are covered hermetically above and below.


def test_no_ignorecase_on_go_http_get():
    """The Go SSRF branch must be case-exact — IGNORECASE is what made it
    swallow Angular's ``this.http.get(``."""
    from cwe_agent.skills.injection_check import SSRF_PATTERNS

    offenders = [
        p.pattern
        for p in SSRF_PATTERNS
        if re.search(r"http\\\.\(?\??:?[Gg]et", p.pattern) and p.flags & re.IGNORECASE
    ]
    assert offenders == [], offenders
