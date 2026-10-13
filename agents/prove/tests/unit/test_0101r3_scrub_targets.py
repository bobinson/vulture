"""Feature 0101 (review round 3): unit contract for the scrub.

1. Totality. Any JSON shape a model answers with (array, object, nested,
   number, null) becomes one scrubbed string; nothing bypasses the scrub.
2. Target routes are target content, not repository content. A finding's
   bare file name is also a common route (``backup.sql``, ``main.js``,
   ``package.json``); a URL on the configured staging target, or a route the
   agent actually requested, keeps it, and the staging host is never
   absorbed into a placeholder. A repository path in the same text is still
   removed.
3. A model echoes a FRAGMENT of a code line far more often than the whole
   line: any contiguous run of a quoted line that clears the excerpt floor
   (24 characters, 2 identifiers) is removed. Shorter fragments are below
   the floor by design.
4. Case-changed and double-encoded paths, and a sibling of the scan root.

Fixtures are synthetic.
"""

import time

from prove_agent.evidence_scrub import (
    CODE_PLACEHOLDER,
    FILE_PLACEHOLDER,
    ROOT_PLACEHOLDER,
    note_route,
    scrubbing,
    scrubbing_all,
)
from shared.transport.event_emitter import AgUiEventEmitter

ROOT = "/tmp/sources/4f1c2a"
STAGING = "https://staging.example.com"
GATEWAY = {
    "id": "A", "file_path": "src/payments/alpha_gateway.go",
    "code_snippet": (
        "29: func charge() {\n"
        '30:     token := os.Getenv("PAYMENT_GATEWAY_SECRET")\n'
        '31:     resp, err := http.Post(gatewayURL+"/charge", "application/json", body)\n'
    ),
}
ROUTE_NAMED = [
    {"id": "P", "file_path": "package.json"},
    {"id": "M", "file_path": "frontend/src/main.js"},
    {"id": "D", "file_path": "db/backup.sql"},
]


def _em(*findings, target=STAGING):
    return scrubbing_all(AgUiEventEmitter("r"), list(findings), source_root=ROOT,
                         target_url=target)


class TestTotality:
    def test_list_dict_nested_become_scrubbed_strings(self):
        em = _em(GATEWAY)
        for value in (["in src/payments/alpha_gateway.go", "x"],
                      {"a": "in src/payments/alpha_gateway.go"},
                      [{"n": ["in src/payments/alpha_gateway.go"]}],
                      ("in src/payments/alpha_gateway.go",)):
            out = em.scrub(value)
            assert isinstance(out, str)
            assert "alpha_gateway" not in out and FILE_PLACEHOLDER in out

    def test_scalars(self):
        em = _em(GATEWAY)
        assert em.scrub(None) == ""
        assert em.scrub(42) == "42"
        assert em.scrub(True) == "True"
        assert em.scrub("") == ""

    def test_deep_nesting_is_bounded(self):
        value: list = ["src/payments/alpha_gateway.go"]
        for _ in range(500):
            value = [value]
        out = _em(GATEWAY).scrub(value)
        assert "alpha_gateway" not in out


class TestTargetRoutes:
    def test_staging_url_with_a_finding_file_name_survives(self):
        em = _em(*ROUTE_NAMED, GATEWAY)
        for text in (f"Sensitive file {STAGING}/backup.sql downloadable (HTTP 200, 4 MB)",
                     f"GET {STAGING}/static/js/main.js leaked API keys"):
            assert em.scrub(text) == text

    def test_repo_path_next_to_a_staging_url_is_still_scrubbed(self):
        out = _em(*ROUTE_NAMED, GATEWAY).scrub(
            f"GET {STAGING}/backup.sql; code in src/payments/alpha_gateway.go")
        assert out == f"GET {STAGING}/backup.sql; code in {FILE_PLACEHOLDER}"

    def test_staging_host_is_never_absorbed(self):
        out = _em(GATEWAY).scrub(f"GET {STAGING}/src/payments/alpha_gateway.go -> 200")
        assert out == f"GET {STAGING}/{FILE_PLACEHOLDER} -> 200"

    def test_other_hosts_get_no_exemption(self):
        out = _em(*ROUTE_NAMED).scrub("see https://code.example.org/acme/pay/blob/main/db/backup.sql")
        assert "backup" not in out and "acme" not in out

    def test_executed_route_named_like_a_finding_file_survives(self):
        em = _em(*ROUTE_NAMED)
        assert em.scrub("GET /package.json returned 200") == f"GET {FILE_PLACEHOLDER} returned 200"
        note_route(em, "/package.json?x=1")
        assert em.scrub("GET /package.json returned 200") == "GET /package.json returned 200"
        # A repository path is not a route because a route was noted.
        assert em.scrub("from frontend/src/main.js") == f"from {FILE_PLACEHOLDER}"

    def test_noted_route_is_shared_by_per_finding_wraps(self):
        em = _em(*ROUTE_NAMED)
        per = scrubbing(em, ROUTE_NAMED[0], target_url=STAGING)
        assert per is em
        note_route(per, "/backup.sql")
        assert em.scrub("GET /backup.sql ok") == "GET /backup.sql ok"

    def test_note_route_on_a_plain_emitter_is_a_no_op(self):
        note_route(AgUiEventEmitter("r"), "/x")

    def test_run_emitter_gains_the_target_on_the_per_finding_wrap(self):
        run = scrubbing_all(AgUiEventEmitter("r"), ROUTE_NAMED, source_root=ROOT)
        per = scrubbing(run, ROUTE_NAMED[2], target_url=STAGING)
        text = f"GET {STAGING}/backup.sql ok"
        assert per.scrub(text) == text


class TestCodeFragments:
    def test_fragment_of_a_quoted_line_is_removed(self):
        out = _em(GATEWAY).scrub(
            'calls os.Getenv("PAYMENT_GATEWAY_SECRET") then http.Post(gatewayURL+"/charge" later')
        assert "PAYMENT_GATEWAY_SECRET" not in out
        assert "gatewayURL" not in out
        assert out.startswith("calls ") and out.endswith(" later")
        assert CODE_PLACEHOLDER in out

    def test_fragment_with_reflowed_whitespace(self):
        out = _em(GATEWAY).scrub('it does os.Getenv( "PAYMENT_GATEWAY_SECRET" ) first')
        assert "PAYMENT_GATEWAY_SECRET" not in out

    def test_fragment_with_json_escaped_quotes(self):
        # A model that double-encodes its JSON writes \" for every quote.
        out = _em(GATEWAY).scrub('reads token := os.Getenv(\\"PAYMENT_GATEWAY_SECRET\\") first')
        assert "PAYMENT_GATEWAY_SECRET" not in out and CODE_PLACEHOLDER in out

    def test_target_string_literal_without_code_syntax_is_kept(self):
        # A message literal the target returns IS the proof; no code syntax.
        em = scrubbing_all(AgUiEventEmitter("r"), [{
            "file_path": "svc/pay.py",
            "code_snippet": '9: raise PayError("payment gateway secret is not configured for merchant")\n',
        }])
        text = 'body: {"detail": "payment gateway secret is not configured for merchant"}'
        assert em.scrub(text) == text

    def test_fragment_below_the_floor_is_kept(self):
        # 'os.Getenv(' is 10 characters: below the excerpt floor, everywhere.
        assert _em(GATEWAY).scrub("uses os.Getenv( here") == "uses os.Getenv( here"

    def test_target_content_sharing_two_words_is_kept(self):
        text = "response: resp err token http body"
        assert _em(GATEWAY).scrub(text) == text

    def test_fragment_cost_with_many_findings(self):
        findings = [{
            "file_path": f"pkg/m{i}/h{i}.go",
            "code_snippet": f'{i}: if err := svc.Handle{i}(ctx, req); err != nil {{ return err }}\n'
                            f'{i + 1}: resp, err := http.Post(url{i}+"/charge", "application/json", body)\n',
        } for i in range(1000)]
        em = scrubbing_all(AgUiEventEmitter("r"), findings, source_root=ROOT)
        text = ("if err != nil { return err } resp, err := http.Post(" * 40)[:5000]
        em.scrub(text)
        start = time.perf_counter()
        for _ in range(20):
            em.scrub(text)
        assert (time.perf_counter() - start) / 20 < 0.01


class TestPathForms:
    def test_case_changed_path(self):
        out = _em(GATEWAY).scrub("see SRC/Payments/Alpha_Gateway.go")
        assert out == f"see {FILE_PLACEHOLDER}"

    def test_double_encoded_path(self):
        out = _em(GATEWAY).scrub("GET /dl?f=src%252Fpayments%252Falpha_gateway.go")
        assert "payments" not in out and "alpha" not in out

    def test_sibling_of_the_scan_root(self):
        out = _em(GATEWAY).scrub(f"{ROOT}-other/x.py was read")
        assert out == f"{ROOT_PLACEHOLDER} was read"
