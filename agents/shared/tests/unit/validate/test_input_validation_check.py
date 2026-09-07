"""An interpolated value that is provably validated must not be CONFIRMED.

Measured on one run: ``seed-poll-verifications.qa.ts:423`` interpolates
``pollId`` into a SQL string and scored 0.99 ``high_confidence``. The
identifier is validated 100 lines above at the handler entry by an anchored
regex (``UUID_RE.test(pollId)`` where ``UUID_RE`` is
``/^[0-9a-f]{8}-...$/i``), so no quote or semicolon can reach the sink. A
sibling row interpolates ``targetLabel``, whitelisted by
``VALID_LABELS.includes(targetLabel)``.

Nothing in the pipeline saw either guard:

* ``sanitizer`` returns weight 0.0 on every branch, so it cannot demote at
  all, and ``SANITIZER_MAP["CWE-89"]`` knows only parameterisation
  (``parameterize|prepared|bind_param``) — Python/PHP-shaped, and blind to
  the other sound strategy, input validation that makes injection
  impossible.
* the judge, the only check carrying weight, saw a +/-2 line window.

This check is deliberately NOT the blunt file-scope sanitizer match, which
was zeroed for good reason: a file using prepared statements in nine places
and interpolating in the tenth must not be demoted. It demotes only when
EVERY identifier interpolated at the cited line is individually guarded.

Anchoring is load-bearing. An UNanchored regex does not prevent injection —
``/[0-9a-f-]+/.test(x)`` passes for ``' OR 1=1--`` because it matches a
substring — so only an anchored pattern counts as a guard.
"""

from __future__ import annotations

import pathlib

import pytest

from shared.validate.context_heuristics import clear_l1_cache, run_l1

pytestmark = pytest.mark.usefixtures("_clear_cache")


@pytest.fixture
def _clear_cache():
    clear_l1_cache()
    yield
    clear_l1_cache()


def _write(tmp_path: pathlib.Path, body: str) -> str:
    p = tmp_path / "handler.ts"
    p.write_text(body)
    return str(p)


def _check(tmp_path: pathlib.Path, body: str, line: int,
           category: str = "CWE-89") -> dict | None:
    path = _write(tmp_path, body)
    results = run_l1(
        [{"category": category, "file_path": path,
          "line_start": line, "line_end": line}],
        source_root=str(tmp_path),
    )
    for c in results[0]:
        if c.id == "input_validation":
            return {"result": c.result, "weight": c.weight, "extras": c.extras}
    return None


def _require(tmp_path: pathlib.Path, body: str, line: int,
             category: str = "CWE-89") -> dict:
    """`_check` for the cases that require the check to exist."""
    c = _check(tmp_path, body, line, category)
    assert c is not None, "an injection-family finding must get the check"
    return c


_ANCHORED_UUID_GUARD = """\
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export default async function handler(request, response) {
  const { pollId } = request.body;
  if (!pollId || !UUID_RE.test(pollId)) {
    response.status(400).json({ error: "bad pollId" });
    return;
  }
  await update(pollId);
}

async function update(pollId) {
  await hasuraRunSql(
    `UPDATE focus_polls SET quality_label = 'X' WHERE id = '${pollId}';`
  );
}
"""


class TestAGuardedIdentifierIsRecognised:
    def test_anchored_regex_test_guards_the_identifier(self, tmp_path):
        c = _require(tmp_path, _ANCHORED_UUID_GUARD, 14)
        assert c["result"] == "guarded"
        assert c["weight"] < 0, "a proven guard must demote"
        assert c["extras"]["identifiers"] == ["pollId"]

    def test_whitelist_membership_guards_the_identifier(self, tmp_path):
        body = """\
const VALID_LABELS = ["UNVERIFIED", "GOLD", "PLATINUM"];

export default async function handler(request, response) {
  const { targetLabel } = request.body;
  if (!VALID_LABELS.includes(targetLabel)) {
    response.status(400).json({ error: "bad label" });
    return;
  }
  await hasuraRunSql(`UPDATE p SET label = '${targetLabel}';`);
}
"""
        c = _require(tmp_path, body, 9)
        assert c["result"] == "guarded"
        assert c["weight"] < 0

    def test_every_identifier_must_be_guarded(self, tmp_path):
        """One unguarded identifier makes the sink injectable regardless."""
        body = """\
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}$/i;

export default async function handler(request, response) {
  const { pollId, label } = request.body;
  if (!UUID_RE.test(pollId)) return;
  await hasuraRunSql(`UPDATE p SET l = '${label}' WHERE id = '${pollId}';`);
}
"""
        c = _require(tmp_path, body, 6)
        assert c["result"] == "partial", "label is unguarded -> no demotion"
        assert c["weight"] == 0.0
        assert set(c["extras"]["unguarded"]) == {"label"}


class TestAnUnprovenGuardMustNotDemote:
    def test_unanchored_regex_is_not_a_guard(self, tmp_path):
        """`/[0-9a-f-]+/.test(x)` passes for `' OR 1=1--` on a substring."""
        body = _ANCHORED_UUID_GUARD.replace(
            "/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i",
            "/[0-9a-f-]+/i",
        )
        c = _require(tmp_path, body, 14)
        assert c["result"] == "unguarded", (
            "an unanchored pattern matches a substring and prevents nothing"
        )
        assert c["weight"] == 0.0

    def test_a_genuinely_unguarded_sink_is_untouched(self, tmp_path):
        body = """\
export default async function handler(request, response) {
  const { name } = request.body;
  await hasuraRunSql(`SELECT * FROM t WHERE n = '${name}';`);
}
"""
        c = _require(tmp_path, body, 3)
        assert c["result"] == "unguarded"
        assert c["weight"] == 0.0

    def test_a_guard_on_a_different_identifier_does_not_count(self, tmp_path):
        body = """\
const UUID_RE = /^[0-9a-f]{8}$/i;

export default async function handler(request, response) {
  const { other, name } = request.body;
  if (!UUID_RE.test(other)) return;
  await hasuraRunSql(`SELECT * FROM t WHERE n = '${name}';`);
}
"""
        c = _require(tmp_path, body, 6)
        assert c["result"] == "unguarded"

    def test_a_sink_with_no_interpolation_is_not_scored(self, tmp_path):
        body = """\
export default async function handler(request, response) {
  await hasuraRunSql("SELECT 1");
}
"""
        c = _require(tmp_path, body, 2)
        assert c["result"] == "no_identifiers"
        assert c["weight"] == 0.0


class TestScope:
    def test_the_check_is_confined_to_the_injection_family(self, tmp_path):
        """A guard says nothing about a hardcoded credential or a bad cipher."""
        c = _check(tmp_path, _ANCHORED_UUID_GUARD, 14, category="CWE-798")
        assert c is None

    @pytest.mark.parametrize("category", ["CWE-89", "CWE-78", "CWE-79", "CWE-22"])
    def test_injection_classes_are_covered(self, tmp_path, category):
        c = _check(tmp_path, _ANCHORED_UUID_GUARD, 14, category=category)
        assert c is not None


class TestTheGuardWithholdsConfirmationNotTruth:
    def test_a_guarded_finding_may_not_be_high_confidence(self):
        """The judge scored the real case 0.99; a proven guard outranks it."""
        from shared.validate.types import ValidationCheck
        from shared.validate.voter import vote

        checks = [
            ValidationCheck(id="llm_judge", result="real_bug", weight=0.525,
                            reason="pollId interpolated into SQL"),
            ValidationCheck(id="input_validation", result="guarded", weight=-0.40,
                            reason="all interpolated identifiers validated"),
        ]
        status, _confidence = vote(checks)
        assert status != "high_confidence", (
            "a mechanically proven guard must withhold the confirmed label"
        )

    def test_it_does_not_assert_likely_fp(self):
        """The guard can be removed tomorrow; the smell is still real."""
        from shared.validate.types import ValidationCheck
        from shared.validate.voter import vote

        checks = [
            ValidationCheck(id="llm_judge", result="real_bug", weight=0.525,
                            reason="pollId interpolated into SQL"),
            ValidationCheck(id="input_validation", result="guarded", weight=-0.40,
                            reason="all interpolated identifiers validated"),
        ]
        assert vote(checks)[0] == "suspicious"


class TestLiteralOnlyValues:
    """A value that can only ever be one of a few string literals is safe.

    Measured: `seed-poll-verifications.qa.ts:367` interpolates BOTH `pollId`
    and `label`. `pollId` is UUID-guarded, but `label` is a local whose every
    assignment is a string constant:

        let label = "UNVERIFIED";
        if (vr >= minVerificationRate) {
          if (cr >= platinumRate) label = "PLATINUM";
          else if (cr >= goldRate) label = "GOLD";
        }

    Three literals cannot carry a quote or a semicolon, so the sink is not
    reachable — but with only the anchored-regex and membership shapes the row
    came out `partial` and kept its 0.99. This closes it.

    A literal DECLARATION is required, not merely all-literal assignments: a
    function parameter has no declaration, so a tainted parameter that happens
    to be reassigned to a constant on one branch can never qualify.
    """

    _LABEL_AND_POLLID = """\
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export default async function handler(request, response) {
  const { pollId } = request.body;
  if (!UUID_RE.test(pollId)) return;
  await updateQualityLabel(pollId);
}

async function updateQualityLabel(pollId) {
  let label = "UNVERIFIED";
  if (eligible > 0) {
    if (cr >= platinumRate) label = "PLATINUM";
    else if (cr >= goldRate) label = "GOLD";
  }
  await hasuraRunSql(`UPDATE p SET quality_label = '${label}' WHERE id = '${pollId}';`);
}
"""

    def test_the_measured_367_shape_is_now_guarded(self, tmp_path):
        c = _require(tmp_path, self._LABEL_AND_POLLID, 15)
        assert c["result"] == "guarded", (
            "both interpolated values are provably constrained"
        )
        assert c["weight"] < 0
        assert c["extras"]["guards"]["label"] == "literal_only"
        assert c["extras"]["guards"]["pollId"] == "anchored_regex"

    def test_a_numeric_literal_counts(self, tmp_path):
        body = """\
function f() {
  let n = 0;
  if (x) n = 25;
  return hasuraRunSql(`SELECT * FROM t LIMIT ${n};`);
}
"""
        c = _require(tmp_path, body, 4)
        assert c["result"] == "guarded"
        assert c["extras"]["guards"]["n"] == "literal_only"


class TestLiteralOnlyRefusesWhatItCannotProve:
    def test_one_non_literal_assignment_disqualifies(self, tmp_path):
        body = """\
function f(request) {
  let label = "UNVERIFIED";
  if (x) label = request.body.label;
  return hasuraRunSql(`UPDATE p SET l = '${label}';`);
}
"""
        c = _require(tmp_path, body, 4)
        assert c["result"] == "unguarded"
        assert c["weight"] == 0.0

    def test_a_parameter_never_qualifies(self, tmp_path):
        """The 212 shape: no declaration, so nothing constrains the input."""
        body = """\
async function sync(pollId) {
  await hasuraRunSql(`UPDATE p SET x = 1 WHERE id = '${pollId}';`);
}
"""
        c = _require(tmp_path, body, 2)
        assert c["result"] == "unguarded"

    def test_a_same_named_parameter_disqualifies_the_declaration(self, tmp_path):
        """A literal local elsewhere must not vouch for a tainted parameter."""
        body = """\
function other() {
  let label = "SAFE";
  return label;
}

function f(label) {
  return hasuraRunSql(`UPDATE p SET l = '${label}';`);
}
"""
        c = _require(tmp_path, body, 7)
        assert c["result"] == "unguarded"

    def test_an_interpolated_template_is_not_a_literal(self, tmp_path):
        body = """\
function f(request) {
  let label = `x${request.body.q}`;
  return hasuraRunSql(`UPDATE p SET l = '${label}';`);
}
"""
        c = _require(tmp_path, body, 3)
        assert c["result"] == "unguarded"

    def test_concatenation_is_not_a_literal(self, tmp_path):
        body = """\
function f(request) {
  let label = "a" + request.body.q;
  return hasuraRunSql(`UPDATE p SET l = '${label}';`);
}
"""
        c = _require(tmp_path, body, 3)
        assert c["result"] == "unguarded"

    def test_compound_assignment_disqualifies(self, tmp_path):
        body = """\
function f(request) {
  let label = "a";
  label += request.body.q;
  return hasuraRunSql(`UPDATE p SET l = '${label}';`);
}
"""
        c = _require(tmp_path, body, 4)
        assert c["result"] == "unguarded"


class TestOnlyARejectionGateCounts:
    """A membership test is not automatically a guard.

    Found by running the rule over a real corpus: `scripts/lib/staged-io.cjs`
    interpolates a `file` parameter into a git argv at line 44, and line 23 of
    a DIFFERENT function reads `if (NOISE_FILES.has(file)) return true;`. That
    is a "skip this file" filter, not a gate — crediting it reintroduced the
    very flaw the file-scope `sanitizer` match was zeroed for.

    A validation gate REJECTS a value outside the permitted set, so it reads
    negated: `if (!UUID_RE.test(id)) return 400`. A positive membership test
    constrains nothing about the path that follows it.

    A positive gate wrapping the sink (`if (VALID.includes(x)) { sink }`) is
    also sound but is NOT recognised — refusing to demote is the safe
    direction, and every measured true positive is negated.
    """

    def test_a_positive_membership_test_is_not_a_guard(self, tmp_path):
        body = """\
const NOISE_FILES = new Set(["package-lock.json"]);

function isNoise(file) {
  if (NOISE_FILES.has(file)) return true;
  return false;
}

function readStagedBlob(file) {
  return execSync(`git show :${file}`);
}
"""
        c = _require(tmp_path, body, 9, category="CWE-78")
        assert c["result"] == "unguarded", (
            "a skip-filter in another function does not constrain this sink"
        )
        assert c["weight"] == 0.0

    def test_a_negated_membership_test_is_a_guard(self, tmp_path):
        body = """\
const ALLOWED = new Set(["a", "b"]);

function run(name) {
  if (!ALLOWED.has(name)) return null;
  return execSync(`git show :${name}`);
}
"""
        c = _require(tmp_path, body, 5, category="CWE-78")
        assert c["result"] == "guarded"
        assert c["extras"]["guards"]["name"] == "membership"

    def test_a_positive_regex_test_is_not_a_guard(self, tmp_path):
        body = """\
const UUID_RE = /^[0-9a-f]{8}$/i;

function looksLikeId(v) {
  if (UUID_RE.test(v)) return true;
  return false;
}

function run(v) {
  return hasuraRunSql(`SELECT * FROM t WHERE id = '${v}';`);
}
"""
        c = _require(tmp_path, body, 9)
        assert c["result"] == "unguarded"

    def test_indexof_counts_only_in_its_rejection_form(self, tmp_path):
        body = """\
const ALLOWED = ["a", "b"];

function run(name) {
  if (ALLOWED.indexOf(name) === -1) return null;
  return execSync(`git show :${name}`);
}
"""
        c = _require(tmp_path, body, 5, category="CWE-78")
        assert c["result"] == "guarded"
        assert c["extras"]["guards"]["name"] == "membership"
