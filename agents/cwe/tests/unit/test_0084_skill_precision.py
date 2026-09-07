"""Skill-precision fixes measured on juice-shop (feature 0084).

TWO fixes, each with a TRUE-POSITIVE guard. Narrowing a detector is the one
change that can silently lose a real finding, so every suppression test is
paired with a positive that must still fire.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "shared"))

from cwe_agent.skills.resource_check import check_resource_management


def _scan(tmp_path, name, body):
    (tmp_path / name).write_text(body)
    res = check_resource_management(str(tmp_path))
    return [f for f in res.get("findings", []) if f.get("category") == "CWE-400"]


# ---- CWE-400: a bounded loop is not uncontrolled consumption ----------------

def test_TP_unbounded_loop_is_still_flagged(tmp_path):
    """NON-VACUITY / TRUE POSITIVE. A genuinely unbounded loop must still fire,
    or the fix below is indistinguishable from deleting the rule."""
    fs = _scan(tmp_path, "bad.ts", """
export function spin () {
  while (true) {
    doWork()
  }
}
""")
    assert fs, "a genuinely unbounded while(true) must still be reported"


def test_FP_loop_with_break_is_not_flagged(tmp_path):
    """The juice-shop case: a polling loop with an explicit exit."""
    fs = _scan(tmp_path, "poll.ts", """
export function waitForDevTools () {
  return async () => {
    while (true) {
      if (window.innerHeight !== initial) {
        break
      }
      await sleep(100)
    }
  }
}
""")
    assert not fs, f"bounded polling loop reported as CWE-400: {[f['title'] for f in fs]}"


def test_FP_loop_that_awaits_is_not_flagged(tmp_path):
    """An awaiting loop yields to the event loop; it is not a spin."""
    fs = _scan(tmp_path, "await.ts", """
async function drain () {
  while (true) {
    const msg = await queue.next()
    handle(msg)
  }
}
""")
    assert not fs, "an awaiting loop is not uncontrolled resource consumption"


def test_FP_loop_with_return_is_not_flagged(tmp_path):
    fs = _scan(tmp_path, "ret.go", """
func find() int {
	for {
		if ok() {
			return 1
		}
	}
}
""")
    assert not fs, "a loop with a return has an exit path"


# ---- CWE-798: NOT changed. Pinning the behaviour I wrongly called a bug -----
#
# I reported the 22 GitHub Actions rows as "~92% false positives". That was
# wrong on two counts, both checkable in five seconds and neither checked:
#   * the detector ALREADY treats `${{ secrets.X }}` as a safe indirection
#     (`is_variable_reference`, single-sourced in tools/var_reference.py);
#   * it emits a DIFFERENT, `info`-severity advisory whose own text says
#     "a variable reference rather than a literal secret".
# It is a hygiene note, correctly worded, working as designed. The only wart is
# the CWE-798 label, and changing a category ripples into the OWASP mapping,
# dedup keys and calibration — not worth it for an info row, and not something
# to do speculatively. These tests pin what exists so a later change is
# deliberate.

def _config_findings(tmp_path, name, body):
    from cwe_agent.skills.secret_scan import check_secrets
    (tmp_path / name).write_text(body)
    return check_secrets(str(tmp_path)).get("findings", [])


def test_TP_a_literal_config_secret_is_still_reported(tmp_path):
    """NON-VACUITY. A literal credential must keep firing. Note the category is
    CWE-260 (Password in Configuration File), not CWE-798 — `_classify` picks
    the most specific arm, which is more precise than I gave it credit for."""
    fs = _config_findings(tmp_path, "app.yml", "password: hunter2SuperSecretValue123\n")
    hits = [f for f in fs if f.get("category") in ("CWE-260", "CWE-526", "CWE-798")]
    assert hits, f"a literal secret must still be reported: {[(f.get('category'), f.get('title')) for f in fs]}"
    assert any(f["severity"] != "info" for f in hits), "a real literal must outrank info"


def test_variable_reference_is_an_info_advisory_not_a_credential_claim(tmp_path):
    """The row is `info` and says plainly that the value is NOT a literal
    secret. Pinned: if someone raises this to medium/high it becomes 22 loud
    false alarms on any repo with a CI workflow."""
    fs = _config_findings(tmp_path, "ci.yml", "password: ${{ secrets.DOCKERHUB_TOKEN }}\n")
    refs = [f for f in fs if "variable reference" in (f.get("title") or "")]
    assert refs, "non-vacuity: the advisory must be emitted"
    for f in refs:
        assert f["severity"] == "info", "a safe indirection must stay informational"
        assert "rather than a literal secret" in f["description"]


# ---- CWE-400: loop patterns must not run against markup/prose ---------------
#
# Found by the fix above: with the 16 bounded-loop FPs gone, the ONE survivor on
# juice-shop was English prose. The Go infinite-loop regex `for\s*\{` matched
#     "Our Privacy Policy for {{applicationName}} is ..."
# in privacy-policy.component.html. A Go loop pattern has no business running
# against HTML.

def test_TP_go_infinite_loop_still_flagged_in_a_go_file(tmp_path):
    """NON-VACUITY. `for {` in real Go must still fire."""
    fs = _scan(tmp_path, "srv.go", """
func serve() {
	for {
		handle()
	}
}
""")
    assert fs, "an unbounded Go for{} must still be reported"


def test_FP_prose_in_markup_is_not_a_loop(tmp_path):
    fs = _scan(tmp_path, "policy.component.html",
               "<p>Our Privacy Policy for {{applicationName}} is created with help.</p>\n")
    assert not fs, f"English prose reported as an unbounded loop: {[f['title'] for f in fs]}"


def test_FP_markdown_prose_is_not_a_loop(tmp_path):
    fs = _scan(tmp_path, "README.md",
               "See the guide for {details} and the changelog for {history}.\n")
    assert not fs, "markdown prose reported as an unbounded loop"
