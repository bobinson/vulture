"""CWE-89: the template-literal clause must require SQL EVIDENCE, not just a
DML-looking word.

Measured on a real audit of ~/src/togetherapp (773 findings): of 27 CWE-89 rows,
19 had no SQL sink anywhere in the file, and 17 of the 25 CRITICAL rows were
false. Every one of those false rows is an ordinary English log message, a JSX
prop, or CSS:

    console.log(`Failed to insert offices for ${name}:`, error)
    console.error(`Failed to update animation flag for ${id}:`, error)
    ariaLabel={`Select ${copy.title}`}
    ${(props) => props.$blur && `backdrop-filter: blur(${props.$blur}px);`}

Two independent defects produced them:

1. `(?:SELECT|INSERT|UPDATE|DELETE|DROP)\\b` carries a word boundary only on the
   RIGHT, so under re.IGNORECASE it matches "drop" inside "back*drop*-filter".
2. A DML word plus a `${` was treated as sufficient evidence that the string is
   executed as SQL. insert/update/select/delete are ordinary English verbs, so
   any interpolated log line qualifies.

Defect 2 is a repeat: the file's own comment records that feature 0070 deleted a
clause-only branch (FROM/WHERE/VALUES/SET) for exactly this reason — "English
prose is full of those words" — but left the verb branch, which has the same
disease.

The gate is scoped to the ONE loose template-literal clause. Python/Go patterns
and the verb+clause bigram are untouched, so the Python/Go corpus fixtures and
the 0070 pattern-level tests keep their meaning.
"""

import tempfile
from pathlib import Path

import pytest

from cwe_agent.skills.injection_check import SQL_INJECTION_PATTERNS, check_injection


def _run(files: dict[str, str]) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return check_injection(str(root))["findings"]


def _sqli(findings) -> list[dict]:
    return [f for f in findings if f.get("category") == "CWE-89"]


# ── the measured false positives, verbatim ────────────────────────────────


FALSE_POSITIVES = {
    "log_insert.ts": (
        "async function saveOffices(representativeName: string) {\n"
        "  try {\n"
        "    await api.post('/offices');\n"
        "  } catch (error) {\n"
        "    console.log(`Failed to insert offices for ${representativeName}:`, error);\n"
        "  }\n"
        "}\n"
    ),
    "log_update.ts": (
        "export function persist(id: string) {\n"
        "  try {\n"
        "    localStorage.setItem('flag', id);\n"
        "  } catch (error) {\n"
        "    console.error(`Failed to update animation flag for ${id}:`, error);\n"
        "  }\n"
        "}\n"
    ),
    "log_blockchain.ts": (
        "export async function mark(id: string) {\n"
        "  try {\n"
        "    await chain.mark(id);\n"
        "  } catch (error) {\n"
        "    console.error(\n"
        "      `Failed to update blockchain status for letterContent ${id}:`,\n"
        "      error instanceof Error ? error.message : String(error),\n"
        "    );\n"
        "  }\n"
        "}\n"
    ),
    "Overlay.styled.tsx": (
        "import styled from 'styled-components';\n"
        "export const Overlay = styled.div`\n"
        "  transition: opacity 0.3s ease-out;\n"
        "  ${(props) => props.$blur && !props.$isIOS && `backdrop-filter: blur(${props.$blur}px);`}\n"
        "`;\n"
    ),
    "ModeStep.tsx": (
        "export function ModeStep({ copy, cardTabIndex }) {\n"
        "  return (\n"
        "    <Card\n"
        "      ariaLabel={`Select ${copy.title}`}\n"
        "      tabIndex={cardTabIndex}\n"
        "    />\n"
        "  );\n"
        "}\n"
    ),
    "throw_update.ts": (
        "export async function step(errorMessage: string) {\n"
        "  if (errorMessage) {\n"
        "    throw new Error(`Failed to update letter status: ${errorMessage}`);\n"
        "  }\n"
        "}\n"
    ),
    "i18n_delete.ts": (
        "export function label(kind: string) {\n"
        "  return t(`errors.delete.${kind}`);\n"
        "}\n"
    ),
    # A DML bigram is not evidence either when the sink is a logger.
    "log_bigram.ts": (
        "export function trace(v: string) {\n"
        "  console.log(`INSERT INTO t VALUES ${v}`);\n"
        "}\n"
    ),
}


@pytest.mark.parametrize("name", sorted(FALSE_POSITIVES))
def test_no_sqli_without_sql_evidence(name):
    findings = _sqli(_run({name: FALSE_POSITIVES[name]}))
    assert findings == [], (
        f"{name}: CWE-89 reported with no SQL sink in the file — "
        f"got {[(f['file_path'], f['line_start']) for f in findings]}"
    )


def test_backdrop_filter_matches_no_sql_pattern_at_all():
    """Pattern level: the missing LEFT word boundary let `DROP` match inside
    "backdrop". Assert at the regex layer so the fix cannot regress behind the
    evidence gate."""
    line = "  ${(props) => props.$blur && `backdrop-filter: blur(${props.$blur}px);`}"
    hits = [p.pattern for p in SQL_INJECTION_PATTERNS if p.search(line)]
    assert hits == [], f"backdrop-filter still matches SQL pattern(s): {hits}"


# ── the true positives that MUST survive (over-suppression guard) ─────────


def test_sink_on_the_same_line_still_detected():
    body = (
        "export async function findUser(email: string) {\n"
        "  return db.query(`SELECT * FROM users WHERE email = '${email}'`);\n"
        "}\n"
    )
    assert _sqli(_run({"login.ts": body})), "same-line sink must still be flagged"


def test_sink_on_a_preceding_line_still_detected():
    """The audited true positives put the sink on the line ABOVE the SQL — this
    is why the evidence window must look backwards, not just at the match."""
    body = (
        "export async function lookup(prefix: string) {\n"
        "  const result = await hasuraRunSql(\n"
        "    `SELECT \"passwordHash\" FROM users WHERE email LIKE ${prefix} LIMIT 1;`\n"
        "  );\n"
        "  return result;\n"
        "}\n"
    )
    assert _sqli(_run({"seed-helpers.ts": body})), "sink on a preceding line must still be flagged"


def test_project_helper_sink_with_bigram_still_detected():
    """`runBatchInsert` is a project-specific wrapper: the SQL forms a real
    verb+clause bigram (INSERT INTO ... VALUES), which is evidence on its own."""
    body = (
        "await runBatchInsert(\n"
        "  records,\n"
        "  (values) => `INSERT INTO letters (id, state) VALUES ${values} ON CONFLICT DO NOTHING;`,\n"
        ");\n"
    )
    assert _sqli(_run({"lsgb-seed-helpers.ts": body})), "bigram + project sink must still be flagged"


def test_update_set_bigram_still_detected():
    body = (
        "await hasuraRunSql(\n"
        "  `UPDATE letters SET is_match = true WHERE \"issueId\" = ${issueId};`\n"
        ");\n"
    )
    assert _sqli(_run({"seed-runner.ts": body})), "UPDATE..SET bigram with sink must still be flagged"


def test_parameterised_query_still_not_flagged():
    body = (
        "export async function ok(email: string) {\n"
        "  return db.query('SELECT * FROM users WHERE email = $1', [email]);\n"
        "}\n"
    )
    assert _sqli(_run({"ok.ts": body})) == [], "parameterised query must stay clean"


def test_rollback_flag_restores_prior_behaviour(monkeypatch):
    """One-release escape hatch: with the gate off, the pre-fix (noisy) result
    returns, so an operator can unblock themselves without a rebuild."""
    monkeypatch.setenv("VULTURE_CWE_SQL_REQUIRE_SINK", "false")
    findings = _sqli(_run({"log_insert.ts": FALSE_POSITIVES["log_insert.ts"]}))
    assert findings, "with the gate disabled the legacy match must reappear"


# ── B1: the sink may be BELOW the SQL ─────────────────────────────────────
#
# Found by adversarial review, not by the FP corpus: the measured target
# happened to contain no instance of this shape, so the suppression was latent.


def test_sink_on_a_following_line_still_detected():
    """The commonest real shape hoists the query then executes it on the NEXT
    line. A backward-only sink probe missed `db.query` while a log line above
    vetoed the finding — genuine injection, silently dropped."""
    body = (
        "export async function f(id) {\n"
        "  logger.info('looking up user');\n"
        "  const q = `SELECT * FROM users WHERE id = ${id}`;\n"
        "  return db.query(q);\n"
        "}\n"
    )
    assert _sqli(_run({"hoisted.ts": body})), (
        "SQL executed on a following line must still be flagged even with a log "
        "statement above it"
    )


def test_console_above_a_real_query_does_not_veto():
    body = (
        "export async function f(email) {\n"
        "  console.error('about to query');\n"
        "  return db.query(`SELECT * FROM users WHERE email = '${email}'`);\n"
        "}\n"
    )
    assert _sqli(_run({"veto.ts": body})), "a nearby log line must never suppress a real sink"


def test_log_only_shape_stays_suppressed_with_the_forward_window():
    """The forward-looking sink probe must not re-admit the measured FPs."""
    for name in ("log_insert.ts", "log_update.ts", "log_blockchain.ts"):
        assert _sqli(_run({name: FALSE_POSITIVES[name]})) == [], name
