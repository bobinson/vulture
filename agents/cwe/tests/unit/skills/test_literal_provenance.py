"""Go `fmt.Sprintf` with only constant text spliced in (CWE-89 precision).

`constant_sprintf` may only ever SUPPRESS a CWE-89 row, so every way a variable
can reach the spliced text must leave it unproven. The reviewers' shapes are
pinned one per test: shadowing, parameters, loop-carried writes, continued
right-hand sides, pointers, `for` headers, multi-name left-hand sides.
"""
from __future__ import annotations

import pytest

from cwe_agent.skills._literal_provenance import constant_sprintf, printf_verbs
from shared.tools.code_view import CodeView

_HEAD = "package repo\n\n"


def _proven(body: str) -> bool:
    """``constant_sprintf`` at the line marked ``//X``."""
    lines = tuple((_HEAD + body).splitlines())
    line_num = next(i for i, text in enumerate(lines, 1) if text.endswith("//X"))
    return constant_sprintf(CodeView(lines, "go"), line_num, lines[line_num - 1].index("Sprintf"))


# ── printf verbs ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("fmt", "verbs"),
    [
        ("UPDATE t SET %s WHERE id = $%d", ["s", "d"]),
        ("%-10s|%5.2f|%+d|%#x|% d|%05d", ["s", "f", "d", "x", "d", "d"]),
        ("100%% of %s", ["s"]),
        ("no verbs", []),
        ("%[1]s again %[1]s", None),   # an explicit index re-uses arguments
        ("%*d", None),                 # a `*` width takes an argument of its own
        ("%-*s", None),
    ],
)
def test_printf_verbs(fmt: str, verbs: list[str] | None) -> None:
    assert printf_verbs(fmt) == verbs


# ── proven constant ─────────────────────────────────────────────────────────


def test_the_audited_repository_method_is_constant() -> None:
    assert _proven(
        "func (r *Repo) ApplyEvidence(id string, ev Evidence) error {\n"
        '\tsets := "evidence_file_hash = $1, updated_at = now()"\n'
        "\targs := []interface{}{ev.FileHash}\n"
        "\tif ev.IncrementSeen {\n"
        '\t\tsets += ", seen_count = COALESCE(seen_count, 1) + 1"\n'
        "\t}\n"
        "\tif ev.UpdateWindow {\n"
        '\t\tsets += fmt.Sprintf(", line_start = $%d, line_end = $%d", len(args)+1, len(args)+2)\n'
        "\t\targs = append(args, ev.LineStart, ev.LineEnd)\n"
        "\t}\n"
        "\targs = append(args, id)\n"
        "\tq := fmt.Sprintf(`UPDATE finding_lineage SET %s WHERE id = $%d`, sets, len(args)) //X\n"
        "\t_, err := r.db.Exec(q, args...)\n"
        "\treturn err\n"
        "}\n"
    )


@pytest.mark.parametrize(
    "body",
    [
        # a literal argument, and a number-only verb whatever its argument
        'func f(n int) string {\n\treturn fmt.Sprintf("DELETE FROM %s WHERE n = %d", "jobs", n) //X\n}\n',
        # `var x string` then literal writes, and `x = x + LIT`
        'func f(b bool) string {\n\tvar sets string\n\tsets = "a = 1"\n\tif b {\n\t\tsets = sets + ", b = 2"\n\t}\n'
        '\treturn fmt.Sprintf("UPDATE t SET %s", sets) //X\n}\n',
        # `var x = LIT`, reads before the call
        'func f() string {\n\tvar sets = "a = 1"\n\tif sets != "" && len(sets) > 0 {\n\t}\n'
        '\treturn fmt.Sprintf("UPDATE t SET %s", sets) //X\n}\n',
    ],
)
def test_constant_text_is_proven(body: str) -> None:
    assert _proven(body)


# ── never proven ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("case", "body"),
    [
        ("parameter", 'func f(sets string) string {\n\treturn fmt.Sprintf("UPDATE t SET %s", sets) //X\n}\n'),
        ("set_from_parameter",
         'func f(col string) string {\n\tsets := col + " = 1"\n\treturn fmt.Sprintf("UPDATE t SET %s", sets) //X\n}\n'),
        ("closure_shadow",
         'func f(col string) string {\n\tsets := col\n\treset := func() { sets := "a = 1"; _ = sets }\n\treset()\n'
         '\treturn fmt.Sprintf("UPDATE t SET %s", sets) //X\n}\n'),
        ("parameter_shadowed_in_a_block",
         'func f(sets string, b bool) string {\n\tif b {\n\t\tsets := "a = 1"\n\t\t_ = sets\n\t}\n'
         '\treturn fmt.Sprintf("UPDATE t SET %s", sets) //X\n}\n'),
        ("multiline_parameters",
         'func f(\n\tsets string,\n) string {\n\tif true {\n\t\tsets := "a"\n\t\t_ = sets\n\t}\n'
         '\treturn fmt.Sprintf("UPDATE t SET %s", sets) //X\n}\n'),
        ("written_after_the_call_in_a_loop",
         'func f(db DB, cols []string) {\n\tprev := "a = 1"\n\tfor _, c := range cols {\n'
         '\t\tdb.Exec(fmt.Sprintf("UPDATE t SET %s", prev)) //X\n\t\tprev = c + " = 1"\n\t}\n}\n'),
        ("typed_var_from_parameter",
         'func f(col string) string {\n\tvar sets string = col\n\treturn fmt.Sprintf("UPDATE t SET %s", sets) //X\n}\n'),
        ("continued_right_hand_side",
         'func f(col string) string {\n\tsets := "name = " +\n\t\tcol\n\treturn fmt.Sprintf("UPDATE t SET %s", sets) //X\n}\n'),
        ("address_taken",
         'func f(col string) string {\n\tsets := "a"\n\tfill(&sets, col)\n\treturn fmt.Sprintf("UPDATE t SET %s", sets) //X\n}\n'),
        ("for_header_write",
         'func f(cols []string) string {\n\tsets := "a"\n\tfor i := 0; i < len(cols); sets += cols[i] {\n\t\ti++\n\t}\n'
         '\treturn fmt.Sprintf("UPDATE t SET %s", sets) //X\n}\n'),
        ("one_line_block_write",
         'func f(cols []string) string {\n\tsets := "a"\n\tfor _, c := range cols { sets += c }\n'
         '\treturn fmt.Sprintf("UPDATE t SET %s", sets) //X\n}\n'),
        ("multi_assign",
         'func f(r R) string {\n\tsets, err := clause(r)\n\t_ = err\n\treturn fmt.Sprintf("UPDATE t SET %s", sets) //X\n}\n'),
        ("if_init_statement",
         'func f(m map[string]string) string {\n\tsets := "a"\n\tif v, ok := m["k"]; ok { sets = v }\n'
         '\treturn fmt.Sprintf("UPDATE t SET %s", sets) //X\n}\n'),
        ("defined_twice",
         'func f(b bool) string {\n\tsets := "a"\n\tif b {\n\t\tsets := "b"\n\t\t_ = sets\n\t}\n'
         '\treturn fmt.Sprintf("UPDATE t SET %s", sets) //X\n}\n'),
        ("package_level", 'var sets = "a"\n\nfunc f() string {\n\treturn fmt.Sprintf("UPDATE t SET %s", sets) //X\n}\n'),
        ("percent_v", 'func f(id string) string {\n\treturn fmt.Sprintf("DELETE FROM t WHERE id = %v", id) //X\n}\n'),
        ("percent_c", 'func f(c int) string {\n\treturn fmt.Sprintf("DELETE FROM t WHERE k = \'%c\'", c) //X\n}\n'),
        ("percent_q", 'func f(s string) string {\n\treturn fmt.Sprintf("DELETE FROM t WHERE k = %q", s) //X\n}\n'),
        ("explicit_index", 'func f(n int) string {\n\treturn fmt.Sprintf("DELETE FROM t WHERE a = %[1]d", n) //X\n}\n'),
        ("escaped_percent",
         'func f(s string) string {\n\treturn fmt.Sprintf("DELETE FROM t WHERE k = \'\\x25s\' AND n = %d", 1, s) //X\n}\n'),
        ("extra_argument", 'func f(s string) string {\n\treturn fmt.Sprintf("DELETE FROM t WHERE n = %d", 1, s) //X\n}\n'),
        ("call_spans_lines",
         'func f(s string) string {\n\treturn fmt.Sprintf("UPDATE t SET %s", //X\n\t\ts)\n}\n'),
        ("format_not_a_literal", 'func f(f, s string) string {\n\treturn fmt.Sprintf(f, s) //X\n}\n'),
        ("rhs_sprintf_with_string_verb",
         'func f(col string) string {\n\tsets := "a"\n\tsets += fmt.Sprintf(", %s = 1", col)\n'
         '\treturn fmt.Sprintf("UPDATE t SET %s", sets) //X\n}\n'),
        ("aliased_package", 'func f(s string) string {\n\treturn f.Sprintf("DELETE FROM t WHERE k = %s", s) //X\n}\n'),
        # the call does not stand alone on its line
        ("concatenated_after",
         'func f(n string) string {\n\treturn fmt.Sprintf("SELECT * FROM t WHERE id = %d", 1) + n //X\n}\n'),
        ("second_call_on_the_line",
         'func f(n string) (string, string) {\n\ta, b := fmt.Sprintf("SELECT %d", 1), fmt.Sprintf("DELETE %s", n) //X\n'
         '\treturn a, b\n}\n'),
        ("wrapped_by_another_call",
         'func f(n string) string {\n\treturn strings.Replace(fmt.Sprintf("SELECT * FROM t WHERE a = %d", 1), "1", n, 1) //X\n}\n'),
        ("closure_in_the_arguments",
         'func f(r R) string {\n\tcol := "name"\n'
         '\treturn fmt.Sprintf("SELECT %s FROM t %d", col, func() int { col = r.V(); return 0 }()) //X\n}\n'),
        # the result is extended after the call
        ("result_extended",
         'func f(db DB, n string) {\n\tq := fmt.Sprintf("SELECT * FROM t WHERE id = %d", 1) //X\n'
         '\tq += " AND n = \'" + n + "\'"\n\tdb.Query(q)\n}\n'),
        # the definition reads an outer variable of the same name
        ("outer_self_reference",
         'var where string\n\nfunc f() string {\n\twhere := " WHERE 1=1" + where\n'
         '\treturn fmt.Sprintf("SELECT * FROM t%s", where) //X\n}\n'),
        ("address_in_parentheses",
         'func f(r R) string {\n\tcol := "name"\n\tdecode(r, &(col))\n\treturn fmt.Sprintf("SELECT %s FROM t", col) //X\n}\n'),
        ("spread_arguments", 'func f(a []any) string {\n\treturn fmt.Sprintf("SELECT * FROM t WHERE n = %d", a...) //X\n}\n'),
        ("continued_multi_name_lhs",
         'func f(r R) string {\n\tcol := "name"\n\tvar n int\n\tcol,\n\t\tn = r.V(), 1\n\t_ = n\n'
         '\treturn fmt.Sprintf("SELECT %s FROM t", col) //X\n}\n'),
    ],
)
def test_anything_unproven_stays_reported(case: str, body: str) -> None:
    assert not _proven(body), case


@pytest.mark.parametrize(
    "body",
    [
        # the query argument of a call that runs SQL, a context argument first
        'func f(db DB, ctx C) {\n\tdb.ExecContext(ctx, fmt.Sprintf("DELETE FROM t WHERE id = %d", 1)) //X\n}\n',
        # a result extended only by literals
        'func f(db DB) {\n\tq := fmt.Sprintf("SELECT * FROM t WHERE id = %d", 1) //X\n\tq += " LIMIT 1"\n\tdb.Query(q)\n}\n',
    ],
)
def test_a_constant_call_used_as_a_whole_is_proven(body: str) -> None:
    assert _proven(body)


def test_a_line_longer_than_the_cap_in_the_function_ends_the_proof() -> None:
    long_write = "\tsets = sets + " + '"a" + ' * 400 + '"b"\n'
    body = 'func f() string {\n\tsets := "a"\n' + long_write + '\treturn fmt.Sprintf("UPDATE t SET %s", sets) //X\n}\n'
    assert not _proven(body)


def test_a_function_beyond_the_lookback_is_not_searched_for() -> None:
    filler = "\t_ = 1\n" * 260
    body = 'func f() string {\n\tsets := "a"\n' + filler + '\treturn fmt.Sprintf("UPDATE t SET %s", sets) //X\n}\n'
    assert not _proven(body)
