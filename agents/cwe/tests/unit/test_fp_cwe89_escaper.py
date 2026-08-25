"""CWE-89 must not fire at `critical` when the value goes through an escaper.

Measured on a real target: 5 of 8 CWE-89 rows were false, all at CRITICAL,
because the interpolated value passed through the project's own `sqlStr()` --
a genuine Postgres string escaper (backslash + single-quote doubling).

Three shapes, all of them escaped:
    `... WHERE id = ${sqlStr(x)}`                       direct
    const p = sqlStr(v); `... LIKE ${p}`                one hop through a local
    (values) => `... VALUES ${values}`  + sqlStr row-builder alongside

RADIUS is measured, not guessed: across the 8 audited rows a radius of 6
lines separates all 5 escaped rows from all 3 genuinely-raw rows, and a
radius of 3 misses one. Calibrated on a single target -- widen only with
new measurement.
"""


from cwe_agent.skills.injection_check import _sql_escaper_nearby

ESCAPED_DIRECT = [
    "  await hasuraRunSql(",
    '    `UPDATE letters SET x = true WHERE "issueId" = ${sqlStr(focusId)};`',
    "  );",
]

ESCAPED_ONE_HOP = [
    "  const likePattern = sqlStr(`${safePrefix}%@${safeDomain}`);",
    "  const result = await hasuraRunSql(",
    '    `SELECT "passwordHash" FROM users WHERE email LIKE ${likePattern} LIMIT 1;`',
    "  );",
]

ESCAPED_ROW_BUILDER = [
    "  await runBatchInsert(",
    "    records,",
    "    (values) => `INSERT INTO t (a, b) VALUES ${values} ON CONFLICT DO NOTHING;`,",
    "    (r) => `(${sqlStr(r.id)}, ${sqlStr(r.name)})`",
    "  );",
]

RAW = [
    "  await hasuraRunSql(",
    "    `UPDATE focus_polls SET quality_label = '${label}' WHERE id = '${pollId}';`",
    "  );",
]


class TestEscaperProximity:
    def test_direct_escaper_detected(self):
        assert _sql_escaper_nearby(ESCAPED_DIRECT, 2)

    def test_one_hop_local_detected(self):
        assert _sql_escaper_nearby(ESCAPED_ONE_HOP, 3)

    def test_row_builder_sibling_detected(self):
        assert _sql_escaper_nearby(ESCAPED_ROW_BUILDER, 3)

    def test_raw_interpolation_has_no_escaper(self):
        assert not _sql_escaper_nearby(RAW, 2)

    def test_comment_mentioning_escaper_does_not_count(self):
        lines = ["  // we should use sqlStr( here one day", "  `DELETE FROM t WHERE id = '${x}'`"]
        assert not _sql_escaper_nearby(lines, 2)
