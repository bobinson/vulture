import { describe, expect, it } from "vitest";
import {
  OWASP_CATEGORY_IDS,
  applyComplianceMapping,
  groupByOwaspCategory,
  hasOwaspCategory,
  isOwaspEdition,
  lineageOwaspLabels,
  owaspCategoryOptions,
  owaspCategoriesOf,
  owaspEditionsOf,
  owaspLabels,
  parseComplianceMapping,
  type ComplianceMapping,
} from "./compliance.ts";
import type { ComplianceLabel, Finding } from "./types.ts";

function f(over: Partial<Finding>): Finding {
  return {
    severity: "medium",
    category: "CWE-798",
    title: "t",
    description: "d",
    file_path: "a.ts",
    recommendation: "r",
    agent_type: "cwe",
    ...over,
  };
}

const A07: ComplianceLabel = {
  framework: "owasp", edition: "2025", category_id: "A07",
  category_name: "Authentication Failures", cwe: "CWE-798",
};
const A05: ComplianceLabel = {
  framework: "owasp", edition: "2025", category_id: "A05", category_name: "Injection", cwe: "CWE-89",
};

const MAPPING: ComplianceMapping = {
  version: 1,
  framework: "owasp",
  edition: "2025",
  selected: [],
  table: {
    "CWE-798": [{ id: "A07", name: "Authentication Failures" }],
    "CWE-89": [{ id: "A05", name: "Injection" }],
  },
};

describe("parseComplianceMapping", () => {
  it("accepts a well-formed v1 mapping, empty table included", () => {
    expect(parseComplianceMapping(MAPPING)).toEqual(MAPPING);
    expect(parseComplianceMapping({ ...MAPPING, table: {} })).toEqual({ ...MAPPING, table: {} });
  });

  it("defaults a missing selected list to all", () => {
    const { selected: _drop, ...rest } = MAPPING;
    void _drop;
    expect(parseComplianceMapping(rest)?.selected).toEqual([]);
  });

  it.each([
    ["absent", undefined],
    ["not an object", "x"],
    ["wrong version", { ...MAPPING, version: 2 }],
    ["wrong framework", { ...MAPPING, framework: "asvs" }],
    ["bad edition", { ...MAPPING, edition: "25" }],
    ["bad table key", { ...MAPPING, table: { "cwe-79": [{ id: "A05", name: "Injection" }] } }],
    ["bad category id", { ...MAPPING, table: { "CWE-79": [{ id: "X5", name: "Injection" }] } }],
    ["table not an object", { ...MAPPING, table: [] }],
    ["bad selected", { ...MAPPING, selected: ["A5"] }],
  ])("rejects a mapping that is %s (all or nothing)", (_name, raw) => {
    expect(parseComplianceMapping(raw)).toBeNull();
  });

  // 0096 L1: the backend validator's exact rules (handler/compliance_mapping.go).
  it("rejects a category name containing NUL, as the backend does (jsonb cannot store it)", () => {
    const raw = { ...MAPPING, table: { "CWE-798": [{ id: "A07", name: "Auth\u0000Failures" }] } };
    expect(parseComplianceMapping(raw)).toBeNull();
  });

  it("counts a name's length in code points, not UTF-16 units (max 120)", () => {
    // 120 astral characters = 240 UTF-16 units: the backend's RuneCount says 120, legal.
    const astral = "\u{1F512}".repeat(120);
    const ok = { ...MAPPING, table: { "CWE-798": [{ id: "A07", name: astral }] } };
    expect(parseComplianceMapping(ok)?.table["CWE-798"][0].name).toBe(astral);
    const tooLong = { ...MAPPING, table: { "CWE-798": [{ id: "A07", name: "\u{1F512}".repeat(121) }] } };
    expect(parseComplianceMapping(tooLong)).toBeNull();
  });

  it("folds a duplicate category id within one CWE, first occurrence wins", () => {
    const raw = {
      ...MAPPING,
      table: {
        "CWE-798": [
          { id: "A07", name: "Authentication Failures" },
          { id: "A07", name: "Duplicate" },
          { id: "A02", name: "Misconfiguration" },
        ],
      },
    };
    expect(parseComplianceMapping(raw)?.table["CWE-798"]).toEqual([
      { id: "A07", name: "Authentication Failures" },
      { id: "A02", name: "Misconfiguration" },
    ]);
  });

  it("caps selected at 100 entries, as the backend does", () => {
    expect(parseComplianceMapping({ ...MAPPING, selected: Array(100).fill("A07") })?.selected).toHaveLength(100);
    expect(parseComplianceMapping({ ...MAPPING, selected: Array(101).fill("A07") })).toBeNull();
  });
});

describe("applyComplianceMapping", () => {
  it("labels every CWE-categorised finding from every scan agent", () => {
    const out = applyComplianceMapping(
      [f({ id: "1" }), f({ id: "2", agent_type: "xss", category: "CWE-89" })],
      MAPPING,
    );
    expect(out[0].compliance_labels).toEqual([A07]);
    expect(out[1].compliance_labels).toEqual([A05]);
  });

  it("leaves an unmapped CWE, a non-CWE category and an OWASP copy row unlabelled", () => {
    const rows = [
      f({ id: "u", category: "CWE-1333" }),
      f({ id: "n", category: "retry" }),
      f({ id: "o", agent_type: "owasp", category: "CWE-798" }),
    ];
    const out = applyComplianceMapping(rows, MAPPING);
    for (const row of out) expect(row.compliance_labels).toBeUndefined();
    // Untouched rows keep their identity (memo-friendly).
    expect(out[0]).toBe(rows[0]);
  });

  it("respects the selected subset", () => {
    const out = applyComplianceMapping(
      [f({ id: "1" }), f({ id: "2", category: "CWE-89" })],
      { ...MAPPING, selected: ["A05"] },
    );
    expect(out[0].compliance_labels).toBeUndefined();
    expect(out[1].compliance_labels).toEqual([A05]);
  });

  it("replaces only this framework+edition, keeping other labels", () => {
    const other: ComplianceLabel = { ...A07, edition: "2021", category_id: "A02" };
    const stale: ComplianceLabel = { ...A07, category_id: "A01" };
    const out = applyComplianceMapping([f({ compliance_labels: [other, stale] })], MAPPING);
    expect(out[0].compliance_labels).toEqual([other, A07]);
  });

  it("canonicalises a zero-padded CWE category before lookup (CWE-089 -> CWE-89)", () => {
    const out = applyComplianceMapping([f({ id: "z", category: "CWE-089" }), f({ id: "zz", category: "CWE-0798" })], MAPPING);
    expect(out[0].compliance_labels).toEqual([A05]);
    expect(out[1].compliance_labels).toEqual([A07]);
  });

  it("keys the table canonically, merging keys that differ only in zero padding", () => {
    const m = parseComplianceMapping({
      ...MAPPING,
      table: { "CWE-089": [{ id: "A05", name: "Injection" }], "CWE-89": [{ id: "A05", name: "Injection" }, { id: "A03", name: "Old" }] },
    });
    expect(m?.table).toEqual({ "CWE-89": [{ id: "A05", name: "Injection" }, { id: "A03", name: "Old" }] });
  });

  it("a duplicate id folded by the parser labels a finding once", () => {
    const m = parseComplianceMapping({
      ...MAPPING,
      table: { "CWE-798": [{ id: "A07", name: "Authentication Failures" }, { id: "A07", name: "Authentication Failures" }] },
    });
    expect(m).not.toBeNull();
    expect(applyComplianceMapping([f({})], m!)[0].compliance_labels).toEqual([A07]);
  });
});

describe("label readers", () => {
  const rows = [
    f({ id: "1", severity: "low", title: "Env secret", compliance_labels: [A07] }),
    f({ id: "2", severity: "critical", title: "SQLi", category: "CWE-89", compliance_labels: [A05] }),
    f({ id: "3", severity: "high", title: "Cred", compliance_labels: [A07] }),
    f({ id: "4", title: "ReDoS", category: "CWE-1333" }),
    f({ id: "5", title: "Other framework", compliance_labels: [{ ...A07, framework: "asvs" }] }),
  ];

  it("owaspLabels and hasOwaspCategory read only OWASP labels", () => {
    expect(owaspLabels(rows[0])).toEqual([A07]);
    expect(owaspLabels(rows[4])).toEqual([]);
    expect(hasOwaspCategory(rows[0], "A07")).toBe(true);
    expect(hasOwaspCategory(rows[0], "A05")).toBe(false);
    expect(hasOwaspCategory(rows[4], "A07")).toBe(false);
  });

  it("owaspCategoryOptions lists the categories present, sorted, once each", () => {
    expect(owaspCategoryOptions(rows)).toEqual([
      { id: "A05", name: "Injection", edition: "2025" },
      { id: "A07", name: "Authentication Failures", edition: "2025" },
    ]);
    expect(owaspCategoryOptions([rows[3]])).toEqual([]);
  });

  it("groupByOwaspCategory groups by edition then category, worst severity first", () => {
    const groups = groupByOwaspCategory(rows);
    expect(groups.map((g) => `${g.edition}/${g.id}`)).toEqual(["2025/A05", "2025/A07"]);
    expect(groups[1].name).toBe("Authentication Failures");
    expect(groups[1].findings.map((x) => x.title)).toEqual(["Cred", "Env secret"]);
  });

  it("lineageOwaspLabels flattens the lineage map, newest edition first", () => {
    expect(
      lineageOwaspLabels({ "owasp:2021": ["A07"], "owasp:2025": ["A07", "A02"], "asvs:5": ["V2"] }),
    ).toEqual([
      { edition: "2025", id: "A02" },
      { edition: "2025", id: "A07" },
      { edition: "2021", id: "A07" },
    ]);
    expect(lineageOwaspLabels(undefined)).toEqual([]);
  });

  it("owaspEditionsOf reads the OWASP editions of a label_editions list, newest first, once each", () => {
    expect(
      owaspEditionsOf([
        { framework: "owasp", edition: "2021" },
        { framework: "asvs", edition: "5000" },
        { framework: "owasp", edition: "2025" },
        { framework: "owasp", edition: "2025" },
        { framework: "owasp", edition: "25" },
      ]),
    ).toEqual(["2025", "2021"]);
    expect(owaspEditionsOf(undefined)).toEqual([]);
    expect(owaspEditionsOf([])).toEqual([]);
  });

  it("owaspCategoriesOf reads one OWASP edition's categories, sorted, valid ids only", () => {
    const le = [
      { framework: "owasp", edition: "2025", categories: ["A09", "A05", "bogus", "A05"] },
      { framework: "owasp", edition: "2021", categories: ["A03"] },
      { framework: "asvs", edition: "2025", categories: ["A01"] },
    ];
    expect(owaspCategoriesOf(le, "2025")).toEqual(["A05", "A09"]);
    expect(owaspCategoriesOf(le, "2021")).toEqual(["A03"]);
    expect(owaspCategoriesOf(le, "2017")).toEqual([]);
    expect(owaspCategoriesOf(undefined, "2025")).toEqual([]);
    expect(owaspCategoriesOf([{ framework: "owasp", edition: "2025" }], "2025")).toEqual([]);
  });

  it("isOwaspEdition accepts only a four-digit edition", () => {
    expect(isOwaspEdition("2025")).toBe(true);
    expect(isOwaspEdition("25")).toBe(false);
    expect(isOwaspEdition("2025;drop")).toBe(false);
    expect(isOwaspEdition(null)).toBe(false);
  });

  it("OWASP_CATEGORY_IDS is the ten Top 10 ids", () => {
    expect(OWASP_CATEGORY_IDS).toEqual(["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]);
  });
});
