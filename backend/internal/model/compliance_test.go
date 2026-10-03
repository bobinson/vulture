package model

import (
	"reflect"
	"testing"
)

func TestIsCWECategory(t *testing.T) {
	for c, want := range map[string]bool{
		"CWE-79": true, "CWE-1234": true, "CWE-": false, "cwe-79": false,
		"CWE-79 ": false, "A07": false, "retry": false, "": false,
	} {
		if got := IsCWECategory(c); got != want {
			t.Errorf("IsCWECategory(%q) = %v, want %v", c, got, want)
		}
	}
}

func TestLineagePatch(t *testing.T) {
	m := &ComplianceMapping{Framework: "owasp", Edition: "2025",
		Table: map[string][]ComplianceCategory{"CWE-798": {{ID: "A07"}}}}
	for _, tc := range []struct {
		name     string
		m        *ComplianceMapping
		category string
		want     map[string][]string
	}{
		{"mapped", m, "CWE-798", map[string][]string{"owasp:2025": {"A07"}}},
		{"unmapped CWE is an explicit empty entry", m, "CWE-89", map[string][]string{"owasp:2025": {}}},
		{"not a CWE", m, "retry", nil},
		{"no mapping", nil, "CWE-798", nil},
		{"empty table carries no knowledge", &ComplianceMapping{Framework: "owasp", Edition: "2025",
			Table: map[string][]ComplianceCategory{}}, "CWE-798", nil},
	} {
		got := tc.m.LineagePatch(tc.category)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
		// An empty entry must marshal as [] (json_patch reads null as delete).
		if ids, ok := got["owasp:2025"]; ok && ids == nil {
			t.Errorf("%s: nil category list would be stored as null", tc.name)
		}
	}
}

func TestUpsertFrameworkEdition(t *testing.T) {
	other := ComplianceLabel{Framework: "asvs", Edition: "5", CategoryID: "V2"}
	older := ComplianceLabel{Framework: "owasp", Edition: "2021", CategoryID: "A02"}
	stale := ComplianceLabel{Framework: "owasp", Edition: "2025", CategoryID: "A01"}
	fresh := ComplianceLabel{Framework: "owasp", Edition: "2025", CategoryID: "A07"}
	got := UpsertFrameworkEdition([]ComplianceLabel{other, stale, older}, "owasp", "2025", []ComplianceLabel{fresh})
	if want := []ComplianceLabel{other, older, fresh}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if got := UpsertFrameworkEdition(nil, "owasp", "2025", nil); got != nil {
		t.Errorf("nothing in, nothing out: %+v", got)
	}
}

// 0096 M12: the agent parses "CWE-089" as 89, so the backend must treat a
// zero-padded id as the same CWE — for the table lookup and in every id it
// writes — and leave a category that is not a CWE id alone.
func TestCanonicalCWE(t *testing.T) {
	for in, want := range map[string]string{
		"CWE-089": "CWE-89", "CWE-89": "CWE-89", "CWE-0": "CWE-0", "CWE-000": "CWE-0",
		"CWE-0100": "CWE-100", "A07": "A07", "retry": "retry", "cwe-089": "cwe-089", "": "",
		"CWE-": "CWE-", "CWE-08x": "CWE-08x",
	} {
		if got := CanonicalCWE(in); got != want {
			t.Errorf("CanonicalCWE(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLabelsCanonicaliseTheCWE(t *testing.T) {
	m := NewComplianceMapping("owasp", "2025", nil,
		map[string][]ComplianceCategory{"CWE-89": {{ID: "A05", Name: "Injection"}}})
	want := []ComplianceLabel{{Framework: "owasp", Edition: "2025", CategoryID: "A05", CategoryName: "Injection", CWE: "CWE-89"}}
	if got := m.Labels("CWE-089"); !reflect.DeepEqual(got, want) {
		t.Errorf("Labels(CWE-089) = %+v, want %+v", got, want)
	}
	if got := m.LineagePatch("CWE-089"); !reflect.DeepEqual(got, map[string][]string{"owasp:2025": {"A05"}}) {
		t.Errorf("LineagePatch(CWE-089) = %v", got)
	}
}

// 0096 H2: a dedup survivor stands for the rows it absorbed, so it is
// labelled from its own CWE PLUS theirs — each label naming the CWE that
// contributed it, one label per (framework, edition, category, cwe).
func TestLabelsForAbsorbedCategories(t *testing.T) {
	m := NewComplianceMapping("owasp", "2025", nil, map[string][]ComplianceCategory{
		"CWE-89": {{ID: "A05", Name: "Injection"}},
		"CWE-22": {{ID: "A01", Name: "BAC"}}, "CWE-73": {{ID: "A06", Name: "Insecure Design"}},
		"CWE-23": {{ID: "A01", Name: "BAC"}},
	})
	lbl := func(id, name, cwe string) ComplianceLabel {
		return ComplianceLabel{Framework: "owasp", Edition: "2025", CategoryID: id, CategoryName: name, CWE: cwe}
	}
	for _, tc := range []struct {
		name string
		f    Finding
		want []ComplianceLabel
	}{
		{"unmapped survivor keeps the absorbed category",
			Finding{Category: "CWE-943", AbsorbedCategories: []string{"CWE-89"}},
			[]ComplianceLabel{lbl("A05", "Injection", "CWE-89")}},
		{"both categories of a 22/73 merge",
			Finding{Category: "CWE-22", AbsorbedCategories: []string{"CWE-73"}},
			[]ComplianceLabel{lbl("A01", "BAC", "CWE-22"), lbl("A06", "Insecure Design", "CWE-73")}},
		{"same category from two CWEs is two labels, a repeated CWE is one",
			Finding{Category: "CWE-22", AbsorbedCategories: []string{"CWE-23", "CWE-022", "CWE-22"}},
			[]ComplianceLabel{lbl("A01", "BAC", "CWE-22"), lbl("A01", "BAC", "CWE-23")}},
		{"no absorbed rows", Finding{Category: "CWE-89"}, []ComplianceLabel{lbl("A05", "Injection", "CWE-89")}},
	} {
		if got := m.LabelsFor(tc.f.LabelSources()); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
	if got := (&Finding{Category: "retry", AbsorbedCategories: nil}).LabelSources(); got != nil {
		t.Errorf("a non-CWE finding has no label sources: %v", got)
	}
	if got, want := m.LineagePatch("CWE-943", "CWE-89"), map[string][]string{"owasp:2025": {"A05"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("LineagePatch over absorbed categories = %v, want %v", got, want)
	}
	if got, want := m.LineagePatch("CWE-22", "CWE-73", "CWE-23"), map[string][]string{"owasp:2025": {"A01", "A06"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("LineagePatch over a 22/73/23 merge = %v, want %v", got, want)
	}
}

func TestSelectsUsesTheSelection(t *testing.T) {
	m := NewComplianceMapping("owasp", "2025", []string{"A07", "A05"}, map[string][]ComplianceCategory{})
	if !m.Selects("A07") || !m.Selects("A05") || m.Selects("A01") {
		t.Errorf("Selects disagrees with the selection %v", m.Selected)
	}
	if all := NewComplianceMapping("owasp", "2025", nil, nil); !all.Selects("A01") {
		t.Error("an empty selection selects every category")
	}
}
