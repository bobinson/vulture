package model

import "testing"

func TestFindingLineage_FormatRef(t *testing.T) {
	cases := []struct {
		name      string
		refNumber int
		expected  string
	}{
		{"zero returns empty", 0, ""},
		{"negative returns empty", -1, ""},
		{"one", 1, "VLT-0001"},
		{"forty two", 42, "VLT-0042"},
		{"four digits", 9999, "VLT-9999"},
		{"five digits", 10000, "VLT-10000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := &FindingLineage{RefNumber: tc.refNumber}
			got := l.FormatRef()
			if got != tc.expected {
				t.Errorf("FormatRef() = %q, want %q", got, tc.expected)
			}
		})
	}
}
