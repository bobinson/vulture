package modelmeta

import "testing"

// 0074 AC6 (verification item 10): the registry canary must fail on a row it
// cannot read instead of skipping it, or a drifted row passes unseen.
func TestScanPyRows_RejectsRowsItCannotRead(t *testing.T) {
	for _, bad := range []string{
		`    "zz-new": DEFAULT_CONTEXT_WINDOW,`,
		`    'zz-new': 4096,`,
		`    "zz-new":`,
	} {
		lines := []string{`    "gpt-4o": 128_000,`, "", "    # a comment", bad}
		if _, err := scanPyRows(lines, pyExactRow); err == nil {
			t.Errorf("row %q was skipped; the canary must fail on it", bad)
		}
	}
}

func TestScanPyRows_ReadsRowsCommentsAndBlanks(t *testing.T) {
	got, err := scanPyRows([]string{`    "a": 1_024,  # note`, "", "  # c", `    "b": 2,`}, pyExactRow)
	if err != nil || len(got) != 2 || got[0] != (pyEntry{"a", 1024}) || got[1] != (pyEntry{"b", 2}) {
		t.Fatalf("got %v, %v", got, err)
	}
}
