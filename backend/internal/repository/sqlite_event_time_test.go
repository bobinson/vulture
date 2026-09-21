package repository

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/vulture/backend/internal/model"
)

// The aggregate labels a row with its NEWEST lineage event, and the timeline
// shows events in the order they happened. Both need created_at to order the
// events a scan writes. SQLite stored it as RFC3339 to the SECOND, so two
// events inside one second tied and the tiebreak fell to the random UUID id —
// the "newest" event was a coin toss. Reproduced by the re-find e2e test:
// `detected` and `reported` written 90 ms apart came back in either order.
func TestSQLiteEventTimestampsKeepSubSecondOrder(t *testing.T) {
	base, err := NewSQLiteRepo(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer base.Close()
	repo := NewSQLiteLineageRepo(base.DB())

	l := &model.FindingLineage{
		Fingerprint: "fp-order", SourcePath: "/p", AgentType: "cwe",
		CurrentStatus: model.LineageStatusOpen, FirstAuditID: "a1", FirstFoundAt: time.Now().UTC(),
		Severity: "high", Category: "CWE-798", Title: "t", FilePath: "/p/x.go",
	}
	if err := repo.UpsertLineage(l); err != nil {
		t.Fatalf("upsert lineage: %v", err)
	}

	base0 := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	// Three events inside ONE second, written out of chronological order, so
	// neither insertion order nor id can be what sorts them correctly.
	for _, ev := range []struct {
		kind model.LineageEventType
		at   time.Time
	}{
		{model.LineageEventOutOfScope, base0.Add(500 * time.Millisecond)},
		{model.LineageEventDetected, base0.Add(100 * time.Millisecond)},
		{model.LineageEventReported, base0.Add(900 * time.Millisecond)},
	} {
		if err := repo.AddEvent(&model.LineageEvent{LineageID: l.ID, EventType: ev.kind, CreatedAt: ev.at}); err != nil {
			t.Fatalf("add %s: %v", ev.kind, err)
		}
	}

	events, err := repo.GetEvents(l.ID)
	if err != nil {
		t.Fatalf("get events: %v", err)
	}
	got := []model.LineageEventType{}
	for _, e := range events {
		got = append(got, e.EventType)
	}
	want := []model.LineageEventType{model.LineageEventDetected, model.LineageEventOutOfScope, model.LineageEventReported}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("events must come back in chronological order within one second: got %v, want %v", got, want)
	}
	// And the stored instant survives the round trip — a truncated timestamp
	// is how the tie was created in the first place.
	if !events[2].CreatedAt.Equal(base0.Add(900 * time.Millisecond)) {
		t.Fatalf("created_at lost precision on the round trip: got %s, want %s",
			events[2].CreatedAt.Format(time.RFC3339Nano), base0.Add(900*time.Millisecond).Format(time.RFC3339Nano))
	}
}

// The aggregate's "last event" is computed by lastEventQuery; it must agree
// with GetEvents on which event is newest under the same sub-second ordering.
func TestSQLiteLastEventIsTheChronologicallyNewest(t *testing.T) {
	base, err := NewSQLiteRepo(filepath.Join(t.TempDir(), "events2.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer base.Close()
	repo := NewSQLiteLineageRepo(base.DB())
	l := &model.FindingLineage{
		Fingerprint: "fp-last", SourcePath: "/p", AgentType: "cwe",
		CurrentStatus: model.LineageStatusOpen, FirstAuditID: "a1", FirstFoundAt: time.Now().UTC(),
		Severity: "high", Category: "CWE-798", Title: "t", FilePath: "/p/x.go",
	}
	if err := repo.UpsertLineage(l); err != nil {
		t.Fatalf("upsert lineage: %v", err)
	}
	base0 := time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)
	for _, ev := range []struct {
		kind model.LineageEventType
		at   time.Time
	}{
		{model.LineageEventReported, base0.Add(900 * time.Millisecond)}, // newest, inserted FIRST
		{model.LineageEventOutOfScope, base0.Add(200 * time.Millisecond)},
	} {
		if err := repo.AddEvent(&model.LineageEvent{LineageID: l.ID, EventType: ev.kind, CreatedAt: ev.at}); err != nil {
			t.Fatalf("add %s: %v", ev.kind, err)
		}
	}
	d := &sqlDialect{pg: false}
	rows, err := base.DB().Query(lastEventQuery(d, []string{l.ID}), d.args...)
	if err != nil {
		t.Fatalf("last event query: %v", err)
	}
	defer rows.Close()
	last, err := scanLastEvents(rows)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if last[l.ID] != string(model.LineageEventReported) {
		t.Fatalf("last_event must be the chronologically newest event, got %q", last[l.ID])
	}
}
