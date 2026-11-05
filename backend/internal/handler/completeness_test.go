package handler

import (
	"reflect"
	"testing"

	"github.com/vulture/backend/internal/model"
)

func drainEvents(evts ...*model.AgUIEvent) DrainResult {
	ch := make(chan *model.AgUIEvent, len(evts))
	for _, e := range evts {
		ch <- e
	}
	close(ch)
	return drainResult(ch, "audit-1", nopSink{})
}

func agentEnd(agentType, status string) *model.AgUIEvent {
	return &model.AgUIEvent{Type: model.EventStepFinished, AgentType: agentType, RunStatus: status}
}

// Only an agent's own completed agent_end marks its run finished.
func TestDrainRecordsOnlyCompletedRuns(t *testing.T) {
	res := drainEvents(
		agentEnd("prove", "completed"),
		agentEnd("discover", "failed"),
		agentEnd("chaos", "skipped"),
		agentEnd("soc2", ""),
		agentEnd("", "completed"),
	)
	want := map[string]bool{"prove": true}
	if !reflect.DeepEqual(res.Finished, want) {
		t.Errorf("Finished = %v, want %v", res.Finished, want)
	}
}

func TestMissingRequestedAgents(t *testing.T) {
	cases := []struct {
		name      string
		requested []string
		res       DrainResult
		want      []string
	}{
		{"default scan names no agent", nil, DrainResult{}, nil},
		{"snapshot reports", []string{"cwe"}, DrainResult{ScanOutcomes: map[string]*model.ScanResult{"cwe": {}}}, nil},
		{"score reports", []string{"cwe"}, DrainResult{Scores: map[string]int{"cwe": 90}}, nil},
		{"finding reports", []string{"cwe"}, DrainResult{Findings: []model.Finding{{AgentType: "cwe"}}}, nil},
		{"finished run reports", []string{"prove"}, DrainResult{Finished: map[string]bool{"prove": true}}, nil},
		{"silent agent is missing", []string{"cwe", "prove"}, DrainResult{Finished: map[string]bool{"prove": true}}, []string{"cwe"}},
		{"order kept, duplicates and blanks dropped", []string{"soc2", "", "chaos", "soc2"}, DrainResult{}, []string{"soc2", "chaos"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := missingRequestedAgents(tc.requested, tc.res); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("missingRequestedAgents = %v, want %v", got, tc.want)
			}
		})
	}
}
