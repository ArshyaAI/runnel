package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArshyaAI/runnel/internal/codex"
	"github.com/ArshyaAI/runnel/internal/live"
	"github.com/ArshyaAI/runnel/internal/model"
	"github.com/ArshyaAI/runnel/internal/platform/darwin"
)

type fakeSnapshotter struct {
	snapshot model.Snapshot
	err      error
}

func (f fakeSnapshotter) Snapshot(context.Context) (model.Snapshot, error) {
	return f.snapshot, f.err
}

type fakeEvidenceBackend struct {
	discovery live.Discovery
	report    live.Report
	err       error
}

func (f fakeEvidenceBackend) Discover(context.Context) (live.Discovery, error) {
	return f.discovery, f.err
}

func (f fakeEvidenceBackend) InspectReport(context.Context, live.Candidate) (live.Report, error) {
	return f.report, f.err
}

func TestExplainMapsOpaqueCandidateAndEmitsOnlySafeEvidence(t *testing.T) {
	snapshot, processSnapshot := evidenceFixtures()
	discovery := live.Discover(processSnapshot)
	if discovery.Count != 1 {
		t.Fatalf("discovery = %#v", discovery)
	}
	service := EvidenceService{
		Radar: fakeSnapshotter{snapshot: snapshot, err: errors.New("synthetic partial")},
		Backend: fakeEvidenceBackend{discovery: discovery, report: live.Report{
			Availability:     model.AvailabilityAvailable,
			Code:             live.CodeOK,
			CompletedSamples: 4,
			StackAttempted:   true,
			Detector: codex.DetectorResult{
				AdapterID: codex.AdapterID, Classification: model.ClassificationSupportedStaleCandidate,
				Availability: model.AvailabilityAvailable, Selectable: true,
				Evidence: []model.EvidenceCode{model.EvidenceOriginExact},
				Codes:    []codex.Code{codex.CodeAdapterExact, codex.CodeOriginExact},
			},
		}},
	}
	output, err := service.Explain(context.Background(), snapshot.Groups[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"Samples: 4/4", "selectable: true", "run `runnel recover`", "partial host metadata"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("missing %q: %s", expected, output)
		}
	}
	for _, private := range []string{"/Applications/", `"pid"`, "501", "state_5.sqlite"} {
		if strings.Contains(output, private) {
			t.Fatalf("output leaked %q: %s", private, output)
		}
	}
}

func TestExplainRejectsUnknownOrMalformedFinding(t *testing.T) {
	snapshot, processSnapshot := evidenceFixtures()
	service := EvidenceService{Radar: fakeSnapshotter{snapshot: snapshot}, Backend: fakeEvidenceBackend{discovery: live.Discover(processSnapshot)}}
	for _, value := range []string{"", "wf-not-hex", "wf-0000000000000000"} {
		if _, err := service.Explain(context.Background(), value); !errors.Is(err, ErrFindingUnavailable) {
			t.Fatalf("%q error = %v", value, err)
		}
	}
}

func evidenceFixtures() (model.Snapshot, darwin.ProcessSnapshot) {
	when := time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC)
	parentIdentity := model.ProcessIdentity{PID: 100, StartTime: when, UID: 501, Executable: "/Applications/ChatGPT.app/Contents/Resources/codex"}
	leafIdentity := model.ProcessIdentity{PID: 101, StartTime: when.Add(time.Second), UID: 501, Executable: "/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node"}
	parent := model.ProcessObservation{Identity: parentIdentity, ParentPID: 1, Argv: []string{}, Availability: []model.ProbeAvailability{}, Evidence: []model.EvidenceCode{}}
	leaf := model.ProcessObservation{Identity: leafIdentity, ParentPID: 100, RSSBytes: 4096, Argv: []string{}, Availability: []model.ProbeAvailability{}, Evidence: []model.EvidenceCode{}}
	group := model.WorkflowGroup{
		ID: "wf-0123456789abcdef", Root: parentIdentity, Family: model.WorkflowFamilyCodex,
		Classification: model.ClassificationQuietUnclassified,
		Attribution:    []model.EvidenceCode{}, Protection: []model.EvidenceCode{},
		Processes: []model.ProcessObservation{parent, leaf},
		Aggregate: model.ResourceAggregate{ProcessCount: 2, RSSBytes: 4096},
	}
	snapshot := model.Snapshot{
		SchemaVersion: model.SnapshotSchemaVersion, ToolVersion: "test", ObservedAt: when,
		Platform:     model.Platform{OS: "darwin", Arch: "arm64"},
		Availability: []model.ProbeAvailability{}, Groups: []model.WorkflowGroup{group},
	}
	processSnapshot := darwin.ProcessSnapshot{
		Availability: model.AvailabilityAvailable,
		Processes: []darwin.ProcessRecord{
			{Observation: parent, ActionIdentity: model.DarwinActionIdentity{ProcessIdentity: parentIdentity, PIDVersion: 7, UniqueID: 8}, ActionAvailable: model.AvailabilityAvailable},
			{Observation: leaf, ActionIdentity: model.DarwinActionIdentity{ProcessIdentity: leafIdentity, PIDVersion: 9, UniqueID: 10}, ActionAvailable: model.AvailabilityAvailable},
		},
		Failures: []darwin.ProcessFailure{},
	}
	return snapshot, processSnapshot
}
