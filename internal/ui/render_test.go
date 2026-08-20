package ui

import (
	"bytes"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArshyaAI/runnel/internal/model"
	tea "github.com/charmbracelet/bubbletea"
)

func testSnapshot() model.Snapshot {
	return model.Snapshot{SchemaVersion: model.SnapshotSchemaVersion, ToolVersion: "test", ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Platform: model.Platform{OS: "darwin", Arch: "arm64"}, Availability: []model.ProbeAvailability{{Probe: model.ProbeCWD, Status: model.AvailabilityAvailable}, {Probe: model.ProbeExecutable, Status: model.AvailabilityAvailable}, {Probe: model.ProbeIdentity, Status: model.AvailabilityAvailable}, {Probe: model.ProbeSockets, Status: model.AvailabilityAvailable}, {Probe: model.ProbeTTY, Status: model.AvailabilityAvailable}}, Groups: []model.WorkflowGroup{}}
}

func TestJSONHasNoANSIAndIsDeterministic(t *testing.T) {
	a, e := JSON(testSnapshot())
	if e != nil {
		t.Fatal(e)
	}
	b, e := JSON(testSnapshot())
	if e != nil {
		t.Fatal(e)
	}
	if string(a) != string(b) {
		t.Fatal("JSON is not deterministic")
	}
	if strings.Contains(string(a), "\x1b[") {
		t.Fatal("ANSI in JSON")
	}
}

func displayGroup(id string, family model.WorkflowFamily, classification model.Classification, rss uint64, protected bool) model.WorkflowGroup {
	identity := model.ProcessIdentity{PID: int32(len(id) + 1), StartTime: time.Date(2026, 1, 1, 0, 0, 0, len(id), time.UTC), UID: 501, Executable: id}
	process := model.ProcessObservation{Identity: identity, RSSBytes: rss, Argv: []string{}, Availability: []model.ProbeAvailability{}, Evidence: []model.EvidenceCode{}}
	protection := []model.EvidenceCode{}
	if protected {
		protection = []model.EvidenceCode{model.EvidenceCurrentProcess}
	}
	return model.WorkflowGroup{ID: id, Root: identity, Family: family, Classification: classification, Attribution: []model.EvidenceCode{}, Protection: protection, Processes: []model.ProcessObservation{process}, Aggregate: model.ResourceAggregate{ProcessCount: 1, RSSBytes: rss}}
}

func TestPlainRanksSafetyAndBoundsUnclassifiedGroups(t *testing.T) {
	snapshot := testSnapshot()
	snapshot.Groups = []model.WorkflowGroup{
		displayGroup("quiet-low", model.WorkflowFamilyUnclassified, model.ClassificationQuietUnclassified, 1, false),
		displayGroup("unknown-big", model.WorkflowFamilyUnclassified, model.ClassificationUnknown, 99<<30, false),
		displayGroup("known-workflow", model.WorkflowFamilyCodex, model.ClassificationQuietUnclassified, 2, false),
		displayGroup("protected-workflow", model.WorkflowFamilyCodex, model.ClassificationProtected, 1, true),
	}
	for i := 0; i < 30; i++ {
		snapshot.Groups = append(snapshot.Groups, displayGroup("unclassified-"+strconv.Itoa(i), model.WorkflowFamilyUnclassified, model.ClassificationQuietUnclassified, uint64(i), false))
	}
	// Plain validates the model's canonical ID ordering, as a scanner snapshot
	// would. The display ranking itself is intentionally separate from JSON.
	sort.Slice(snapshot.Groups, func(i, j int) bool { return snapshot.Groups[i].ID < snapshot.Groups[j].ID })
	var out bytes.Buffer
	if err := Plain(&out, snapshot); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !strings.Contains(text, "showing 24, omitted 10 low-signal group(s)") {
		t.Fatalf("missing bounded summary: %s", text[:min(len(text), 300)])
	}
	if strings.Index(text, "PROTECTED protected-workflow") > strings.Index(text, "UNKNOWN unknown-big") {
		t.Fatal("protected workflow was not ranked first")
	}
	unknownIndex := strings.Index(text, "UNKNOWN unknown-big")
	quietIndex := strings.Index(text, "QUIET quiet-low")
	if unknownIndex < 0 || quietIndex >= 0 && unknownIndex > quietIndex {
		t.Fatal("high-RSS unknown was hidden behind quiet unclassified work")
	}
	knownIndex := strings.Index(text, "QUIET known-workflow")
	if knownIndex < 0 || quietIndex >= 0 && knownIndex > quietIndex {
		t.Fatal("known workflow was not prioritized over unclassified work")
	}
	if strings.Contains(text, "unclassified-0") {
		t.Fatal("low-signal group escaped the plain output cap")
	}
}

func TestJSONRetainsGroupsOmittedFromPlain(t *testing.T) {
	snapshot := testSnapshot()
	for i := 0; i < plainGroupLimit+1; i++ {
		snapshot.Groups = append(snapshot.Groups, displayGroup("json-group-"+strconv.Itoa(i), model.WorkflowFamilyUnclassified, model.ClassificationQuietUnclassified, 0, false))
	}
	sort.Slice(snapshot.Groups, func(i, j int) bool { return snapshot.Groups[i].ID < snapshot.Groups[j].ID })
	data, err := JSON(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"id":"json-group-24"`) {
		t.Fatal("JSON lost a group omitted from bounded plain output")
	}
}

func TestTUIResizeCancelAndEvidence(t *testing.T) {
	m := NewTUIModel(testSnapshot())
	next, _ := m.Update(tea.WindowSizeMsg{Width: 40, Height: 8})
	m = next.(TUIModel)
	if m.Width != 40 || m.Height != 8 {
		t.Fatalf("size=%dx%d", m.Width, m.Height)
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(TUIModel)
	if !strings.Contains(m.View(), "Evidence drilldown") {
		t.Fatal("missing drilldown")
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEscape})
	m = next.(TUIModel)
	if m.Drilldown != "" || m.Done {
		t.Fatal("escape did not close drilldown")
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	m = next.(TUIModel)
	if !m.Done || !m.Cancelled {
		t.Fatal("cancel not handled")
	}
}
