package workflow

import (
	"fmt"
	"math"
	"math/rand"
	"slices"
	"testing"
	"time"

	"github.com/ArshyaAI/runnel/internal/model"
)

var workflowTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func TestCurrentUIDAloneStaysUnclassified(t *testing.T) {
	process := observation(101, 1, "/synthetic/bin/background", "", nil)
	groups, err := Group([]model.ProcessObservation{process}, Options{CurrentUID: 9001})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].Family != model.WorkflowFamilyUnclassified || groups[0].Classification != model.ClassificationQuietUnclassified {
		t.Fatalf("current UID caused attribution: %#v", groups)
	}
}

func TestAttributionRequiresTwoIndependentSignals(t *testing.T) {
	tests := []struct {
		name, cwd, tty string
		want           model.WorkflowFamily
	}{
		{"executable only", "", "", model.WorkflowFamilyUnclassified},
		{"executable and cwd", "/synthetic/worktree", "", model.WorkflowFamilyCodex},
		{"executable and tty", "", "synthetic-tty", model.WorkflowFamilyCodex},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			process := observation(101, 1, "/synthetic/bin/codex", tt.cwd, nil)
			process.TTY = tt.tty
			groups, err := Group([]model.ProcessObservation{process}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if groups[0].Family != tt.want {
				t.Fatalf("family = %s, want %s", groups[0].Family, tt.want)
			}
		})
	}
}

func TestProtectionPolicyTable(t *testing.T) {
	tests := []struct {
		name, executable string
		tty              string
		availability     []model.ProbeAvailability
		want             model.EvidenceCode
	}{
		{"cmux", "/synthetic/bin/cmux", "", available(), model.EvidenceCMUXOwner},
		{"editor", "/synthetic/bin/cursor", "", available(), model.EvidenceEditorOwner},
		{"database", "/synthetic/bin/postgres", "", available(), model.EvidenceDatabaseProcess},
		{"sync", "/synthetic/bin/dropbox", "", available(), model.EvidenceSyncProcess},
		{"vpn", "/synthetic/bin/tailscaled", "", available(), model.EvidenceVPNProcess},
		{"security", "/synthetic/bin/securityd", "", available(), model.EvidenceSecurityProcess},
		{"tty", "/synthetic/bin/tool", "synthetic-tty", available(), model.EvidenceTTYOwner},
		{"incomplete", "", "", available(), model.EvidenceIncompleteOwnership},
		{"contradictory", "/synthetic/bin/tool", "", []model.ProbeAvailability{{Probe: model.ProbeIdentity, Status: model.AvailabilityContradictory}}, model.EvidenceContradictoryOwnership},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			process := observation(101, 1, tt.executable, "", nil)
			process.TTY, process.Availability = tt.tty, tt.availability
			groups, err := Group([]model.ProcessObservation{process}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if groups[0].Classification != model.ClassificationProtected || !slices.Contains(groups[0].Protection, tt.want) {
				t.Fatalf("not protected by %s: %#v", tt.want, groups[0])
			}
		})
	}
}

func TestCurrentProcessAndAncestorsProtected(t *testing.T) {
	parent := observation(100, 1, "/synthetic/bin/shell", "", nil)
	current := observation(200, 100, "/synthetic/bin/runnel", "", nil)
	child := observation(300, 200, "/synthetic/bin/background", "", nil)
	groups, err := Group([]model.ProcessObservation{child, parent, current}, Options{CurrentPID: 200})
	if err != nil {
		t.Fatal(err)
	}
	var reasons []model.EvidenceCode
	for _, group := range groups {
		reasons = append(reasons, group.Protection...)
	}
	if !slices.Contains(reasons, model.EvidenceCurrentProcess) || !slices.Contains(reasons, model.EvidenceAncestor) {
		t.Fatalf("missing ancestry protection: %v", reasons)
	}
}

func TestRootlessCycleUsesLexicalMinimumAndCountsOnce(t *testing.T) {
	a := observation(300, 200, "/synthetic/bin/a", "", nil)
	b := observation(200, 300, "/synthetic/bin/b", "", nil)
	descendant := observation(400, 300, "/synthetic/bin/c", "", nil)
	groups, err := Group([]model.ProcessObservation{a, descendant, b}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(groups))
	}
	if groups[0].Root.PID != 200 {
		t.Fatalf("cycle root pid = %d, want lexical minimum 200", groups[0].Root.PID)
	}
	if groups[0].Aggregate.ProcessCount != 3 || len(groups[0].Processes) != 3 {
		t.Fatalf("not counted exactly once: %#v", groups[0].Aggregate)
	}
	if !hasProcessEvidence(groups[0], model.EvidenceRootlessCycle) {
		t.Fatal("cycle evidence missing")
	}
}

func TestStableSortingAndExactAggregationAcrossPermutations(t *testing.T) {
	input := []model.ProcessObservation{
		observationWithResources(300, 100, 13, 17), observationWithResources(100, 1, 5, 7), observationWithResources(200, 100, 11, 3),
	}
	var baseline []model.WorkflowGroup
	for seed := int64(0); seed < 20; seed++ {
		permutation := slices.Clone(input)
		rand.New(rand.NewSource(seed)).Shuffle(len(permutation), func(i, j int) { permutation[i], permutation[j] = permutation[j], permutation[i] })
		groups, err := Group(permutation, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if seed == 0 {
			baseline = groups
			continue
		}
		if !equalGroups(baseline, groups) {
			t.Fatalf("seed %d changed grouping", seed)
		}
	}
	if len(baseline) != 1 || baseline[0].Aggregate != (model.ResourceAggregate{ProcessCount: 3, CPUTimeNS: 29, RSSBytes: 27}) {
		t.Fatalf("aggregate = %#v", baseline)
	}
}

func TestAggregationOverflowFails(t *testing.T) {
	a := observationWithResources(100, 1, math.MaxUint64, 1)
	b := observationWithResources(200, 100, 1, 1)
	if _, err := Group([]model.ProcessObservation{a, b}, Options{}); err == nil {
		t.Fatal("overflow accepted")
	}
}

func TestDuplicatePIDFailsClosed(t *testing.T) {
	a := observation(100, 1, "/synthetic/bin/a", "", nil)
	b := observation(100, 1, "/synthetic/bin/b", "", nil)
	b.Identity.StartTime = b.Identity.StartTime.Add(time.Second)
	groups, err := Group([]model.ProcessObservation{a, b}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range groups {
		if group.Classification != model.ClassificationProtected || !slices.Contains(group.Protection, model.EvidenceIncompleteOwnership) {
			t.Fatalf("duplicate PID not protected: %#v", group)
		}
	}
}

func FuzzGroupNeverDropsOrDuplicates(f *testing.F) {
	f.Add(uint8(3), uint64(1))
	f.Fuzz(func(t *testing.T, count uint8, seed uint64) {
		n := int(count % 32)
		processes := make([]model.ProcessObservation, n)
		rng := rand.New(rand.NewSource(int64(seed)))
		for i := range processes {
			pid := int32(i + 100)
			parent := int32(0)
			if i > 0 {
				parent = int32(rng.Intn(i) + 100)
			}
			processes[i] = observation(pid, parent, "/synthetic/bin/tool", "", nil)
		}
		groups, err := Group(processes, Options{})
		if err != nil {
			t.Fatal(err)
		}
		seen := make(map[string]bool)
		for _, group := range groups {
			for _, process := range group.Processes {
				key := identityKey(process.Identity)
				if seen[key] {
					t.Fatalf("duplicate %s", key)
				}
				seen[key] = true
			}
		}
		if len(seen) != len(processes) {
			t.Fatalf("count = %d, want %d", len(seen), len(processes))
		}
	})
}

func BenchmarkGroupProcessTrees(b *testing.B) {
	for _, size := range []int{100, 500, 1500, 5000} {
		b.Run(fmt.Sprintf("processes_%d", size), func(b *testing.B) {
			processes := make([]model.ProcessObservation, size)
			for i := range processes {
				pid := int32(i + 100)
				parent := int32(1)
				if i > 0 {
					parent = int32((i-1)/8 + 100)
				}
				processes[i] = observationWithResources(pid, parent, uint64(i+1), uint64((i+1)*4096))
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				groups, err := Group(processes, Options{CurrentPID: processes[len(processes)-1].Identity.PID, CurrentUID: 9001})
				if err != nil {
					b.Fatal(err)
				}
				if len(groups) == 0 {
					b.Fatal("grouping returned no groups")
				}
			}
		})
	}
}

func observation(pid, parent int32, executable, cwd string, argv []string) model.ProcessObservation {
	return model.ProcessObservation{
		Identity:  model.ProcessIdentity{PID: pid, StartTime: workflowTime.Add(time.Duration(pid) * time.Second), UID: 9001, Executable: executable},
		ParentPID: parent, CWD: cwd, Argv: nonNil(argv), Availability: available(), Evidence: []model.EvidenceCode{},
	}
}
func observationWithResources(pid, parent int32, cpu, rss uint64) model.ProcessObservation {
	value := observation(pid, parent, "/synthetic/bin/tool", "", nil)
	value.CPUTimeNS, value.RSSBytes = cpu, rss
	return value
}
func available() []model.ProbeAvailability {
	return []model.ProbeAvailability{{Probe: model.ProbeIdentity, Status: model.AvailabilityAvailable}}
}
func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
func hasProcessEvidence(group model.WorkflowGroup, code model.EvidenceCode) bool {
	for _, process := range group.Processes {
		if slices.Contains(process.Evidence, code) {
			return true
		}
	}
	return false
}
func equalGroups(a, b []model.WorkflowGroup) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Aggregate != b[i].Aggregate || len(a[i].Processes) != len(b[i].Processes) {
			return false
		}
		for j := range a[i].Processes {
			if !a[i].Processes[j].Identity.Equal(b[i].Processes[j].Identity) {
				return false
			}
		}
	}
	return true
}
