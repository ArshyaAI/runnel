package live

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArshyaAI/runnel/internal/codex"
	"github.com/ArshyaAI/runnel/internal/model"
	"github.com/ArshyaAI/runnel/internal/platform/darwin"
)

const (
	testNodePath    = "/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node"
	testCodexPath   = "/Applications/ChatGPT.app/Contents/Resources/codex"
	testWorkerPath  = "/private/tmp/runnel-live-worker/trusted-worker.js"
	testCWD         = "/Users/test/project"
	testStatePath   = "/Users/test/.codex/state_5.sqlite"
	testRolloutPath = "/Users/test/.codex/sessions/2026/08/20/rollout-2026-08-20T04-00-00-01234567-89ab-cdef-0123-456789abcdef.jsonl"
)

var testStart = time.Date(2026, 8, 20, 4, 0, 0, 0, time.UTC)

func testIdentity(pid int32, executable string, version uint32, unique uint64) model.DarwinActionIdentity {
	return model.DarwinActionIdentity{
		ProcessIdentity: model.ProcessIdentity{
			PID: pid, StartTime: testStart.Add(time.Duration(pid) * time.Millisecond),
			UID: 501, Executable: executable,
		},
		PIDVersion: version, UniqueID: unique,
	}
}

func testPair() PairObservation {
	return PairObservation{
		Leaf:   testIdentity(42, testNodePath, 7, 42_007),
		Parent: testIdentity(41, testCodexPath, 6, 41_006),
	}
}

func processRecord(identity model.DarwinActionIdentity, ppid int32, cpu, rss uint64, tty string) darwin.ProcessRecord {
	return darwin.ProcessRecord{
		Observation: model.ProcessObservation{
			Identity: identity.ProcessIdentity, ParentPID: ppid, CPUTimeNS: cpu, RSSBytes: rss,
			TTY: tty, Argv: []string{},
			Availability: []model.ProbeAvailability{{Probe: model.ProbeTTY, Status: model.AvailabilityAvailable}},
			Evidence:     []model.EvidenceCode{},
		},
		ActionIdentity: identity, ActionAvailable: model.AvailabilityAvailable,
	}
}

func exactSnapshot(cpu uint64) darwin.ProcessSnapshot {
	pair := testPair()
	return darwin.ProcessSnapshot{
		Availability: model.AvailabilityAvailable,
		Processes: []darwin.ProcessRecord{
			processRecord(pair.Parent, 1, cpu/2, 32<<20, ""),
			processRecord(pair.Leaf, pair.Parent.PID, cpu, 128<<20, ""),
		},
		Failures: []darwin.ProcessFailure{},
	}
}

func exactCandidate(t *testing.T) Candidate {
	t.Helper()
	discovery := Discover(exactSnapshot(100))
	if discovery.Code != CodeOK || discovery.Count != 1 {
		t.Fatalf("unexpected discovery: %#v", discovery)
	}
	return discovery.Candidates()[0]
}

func exactOrigin() codex.DarwinOriginObservation {
	leaf := []string{testNodePath, "--experimental-vm-modules", testWorkerPath, testCWD}
	parent := append([]string{testCodexPath, "sandbox", "--"}, leaf...)
	return codex.DarwinOriginObservation{
		Availability: model.AvailabilityAvailable,
		LeafArgv:     leaf, ParentArgv: parent,
		Origin: codex.OriginEvidence{
			Availability: model.AvailabilityAvailable,
			Codex: codex.SignedArtifact{
				Availability: model.AvailabilityAvailable, ResolvedPath: testCodexPath,
				Identifier: codex.CodexIdentifier, TeamIdentifier: codex.OpenAITeamIdentifier,
				SHA256: codex.CodexSHA256, SignatureValid: true,
			},
			Node: codex.SignedArtifact{
				Availability: model.AvailabilityAvailable, ResolvedPath: testNodePath,
				Identifier: codex.NodeIdentifier, TeamIdentifier: codex.OpenAITeamIdentifier,
				SHA256: codex.NodeSHA256, SignatureValid: true,
			},
			Worker: codex.HashedArtifact{
				Availability: model.AvailabilityAvailable, ResolvedPath: testWorkerPath,
				SHA256: codex.WorkerSHA256,
			},
			LeafUID: 501, ParentUID: 501,
		},
	}
}

func exactDescriptorSnapshot(paths ...string) darwin.DescriptorSnapshot {
	if len(paths) == 0 {
		paths = []string{testRolloutPath}
	}
	descriptors := make([]darwin.Descriptor, 0, len(paths))
	for index, path := range paths {
		descriptors = append(descriptors, darwin.Descriptor{
			FD: int32(index + 10), Kind: darwin.DescriptorVnode, Availability: model.AvailabilityAvailable,
			File: &darwin.FileDescriptorStat{Path: path, Device: 7, Inode: uint64(9 + index), Writable: false},
		})
	}
	return darwin.DescriptorSnapshot{
		Identity: testPair().Leaf, Descriptors: descriptors,
		Availability: model.AvailabilityAvailable,
	}
}

func exactDescriptorObservation() codex.DarwinDescriptorObservation {
	return codex.DarwinDescriptorObservation{
		Availability: model.AvailabilityAvailable,
		Descriptor: codex.DescriptorEvidence{
			Availability: model.AvailabilityAvailable, Path: testRolloutPath,
			Device: 7, Inode: 9, Access: codex.DescriptorReadOnly,
		},
		Sockets:          codex.SocketProbe{Availability: model.AvailabilityAvailable},
		WritableActivity: codex.PresenceProbe{Availability: model.AvailabilityAvailable},
	}
}

type fakePlatform struct {
	mu                                   sync.Mutex
	processCalls, pairCalls, originCalls int
	childrenCalls, descriptorCalls       int
	evidenceCalls, stackCalls            int
	fixedCPU                             bool
	pairRaceCall                         int
	originErr                            error
	descriptorPaths                      []string
	clock                                *fakeClock
	processWork                          time.Duration
	processTimes                         []time.Time
	unrelatedFailures                    bool
	targetFailurePID                     int32
	children                             []darwin.ProcessRecord
}

func (f *fakePlatform) Processes(context.Context) (darwin.ProcessSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.clock != nil {
		f.processTimes = append(f.processTimes, f.clock.Now())
		f.clock.advance(f.processWork)
	}
	f.processCalls++
	cpu := uint64(100 + f.processCalls)
	if f.fixedCPU {
		cpu = 100
	}
	snapshot := exactSnapshot(cpu)
	if f.unrelatedFailures {
		snapshot.Failures = []darwin.ProcessFailure{{PID: 777, Availability: model.AvailabilityPermissionDenied}}
	}
	if f.targetFailurePID > 0 {
		snapshot.Failures = append(snapshot.Failures, darwin.ProcessFailure{
			PID: f.targetFailurePID, Availability: model.AvailabilityPermissionDenied,
		})
	}
	return snapshot, nil
}

func (f *fakePlatform) Pair(context.Context, Candidate) (PairObservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pairCalls++
	pair := testPair()
	if f.pairRaceCall == f.pairCalls {
		pair.Leaf.PIDVersion++
	}
	return pair, nil
}

func (f *fakePlatform) Origin(context.Context, Candidate, PairObservation, uint32, []string) (codex.DarwinOriginObservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.originCalls++
	if f.originErr != nil {
		observation := exactOrigin()
		observation.Availability = model.AvailabilityPermissionDenied
		observation.Origin.Availability = model.AvailabilityPermissionDenied
		return observation, f.originErr
	}
	return exactOrigin(), nil
}

func (f *fakePlatform) Children(context.Context, Candidate, PairObservation) (darwin.ChildSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.childrenCalls++
	return darwin.ChildSnapshot{
		Identity: testPair().Leaf, Children: append([]darwin.ProcessRecord{}, f.children...),
		Failures: []darwin.ProcessFailure{}, Availability: model.AvailabilityAvailable,
	}, nil
}

func (f *fakePlatform) Descriptors(context.Context, Candidate, PairObservation) (darwin.DescriptorSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.descriptorCalls++
	return exactDescriptorSnapshot(f.descriptorPaths...), nil
}

func (f *fakePlatform) DescriptorEvidence(context.Context, Candidate, PairObservation, string) (codex.DarwinDescriptorObservation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.evidenceCalls++
	return exactDescriptorObservation(), nil
}

func (f *fakePlatform) Stack(context.Context, Candidate, PairObservation) (darwin.SampleReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stackCalls++
	return darwin.SampleReport{
		Availability: model.AvailabilityAvailable,
		Predicates: []darwin.StackPredicate{
			darwin.StackPredicateReadSyscall,
			darwin.StackPredicateJSONDecoder,
			darwin.StackPredicateReadDecodeChain,
		},
	}, nil
}

type fakeStore struct {
	mu     sync.Mutex
	paths  []string
	closed bool
}

func (s *fakeStore) Snapshot(_ context.Context, path string) (codex.MetadataSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paths = append(s.paths, path)
	return codex.MetadataSnapshot{
		Availability: model.AvailabilityAvailable, DataVersion: 11,
		CLIVersion: codex.SupportedCodexVersion, ThreadSource: "subagent", EdgeStatus: "closed",
		ThreadID: "private-child", ParentThreadID: "private-parent", RolloutPath: path,
	}, nil
}

func (s *fakeStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

type fakeTail struct {
	mu    sync.Mutex
	paths []string
}

func (t *fakeTail) Read(_ context.Context, path string, descriptor codex.DescriptorEvidence) (codex.TailSnapshot, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.paths = append(t.paths, path)
	return codex.TailSnapshot{
		Availability: model.AvailabilityAvailable, EnvelopeType: "event_msg",
		EventType: "task_complete", Successful: true,
		File: codex.FileIdentity{Device: descriptor.Device, Inode: descriptor.Inode, Size: 4096, ModifiedNS: 99},
	}, nil
}

type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(ctx context.Context, duration time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	c.sleeps = append(c.sleeps, duration)
	c.now = c.now.Add(duration)
	return nil
}

func (c *fakeClock) advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

type testRig struct {
	inspector       *Inspector
	platform        *fakePlatform
	store           *fakeStore
	tail            *fakeTail
	clock           *fakeClock
	resolveCalls    *int
	protectionCalls *int
}

func newTestRig(t *testing.T, configure func(*fakePlatform)) testRig {
	t.Helper()
	platform := &fakePlatform{}
	if configure != nil {
		configure(platform)
	}
	store := &fakeStore{}
	tail := &fakeTail{}
	clock := &fakeClock{now: testStart}
	platform.clock = clock
	resolveCalls := 0
	protectionCalls := 0
	inspector, err := New(Options{
		CurrentUID: 501,
		TempRoots:  []string{"/private/tmp/runnel-live-worker"},
		StatePath: StatePathResolveFunc(func() (string, error) {
			resolveCalls++
			return testStatePath, nil
		}),
	}, Dependencies{
		Platform: platform,
		State:    StateStoreOpenFunc(func(context.Context, string) (MetadataStore, error) { return store, nil }),
		Tail:     tail, Clock: clock, Sleeper: clock,
		Protection: ProtectionFunc(func(darwin.ProcessSnapshot, Candidate, PairObservation, []darwin.ProcessRecord) (ProtectionObservation, error) {
			protectionCalls++
			return ProtectionObservation{Availability: model.AvailabilityAvailable, Protected: []model.DarwinActionIdentity{}}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return testRig{
		inspector: inspector, platform: platform, store: store, tail: tail, clock: clock,
		resolveCalls: &resolveCalls, protectionCalls: &protectionCalls,
	}
}

func TestDiscoverRequiresExactPlausiblePair(t *testing.T) {
	discovery := Discover(exactSnapshot(100))
	if discovery.Count != 1 || discovery.Availability != model.AvailabilityAvailable || discovery.Code != CodeOK {
		t.Fatalf("unexpected exact discovery: %#v", discovery)
	}
	if encoded, err := json.Marshal(discovery.Candidates()[0]); err != nil || string(encoded) != "{}" {
		t.Fatalf("candidate leaked through JSON: %s %v", encoded, err)
	}

	sameUIDOnly := exactSnapshot(100)
	lookalike := testIdentity(99, "/usr/local/bin/node", 9, 99)
	sameUIDOnly.Processes = append(sameUIDOnly.Processes, processRecord(lookalike, testPair().Parent.PID, 1, 1, ""))
	if got := Discover(sameUIDOnly); got.Count != 1 {
		t.Fatalf("same-UID lookalike attributed: %#v", got)
	}

	wrongParent := exactSnapshot(100)
	wrongParent.Processes[0].ActionIdentity.Executable = "/Applications/Elsewhere/codex"
	wrongParent.Processes[0].Observation.Identity.Executable = "/Applications/Elsewhere/codex"
	if got := Discover(wrongParent); got.Count != 0 || got.Code != CodeOK {
		t.Fatalf("wrong parent discovered: %#v", got)
	}

	ambiguous := exactSnapshot(100)
	ambiguous.Processes = append(ambiguous.Processes, ambiguous.Processes[1])
	if got := Discover(ambiguous); got.Count != 0 || got.Code != CodeDiscoveryAmbiguous || got.Availability != model.AvailabilityContradictory {
		t.Fatalf("duplicate PID did not fail closed: %#v", got)
	}

	permission := exactSnapshot(100)
	permission.Failures = []darwin.ProcessFailure{{PID: 77, Availability: model.AvailabilityPermissionDenied}}
	if got := Discover(permission); got.Count != 1 || got.Code != CodeOK {
		t.Fatalf("unrelated permission gap blocked exact pair: %#v", got)
	}
	permission.Failures = []darwin.ProcessFailure{{PID: testPair().Leaf.PID, Availability: model.AvailabilityPermissionDenied}}
	if got := Discover(permission); got.Count != 0 || got.Code != CodeDiscoveryAmbiguous {
		t.Fatalf("target permission gap did not fail closed: %#v", got)
	}
}

func TestCandidateMatchesOnlyExactLeafIdentity(t *testing.T) {
	candidate := exactCandidate(t)
	pair := testPair()
	if !candidate.Matches(pair.Leaf.ProcessIdentity) {
		t.Fatal("exact leaf did not match")
	}
	if candidate.Matches(pair.Parent.ProcessIdentity) {
		t.Fatal("parent identity matched leaf candidate")
	}
	changed := pair.Leaf.ProcessIdentity
	changed.StartTime = changed.StartTime.Add(time.Nanosecond)
	if candidate.Matches(changed) {
		t.Fatal("changed leaf identity matched")
	}
	if (Candidate{}).Matches(pair.Leaf.ProcessIdentity) {
		t.Fatal("zero candidate matched")
	}
}

func TestInspectorDiscoverUsesOneSnapshotAndDefersState(t *testing.T) {
	t.Run("unrelated failure tolerated", func(t *testing.T) {
		rig := newTestRig(t, func(platform *fakePlatform) { platform.unrelatedFailures = true })
		discovery, err := rig.inspector.Discover(context.Background())
		if err != nil || discovery.Count != 1 || discovery.Code != CodeOK ||
			rig.platform.processCalls != 1 || *rig.resolveCalls != 0 {
			t.Fatalf("unexpected discovery=%#v err=%v processes=%d state=%d", discovery, err, rig.platform.processCalls, *rig.resolveCalls)
		}
	})

	t.Run("target failure refused", func(t *testing.T) {
		rig := newTestRig(t, func(platform *fakePlatform) { platform.targetFailurePID = testPair().Leaf.PID })
		discovery, err := rig.inspector.Discover(context.Background())
		if err != nil || discovery.Count != 0 || discovery.Code != CodeDiscoveryAmbiguous ||
			discovery.Availability != model.AvailabilityContradictory || rig.platform.processCalls != 1 {
			t.Fatalf("target failure passed: discovery=%#v err=%v processes=%d", discovery, err, rig.platform.processCalls)
		}
	})

	t.Run("parent failure refused", func(t *testing.T) {
		rig := newTestRig(t, func(platform *fakePlatform) { platform.targetFailurePID = testPair().Parent.PID })
		discovery, err := rig.inspector.Discover(context.Background())
		if err != nil || discovery.Count != 0 || discovery.Code != CodeDiscoveryAmbiguous ||
			discovery.Availability != model.AvailabilityContradictory || rig.platform.processCalls != 1 {
			t.Fatalf("parent failure passed: discovery=%#v err=%v processes=%d", discovery, err, rig.platform.processCalls)
		}
	})
}

func TestInspectorExactScheduleCompleteRefreshAndPrivateHandoff(t *testing.T) {
	rig := newTestRig(t, func(platform *fakePlatform) {
		platform.processWork = 250 * time.Millisecond
		platform.unrelatedFailures = true
	})
	if *rig.resolveCalls != 0 {
		t.Fatal("state path was resolved eagerly")
	}
	finding, err := rig.inspector.Inspect(context.Background(), exactCandidate(t))
	if err != nil {
		t.Fatal(err)
	}
	report := finding.Report()
	if report.Code != CodeOK || !report.Detector.Selectable || report.CompletedSamples != 4 || !report.StackAttempted {
		t.Fatalf("candidate refused: %#v", report)
	}
	if finding.DetectorResult().Authority() == nil {
		t.Fatal("neutral detector handoff dropped the opaque codex authority")
	}
	if *rig.resolveCalls != 1 {
		t.Fatalf("state resolver calls=%d", *rig.resolveCalls)
	}
	if !slices.Equal(rig.clock.sleeps, []time.Duration{1750 * time.Millisecond, 1750 * time.Millisecond, 1750 * time.Millisecond}) {
		t.Fatalf("schedule=%v", rig.clock.sleeps)
	}
	wantTimes := []time.Time{
		testStart,
		testStart.Add(2 * time.Second),
		testStart.Add(4 * time.Second),
		testStart.Add(6 * time.Second),
	}
	if !slices.Equal(rig.platform.processTimes, wantTimes) {
		t.Fatalf("sample starts=%v want=%v", rig.platform.processTimes, wantTimes)
	}
	if rig.platform.processCalls != 4 || rig.platform.pairCalls != 9 || rig.platform.originCalls != 4 ||
		rig.platform.childrenCalls != 4 || rig.platform.descriptorCalls != 4 ||
		rig.platform.evidenceCalls != 4 || rig.platform.stackCalls != 1 ||
		*rig.protectionCalls != 4 {
		t.Fatalf("refresh calls process/pair/origin/children/descriptor/evidence/stack/protection=%d/%d/%d/%d/%d/%d/%d/%d",
			rig.platform.processCalls, rig.platform.pairCalls, rig.platform.originCalls,
			rig.platform.childrenCalls, rig.platform.descriptorCalls, rig.platform.evidenceCalls, rig.platform.stackCalls,
			*rig.protectionCalls)
	}
	if len(rig.store.paths) != 4 || len(rig.tail.paths) != 4 || !rig.store.closed {
		t.Fatalf("state/tail lifecycle=%v/%v closed=%v", rig.store.paths, rig.tail.paths, rig.store.closed)
	}
	for _, path := range append(slices.Clone(rig.store.paths), rig.tail.paths...) {
		if path != testRolloutPath {
			t.Fatalf("non-exact rollout path: %q", path)
		}
	}

	contextValue, ok := finding.RecoveryContext()
	if !ok || contextValue.StatePath() != testStatePath || contextValue.RolloutPath() != testRolloutPath ||
		contextValue.RSSBytes() != 128<<20 || !contextValue.DetectorResult().Selectable ||
		contextValue.DetectorResult().Authority() == nil {
		t.Fatalf("missing immutable handoff: %#v ok=%v", contextValue, ok)
	}
	leaf, parent := contextValue.Identities()
	if !leaf.Equal(testPair().Leaf) || !parent.Equal(testPair().Parent) {
		t.Fatal("handoff identities changed")
	}
	if encoded, err := json.Marshal(finding); err != nil {
		t.Fatal(err)
	} else {
		body := string(encoded)
		for _, forbidden := range []string{
			"/Users/", "/private/tmp/", "trusted-worker.js", "rollout-", "private-child", "private-parent", `"pid"`,
		} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("privacy leak %q in %s", forbidden, body)
			}
		}
	}
	if encoded, err := json.Marshal(contextValue); err != nil || string(encoded) != "{}" {
		t.Fatalf("recovery context leaked through JSON: %s %v", encoded, err)
	}
}

func TestInspectorSkipsStackWhenCheaperGateFails(t *testing.T) {
	rig := newTestRig(t, func(platform *fakePlatform) { platform.fixedCPU = true })
	finding, err := rig.inspector.Inspect(context.Background(), exactCandidate(t))
	if err != nil {
		t.Fatal(err)
	}
	report := finding.Report()
	if report.Detector.Selectable || report.StackAttempted || rig.platform.stackCalls != 0 || report.Code != CodeStackSkipped {
		t.Fatalf("stack gate weakened: %#v calls=%d", report, rig.platform.stackCalls)
	}
	if _, ok := finding.RecoveryContext(); ok {
		t.Fatal("unselectable finding issued recovery context")
	}
}

func TestInspectorUsesIdentityBoundChildrenNotHostWideInference(t *testing.T) {
	childIdentity := testIdentity(43, "/usr/bin/helper", 8, 43_008)
	child := processRecord(childIdentity, testPair().Leaf.PID, 1, 1<<20, "")
	rig := newTestRig(t, func(platform *fakePlatform) {
		platform.children = []darwin.ProcessRecord{child}
		platform.unrelatedFailures = true
	})
	finding, err := rig.inspector.Inspect(context.Background(), exactCandidate(t))
	if err != nil {
		t.Fatal(err)
	}
	report := finding.Report()
	if report.Detector.Selectable || report.StackAttempted || rig.platform.stackCalls != 0 ||
		rig.platform.childrenCalls != 4 || !slices.Contains(report.Detector.Codes, codex.CodeNewChild) {
		t.Fatalf("identity-bound child was not decisive: %#v calls=%d", report, rig.platform.childrenCalls)
	}
}

func TestInspectorFailsClosedOnDescriptorAmbiguityAndIdentityRace(t *testing.T) {
	t.Run("descriptor ambiguity", func(t *testing.T) {
		second := "/Users/test/.codex/sessions/2026/08/20/rollout-2026-08-20T04-00-01-fedcba98-7654-3210-fedc-ba9876543210.jsonl"
		rig := newTestRig(t, func(platform *fakePlatform) {
			platform.descriptorPaths = []string{testRolloutPath, second}
		})
		finding, err := rig.inspector.Inspect(context.Background(), exactCandidate(t))
		if err != nil {
			t.Fatal(err)
		}
		report := finding.Report()
		if report.Detector.Selectable || report.StackAttempted || report.Code != CodeDescriptorAmbiguous || rig.platform.stackCalls != 0 {
			t.Fatalf("ambiguity passed: %#v", report)
		}
	})

	t.Run("identity race", func(t *testing.T) {
		rig := newTestRig(t, func(platform *fakePlatform) { platform.pairRaceCall = 1 })
		finding, err := rig.inspector.Inspect(context.Background(), exactCandidate(t))
		if err != nil {
			t.Fatal(err)
		}
		report := finding.Report()
		if report.Detector.Selectable || report.StackAttempted || !slices.Contains(report.Detector.Codes, codex.CodeContradictory) ||
			rig.platform.originCalls != 3 || rig.platform.childrenCalls != 3 || rig.platform.descriptorCalls != 3 {
			t.Fatalf("identity race passed: %#v", report)
		}
	})
}

func TestInspectorFailsClosedOnPermissionAndInvalidLazyState(t *testing.T) {
	t.Run("origin permission", func(t *testing.T) {
		rig := newTestRig(t, func(platform *fakePlatform) {
			platform.originErr = &darwin.OperationError{Op: "origin", Availability: model.AvailabilityPermissionDenied, Err: errors.New("private detail")}
		})
		finding, err := rig.inspector.Inspect(context.Background(), exactCandidate(t))
		if err != nil {
			t.Fatal(err)
		}
		report := finding.Report()
		if report.Detector.Selectable || report.StackAttempted || report.Code != CodeOriginUnavailable || report.Availability != model.AvailabilityPermissionDenied {
			t.Fatalf("permission gap passed: %#v", report)
		}
	})

	t.Run("invalid state path", func(t *testing.T) {
		platform := &fakePlatform{}
		calls := 0
		inspector, err := New(Options{
			CurrentUID: 501, TempRoots: []string{"/private/tmp/runnel-live-worker"},
			StatePath: StatePathResolveFunc(func() (string, error) {
				calls++
				return "/Users/test/.codex/../state_5.sqlite", errors.New("secret path detail")
			}),
		}, Dependencies{
			Platform: platform,
			State:    StateStoreOpenFunc(func(context.Context, string) (MetadataStore, error) { return &fakeStore{}, nil }),
			Tail:     &fakeTail{}, Clock: &fakeClock{now: testStart}, Sleeper: &fakeClock{now: testStart},
			Protection: ProtectionFunc(func(darwin.ProcessSnapshot, Candidate, PairObservation, []darwin.ProcessRecord) (ProtectionObservation, error) {
				return ProtectionObservation{Availability: model.AvailabilityAvailable, Protected: []model.DarwinActionIdentity{}}, nil
			}),
		})
		if err != nil || calls != 0 {
			t.Fatalf("constructor resolved path: err=%v calls=%d", err, calls)
		}
		finding, inspectErr := inspector.Inspect(context.Background(), exactCandidate(t))
		if inspectErr == nil || inspectErr.Error() != "live inspector: state_path_unavailable" || calls != 1 || platform.processCalls != 0 {
			t.Fatalf("invalid path handling finding=%#v err=%v calls=%d probes=%d", finding.Report(), inspectErr, calls, platform.processCalls)
		}
		if strings.Contains(inspectErr.Error(), "secret") || strings.Contains(inspectErr.Error(), "/Users") {
			t.Fatalf("raw path error leaked: %v", inspectErr)
		}
	})
}

func TestNewRequiresExplicitCanonicalTempRoots(t *testing.T) {
	deps := Dependencies{
		Platform: &fakePlatform{},
		State:    StateStoreOpenFunc(func(context.Context, string) (MetadataStore, error) { return &fakeStore{}, nil }),
		Tail:     &fakeTail{}, Clock: &fakeClock{now: testStart}, Sleeper: &fakeClock{now: testStart},
		Protection: ProtectionFunc(func(darwin.ProcessSnapshot, Candidate, PairObservation, []darwin.ProcessRecord) (ProtectionObservation, error) {
			return ProtectionObservation{Availability: model.AvailabilityAvailable, Protected: []model.DarwinActionIdentity{}}, nil
		}),
	}
	for _, roots := range [][]string{nil, {}, {"relative"}, {"/private/tmp/../tmp"}, {"/private/tmp", "/private/tmp"}} {
		if _, err := New(Options{TempRoots: roots, StatePath: StatePathResolveFunc(func() (string, error) { return testStatePath, nil })}, deps); err == nil {
			t.Fatalf("invalid roots accepted: %v", roots)
		}
	}
}

func TestStructuralProtectionScopesUnrelatedFailures(t *testing.T) {
	pair := testPair()
	current := testIdentity(100, "/usr/local/bin/runnel", 10, 100_010)
	snapshot := exactSnapshot(100)
	snapshot.Processes = append(snapshot.Processes, processRecord(current, 0, 1, 1, ""))
	snapshot.Failures = []darwin.ProcessFailure{{PID: 777, Availability: model.AvailabilityPermissionDenied}}
	policy := newStructuralProtection(current.PID, nil)
	result, err := policy.Observe(snapshot, exactCandidate(t), pair, []darwin.ProcessRecord{})
	if err != nil || result.Availability != model.AvailabilityAvailable || result.LeafProtected ||
		!containsIdentity(result.Protected, current) || !containsIdentity(result.Protected, pair.Parent) {
		t.Fatalf("unrelated failure blocked protection: %#v err=%v", result, err)
	}

	snapshot.Failures = []darwin.ProcessFailure{{PID: current.PID, Availability: model.AvailabilityPermissionDenied}}
	if result, err := policy.Observe(snapshot, exactCandidate(t), pair, []darwin.ProcessRecord{}); err == nil ||
		result.Availability == model.AvailabilityAvailable {
		t.Fatalf("current ancestry failure passed: %#v err=%v", result, err)
	}

	snapshot.Failures = nil
	for index := range snapshot.Processes {
		if snapshot.Processes[index].ActionIdentity.Equal(pair.Leaf) {
			snapshot.Processes[index].Observation.TTY = "/dev/ttys001"
		}
	}
	result, err = policy.Observe(snapshot, exactCandidate(t), pair, []darwin.ProcessRecord{})
	if err != nil || !result.LeafProtected {
		t.Fatalf("target TTY was not protected: %#v err=%v", result, err)
	}
}
