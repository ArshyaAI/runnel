package app

import (
	"context"
	"errors"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/ArshyaAI/runnel/internal/codex"
	"github.com/ArshyaAI/runnel/internal/model"
	"github.com/ArshyaAI/runnel/internal/platform/darwin"
	"github.com/ArshyaAI/runnel/internal/recovery"
)

type identityResponse struct {
	identity model.DarwinActionIdentity
	err      error
}

type recoveryFakeCollector struct {
	identities   map[int32]model.DarwinActionIdentity
	responses    map[int32][]identityResponse
	indexes      map[int32]int
	snapshot     darwin.ProcessSnapshot
	processErr   error
	children     darwin.ChildSnapshot
	childErr     error
	actionCalls  map[int32]int
	childCalls   int
	processCalls int
}

func (f *recoveryFakeCollector) ActionIdentity(_ context.Context, pid int32) (model.DarwinActionIdentity, error) {
	if f.actionCalls == nil {
		f.actionCalls = map[int32]int{}
	}
	f.actionCalls[pid]++
	if values := f.responses[pid]; len(values) != 0 {
		if f.indexes == nil {
			f.indexes = map[int32]int{}
		}
		index := f.indexes[pid]
		if index >= len(values) {
			index = len(values) - 1
		} else {
			f.indexes[pid]++
		}
		return values[index].identity, values[index].err
	}
	value, ok := f.identities[pid]
	if !ok {
		return model.DarwinActionIdentity{}, syscall.ESRCH
	}
	return value, nil
}

func (f *recoveryFakeCollector) Processes(context.Context) (darwin.ProcessSnapshot, error) {
	f.processCalls++
	return f.snapshot, f.processErr
}

func (f *recoveryFakeCollector) Children(context.Context, model.DarwinActionIdentity, int) (darwin.ChildSnapshot, error) {
	f.childCalls++
	return f.children, f.childErr
}

type recoveryFakeRechecker struct {
	result codex.RecheckResult
	calls  int
	input  codex.DarwinRecheckInput
	hook   func()
}

func (f *recoveryFakeRechecker) RecheckDarwin(_ context.Context, _ codex.DetectorResult, input codex.DarwinRecheckInput, _ codex.MetadataReader, _ codex.CompletionTailReader) codex.RecheckResult {
	f.calls++
	f.input = input
	if f.hook != nil {
		f.hook()
	}
	return f.result
}

type recoveryFakeMetadata struct{ closes int }

func (*recoveryFakeMetadata) Snapshot(context.Context, string) (codex.MetadataSnapshot, error) {
	return codex.MetadataSnapshot{}, nil
}
func (m *recoveryFakeMetadata) Close() error { m.closes++; return nil }

type recoveryFakeStateOpener struct {
	store *recoveryFakeMetadata
	path  string
	calls int
	err   error
}

func (o *recoveryFakeStateOpener) Open(_ context.Context, path string) (recoveryMetadataStore, error) {
	o.calls++
	o.path = path
	return o.store, o.err
}

type recoveryFakeTail struct{}

func (recoveryFakeTail) Read(context.Context, string, codex.DescriptorEvidence) (codex.TailSnapshot, error) {
	return codex.TailSnapshot{}, nil
}

func TestActionTimeRevalidatorReturnsExactValueOnlyWhenEveryGateAllows(t *testing.T) {
	_, _, detector, recoveryContext := recoveryCompositionFixture(t)
	plan, err := recovery.NewPlan(detector.Authority(), recoveryContext.Protected(), recoveryContext.RSSBytes(), model.PressureUnknown, "test")
	if err != nil {
		t.Fatal(err)
	}
	leaf, parent := recoveryContext.Identities()
	protected := recoveryContext.Protected()[0]
	targetObservation := processObservation(leaf.ProcessIdentity, parent.PID, 8192)
	baseCollector := func() *recoveryFakeCollector {
		return &recoveryFakeCollector{
			identities: map[int32]model.DarwinActionIdentity{leaf.PID: leaf, parent.PID: parent, protected.PID: protected},
			snapshot: darwin.ProcessSnapshot{
				Availability: model.AvailabilityAvailable,
				Processes:    []darwin.ProcessRecord{{Observation: targetObservation, ActionIdentity: leaf, ActionAvailable: model.AvailabilityAvailable}},
				Failures:     []darwin.ProcessFailure{},
			},
			children: darwin.ChildSnapshot{Identity: leaf, Children: []darwin.ProcessRecord{}, Failures: []darwin.ProcessFailure{}, Availability: model.AvailabilityAvailable},
		}
	}

	metadata := &recoveryFakeMetadata{}
	state := &recoveryFakeStateOpener{store: metadata}
	rechecker := &recoveryFakeRechecker{result: codex.RecheckResult{Allowed: true, Availability: model.AvailabilityAvailable, Codes: []codex.Code{codex.CodeActionRecheckExact}}}
	revalidator := &actionTimeRevalidator{context: recoveryContext, collector: baseCollector(), adapter: rechecker, state: state, tails: recoveryFakeTail{}}
	got, err := revalidator.Revalidate(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if got.SelectedRSSBytes != 8192 || got.Pressure != model.PressureUnknown || !got.Candidate.Target.Equal(leaf) || !slices.EqualFunc(got.Protected, plan.Protected(), func(a, b model.DarwinActionIdentity) bool { return a.Equal(b) }) {
		t.Fatalf("revalidation = %#v", got)
	}
	if rechecker.calls != 1 || rechecker.input.TTY.Present || rechecker.input.TTY.Availability != model.AvailabilityAvailable || len(rechecker.input.Children.Children) != 0 {
		t.Fatalf("recheck input = %#v calls=%d", rechecker.input, rechecker.calls)
	}
	if state.calls != 1 || state.path != recoveryContext.StatePath() || metadata.closes != 1 {
		t.Fatalf("state opens=%d path=%q closes=%d", state.calls, state.path, metadata.closes)
	}

	for _, test := range []struct {
		name        string
		mutate      func(*recoveryFakeCollector, *recoveryFakeRechecker)
		wantRecheck int
	}{
		{name: "new child", mutate: func(c *recoveryFakeCollector, _ *recoveryFakeRechecker) {
			child := actionIdentity(88, "/safe/new-child", 88)
			c.children.Children = []darwin.ProcessRecord{{Observation: processObservation(child.ProcessIdentity, leaf.PID, 1), ActionIdentity: child, ActionAvailable: model.AvailabilityAvailable}}
		}, wantRecheck: 0},
		{name: "target tty", mutate: func(c *recoveryFakeCollector, _ *recoveryFakeRechecker) {
			c.snapshot.Processes[0].Observation.TTY = "/dev/ttys001"
		}, wantRecheck: 0},
		{name: "protected replacement", mutate: func(c *recoveryFakeCollector, _ *recoveryFakeRechecker) {
			replacement := protected
			replacement.PIDVersion++
			c.identities[protected.PID] = replacement
		}, wantRecheck: 0},
		{name: "codex recheck refusal", mutate: func(_ *recoveryFakeCollector, r *recoveryFakeRechecker) {
			r.result = codex.RecheckResult{Availability: model.AvailabilityContradictory, Codes: []codex.Code{codex.CodeIdentityChanged}}
		}, wantRecheck: 1},
		{name: "drift after codex recheck", mutate: func(c *recoveryFakeCollector, r *recoveryFakeRechecker) {
			r.hook = func() { c.snapshot.Processes[0].Observation.TTY = "/dev/ttys001" }
		}, wantRecheck: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			collector := baseCollector()
			adapter := &recoveryFakeRechecker{result: codex.RecheckResult{Allowed: true, Availability: model.AvailabilityAvailable, Codes: []codex.Code{codex.CodeActionRecheckExact}}}
			test.mutate(collector, adapter)
			state := &recoveryFakeStateOpener{store: &recoveryFakeMetadata{}}
			value := &actionTimeRevalidator{context: recoveryContext, collector: collector, adapter: adapter, state: state, tails: recoveryFakeTail{}}
			if got, err := value.Revalidate(context.Background(), plan); err == nil || got.Candidate.DetectorID != "" || got.Protected != nil || got.SelectedRSSBytes != 0 || got.Pressure != "" {
				t.Fatalf("got=%#v err=%v", got, err)
			}
			if adapter.calls != test.wantRecheck {
				t.Fatalf("recheck calls=%d want=%d", adapter.calls, test.wantRecheck)
			}
		})
	}
}

func TestPostSignalVerifierRequiresAbsenceProtectedSurvivalAndNoLeakage(t *testing.T) {
	_, _, _, recoveryContext := recoveryCompositionFixture(t)
	target, _ := recoveryContext.Identities()
	protected := recoveryContext.Protected()[0]
	finalSnapshot := darwin.ProcessSnapshot{
		Availability: model.AvailabilityAvailable,
		Processes:    []darwin.ProcessRecord{{Observation: processObservation(protected.ProcessIdentity, 1, 10), ActionIdentity: protected, ActionAvailable: model.AvailabilityAvailable}},
		Failures:     []darwin.ProcessFailure{},
	}
	collector := &recoveryFakeCollector{
		responses: map[int32][]identityResponse{
			target.PID:    {{identity: target}, {err: syscall.ESRCH}, {err: syscall.ESRCH}},
			protected.PID: {{identity: protected}},
		},
		snapshot: finalSnapshot,
		children: darwin.ChildSnapshot{Identity: target, Children: []darwin.ProcessRecord{}, Failures: []darwin.ProcessFailure{}, Availability: model.AvailabilityAvailable},
	}
	verifier := &postSignalVerifier{collector: collector, timeout: time.Second, interval: 100 * time.Millisecond, sleep: func(context.Context, time.Duration) error { return nil }}
	got, err := verifier.Verify(context.Background(), target, []model.DarwinActionIdentity{protected})
	if err != nil {
		t.Fatal(err)
	}
	if !got.TargetAbsent || got.Pressure != model.PressureUnknown || len(got.ProtectedPresent) != 1 || !got.ProtectedPresent[0].Equal(protected) {
		t.Fatalf("verification = %#v", got)
	}
	if collector.childCalls != 1 || collector.processCalls != 1 || collector.actionCalls[target.PID] != 3 {
		t.Fatalf("calls: child=%d process=%d target=%d", collector.childCalls, collector.processCalls, collector.actionCalls[target.PID])
	}

	for _, test := range []struct {
		name      string
		collector *recoveryFakeCollector
	}{
		{name: "replacement confusion", collector: &recoveryFakeCollector{
			responses: map[int32][]identityResponse{target.PID: {{identity: func() model.DarwinActionIdentity { value := target; value.PIDVersion++; return value }()}}, protected.PID: {{identity: protected}}},
		}},
		{name: "new child leakage", collector: &recoveryFakeCollector{
			responses: map[int32][]identityResponse{target.PID: {{identity: target}}, protected.PID: {{identity: protected}}},
			children: func() darwin.ChildSnapshot {
				child := actionIdentity(89, "/safe/leaked-child", 89)
				return darwin.ChildSnapshot{Identity: target, Availability: model.AvailabilityAvailable, Failures: []darwin.ProcessFailure{}, Children: []darwin.ProcessRecord{{Observation: processObservation(child.ProcessIdentity, target.PID, 1), ActionIdentity: child, ActionAvailable: model.AvailabilityAvailable}}}
			}(),
		}},
		{name: "protected disappeared", collector: &recoveryFakeCollector{
			responses: map[int32][]identityResponse{protected.PID: {{err: syscall.ESRCH}}},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := &postSignalVerifier{collector: test.collector, timeout: time.Millisecond, interval: time.Millisecond, sleep: func(context.Context, time.Duration) error { return nil }}
			got, err := value.Verify(context.Background(), target, []model.DarwinActionIdentity{protected})
			if err == nil || got.TargetAbsent {
				t.Fatalf("verification=%#v err=%v", got, err)
			}
		})
	}
}

func TestPostSignalVerifierTimeoutIsBoundedAndNeverEscalatesSignal(t *testing.T) {
	_, _, _, recoveryContext := recoveryCompositionFixture(t)
	target, _ := recoveryContext.Identities()
	protected := recoveryContext.Protected()[0]
	collector := &recoveryFakeCollector{
		responses: map[int32][]identityResponse{target.PID: {{identity: target}}, protected.PID: {{identity: protected}}},
		children:  darwin.ChildSnapshot{Identity: target, Children: []darwin.ProcessRecord{}, Failures: []darwin.ProcessFailure{}, Availability: model.AvailabilityAvailable},
	}
	sleeps := 0
	verifier := &postSignalVerifier{collector: collector, timeout: 3 * time.Millisecond, interval: time.Millisecond, sleep: func(context.Context, time.Duration) error { sleeps++; return nil }}
	got, err := verifier.Verify(context.Background(), target, []model.DarwinActionIdentity{protected})
	if err == nil || got.TargetAbsent {
		t.Fatalf("verification=%#v err=%v", got, err)
	}
	if collector.actionCalls[target.PID] != 4 || sleeps != 3 {
		t.Fatalf("bounded polls=%d sleeps=%d", collector.actionCalls[target.PID], sleeps)
	}
	if !errors.Is(err, errPostSignalUnverified) {
		t.Fatalf("error=%v", err)
	}
}
