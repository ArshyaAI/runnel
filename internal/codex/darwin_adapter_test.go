package codex

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/ArshyaAI/runnel/internal/model"
	"github.com/ArshyaAI/runnel/internal/platform/darwin"
)

type fakeDarwinCollector struct {
	actions          map[int32]model.DarwinActionIdentity
	actionErr        map[int32]error
	argv             map[int32][]string
	argvAvailability map[int32]model.Availability
	argvErr          map[int32]error
	descriptors      darwin.DescriptorSnapshot
	descriptorErr    error
}

func (f *fakeDarwinCollector) ActionIdentity(_ context.Context, pid int32) (model.DarwinActionIdentity, error) {
	if err := f.actionErr[pid]; err != nil {
		return model.DarwinActionIdentity{}, err
	}
	return f.actions[pid], nil
}

func (f *fakeDarwinCollector) Argv(_ context.Context, identity model.DarwinActionIdentity, _ int) ([]string, model.Availability, error) {
	availability := f.argvAvailability[identity.PID]
	if !availability.Valid() {
		availability = model.AvailabilityAvailable
	}
	return append([]string(nil), f.argv[identity.PID]...), availability, f.argvErr[identity.PID]
}

func (f *fakeDarwinCollector) Descriptors(_ context.Context, _ model.DarwinActionIdentity, _ int) (darwin.DescriptorSnapshot, error) {
	return f.descriptors, f.descriptorErr
}

type fakeDarwinOrigin struct {
	node         darwin.OriginResult
	codex        darwin.OriginResult
	err          error
	childPolicy  darwin.OriginPolicy
	parentPolicy darwin.OriginPolicy
}

func (f *fakeDarwinOrigin) VerifyParentChain(
	_ context.Context,
	_, _ model.DarwinActionIdentity,
	childPolicy, parentPolicy darwin.OriginPolicy,
) (darwin.OriginResult, darwin.OriginResult, error) {
	f.childPolicy = childPolicy
	f.parentPolicy = parentPolicy
	return f.node, f.codex, f.err
}

func testDarwinAdapter(t *testing.T) (*DarwinAdapter, *fakeDarwinCollector, *fakeDarwinOrigin, model.DarwinActionIdentity, model.DarwinActionIdentity) {
	t.Helper()
	samples := validDeepSamples(t)
	leaf := samples[0].Identity
	parent := samples[0].Parent
	leafArgv, parentArgv, _ := validArgv()
	collector := &fakeDarwinCollector{
		actions:          map[int32]model.DarwinActionIdentity{leaf.PID: leaf, parent.PID: parent},
		actionErr:        map[int32]error{},
		argv:             map[int32][]string{leaf.PID: leafArgv, parent.PID: parentArgv},
		argvAvailability: map[int32]model.Availability{},
		argvErr:          map[int32]error{},
	}
	origin := &fakeDarwinOrigin{
		node: darwin.OriginResult{
			Identity: leaf, Path: leafArgv[0], Team: OpenAITeamIdentifier,
			Identifier: NodeIdentifier, SHA256Hex: NodeSHA256,
			Availability: model.AvailabilityAvailable,
		},
		codex: darwin.OriginResult{
			Identity: parent, Path: parentArgv[0], Team: OpenAITeamIdentifier,
			Identifier: CodexIdentifier, SHA256Hex: CodexSHA256,
			Availability: model.AvailabilityAvailable,
		},
	}
	adapter := &DarwinAdapter{
		collector:   collector,
		origin:      origin,
		argvBytes:   defaultDarwinArgvBytes,
		workerBytes: defaultWorkerDigestBytes,
		fileDigest: func(_ context.Context, path, expected string, _ int64) (darwin.FileDigestResult, error) {
			if path != leafArgv[2] || expected != WorkerSHA256 {
				t.Fatalf("unexpected worker digest request")
			}
			return darwin.FileDigestResult{
				Path: path, SHA256Hex: WorkerSHA256, OwnerUID: leaf.UID,
				Availability: model.AvailabilityAvailable,
			}, nil
		},
	}
	return adapter, collector, origin, leaf, parent
}

func TestDarwinAdapterObserveOriginUsesExactLiveSurfaces(t *testing.T) {
	adapter, _, verifier, leaf, parent := testDarwinAdapter(t)
	observation, err := adapter.ObserveOrigin(context.Background(), leaf, parent, leaf.UID, []string{"/synthetic/tmp"})
	if err != nil {
		t.Fatal(err)
	}
	if observation.Availability != model.AvailabilityAvailable ||
		observation.Grammar.WorkerPath != observation.LeafArgv[2] ||
		observation.Origin.Worker.SHA256 != WorkerSHA256 {
		t.Fatalf("unexpected observation: %#v", observation)
	}
	if verifier.childPolicy.DesignatedRequirement != NodeDesignatedRequirement ||
		verifier.childPolicy.TeamIdentifier != OpenAITeamIdentifier ||
		verifier.childPolicy.Identifier != NodeIdentifier ||
		verifier.childPolicy.SHA256Hex != NodeSHA256 ||
		verifier.parentPolicy.DesignatedRequirement != CodexDesignatedRequirement ||
		verifier.parentPolicy.Identifier != CodexIdentifier ||
		verifier.parentPolicy.SHA256Hex != CodexSHA256 {
		t.Fatal("live verifier policy was not exact")
	}
}

func TestDarwinAdapterObserveOriginFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		edit func(*DarwinAdapter, *fakeDarwinCollector, *fakeDarwinOrigin, model.DarwinActionIdentity)
		code Code
	}{
		{"argv unavailable", func(_ *DarwinAdapter, c *fakeDarwinCollector, _ *fakeDarwinOrigin, leaf model.DarwinActionIdentity) {
			c.argvAvailability[leaf.PID] = model.AvailabilityPermissionDenied
		}, CodeArgvMismatch},
		{"argv malformed", func(_ *DarwinAdapter, c *fakeDarwinCollector, _ *fakeDarwinOrigin, leaf model.DarwinActionIdentity) {
			c.argv[leaf.PID] = []string{"/usr/bin/node"}
		}, CodeArgvMismatch},
		{"worker owner mismatch", func(a *DarwinAdapter, _ *fakeDarwinCollector, _ *fakeDarwinOrigin, leaf model.DarwinActionIdentity) {
			a.fileDigest = func(_ context.Context, path, _ string, _ int64) (darwin.FileDigestResult, error) {
				return darwin.FileDigestResult{Path: path, SHA256Hex: WorkerSHA256, OwnerUID: leaf.UID + 1, Availability: model.AvailabilityAvailable}, nil
			}
		}, CodeOriginMismatch},
		{"worker digest mismatch", func(a *DarwinAdapter, _ *fakeDarwinCollector, _ *fakeDarwinOrigin, _ model.DarwinActionIdentity) {
			a.fileDigest = func(context.Context, string, string, int64) (darwin.FileDigestResult, error) {
				return darwin.FileDigestResult{Availability: model.AvailabilityContradictory}, errors.New("digest mismatch")
			}
		}, CodeOriginMismatch},
		{"parent chain mismatch", func(_ *DarwinAdapter, _ *fakeDarwinCollector, o *fakeDarwinOrigin, _ model.DarwinActionIdentity) {
			o.err = &darwin.OperationError{Op: "origin_parent", Availability: model.AvailabilityContradictory, Err: darwin.ErrOriginMismatch}
		}, CodeOriginMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter, collector, origin, leaf, parent := testDarwinAdapter(t)
			test.edit(adapter, collector, origin, leaf)
			_, err := adapter.ObserveOrigin(context.Background(), leaf, parent, leaf.UID, []string{"/synthetic/tmp"})
			if err == nil || codeOf(err, "") != test.code {
				t.Fatalf("got %v want %s", err, test.code)
			}
		})
	}
}

func exactDarwinDescriptorSnapshot(identity model.DarwinActionIdentity, path string, device, inode uint64) darwin.DescriptorSnapshot {
	return darwin.DescriptorSnapshot{
		Identity:     identity,
		Availability: model.AvailabilityAvailable,
		Descriptors: []darwin.Descriptor{{
			FD: 7, Kind: darwin.DescriptorVnode, Availability: model.AvailabilityAvailable,
			File: &darwin.FileDescriptorStat{Path: path, Device: device, Inode: inode},
		}},
	}
}

func TestDarwinAdapterObserveDescriptorsAndStack(t *testing.T) {
	adapter, collector, _, leaf, _ := testDarwinAdapter(t)
	path := "/synthetic/rollout.jsonl"
	collector.descriptors = exactDarwinDescriptorSnapshot(leaf, path, 41, 42)
	collector.descriptors.Listening = 1
	collector.descriptors.Established = 2
	collector.descriptors.Descriptors = append(collector.descriptors.Descriptors, darwin.Descriptor{
		FD: 8, Kind: darwin.DescriptorVnode, Availability: model.AvailabilityAvailable,
		File: &darwin.FileDescriptorStat{Path: "/synthetic/output", Device: 41, Inode: 43, Writable: true},
	})
	observation, err := adapter.ObserveDescriptors(context.Background(), leaf, path)
	if err != nil {
		t.Fatal(err)
	}
	if observation.Descriptor.Access != DescriptorReadOnly || observation.Descriptor.Device != 41 || observation.Descriptor.Inode != 42 ||
		observation.Sockets.Listeners != 1 || observation.Sockets.Established != 2 || !observation.WritableActivity.Present {
		t.Fatalf("unexpected descriptor observation: %#v", observation)
	}

	stack := StackEvidenceFromDarwin(darwin.SampleReport{
		Availability: model.AvailabilityAvailable,
		Predicates: []darwin.StackPredicate{
			darwin.StackPredicateJSONDecoder,
			darwin.StackPredicateReadDecodeChain,
			darwin.StackPredicateReadSyscall,
		},
	})
	if stack.Predicate != SupportedStackPredicate {
		t.Fatalf("supported stack not normalized: %#v", stack)
	}
	unsupported := StackEvidenceFromDarwin(darwin.SampleReport{
		Availability: model.AvailabilityAvailable,
		Predicates:   []darwin.StackPredicate{darwin.StackPredicateNodeEventLoop},
	})
	if unsupported.Predicate != "" {
		t.Fatal("unsupported stack accepted")
	}
}

func TestDarwinAdapterObserveDescriptorsRejectsAmbiguity(t *testing.T) {
	adapter, collector, _, leaf, _ := testDarwinAdapter(t)
	path := "/synthetic/rollout.jsonl"
	collector.descriptors = exactDarwinDescriptorSnapshot(leaf, path, 41, 42)
	collector.descriptors.Descriptors = append(collector.descriptors.Descriptors, collector.descriptors.Descriptors[0])
	observation, err := adapter.ObserveDescriptors(context.Background(), leaf, path)
	if err == nil || codeOf(err, "") != CodeDescriptorMismatch || observation.Availability != model.AvailabilityContradictory {
		t.Fatalf("got observation=%#v err=%v", observation, err)
	}
}

func TestDarwinAdapterRecheckRefreshesLiveEvidenceWithoutSignaling(t *testing.T) {
	samples := validDeepSamples(t)
	detector := Evaluate(samples)
	adapter, collector, _, leaf, _ := testDarwinAdapter(t)
	collector.descriptors = exactDarwinDescriptorSnapshot(
		leaf,
		detector.Baseline.metadata.RolloutPath,
		detector.Baseline.descriptor.Device,
		detector.Baseline.descriptor.Inode,
	)
	input := DarwinRecheckInput{
		CurrentUID: leaf.UID,
		TempRoots:  []string{"/synthetic/tmp"},
		TTY:        PresenceProbe{Availability: model.AvailabilityAvailable},
		Children:   ChildrenProbe{Availability: model.AvailabilityAvailable, Children: []model.ProcessIdentity{}},
	}
	metadata := metadataReaderFunc(func(context.Context, string) (MetadataSnapshot, error) {
		return detector.Baseline.metadata, nil
	})
	tails := tailReaderFunc(func(context.Context, string, DescriptorEvidence) (TailSnapshot, error) {
		return detector.Baseline.tail, nil
	})
	result := adapter.RecheckDarwin(context.Background(), detector, input, metadata, tails)
	if !result.Allowed || !slices.Equal(result.Codes, []Code{CodeActionRecheckExact}) {
		t.Fatalf("live recheck refused: %#v", result)
	}

	collector.actions[leaf.PID] = model.DarwinActionIdentity{}
	changed := adapter.RecheckDarwin(context.Background(), detector, input, metadata, tails)
	if changed.Allowed || !slices.Contains(changed.Codes, CodeIdentityChanged) {
		t.Fatalf("changed identity accepted: %#v", changed)
	}
}
