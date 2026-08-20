package codex

import (
	"context"
	"errors"
	"slices"

	"github.com/ArshyaAI/runnel/internal/model"
	"github.com/ArshyaAI/runnel/internal/platform/darwin"
)

const (
	CodexDesignatedRequirement = `identifier "codex" and anchor apple generic and certificate leaf[subject.OU] = "2DC432GLL2"`
	NodeDesignatedRequirement  = `identifier "node" and anchor apple generic and certificate leaf[subject.OU] = "2DC432GLL2"`

	defaultDarwinArgvBytes   = 256 << 10
	defaultWorkerDigestBytes = 64 << 20
)

type darwinCollector interface {
	ActionIdentity(context.Context, int32) (model.DarwinActionIdentity, error)
	Argv(context.Context, model.DarwinActionIdentity, int) ([]string, model.Availability, error)
	Descriptors(context.Context, model.DarwinActionIdentity, int) (darwin.DescriptorSnapshot, error)
}

type darwinOriginVerifier interface {
	VerifyParentChain(
		context.Context,
		model.DarwinActionIdentity,
		model.DarwinActionIdentity,
		darwin.OriginPolicy,
		darwin.OriginPolicy,
	) (darwin.OriginResult, darwin.OriginResult, error)
}

type fileDigestVerifier func(context.Context, string, string, int64) (darwin.FileDigestResult, error)

// DarwinAdapter is the live read-only capability bridge. It owns no signaler
// and cannot mutate a process or account.
type DarwinAdapter struct {
	collector   darwinCollector
	origin      darwinOriginVerifier
	fileDigest  fileDigestVerifier
	argvBytes   int
	workerBytes int64
	maxFDs      int
}

func NewDarwinAdapter(collector *darwin.Collector, origin *darwin.OriginVerifier) *DarwinAdapter {
	return &DarwinAdapter{
		collector: collector, origin: origin, fileDigest: darwin.VerifyFileDigest,
		argvBytes: defaultDarwinArgvBytes, workerBytes: defaultWorkerDigestBytes,
	}
}

type DarwinOriginObservation struct {
	Availability model.Availability
	LeafArgv     []string
	ParentArgv   []string
	Grammar      ProcessGrammar
	Origin       OriginEvidence
}

// ObserveOrigin reads exact argv for the leaf and parent, verifies their
// identity-bound signatures/digests, and no-follow hashes trusted-worker.js.
func (a *DarwinAdapter) ObserveOrigin(
	ctx context.Context,
	leaf, parent model.DarwinActionIdentity,
	currentUID uint32,
	tempRoots []string,
) (DarwinOriginObservation, error) {
	if a == nil || a.collector == nil || a.origin == nil || a.fileDigest == nil {
		return DarwinOriginObservation{Availability: model.AvailabilityUnsupportedPlatform}, safeError(CodeOriginUnavailable)
	}
	leafArgv, availability, err := a.collector.Argv(ctx, leaf, a.argvBytes)
	if err != nil || availability != model.AvailabilityAvailable {
		return DarwinOriginObservation{Availability: normalizedAvailability(availability)}, safeWrap(CodeArgvMismatch, err)
	}
	parentArgv, parentAvailability, err := a.collector.Argv(ctx, parent, a.argvBytes)
	if err != nil || parentAvailability != model.AvailabilityAvailable {
		return DarwinOriginObservation{Availability: normalizedAvailability(parentAvailability)}, safeWrap(CodeParentMismatch, err)
	}
	grammar, err := NormalizeProcessGrammar(leafArgv, parentArgv, tempRoots)
	if err != nil {
		return DarwinOriginObservation{Availability: model.AvailabilityAvailable}, err
	}
	workerResult, err := a.fileDigest(ctx, grammar.WorkerPath, WorkerSHA256, a.workerBytes)
	if err != nil || workerResult.Availability != model.AvailabilityAvailable || workerResult.OwnerUID != currentUID {
		return DarwinOriginObservation{Availability: normalizedAvailability(workerResult.Availability)}, safeWrap(CodeOriginMismatch, err)
	}
	nodeResult, codexResult, err := a.origin.VerifyParentChain(
		ctx,
		leaf,
		parent,
		darwin.OriginPolicy{
			DesignatedRequirement: NodeDesignatedRequirement,
			TeamIdentifier:        OpenAITeamIdentifier,
			Identifier:            NodeIdentifier,
			SHA256Hex:             NodeSHA256,
		},
		darwin.OriginPolicy{
			DesignatedRequirement: CodexDesignatedRequirement,
			TeamIdentifier:        OpenAITeamIdentifier,
			Identifier:            CodexIdentifier,
			SHA256Hex:             CodexSHA256,
		},
	)
	if err != nil {
		return DarwinOriginObservation{Availability: availabilityForDarwinError(err)}, safeWrap(CodeOriginMismatch, err)
	}
	originEvidence := OriginEvidence{
		Availability: model.AvailabilityAvailable,
		Codex: SignedArtifact{
			Availability: model.AvailabilityAvailable, ResolvedPath: codexResult.Path,
			Identifier: codexResult.Identifier, TeamIdentifier: codexResult.Team,
			SHA256: codexResult.SHA256Hex, SignatureValid: true,
		},
		Node: SignedArtifact{
			Availability: model.AvailabilityAvailable, ResolvedPath: nodeResult.Path,
			Identifier: nodeResult.Identifier, TeamIdentifier: nodeResult.Team,
			SHA256: nodeResult.SHA256Hex, SignatureValid: true,
		},
		Worker: HashedArtifact{
			Availability: model.AvailabilityAvailable,
			ResolvedPath: workerResult.Path,
			SHA256:       workerResult.SHA256Hex,
		},
		LeafUID: leaf.UID, ParentUID: parent.UID,
	}
	if err := VerifyOrigin(originEvidence, grammar, currentUID); err != nil {
		return DarwinOriginObservation{Availability: model.AvailabilityContradictory}, err
	}
	return DarwinOriginObservation{
		Availability: model.AvailabilityAvailable,
		LeafArgv:     append([]string(nil), leafArgv...),
		ParentArgv:   append([]string(nil), parentArgv...),
		Grammar:      grammar,
		Origin:       originEvidence,
	}, nil
}

type DarwinDescriptorObservation struct {
	Availability     model.Availability
	Descriptor       DescriptorEvidence
	Sockets          SocketProbe
	WritableActivity PresenceProbe
}

// ObserveDescriptors extracts exactly one descriptor for the canonical
// rollout path and normalizes socket/writable disqualifiers without returning
// ports or unrelated paths.
func (a *DarwinAdapter) ObserveDescriptors(
	ctx context.Context,
	identity model.DarwinActionIdentity,
	canonicalRolloutPath string,
) (DarwinDescriptorObservation, error) {
	if a == nil || a.collector == nil {
		return DarwinDescriptorObservation{Availability: model.AvailabilityUnsupportedPlatform}, safeError(CodeDescriptorUnavailable)
	}
	snapshot, err := a.collector.Descriptors(ctx, identity, a.maxFDs)
	if err != nil {
		availability := availabilityForDarwinError(err)
		return DarwinDescriptorObservation{Availability: availability}, safeWrap(CodeDescriptorUnavailable, err)
	}
	availability := normalizedAvailability(snapshot.Availability)
	observation := DarwinDescriptorObservation{
		Availability: availability,
		Sockets: SocketProbe{
			Availability: availability,
			Listeners:    snapshot.Listening, Established: snapshot.Established,
		},
		WritableActivity: PresenceProbe{Availability: availability},
	}
	if snapshot.Truncated || availability != model.AvailabilityAvailable {
		if snapshot.Truncated {
			observation.Availability = model.AvailabilityContradictory
			observation.Sockets.Availability = model.AvailabilityContradictory
			observation.WritableActivity.Availability = model.AvailabilityContradictory
		}
		return observation, safeError(CodeDescriptorUnavailable)
	}
	var matches []darwin.FileDescriptorStat
	for _, descriptor := range snapshot.Descriptors {
		if descriptor.Availability != model.AvailabilityAvailable {
			return DarwinDescriptorObservation{Availability: descriptor.Availability}, safeError(CodeDescriptorUnavailable)
		}
		if descriptor.File == nil {
			continue
		}
		if descriptor.File.Writable {
			observation.WritableActivity.Present = true
		}
		if descriptor.File.Path == canonicalRolloutPath {
			matches = append(matches, *descriptor.File)
		}
	}
	if len(matches) != 1 {
		observation.Availability = model.AvailabilityContradictory
		return observation, safeError(CodeDescriptorMismatch)
	}
	match := matches[0]
	access := DescriptorReadOnly
	if match.Writable {
		access = DescriptorReadWrite
	}
	observation.Descriptor = DescriptorEvidence{
		Availability: model.AvailabilityAvailable,
		Path:         canonicalRolloutPath,
		Device:       match.Device,
		Inode:        match.Inode,
		Access:       access,
	}
	return observation, nil
}

// StackEvidenceFromDarwin requires a same-thread read/decode chain and never
// accepts or returns raw sample output.
func StackEvidenceFromDarwin(report darwin.SampleReport) StackEvidence {
	evidence := StackEvidence{Availability: normalizedAvailability(report.Availability)}
	if evidence.Availability != model.AvailabilityAvailable {
		return evidence
	}
	if slices.Contains(report.Predicates, darwin.StackPredicateReadDecodeChain) &&
		slices.Contains(report.Predicates, darwin.StackPredicateJSONDecoder) &&
		(slices.Contains(report.Predicates, darwin.StackPredicateReadSyscall) ||
			slices.Contains(report.Predicates, darwin.StackPredicateFileRead)) {
		evidence.Predicate = SupportedStackPredicate
	}
	return evidence
}

type DarwinRecheckInput struct {
	CurrentUID        uint32
	TempRoots         []string
	TTY               PresenceProbe
	Children          ChildrenProbe
	LeafProtected     bool
	ProtectedChildren uint32
}

// RecheckDarwin refreshes identities, argv, origin, worker digest, descriptor,
// socket and writable evidence before delegating to the stable SQLite/tail
// recheck. It has no signaler and cannot act on the returned permission.
func (a *DarwinAdapter) RecheckDarwin(
	ctx context.Context,
	result DetectorResult,
	input DarwinRecheckInput,
	metadata MetadataReader,
	tails CompletionTailReader,
) RecheckResult {
	if !result.Selectable || result.Baseline == nil || a == nil || a.collector == nil {
		return RecheckResult{
			Availability: model.AvailabilityContradictory,
			Codes:        []Code{CodeContradictory},
		}
	}
	baseline := result.Baseline
	leaf, err := a.collector.ActionIdentity(ctx, baseline.identity.PID)
	if err != nil {
		return refusedDarwinRecheck(CodeIdentityChanged, availabilityForDarwinError(err))
	}
	if leaf.Validate() != nil || !leaf.Equal(baseline.identity) {
		return refusedDarwinRecheck(CodeIdentityChanged, model.AvailabilityContradictory)
	}
	parent, err := a.collector.ActionIdentity(ctx, baseline.parent.PID)
	if err != nil {
		return refusedDarwinRecheck(CodeParentChanged, availabilityForDarwinError(err))
	}
	if parent.Validate() != nil || !parent.Equal(baseline.parent) {
		return refusedDarwinRecheck(CodeParentChanged, model.AvailabilityContradictory)
	}
	origin, err := a.ObserveOrigin(ctx, leaf, parent, input.CurrentUID, input.TempRoots)
	if err != nil {
		return refusedDarwinRecheck(codeOf(err, CodeOriginMismatch), origin.Availability)
	}
	descriptors, err := a.ObserveDescriptors(ctx, leaf, baseline.metadata.RolloutPath)
	if err != nil {
		return refusedDarwinRecheck(codeOf(err, CodeDescriptorUnavailable), descriptors.Availability)
	}
	request := ActionRecheckRequest{
		IdentityAvailability: model.AvailabilityAvailable,
		Identity:             leaf,
		ParentAvailability:   model.AvailabilityAvailable,
		Parent:               parent,
		CurrentUID:           input.CurrentUID,
		LeafArgv:             origin.LeafArgv,
		ParentArgv:           origin.ParentArgv,
		TempRoots:            append([]string(nil), input.TempRoots...),
		Origin:               origin.Origin,
		Descriptor:           descriptors.Descriptor,
		TTY:                  input.TTY,
		Sockets:              descriptors.Sockets,
		WritableActivity:     descriptors.WritableActivity,
		Children:             input.Children,
		LeafProtected:        input.LeafProtected,
		ProtectedChildren:    input.ProtectedChildren,
	}
	return Recheck(ctx, result, request, metadata, tails)
}

func refusedDarwinRecheck(code Code, availability model.Availability) RecheckResult {
	return RecheckResult{
		Availability: normalizedAvailability(availability),
		Codes:        normalizeCodes([]Code{code}),
	}
}

func availabilityForDarwinError(err error) model.Availability {
	var operation *darwin.OperationError
	if errors.As(err, &operation) {
		return normalizedAvailability(operation.Availability)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return model.AvailabilityTimeout
	}
	if errors.Is(err, context.Canceled) {
		return model.AvailabilityTimeout
	}
	return model.AvailabilityContradictory
}

func normalizedAvailability(value model.Availability) model.Availability {
	if !value.Valid() {
		return model.AvailabilityContradictory
	}
	return value
}
