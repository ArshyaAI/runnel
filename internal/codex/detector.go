package codex

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"slices"
	"time"

	"github.com/ArshyaAI/runnel/internal/model"
)

var requiredSampleOffsets = [...]time.Duration{0, 2 * time.Second, 4 * time.Second, 6 * time.Second}

type PresenceProbe struct {
	Availability model.Availability `json:"availability"`
	Present      bool               `json:"present"`
}

type SocketProbe struct {
	Availability model.Availability `json:"availability"`
	Listeners    uint32             `json:"listeners"`
	Established  uint32             `json:"established"`
}

type ChildrenProbe struct {
	Availability model.Availability      `json:"availability"`
	Children     []model.ProcessIdentity `json:"-"`
}

type StackEvidence struct {
	Availability model.Availability `json:"availability"`
	Predicate    string             `json:"predicate"`
	Changed      bool               `json:"changed"`
}

// DeepSample is injected read-only evidence. Raw stack output and rollout
// payloads have no representation in this type.
type DeepSample struct {
	Offset time.Duration `json:"offset"`

	IdentityAvailability model.Availability         `json:"identity_availability"`
	Identity             model.DarwinActionIdentity `json:"-"`
	ParentAvailability   model.Availability         `json:"parent_availability"`
	Parent               model.DarwinActionIdentity `json:"-"`
	CurrentUID           uint32                     `json:"current_uid"`

	LeafArgv   []string       `json:"-"`
	ParentArgv []string       `json:"-"`
	TempRoots  []string       `json:"-"`
	Origin     OriginEvidence `json:"origin"`

	Metadata        MetadataSnapshot   `json:"metadata"`
	MetadataFailure Code               `json:"metadata_failure,omitempty"`
	Tail            TailSnapshot       `json:"tail"`
	TailFailure     Code               `json:"tail_failure,omitempty"`
	Descriptor      DescriptorEvidence `json:"descriptor"`

	CPUTimeNS uint64 `json:"cpu_time_ns"`
	RSSBytes  uint64 `json:"rss_bytes"`

	TTY               PresenceProbe `json:"tty"`
	Sockets           SocketProbe   `json:"sockets"`
	WritableActivity  PresenceProbe `json:"writable_activity"`
	Children          ChildrenProbe `json:"children"`
	LeafProtected     bool          `json:"leaf_protected"`
	ProtectedChildren uint32        `json:"protected_children"`
	Stack             StackEvidence `json:"stack"`
	Contradictory     bool          `json:"contradictory"`
}

// Baseline is an opaque action-time proof. Its contents cannot be serialized;
// callers can only hand it back to Recheck.
type Baseline struct {
	identity   model.DarwinActionIdentity
	parent     model.DarwinActionIdentity
	currentUID uint32
	grammar    ProcessGrammar
	metadata   MetadataSnapshot
	tail       TailSnapshot
	descriptor DescriptorEvidence
}

// ActionAuthority is an opaque, non-serializable recovery capability. Only an
// exact selectable Evaluate result can issue one. Its state and integrity seal
// are deliberately unavailable to callers.
type ActionAuthority struct {
	state *actionAuthorityState
	self  *ActionAuthority
}

type actionAuthorityState struct {
	candidate  model.ActionCandidate
	baseline   Baseline
	provenance [sha256.Size]byte
}

var errActionAuthoritySerialization = errors.New("codex: action authority cannot be serialized")

func (ActionAuthority) MarshalJSON() ([]byte, error) {
	return nil, errActionAuthoritySerialization
}

func (*ActionAuthority) UnmarshalJSON([]byte) error {
	return errActionAuthoritySerialization
}

type DetectorResult struct {
	AdapterID      string               `json:"adapter_id"`
	Classification model.Classification `json:"classification"`
	Availability   model.Availability   `json:"availability"`
	Selectable     bool                 `json:"selectable"`
	Evidence       []model.EvidenceCode `json:"evidence"`
	Codes          []Code               `json:"codes"`
	Baseline       *Baseline            `json:"-"`
	authority      *ActionAuthority
}

// Authority returns the recovery capability issued with this exact detector
// result. Any mutation of the public result or its opaque baseline fails
// closed. A non-selectable result never has an authority.
func (r DetectorResult) Authority() *ActionAuthority {
	if r.authority == nil || !r.authority.valid() || r.Baseline == nil ||
		r.AdapterID != AdapterID ||
		r.Classification != model.ClassificationSupportedStaleCandidate ||
		r.Availability != model.AvailabilityAvailable || !r.Selectable ||
		!slices.Equal(r.Codes, candidateCodes()) ||
		!slices.Equal(r.Evidence, candidateEvidence()) ||
		!baselineEqual(*r.Baseline, r.authority.state.baseline) {
		return nil
	}
	candidate, ok := r.authority.Candidate()
	if !ok || !candidate.Target.Equal(r.Baseline.identity) {
		return nil
	}
	return r.authority
}

// Candidate returns an isolated copy of the action-grade candidate carried by
// this authority. The boolean is false for zero, copied, or tampered values.
func (a *ActionAuthority) Candidate() (model.ActionCandidate, bool) {
	if !a.valid() {
		return model.ActionCandidate{}, false
	}
	return cloneActionCandidate(a.state.candidate), true
}

// Provenance returns the privacy-safe integrity digest recovery binds into its
// own plan proof. It exposes no rollout path or thread identifier.
func (a *ActionAuthority) Provenance() ([sha256.Size]byte, bool) {
	if !a.valid() {
		return [sha256.Size]byte{}, false
	}
	return a.state.provenance, true
}

// Evaluate applies the four-sample fail-closed detector. A candidate exists
// only when every required positive is proved and no disqualifier is present.
func Evaluate(samples []DeepSample) DetectorResult {
	result := DetectorResult{
		AdapterID:      AdapterID,
		Classification: model.ClassificationUnknown,
		Availability:   model.AvailabilityAvailable,
		Evidence:       []model.EvidenceCode{},
		Codes:          []Code{CodeAdapterExact},
	}
	if len(samples) != len(requiredSampleOffsets) {
		result.Codes = normalizeCodes(append(result.Codes, CodeSampleCountInvalid))
		return result
	}

	var codes []Code
	var availability []model.Availability
	grammars := make([]ProcessGrammar, len(samples))
	allGrammar, allOrigin, allMetadata, allTail, allDescriptor := true, true, true, true, true
	allIdentity, allParent, allUID := true, true, true
	allTTY, allSockets, allWritable, allChildless, allUnprotected := true, true, true, true, true

	for i := range samples {
		sample := &samples[i]
		if sample.Offset != requiredSampleOffsets[i] {
			codes = append(codes, CodeSampleOffsetInvalid)
		}
		if sample.Contradictory {
			codes = append(codes, CodeContradictory)
		}

		availability = append(availability,
			sample.IdentityAvailability,
			sample.ParentAvailability,
			sample.Origin.Availability,
			sample.Origin.Codex.Availability,
			sample.Origin.Node.Availability,
			sample.Origin.Worker.Availability,
			sample.Metadata.Availability,
			sample.Tail.Availability,
			sample.Descriptor.Availability,
			sample.TTY.Availability,
			sample.Sockets.Availability,
			sample.WritableActivity.Availability,
			sample.Children.Availability,
		)

		if sample.IdentityAvailability != model.AvailabilityAvailable || sample.Identity.Validate() != nil {
			codes = append(codes, CodeIdentityUnavailable)
			allIdentity = false
			allUID = false
		}
		if sample.ParentAvailability != model.AvailabilityAvailable || sample.Parent.Validate() != nil {
			codes = append(codes, CodeParentUnavailable)
			if sample.ParentAvailability == model.AvailabilityContradictory {
				codes = append(codes, CodeParentMismatch)
			}
			allParent = false
			allUID = false
		}
		if sample.Identity.UID != sample.CurrentUID || sample.Parent.UID != sample.CurrentUID {
			codes = append(codes, CodeUIDMismatch)
			allUID = false
		}

		grammar, err := NormalizeProcessGrammar(sample.LeafArgv, sample.ParentArgv, sample.TempRoots)
		if err != nil {
			code := codeOf(err, CodeArgvMismatch)
			codes = append(codes, code)
			allGrammar = false
			allOrigin = false
		} else {
			grammars[i] = grammar
			if err := VerifyOrigin(sample.Origin, grammar, sample.CurrentUID); err != nil {
				codes = append(codes, codeOf(err, CodeOriginMismatch))
				allOrigin = false
			}
		}
		if anyContradictory(
			sample.Origin.Availability,
			sample.Origin.Codex.Availability,
			sample.Origin.Node.Availability,
			sample.Origin.Worker.Availability,
		) {
			codes = append(codes, CodeOriginContradictory)
			allOrigin = false
		}

		if sample.MetadataFailure != "" {
			codes = append(codes, sample.MetadataFailure)
			allMetadata = false
		}
		if sample.Metadata.Availability != model.AvailabilityAvailable {
			codes = append(codes, metadataAvailabilityCode(sample.Metadata.Availability))
			allMetadata = false
		} else if !validMetadataSample(sample.Metadata) {
			if sample.Metadata.CLIVersion != SupportedCodexVersion {
				codes = append(codes, CodeVersionMismatch)
			} else {
				codes = append(codes, CodeMetadataValueInvalid)
			}
			allMetadata = false
		}

		if sample.TailFailure != "" {
			codes = append(codes, sample.TailFailure)
			allTail = false
		}
		if sample.Tail.Availability != model.AvailabilityAvailable {
			codes = append(codes, tailAvailabilityCode(sample.Tail.Availability))
			allTail = false
		} else if sample.Tail.EnvelopeType != "event_msg" || sample.Tail.EventType != "task_complete" {
			codes = append(codes, CodeTerminalUnknown)
			allTail = false
		} else if !sample.Tail.Successful {
			codes = append(codes, CodeTerminalFailed)
			allTail = false
		}

		if sample.Descriptor.Availability != model.AvailabilityAvailable {
			codes = append(codes, CodeDescriptorUnavailable)
			if sample.Descriptor.Availability == model.AvailabilityContradictory {
				codes = append(codes, CodeDescriptorMismatch)
			}
			allDescriptor = false
		} else if sample.Descriptor.Access != DescriptorReadOnly {
			codes = append(codes, CodeDescriptorWritable)
			allDescriptor = false
		} else if sample.Descriptor.Path != sample.Metadata.RolloutPath ||
			sample.Descriptor.Device == 0 || sample.Descriptor.Inode == 0 ||
			sample.Descriptor.Device != sample.Tail.File.Device || sample.Descriptor.Inode != sample.Tail.File.Inode {
			codes = append(codes, CodeDescriptorMismatch)
			allDescriptor = false
		}

		if sample.TTY.Availability != model.AvailabilityAvailable {
			codes = append(codes, CodeTTYUnavailable)
			allTTY = false
		} else if sample.TTY.Present {
			codes = append(codes, CodeTTYPresent)
			allTTY = false
		}
		if sample.Sockets.Availability != model.AvailabilityAvailable {
			codes = append(codes, CodeSocketUnavailable)
			allSockets = false
		} else {
			if sample.Sockets.Listeners != 0 {
				codes = append(codes, CodeListenerPresent)
				allSockets = false
			}
			if sample.Sockets.Established != 0 {
				codes = append(codes, CodeEstablishedSocket)
				allSockets = false
			}
		}
		if sample.WritableActivity.Availability != model.AvailabilityAvailable {
			codes = append(codes, CodeWritableProbeUnavailable)
			allWritable = false
		} else if sample.WritableActivity.Present {
			codes = append(codes, CodeWritableActivity)
			allWritable = false
		}
		if sample.Children.Availability != model.AvailabilityAvailable {
			codes = append(codes, CodeChildrenUnavailable)
			allChildless = false
		} else if len(sample.Children.Children) != 0 {
			codes = append(codes, CodeNewChild)
			allChildless = false
		}
		if sample.LeafProtected || sample.ProtectedChildren != 0 {
			codes = append(codes, CodeProtectedIdentity)
			allUnprotected = false
		}
	}

	if transition := identityTransitionCodes(samples); len(transition) != 0 {
		codes = append(codes, transition...)
		allIdentity = false
	}
	if allParent && !allSameParent(samples) {
		codes = append(codes, CodeParentChanged)
		allParent = false
	}
	if allGrammar && !allSameGrammar(grammars) {
		codes = append(codes, CodeArgvMismatch, CodeParentMismatch)
		allGrammar = false
	}
	if allMetadata && !allSameMetadata(samples) {
		codes = append(codes, CodeMetadataChanged)
		allMetadata = false
	}
	if allTail {
		if !allSameTailFile(samples) {
			codes = append(codes, CodeFileChanged)
			allTail = false
		}
		if !allSameTerminalEnvelope(samples) {
			codes = append(codes, CodeTailChanged)
			allTail = false
		}
	}
	if allDescriptor && !allSameDescriptor(samples) {
		codes = append(codes, CodeDescriptorMismatch)
		allDescriptor = false
	}

	cpuIncreasing := true
	for i := 1; i < len(samples); i++ {
		if samples[i].CPUTimeNS <= samples[i-1].CPUTimeNS {
			cpuIncreasing = false
			break
		}
	}
	if !cpuIncreasing {
		codes = append(codes, CodeCPUNotIncreasing)
	}
	finalStack := samples[len(samples)-1].Stack
	stackSupported := finalStack.Availability == model.AvailabilityAvailable &&
		finalStack.Predicate == SupportedStackPredicate && !finalStack.Changed
	cheaperGatesPass := allIdentity && allParent && allUID && allGrammar && allOrigin &&
		allMetadata && allTail && allDescriptor && cpuIncreasing && allTTY && allSockets &&
		allWritable && allChildless && allUnprotected
	if finalStack.Changed {
		if finalStack.Availability != model.AvailabilityAvailable {
			availability = append(availability, finalStack.Availability)
		}
		codes = append(codes, CodeStackChanged)
	} else if finalStack.Availability == model.AvailabilityNotApplicable && !cheaperGatesPass {
		// The stack command is deliberately skipped after any cheaper gate fails.
		// Not-applicable is therefore not an availability failure in this branch.
	} else if finalStack.Availability != model.AvailabilityAvailable {
		availability = append(availability, finalStack.Availability)
		codes = append(codes, CodeStackUnavailable)
	} else if finalStack.Predicate != SupportedStackPredicate {
		codes = append(codes, CodeStackMismatch)
	}

	if allIdentity {
		codes = append(codes, CodeIdentityStable)
	}
	if allParent {
		codes = append(codes, CodeParentIdentityStable)
	}
	if allUID {
		codes = append(codes, CodeUIDExact)
	}
	if allGrammar {
		codes = append(codes, CodeArgvExact, CodeParentExact)
	}
	if allOrigin {
		codes = append(codes, CodeOriginExact)
	}
	if allMetadata {
		codes = append(codes, CodeMetadataComplete, CodeVersionExact)
	}
	if allTail {
		codes = append(codes, CodeRolloutComplete)
	}
	if allTail && allDescriptor {
		codes = append(codes, CodeRolloutUnchanged, CodeDescriptorExact)
	}
	if cpuIncreasing {
		codes = append(codes, CodeCPUIncreasing)
	}
	if stackSupported {
		codes = append(codes, CodeStackSupported)
	}
	if allTTY {
		codes = append(codes, CodeNoTTY)
	}
	if allSockets {
		codes = append(codes, CodeNoListener, CodeNoEstablishedSocket)
	}
	if allWritable {
		codes = append(codes, CodeNoWritableOutput)
	}
	if allChildless {
		codes = append(codes, CodeChildless)
	}
	if allUnprotected {
		codes = append(codes, CodeNoProtectedIdentity)
	}

	result.Codes = normalizeCodes(append(result.Codes, codes...))
	result.Availability = aggregateAvailability(availability)
	if result.Availability == model.AvailabilityAvailable {
		result.Availability = availabilityFromCodes(result.Codes)
	}
	selectable := len(negativeCodes(result.Codes)) == 0 &&
		allIdentity && allParent && allUID && allGrammar && allOrigin && allMetadata && allTail &&
		allDescriptor && cpuIncreasing && stackSupported && allTTY && allSockets && allWritable &&
		allChildless && allUnprotected
	if selectable {
		result.Selectable = true
		result.Classification = model.ClassificationSupportedStaleCandidate
		result.Availability = model.AvailabilityAvailable
		result.Evidence = candidateEvidence()
		last := samples[len(samples)-1]
		baseline := Baseline{
			identity:   last.Identity,
			parent:     last.Parent,
			currentUID: last.CurrentUID,
			grammar:    grammars[len(grammars)-1],
			metadata:   last.Metadata,
			tail:       last.Tail,
			descriptor: last.Descriptor,
		}
		candidate := model.ActionCandidate{
			DetectorID:     AdapterID,
			Classification: model.ClassificationSupportedStaleCandidate,
			Target:         last.Identity,
			Evidence: model.DetectorEvidence{
				Availability: candidateAvailability(),
				Codes:        candidateEvidence(),
			},
		}
		authority := issueActionAuthority(candidate, baseline)
		if authority == nil {
			result.Selectable = false
			result.Classification = model.ClassificationUnknown
			result.Availability = model.AvailabilityContradictory
			result.Evidence = failureEvidence([]Code{CodeContradictory})
			result.Codes = normalizeCodes(append(result.Codes, CodeContradictory))
			return result
		}
		result.Baseline = &baseline
		result.authority = authority
		return result
	}
	result.Evidence = failureEvidence(result.Codes)
	result.Classification = failedClassification(result.Codes)
	return result
}

func validMetadataSample(value MetadataSnapshot) bool {
	return value.Availability == model.AvailabilityAvailable &&
		value.DataVersion >= 0 && value.CLIVersion == SupportedCodexVersion &&
		value.ThreadSource == "subagent" && value.EdgeStatus == "closed" &&
		value.ThreadID != "" && value.ParentThreadID != "" && value.ThreadID != value.ParentThreadID &&
		value.RolloutPath != ""
}

func identityTransitionCodes(samples []DeepSample) []Code {
	if len(samples) == 0 || samples[0].Identity.Validate() != nil {
		return nil
	}
	first := samples[0].Identity
	for i := 1; i < len(samples); i++ {
		current := samples[i].Identity
		if current.Validate() != nil || current.Equal(first) {
			continue
		}
		codes := []Code{CodeIdentityChanged}
		switch {
		case current.PID == first.PID && !current.StartTime.Equal(first.StartTime):
			codes = append(codes, CodePIDReused)
		case current.PID == first.PID && current.StartTime.Equal(first.StartTime) &&
			(current.Executable != first.Executable || current.PIDVersion != first.PIDVersion):
			codes = append(codes, CodeExecChanged)
		}
		return codes
	}
	return nil
}

func allSameParent(samples []DeepSample) bool {
	for i := 1; i < len(samples); i++ {
		if !samples[0].Parent.Equal(samples[i].Parent) {
			return false
		}
	}
	return true
}

func allSameGrammar(values []ProcessGrammar) bool {
	for i := 1; i < len(values); i++ {
		if values[i] != values[0] {
			return false
		}
	}
	return true
}

func allSameMetadata(samples []DeepSample) bool {
	for i := 1; i < len(samples); i++ {
		if !samples[0].Metadata.actionEqual(samples[i].Metadata) {
			return false
		}
	}
	return true
}

func allSameTailFile(samples []DeepSample) bool {
	for i := 1; i < len(samples); i++ {
		if !samples[0].Tail.File.Equal(samples[i].Tail.File) {
			return false
		}
	}
	return true
}

func allSameTerminalEnvelope(samples []DeepSample) bool {
	first := samples[0].Tail
	for i := 1; i < len(samples); i++ {
		current := samples[i].Tail
		if first.Availability != current.Availability ||
			first.EnvelopeType != current.EnvelopeType ||
			first.EventType != current.EventType ||
			first.Successful != current.Successful || first.digest != current.digest {
			return false
		}
	}
	return true
}

func allSameDescriptor(samples []DeepSample) bool {
	for i := 1; i < len(samples); i++ {
		if samples[i].Descriptor != samples[0].Descriptor {
			return false
		}
	}
	return true
}

func candidateEvidence() []model.EvidenceCode {
	values := []model.EvidenceCode{
		model.EvidenceArgvExact,
		model.EvidenceCPUIncreasing,
		model.EvidenceChildless,
		model.EvidenceNoEstablishedSocket,
		model.EvidenceNoListener,
		model.EvidenceNoTTY,
		model.EvidenceNoWritableOutput,
		model.EvidenceOriginExact,
		model.EvidenceParentExact,
		model.EvidenceRolloutComplete,
		model.EvidenceRolloutUnchanged,
		model.EvidenceSupportedReadStack,
		model.EvidenceVersionExact,
	}
	slices.Sort(values)
	return values
}

func candidateAvailability() []model.ProbeAvailability {
	values := []model.ProbeAvailability{
		{Probe: model.ProbeDescriptors, Status: model.AvailabilityAvailable},
		{Probe: model.ProbeExecutable, Status: model.AvailabilityAvailable},
		{Probe: model.ProbeIdentity, Status: model.AvailabilityAvailable},
		{Probe: model.ProbeMetadata, Status: model.AvailabilityAvailable},
		{Probe: model.ProbeOrigin, Status: model.AvailabilityAvailable},
		{Probe: model.ProbeRolloutTail, Status: model.AvailabilityAvailable},
		{Probe: model.ProbeSockets, Status: model.AvailabilityAvailable},
		{Probe: model.ProbeStack, Status: model.AvailabilityAvailable},
		{Probe: model.ProbeTTY, Status: model.AvailabilityAvailable},
	}
	slices.SortFunc(values, func(a, b model.ProbeAvailability) int {
		return compareText(string(a.Probe), string(b.Probe))
	})
	return values
}

func candidateCodes() []Code {
	values := []Code{
		CodeAdapterExact,
		CodeIdentityStable,
		CodeParentIdentityStable,
		CodeUIDExact,
		CodeOriginExact,
		CodeVersionExact,
		CodeArgvExact,
		CodeParentExact,
		CodeMetadataComplete,
		CodeRolloutComplete,
		CodeRolloutUnchanged,
		CodeDescriptorExact,
		CodeCPUIncreasing,
		CodeStackSupported,
		CodeNoTTY,
		CodeNoListener,
		CodeNoEstablishedSocket,
		CodeNoWritableOutput,
		CodeChildless,
		CodeNoProtectedIdentity,
	}
	slices.Sort(values)
	return values
}

func compareText(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func issueActionAuthority(candidate model.ActionCandidate, baseline Baseline) *ActionAuthority {
	if !exactActionCandidate(candidate) || !validAuthorityBaseline(candidate, baseline) {
		return nil
	}
	provenance, err := actionAuthorityProvenance(candidate, baseline)
	if err != nil || provenance == ([sha256.Size]byte{}) {
		return nil
	}
	authority := &ActionAuthority{state: &actionAuthorityState{
		candidate:  cloneActionCandidate(candidate),
		baseline:   baseline,
		provenance: provenance,
	}}
	authority.self = authority
	return authority
}

func (a *ActionAuthority) valid() bool {
	if a == nil || a.self != a || a.state == nil ||
		!exactActionCandidate(a.state.candidate) ||
		!validAuthorityBaseline(a.state.candidate, a.state.baseline) {
		return false
	}
	want, err := actionAuthorityProvenance(a.state.candidate, a.state.baseline)
	return err == nil && want != ([sha256.Size]byte{}) && want == a.state.provenance
}

func exactActionCandidate(candidate model.ActionCandidate) bool {
	if candidate.Validate() != nil || candidate.DetectorID != AdapterID ||
		candidate.Classification != model.ClassificationSupportedStaleCandidate {
		return false
	}
	return slices.Equal(candidate.Evidence.Availability, candidateAvailability()) &&
		slices.Equal(candidate.Evidence.Codes, candidateEvidence())
}

func validAuthorityBaseline(candidate model.ActionCandidate, baseline Baseline) bool {
	return baseline.identity.Validate() == nil && baseline.parent.Validate() == nil &&
		candidate.Target.Equal(baseline.identity) &&
		baseline.identity.UID == baseline.currentUID && baseline.parent.UID == baseline.currentUID &&
		baseline.identity.Executable == baseline.grammar.NodePath &&
		baseline.parent.Executable == baseline.grammar.CodexPath &&
		validMetadataSample(baseline.metadata) &&
		baseline.tail.Availability == model.AvailabilityAvailable &&
		baseline.tail.EnvelopeType == "event_msg" && baseline.tail.EventType == "task_complete" &&
		baseline.tail.Successful &&
		baseline.descriptor.Availability == model.AvailabilityAvailable &&
		baseline.descriptor.Access == DescriptorReadOnly &&
		baseline.descriptor.Path == baseline.metadata.RolloutPath &&
		baseline.descriptor.Device != 0 && baseline.descriptor.Inode != 0 &&
		baseline.descriptor.Device == baseline.tail.File.Device &&
		baseline.descriptor.Inode == baseline.tail.File.Inode
}

func cloneActionCandidate(candidate model.ActionCandidate) model.ActionCandidate {
	cloned := candidate
	cloned.Evidence.Availability = slices.Clone(candidate.Evidence.Availability)
	cloned.Evidence.Codes = slices.Clone(candidate.Evidence.Codes)
	return cloned
}

func baselineEqual(a, b Baseline) bool {
	return a.identity.Equal(b.identity) && a.parent.Equal(b.parent) &&
		a.currentUID == b.currentUID && a.grammar == b.grammar &&
		a.metadata.actionEqual(b.metadata) && a.tail.actionEqual(b.tail) &&
		a.descriptor == b.descriptor
}

func actionAuthorityProvenance(candidate model.ActionCandidate, baseline Baseline) ([sha256.Size]byte, error) {
	candidateJSON, err := model.MarshalDeterministic(candidate)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	h := sha256.New()
	writeAuthorityBytes(h, []byte("runnel-codex-action-authority/v1"))
	writeAuthorityBytes(h, candidateJSON)
	for _, code := range candidateCodes() {
		writeAuthorityBytes(h, []byte(code))
	}
	writeAuthorityIdentity(h, baseline.identity)
	writeAuthorityIdentity(h, baseline.parent)
	writeAuthorityUint64(h, uint64(baseline.currentUID))
	for _, value := range []string{
		baseline.grammar.NodePath,
		baseline.grammar.WorkerPath,
		baseline.grammar.CWD,
		baseline.grammar.CodexPath,
		string(baseline.metadata.Availability),
		baseline.metadata.CLIVersion,
		baseline.metadata.ThreadSource,
		baseline.metadata.EdgeStatus,
		baseline.metadata.ThreadID,
		baseline.metadata.ParentThreadID,
		baseline.metadata.RolloutPath,
		string(baseline.tail.Availability),
		baseline.tail.EnvelopeType,
		baseline.tail.EventType,
		string(baseline.descriptor.Availability),
		baseline.descriptor.Path,
		string(baseline.descriptor.Access),
	} {
		writeAuthorityBytes(h, []byte(value))
	}
	writeAuthorityUint64(h, uint64(baseline.metadata.DataVersion))
	if baseline.tail.Successful {
		writeAuthorityUint64(h, 1)
	} else {
		writeAuthorityUint64(h, 0)
	}
	writeAuthorityUint64(h, baseline.tail.File.Device)
	writeAuthorityUint64(h, baseline.tail.File.Inode)
	writeAuthorityUint64(h, uint64(baseline.tail.File.Size))
	writeAuthorityUint64(h, uint64(baseline.tail.File.ModifiedNS))
	writeAuthorityBytes(h, baseline.tail.digest[:])
	writeAuthorityUint64(h, baseline.descriptor.Device)
	writeAuthorityUint64(h, baseline.descriptor.Inode)
	var proof [sha256.Size]byte
	copy(proof[:], h.Sum(nil))
	return proof, nil
}

func writeAuthorityIdentity(h hash.Hash, identity model.DarwinActionIdentity) {
	writeAuthorityUint64(h, uint64(identity.PID))
	writeAuthorityBytes(h, []byte(identity.StartTime.UTC().Format(time.RFC3339Nano)))
	writeAuthorityUint64(h, uint64(identity.UID))
	writeAuthorityBytes(h, []byte(identity.Executable))
	writeAuthorityUint64(h, uint64(identity.PIDVersion))
	writeAuthorityUint64(h, identity.UniqueID)
}

func writeAuthorityBytes(h hash.Hash, value []byte) {
	writeAuthorityUint64(h, uint64(len(value)))
	_, _ = h.Write(value)
}

func writeAuthorityUint64(h hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = h.Write(encoded[:])
}

func failureEvidence(codes []Code) []model.EvidenceCode {
	var evidence []model.EvidenceCode
	appendOne := func(code model.EvidenceCode) {
		if !slices.Contains(evidence, code) {
			evidence = append(evidence, code)
		}
	}
	switch {
	case slices.Contains(codes, CodePIDReused):
		appendOne(model.EvidencePIDReused)
	case slices.Contains(codes, CodeExecChanged):
		appendOne(model.EvidenceExecChanged)
	case slices.Contains(codes, CodeTailTruncated):
		appendOne(model.EvidenceTailTruncated)
	case slices.Contains(codes, CodeTerminalUnknown):
		appendOne(model.EvidenceUnknownTerminalEvent)
	case slices.Contains(codes, CodeStackChanged):
		appendOne(model.EvidenceStackChanged)
	case slices.Contains(codes, CodeListenerPresent) || slices.Contains(codes, CodeEstablishedSocket):
		appendOne(model.EvidenceSocketPresent)
	case slices.Contains(codes, CodeTTYPresent):
		appendOne(model.EvidenceTTYPresent)
	case slices.Contains(codes, CodeMetadataContradictory) || slices.Contains(codes, CodeContradictory):
		appendOne(model.EvidenceContradictoryOwnership)
	case slices.Contains(codes, CodeOriginContradictory) || slices.Contains(codes, CodeParentMismatch) || slices.Contains(codes, CodeDescriptorMismatch):
		appendOne(model.EvidenceDescriptorMismatch)
	case slices.Contains(codes, CodeCPUIncreasing) && slices.Contains(codes, CodeFileChanged):
		appendOne(model.EvidenceCPUIncreasing)
	}
	slices.Sort(evidence)
	if evidence == nil {
		return []model.EvidenceCode{}
	}
	return evidence
}

func metadataAvailabilityCode(value model.Availability) Code {
	switch value {
	case model.AvailabilitySchemaIncompatible:
		return CodeSchemaIncompatible
	case model.AvailabilityContradictory:
		return CodeMetadataContradictory
	case model.AvailabilityTimeout:
		return CodeReadTimeout
	default:
		return CodeMetadataUnavailable
	}
}

func tailAvailabilityCode(value model.Availability) Code {
	switch value {
	case model.AvailabilityMalformedOutput:
		return CodeTailMalformed
	case model.AvailabilityContradictory:
		return CodeTailChanged
	case model.AvailabilityTimeout:
		return CodeReadTimeout
	default:
		return CodeTailUnavailable
	}
}

func aggregateAvailability(values []model.Availability) model.Availability {
	precedence := []model.Availability{
		model.AvailabilityContradictory,
		model.AvailabilitySchemaIncompatible,
		model.AvailabilityUnsupportedVersion,
		model.AvailabilityPermissionDenied,
		model.AvailabilityUnsupportedPlatform,
		model.AvailabilityProcessExited,
		model.AvailabilityTimeout,
		model.AvailabilityMalformedOutput,
		model.AvailabilityNotApplicable,
	}
	for _, candidate := range precedence {
		if slices.Contains(values, candidate) {
			return candidate
		}
	}
	return model.AvailabilityAvailable
}

func availabilityFromCodes(codes []Code) model.Availability {
	if slices.Contains(codes, CodeContradictory) || slices.Contains(codes, CodeMetadataContradictory) || slices.Contains(codes, CodeMetadataUnstable) {
		return model.AvailabilityContradictory
	}
	if slices.Contains(codes, CodeSchemaIncompatible) {
		return model.AvailabilitySchemaIncompatible
	}
	if slices.Contains(codes, CodeVersionMismatch) {
		return model.AvailabilityUnsupportedVersion
	}
	if slices.Contains(codes, CodeReadTimeout) {
		return model.AvailabilityTimeout
	}
	if slices.Contains(codes, CodeTailMalformed) {
		return model.AvailabilityMalformedOutput
	}
	return model.AvailabilityAvailable
}

func anyContradictory(values ...model.Availability) bool {
	return slices.Contains(values, model.AvailabilityContradictory)
}

func negativeCodes(codes []Code) []Code {
	positive := map[Code]bool{
		CodeAdapterExact: true, CodeIdentityStable: true, CodeParentIdentityStable: true,
		CodeUIDExact: true, CodeOriginExact: true, CodeVersionExact: true,
		CodeArgvExact: true, CodeParentExact: true, CodeMetadataComplete: true,
		CodeRolloutComplete: true, CodeRolloutUnchanged: true, CodeDescriptorExact: true,
		CodeCPUIncreasing: true, CodeStackSupported: true, CodeNoTTY: true,
		CodeNoListener: true, CodeNoEstablishedSocket: true, CodeNoWritableOutput: true,
		CodeChildless: true, CodeNoProtectedIdentity: true, CodeActionRecheckExact: true,
	}
	var result []Code
	for _, code := range codes {
		if !positive[code] {
			result = append(result, code)
		}
	}
	return result
}

func failedClassification(codes []Code) model.Classification {
	if slices.Contains(codes, CodeProtectedIdentity) || slices.Contains(codes, CodeTTYPresent) {
		return model.ClassificationProtected
	}
	if slices.Contains(codes, CodeContradictory) || slices.Contains(codes, CodeMetadataContradictory) {
		return model.ClassificationUnknown
	}
	for _, code := range []Code{CodeWritableActivity, CodeNewChild, CodeFileChanged} {
		if slices.Contains(codes, code) {
			return model.ClassificationRecentlyActive
		}
	}
	for _, code := range []Code{CodeCPUNotIncreasing, CodeStackMismatch} {
		if slices.Contains(codes, code) {
			return model.ClassificationQuietUnclassified
		}
	}
	return model.ClassificationUnknown
}
