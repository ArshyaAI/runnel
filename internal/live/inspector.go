package live

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ArshyaAI/runnel/internal/codex"
	"github.com/ArshyaAI/runnel/internal/model"
	"github.com/ArshyaAI/runnel/internal/platform/darwin"
)

var sampleOffsets = [...]time.Duration{0, 2 * time.Second, 4 * time.Second, 6 * time.Second}

// Inspector schedules and composes only read-only capabilities.
type Inspector struct {
	options Options
	deps    Dependencies
}

// New builds an injected inspector. Temp roots are mandatory, explicit, and
// canonical; no environment or /tmp inference is permitted.
func New(options Options, deps Dependencies) (*Inspector, error) {
	if deps.Platform == nil || deps.State == nil || deps.Tail == nil || deps.Clock == nil ||
		deps.Sleeper == nil || deps.Protection == nil || options.StatePath == nil {
		return nil, safeError(CodeInvalidConfig, nil)
	}
	if len(options.TempRoots) == 0 {
		return nil, safeError(CodeInvalidConfig, nil)
	}
	seenRoots := make(map[string]struct{}, len(options.TempRoots))
	for _, root := range options.TempRoots {
		if !canonicalAbsolute(root) {
			return nil, safeError(CodeInvalidConfig, nil)
		}
		if _, exists := seenRoots[root]; exists {
			return nil, safeError(CodeInvalidConfig, nil)
		}
		seenRoots[root] = struct{}{}
	}
	if err := validateProtected(options.Protected); err != nil {
		return nil, safeError(CodeInvalidConfig, err)
	}
	options.TempRoots = slices.Clone(options.TempRoots)
	options.Protected = slices.Clone(options.Protected)
	return &Inspector{options: options, deps: deps}, nil
}

type collectedSample struct {
	deep        codex.DeepSample
	pair        PairObservation
	rolloutPath string
	protected   []model.DarwinActionIdentity
	code        Code
}

// Discover performs exactly one host-wide process enumeration through the
// injected read-only platform and returns safe metadata plus opaque candidates.
// It does not resolve state, read argv, or open SQLite.
func (i *Inspector) Discover(ctx context.Context) (Discovery, error) {
	if i == nil || i.deps.Platform == nil {
		return Discovery{
			Availability: model.AvailabilityContradictory,
			Code:         CodeDiscoveryUnavailable,
			candidates:   []Candidate{},
		}, safeError(CodeInvalidConfig, nil)
	}
	snapshot, err := i.deps.Platform.Processes(ctx)
	if err != nil {
		return Discovery{
			Availability: availabilityFromError(err),
			Code:         CodeDiscoveryUnavailable,
			candidates:   []Candidate{},
		}, safeError(CodeDiscoveryUnavailable, err)
	}
	return Discover(snapshot), nil
}

// Inspect runs one exact 0/2/4/6-second evidence window. Candidate is opaque;
// there is intentionally no InspectPID variant.
func (i *Inspector) Inspect(ctx context.Context, candidate Candidate) (Finding, error) {
	if i == nil || !candidate.valid() {
		return Finding{}, safeError(CodeInvalidCandidate, nil)
	}
	statePath, err := i.options.StatePath.Resolve()
	if err != nil || !validStatePath(statePath) {
		return failedFinding(CodeStatePathUnavailable), safeError(CodeStatePathUnavailable, err)
	}
	sessionsRoot := filepath.Join(filepath.Dir(statePath), "sessions")
	if !canonicalAbsolute(sessionsRoot) {
		return failedFinding(CodeStatePathUnavailable), safeError(CodeStatePathUnavailable, nil)
	}

	store, storeErr := i.deps.State.Open(ctx, statePath)
	if store != nil {
		openedStore := store
		defer func() { _ = openedStore.Close() }()
	}
	firstCode := CodeOK
	if storeErr != nil || store == nil {
		firstCode = CodeStateStoreUnavailable
		store = nil
	}

	started := i.deps.Clock.Now()
	collected := make([]collectedSample, 0, len(sampleOffsets))
	deep := make([]codex.DeepSample, 0, len(sampleOffsets))
	for _, offset := range sampleOffsets {
		if err := i.waitUntil(ctx, started.Add(offset)); err != nil {
			code := CodeScheduleUnavailable
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				code = CodeContextCancelled
			}
			finding := partialFinding(code, deep)
			return finding, safeError(code, err)
		}
		current := i.collectCheap(ctx, candidate, offset, sessionsRoot, store)
		collected = append(collected, current)
		deep = append(deep, current.deep)
		if firstCode == CodeOK && current.code != CodeOK {
			firstCode = current.code
		}
	}

	preflight := codex.Evaluate(deep)
	stackAttempted := false
	if cheaperGatesPass(preflight) {
		stackAttempted = true
		last := &collected[len(collected)-1]
		report, stackErr := i.deps.Platform.Stack(ctx, candidate, last.pair)
		last.deep.Stack = codex.StackEvidenceFromDarwin(report)
		if stackErr != nil {
			last.deep.Stack.Availability = availabilityFromError(stackErr)
			if errors.Is(stackErr, darwin.ErrIdentityMismatch) {
				last.deep.Stack.Changed = true
			}
			if firstCode == CodeOK {
				firstCode = CodeStackUnavailable
			}
		}
		after, afterErr := i.deps.Platform.Pair(ctx, candidate)
		if afterErr != nil || !pairExact(candidate, after) || !samePair(last.pair, after) {
			last.deep.Stack.Changed = true
			if afterErr != nil {
				last.deep.Stack.Availability = availabilityFromError(afterErr)
			} else {
				last.deep.Stack.Availability = model.AvailabilityContradictory
			}
			if firstCode == CodeOK {
				firstCode = CodeContradictory
			}
		}
		deep[len(deep)-1] = last.deep
	} else if firstCode == CodeOK {
		firstCode = CodeStackSkipped
	}

	result := codex.Evaluate(deep)
	if result.Selectable {
		firstCode = CodeOK
	} else if firstCode == CodeOK {
		firstCode = CodeContradictory
	}
	report := Report{
		Availability:     result.Availability,
		Code:             firstCode,
		CompletedSamples: len(deep),
		StackAttempted:   stackAttempted,
		Detector:         result,
	}
	finding := Finding{report: report}
	if result.Selectable {
		last := collected[len(collected)-1]
		finding.context = &RecoveryContext{
			candidate: candidate, detector: result,
			leaf: last.deep.Identity, parent: last.deep.Parent,
			currentUID: i.options.CurrentUID, tempRoots: slices.Clone(i.options.TempRoots),
			statePath: statePath, rolloutPath: last.rolloutPath,
			protected: slices.Clone(last.protected), rssBytes: last.deep.RSSBytes,
		}
	}
	return finding, nil
}

func (i *Inspector) waitUntil(ctx context.Context, target time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	remaining := target.Sub(i.deps.Clock.Now())
	if remaining > 0 {
		if err := i.deps.Sleeper.Sleep(ctx, remaining); err != nil {
			return err
		}
	}
	if i.deps.Clock.Now().Before(target) {
		return safeError(CodeScheduleUnavailable, nil)
	}
	return ctx.Err()
}

func (i *Inspector) collectCheap(ctx context.Context, candidate Candidate, offset time.Duration, sessionsRoot string, store MetadataStore) collectedSample {
	out := collectedSample{deep: unavailableSample(offset, i.options.CurrentUID, i.options.TempRoots), code: CodeOK}

	snapshot, snapshotErr := i.deps.Platform.Processes(ctx)
	snapshotOK := snapshotErr == nil && exactSnapshotAvailable(snapshot)
	if !snapshotOK {
		out.code = CodeProcessTreeUnavailable
	}

	pair, pairErr := i.deps.Platform.Pair(ctx, candidate)
	out.pair = pair
	if pairErr != nil {
		availability := availabilityFromError(pairErr)
		out.deep.IdentityAvailability = availability
		out.deep.ParentAvailability = availability
		out.code = firstFailure(out.code, CodeIdentityUnavailable)
	} else {
		out.deep.Identity = pair.Leaf
		out.deep.Parent = pair.Parent
		out.deep.IdentityAvailability = model.AvailabilityAvailable
		out.deep.ParentAvailability = model.AvailabilityAvailable
		if !pairExact(candidate, pair) {
			out.deep.Contradictory = true
			out.deep.IdentityAvailability = model.AvailabilityContradictory
			out.deep.ParentAvailability = model.AvailabilityContradictory
			out.code = firstFailure(out.code, CodeContradictory)
		}
	}

	var children []darwin.ProcessRecord
	treeExact := false
	pairUsable := pairErr == nil && pairExact(candidate, pair)
	if snapshotOK && pairUsable {
		leafRecord, _, treeErr := exactTreeFacts(snapshot, pair)
		if treeErr != nil {
			out.deep.TTY.Availability = model.AvailabilityContradictory
			out.deep.Contradictory = true
			out.code = firstFailure(out.code, CodeProcessTreeUnavailable)
		} else {
			treeExact = true
			out.deep.CPUTimeNS = leafRecord.Observation.CPUTimeNS
			out.deep.RSSBytes = leafRecord.Observation.RSSBytes
			ttyAvailability := observationAvailability(leafRecord.Observation, model.ProbeTTY)
			out.deep.TTY = codex.PresenceProbe{
				Availability: ttyAvailability,
				Present:      leafRecord.Observation.TTY != "",
			}
			if ttyAvailability != model.AvailabilityAvailable {
				out.code = firstFailure(out.code, CodeProcessTreeUnavailable)
			}
		}
	}
	if pairUsable {
		childSnapshot, childErr := i.deps.Platform.Children(ctx, candidate, pair)
		if childErr != nil || !exactChildSnapshot(childSnapshot, pair.Leaf) {
			availability := availabilityFromError(childErr)
			if childErr == nil {
				availability = model.AvailabilityContradictory
			}
			out.deep.Children.Availability = availability
			out.code = firstFailure(out.code, CodeProcessTreeUnavailable)
		} else {
			children = slices.Clone(childSnapshot.Children)
			portable := make([]model.ProcessIdentity, 0, len(children))
			for _, child := range children {
				portable = append(portable, child.Observation.Identity)
			}
			out.deep.Children = codex.ChildrenProbe{
				Availability: model.AvailabilityAvailable,
				Children:     portable,
			}
		}
	}

	if treeExact && pairUsable && out.deep.Children.Availability == model.AvailabilityAvailable {
		protection, protectionErr := i.deps.Protection.Observe(snapshot, candidate, pair, children)
		if protectionErr != nil || protection.Availability != model.AvailabilityAvailable ||
			!validProtection(protection, pair, children) {
			out.deep.Contradictory = true
			out.code = firstFailure(out.code, CodeProtectionUnavailable)
		} else {
			out.deep.LeafProtected = protection.LeafProtected
			out.deep.ProtectedChildren = protection.ProtectedChildren
			out.protected = slices.Clone(protection.Protected)
		}
	}

	if pairUsable {
		origin, originErr := i.deps.Platform.Origin(ctx, candidate, pair, i.options.CurrentUID, i.options.TempRoots)
		out.deep.Origin = origin.Origin
		out.deep.LeafArgv = slices.Clone(origin.LeafArgv)
		out.deep.ParentArgv = slices.Clone(origin.ParentArgv)
		if originErr != nil {
			availability := availabilityFromError(originErr)
			if out.deep.Origin.Availability == "" {
				out.deep.Origin.Availability = availability
			}
			if out.deep.Origin.Codex.Availability == "" {
				out.deep.Origin.Codex.Availability = availability
			}
			if out.deep.Origin.Node.Availability == "" {
				out.deep.Origin.Node.Availability = availability
			}
			if out.deep.Origin.Worker.Availability == "" {
				out.deep.Origin.Worker.Availability = availability
			}
			out.code = firstFailure(out.code, CodeOriginUnavailable)
		}

		rawDescriptors, descriptorErr := i.deps.Platform.Descriptors(ctx, candidate, pair)
		if descriptorErr != nil {
			out.deep.Descriptor.Availability = availabilityFromError(descriptorErr)
			out.deep.Sockets.Availability = availabilityFromError(descriptorErr)
			out.deep.WritableActivity.Availability = availabilityFromError(descriptorErr)
			out.code = firstFailure(out.code, CodeDescriptorUnavailable)
		} else {
			selected, selectCode, selectErr := selectRolloutDescriptor(rawDescriptors, pair.Leaf, sessionsRoot)
			if selectErr != nil {
				out.deep.Descriptor.Availability = model.AvailabilityContradictory
				out.deep.Sockets.Availability = model.AvailabilityContradictory
				out.deep.WritableActivity.Availability = model.AvailabilityContradictory
				out.code = firstFailure(out.code, selectCode)
			} else {
				out.rolloutPath = selected.Path
				descriptor, evidenceErr := i.deps.Platform.DescriptorEvidence(ctx, candidate, pair, selected.Path)
				out.deep.Descriptor = descriptor.Descriptor
				out.deep.Sockets = descriptor.Sockets
				out.deep.WritableActivity = descriptor.WritableActivity
				if evidenceErr != nil {
					availability := availabilityFromError(evidenceErr)
					if out.deep.Descriptor.Availability == "" {
						out.deep.Descriptor.Availability = availability
					}
					if out.deep.Sockets.Availability == "" {
						out.deep.Sockets.Availability = availability
					}
					if out.deep.WritableActivity.Availability == "" {
						out.deep.WritableActivity.Availability = availability
					}
					out.code = firstFailure(out.code, CodeDescriptorUnavailable)
				} else if descriptor.Availability != model.AvailabilityAvailable || descriptor.Descriptor != selected {
					out.deep.Descriptor.Availability = model.AvailabilityContradictory
					out.deep.Contradictory = true
					out.code = firstFailure(out.code, CodeContradictory)
				}
			}
		}
	}

	if out.rolloutPath != "" && out.deep.Descriptor.Availability == model.AvailabilityAvailable {
		if store == nil {
			out.deep.Metadata.Availability = model.AvailabilityContradictory
			out.deep.MetadataFailure = codex.CodeMetadataUnavailable
			out.code = firstFailure(out.code, CodeMetadataUnavailable)
		} else {
			metadata, metadataErr := store.Snapshot(ctx, out.rolloutPath)
			out.deep.Metadata = metadata
			if metadataErr != nil {
				out.deep.Metadata.Availability = availabilityFromError(metadataErr)
				out.deep.MetadataFailure = codexErrorCode(metadataErr, codex.CodeMetadataUnavailable)
				out.code = firstFailure(out.code, CodeMetadataUnavailable)
			} else if metadata.RolloutPath != out.rolloutPath {
				out.deep.Metadata.Availability = model.AvailabilityContradictory
				out.deep.MetadataFailure = codex.CodeMetadataContradictory
				out.deep.Contradictory = true
				out.code = firstFailure(out.code, CodeContradictory)
			}
		}
	}

	if out.deep.Metadata.Availability == model.AvailabilityAvailable && out.deep.MetadataFailure == "" {
		tail, tailErr := i.deps.Tail.Read(ctx, out.rolloutPath, out.deep.Descriptor)
		out.deep.Tail = tail
		if tailErr != nil {
			out.deep.Tail.Availability = availabilityFromError(tailErr)
			out.deep.TailFailure = codexErrorCode(tailErr, codex.CodeTailUnavailable)
			out.code = firstFailure(out.code, CodeTailUnavailable)
		}
	}

	if pairErr == nil {
		after, afterErr := i.deps.Platform.Pair(ctx, candidate)
		if afterErr != nil || !pairExact(candidate, after) || !samePair(pair, after) {
			out.deep.Contradictory = true
			out.deep.IdentityAvailability = model.AvailabilityContradictory
			out.deep.ParentAvailability = model.AvailabilityContradictory
			out.code = firstFailure(out.code, CodeContradictory)
		}
	}
	return out
}

func unavailableSample(offset time.Duration, uid uint32, tempRoots []string) codex.DeepSample {
	na := model.AvailabilityNotApplicable
	return codex.DeepSample{
		Offset: offset, CurrentUID: uid, TempRoots: slices.Clone(tempRoots),
		IdentityAvailability: na, ParentAvailability: na,
		Origin: codex.OriginEvidence{
			Availability: na,
			Codex:        codex.SignedArtifact{Availability: na},
			Node:         codex.SignedArtifact{Availability: na},
			Worker:       codex.HashedArtifact{Availability: na},
		},
		Metadata:         codex.MetadataSnapshot{Availability: na},
		Tail:             codex.TailSnapshot{Availability: na},
		Descriptor:       codex.DescriptorEvidence{Availability: na},
		TTY:              codex.PresenceProbe{Availability: na},
		Sockets:          codex.SocketProbe{Availability: na},
		WritableActivity: codex.PresenceProbe{Availability: na},
		Children:         codex.ChildrenProbe{Availability: na},
		Stack:            codex.StackEvidence{Availability: na},
	}
}

func pairExact(candidate Candidate, pair PairObservation) bool {
	return pair.Leaf.Validate() == nil && pair.Parent.Validate() == nil &&
		pair.Leaf.Equal(candidate.leaf) && pair.Parent.Equal(candidate.parent)
}

func samePair(a, b PairObservation) bool { return a.Leaf.Equal(b.Leaf) && a.Parent.Equal(b.Parent) }

func exactTreeFacts(snapshot darwin.ProcessSnapshot, pair PairObservation) (darwin.ProcessRecord, darwin.ProcessRecord, error) {
	leaf, err := uniqueExactRecord(snapshot, pair.Leaf.PID)
	if err != nil {
		return darwin.ProcessRecord{}, darwin.ProcessRecord{}, err
	}
	parent, err := uniqueExactRecord(snapshot, pair.Parent.PID)
	if err != nil {
		return darwin.ProcessRecord{}, darwin.ProcessRecord{}, err
	}
	if !leaf.ActionIdentity.Equal(pair.Leaf) || !parent.ActionIdentity.Equal(pair.Parent) ||
		leaf.Observation.ParentPID != pair.Parent.PID {
		return darwin.ProcessRecord{}, darwin.ProcessRecord{}, errors.New("pair absent from exact tree")
	}
	return leaf, parent, nil
}

func exactChildSnapshot(snapshot darwin.ChildSnapshot, identity model.DarwinActionIdentity) bool {
	if snapshot.Availability != model.AvailabilityAvailable || snapshot.Truncated || len(snapshot.Failures) != 0 ||
		!snapshot.Identity.Equal(identity) || snapshot.Children == nil {
		return false
	}
	seen := make(map[int32]struct{}, len(snapshot.Children))
	for _, child := range snapshot.Children {
		if !exactActionRecord(child) || child.Observation.ParentPID != identity.PID {
			return false
		}
		pid := child.ActionIdentity.PID
		if _, exists := seen[pid]; exists {
			return false
		}
		seen[pid] = struct{}{}
	}
	return true
}

func uniqueExactRecord(snapshot darwin.ProcessSnapshot, pid int32) (darwin.ProcessRecord, error) {
	if failurePIDs(snapshot.Failures)[pid] {
		return darwin.ProcessRecord{}, errors.New("relevant process detail unavailable")
	}
	var found darwin.ProcessRecord
	count := 0
	for _, record := range snapshot.Processes {
		if record.Observation.Identity.PID != pid {
			continue
		}
		found = record
		count++
	}
	if count != 1 || !exactActionRecord(found) {
		return darwin.ProcessRecord{}, errors.New("relevant process identity ambiguous")
	}
	return found, nil
}

func observationAvailability(observation model.ProcessObservation, probe model.ProbeKind) model.Availability {
	count := 0
	status := model.AvailabilityContradictory
	for _, value := range observation.Availability {
		if value.Probe == probe {
			count++
			status = value.Status
		}
	}
	if count != 1 || !status.Valid() {
		return model.AvailabilityContradictory
	}
	return status
}

func validProtection(value ProtectionObservation, pair PairObservation, children []darwin.ProcessRecord) bool {
	if value.Protected == nil {
		return false
	}
	for index, identity := range value.Protected {
		if identity.Validate() != nil || index > 0 && !identityOrder(value.Protected[index-1], identity) {
			return false
		}
	}
	if value.LeafProtected != containsIdentity(value.Protected, pair.Leaf) {
		return false
	}
	var protectedChildren uint32
	for _, child := range children {
		if slices.ContainsFunc(value.Protected, func(identity model.DarwinActionIdentity) bool {
			return identity.Equal(child.ActionIdentity)
		}) {
			protectedChildren++
		}
	}
	return value.ProtectedChildren == protectedChildren
}

func exactSnapshotAvailable(snapshot darwin.ProcessSnapshot) bool {
	return snapshot.Availability == model.AvailabilityAvailable && !snapshot.Truncated
}

func identityOrder(a, b model.DarwinActionIdentity) bool {
	if a.PID != b.PID {
		return a.PID < b.PID
	}
	if !a.StartTime.Equal(b.StartTime) {
		return a.StartTime.Before(b.StartTime)
	}
	if a.PIDVersion != b.PIDVersion {
		return a.PIDVersion < b.PIDVersion
	}
	return a.UniqueID < b.UniqueID
}

func selectRolloutDescriptor(snapshot darwin.DescriptorSnapshot, identity model.DarwinActionIdentity, sessionsRoot string) (codex.DescriptorEvidence, Code, error) {
	if snapshot.Availability != model.AvailabilityAvailable || snapshot.Truncated || !snapshot.Identity.Equal(identity) {
		return codex.DescriptorEvidence{}, CodeDescriptorUnavailable, errors.New("descriptor snapshot unavailable")
	}
	matches := make([]codex.DescriptorEvidence, 0, 2)
	for _, descriptor := range snapshot.Descriptors {
		if descriptor.Availability != model.AvailabilityAvailable {
			return codex.DescriptorEvidence{}, CodeDescriptorUnavailable, errors.New("descriptor detail unavailable")
		}
		if descriptor.File == nil || descriptor.File.Writable || !validRolloutPath(descriptor.File.Path, sessionsRoot) {
			continue
		}
		if descriptor.File.Device == 0 || descriptor.File.Inode == 0 {
			return codex.DescriptorEvidence{}, CodeDescriptorUnavailable, errors.New("descriptor identity incomplete")
		}
		matches = append(matches, codex.DescriptorEvidence{
			Availability: model.AvailabilityAvailable,
			Path:         descriptor.File.Path, Device: descriptor.File.Device, Inode: descriptor.File.Inode,
			Access: codex.DescriptorReadOnly,
		})
	}
	if len(matches) != 1 {
		return codex.DescriptorEvidence{}, CodeDescriptorAmbiguous, errors.New("rollout descriptor count is not one")
	}
	return matches[0], CodeOK, nil
}

func validStatePath(path string) bool {
	return canonicalAbsolute(path) && filepath.Base(path) == "state_5.sqlite" &&
		filepath.Base(filepath.Dir(path)) == ".codex"
}

func validRolloutPath(path, sessionsRoot string) bool {
	if !canonicalAbsolute(path) || !canonicalAbsolute(sessionsRoot) {
		return false
	}
	relative, err := filepath.Rel(sessionsRoot, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false
	}
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if len(parts) != 4 || len(parts[0]) != 4 || len(parts[1]) != 2 || len(parts[2]) != 2 {
		return false
	}
	base := parts[3]
	if !strings.HasPrefix(base, "rollout-") || !strings.HasSuffix(base, ".jsonl") {
		return false
	}
	stem := strings.TrimSuffix(strings.TrimPrefix(base, "rollout-"), ".jsonl")
	if len(stem) != len("2006-01-02T15-04-05-")+36 {
		return false
	}
	stamp := stem[:len("2006-01-02T15-04-05")]
	parsed, err := time.Parse("2006-01-02T15-04-05", stamp)
	if err != nil || parsed.Format("2006") != parts[0] || parsed.Format("01") != parts[1] || parsed.Format("02") != parts[2] {
		return false
	}
	return validLowerUUID(stem[len("2006-01-02T15-04-05-"):])
}

func validLowerUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, char := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if char != '-' {
				return false
			}
			continue
		}
		if !(char >= '0' && char <= '9') && !(char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func cheaperGatesPass(result codex.DetectorResult) bool {
	expected := []codex.Code{
		codex.CodeAdapterExact, codex.CodeArgvExact, codex.CodeChildless,
		codex.CodeCPUIncreasing, codex.CodeDescriptorExact, codex.CodeIdentityStable,
		codex.CodeMetadataComplete, codex.CodeNoEstablishedSocket, codex.CodeNoListener,
		codex.CodeNoProtectedIdentity, codex.CodeNoTTY, codex.CodeNoWritableOutput,
		codex.CodeOriginExact, codex.CodeParentExact, codex.CodeParentIdentityStable,
		codex.CodeRolloutComplete, codex.CodeRolloutUnchanged, codex.CodeStackUnavailable,
		codex.CodeUIDExact, codex.CodeVersionExact,
	}
	slices.Sort(expected)
	return result.Availability == model.AvailabilityNotApplicable && slices.Equal(result.Codes, expected)
}

func availabilityFromError(err error) model.Availability {
	if err == nil {
		return model.AvailabilityAvailable
	}
	var operation *darwin.OperationError
	if errors.As(err, &operation) && operation.Availability.Valid() {
		return operation.Availability
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return model.AvailabilityTimeout
	}
	var safe *codex.SafeError
	if errors.As(err, &safe) {
		switch safe.Code {
		case codex.CodeSchemaIncompatible:
			return model.AvailabilitySchemaIncompatible
		case codex.CodeVersionMismatch:
			return model.AvailabilityUnsupportedVersion
		case codex.CodeReadTimeout, codex.CodeContextCancelled:
			return model.AvailabilityTimeout
		case codex.CodeTailMalformed:
			return model.AvailabilityMalformedOutput
		case codex.CodeMetadataContradictory, codex.CodeOriginContradictory,
			codex.CodeDescriptorMismatch, codex.CodeMetadataUnstable, codex.CodeContradictory:
			return model.AvailabilityContradictory
		}
	}
	return model.AvailabilityContradictory
}

func codexErrorCode(err error, fallback codex.Code) codex.Code {
	var safe *codex.SafeError
	if errors.As(err, &safe) {
		return safe.Code
	}
	return fallback
}

func firstFailure(current, next Code) Code {
	if current == CodeOK {
		return next
	}
	return current
}

func failedFinding(code Code) Finding {
	result := codex.Evaluate(nil)
	return Finding{report: Report{
		Availability: model.AvailabilityContradictory,
		Code:         code, Detector: result,
	}}
}

func partialFinding(code Code, samples []codex.DeepSample) Finding {
	result := codex.Evaluate(samples)
	availability := model.AvailabilityContradictory
	if code == CodeContextCancelled {
		availability = model.AvailabilityTimeout
	}
	return Finding{report: Report{
		Availability: availability, Code: code,
		CompletedSamples: len(samples), Detector: result,
	}}
}
