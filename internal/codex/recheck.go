package codex

import (
	"context"

	"github.com/ArshyaAI/runnel/internal/model"
)

type MetadataReader interface {
	Snapshot(context.Context, string) (MetadataSnapshot, error)
}

type CompletionTailReader interface {
	Read(context.Context, string, DescriptorEvidence) (TailSnapshot, error)
}

type ActionRecheckRequest struct {
	IdentityAvailability model.Availability
	Identity             model.DarwinActionIdentity
	ParentAvailability   model.Availability
	Parent               model.DarwinActionIdentity
	CurrentUID           uint32
	LeafArgv             []string
	ParentArgv           []string
	TempRoots            []string
	Origin               OriginEvidence
	Descriptor           DescriptorEvidence
	TTY                  PresenceProbe
	Sockets              SocketProbe
	WritableActivity     PresenceProbe
	Children             ChildrenProbe
	LeafProtected        bool
	ProtectedChildren    uint32
}

type RecheckResult struct {
	Allowed      bool               `json:"allowed"`
	Availability model.Availability `json:"availability"`
	Codes        []Code             `json:"codes"`
}

// Recheck repeats all cheap identity/origin/grammar/activity gates plus a new
// stable SQLite row and descriptor-bound completion-tail read. It has no
// signaling capability.
func Recheck(
	ctx context.Context,
	result DetectorResult,
	request ActionRecheckRequest,
	metadata MetadataReader,
	tails CompletionTailReader,
) RecheckResult {
	response := RecheckResult{Availability: model.AvailabilityAvailable, Codes: []Code{}}
	if !result.Selectable || result.Baseline == nil || metadata == nil || tails == nil {
		response.Codes = []Code{CodeContradictory}
		response.Availability = model.AvailabilityContradictory
		return response
	}
	baseline := result.Baseline
	var codes []Code
	var availability []model.Availability

	availability = append(availability,
		request.IdentityAvailability,
		request.ParentAvailability,
		request.Origin.Availability,
		request.Descriptor.Availability,
		request.TTY.Availability,
		request.Sockets.Availability,
		request.WritableActivity.Availability,
		request.Children.Availability,
	)
	if request.IdentityAvailability != model.AvailabilityAvailable || request.Identity.Validate() != nil {
		codes = append(codes, CodeIdentityUnavailable)
	} else if !request.Identity.Equal(baseline.identity) {
		codes = append(codes, CodeIdentityChanged)
	}
	if request.ParentAvailability != model.AvailabilityAvailable || request.Parent.Validate() != nil {
		codes = append(codes, CodeParentUnavailable)
	} else if !request.Parent.Equal(baseline.parent) {
		codes = append(codes, CodeParentChanged)
	}
	if request.CurrentUID != baseline.currentUID || request.Identity.UID != request.CurrentUID || request.Parent.UID != request.CurrentUID {
		codes = append(codes, CodeUIDMismatch)
	}
	grammar, err := NormalizeProcessGrammar(request.LeafArgv, request.ParentArgv, request.TempRoots)
	if err != nil {
		codes = append(codes, codeOf(err, CodeArgvMismatch))
	} else if grammar != baseline.grammar {
		codes = append(codes, CodeArgvMismatch, CodeParentMismatch)
	} else if err := VerifyOrigin(request.Origin, grammar, request.CurrentUID); err != nil {
		codes = append(codes, codeOf(err, CodeOriginMismatch))
	}
	if request.Descriptor.Availability != model.AvailabilityAvailable {
		codes = append(codes, CodeDescriptorUnavailable)
	} else if request.Descriptor.Access != DescriptorReadOnly {
		codes = append(codes, CodeDescriptorWritable)
	} else if request.Descriptor != baseline.descriptor {
		codes = append(codes, CodeDescriptorMismatch)
	}
	if request.TTY.Availability != model.AvailabilityAvailable {
		codes = append(codes, CodeTTYUnavailable)
	} else if request.TTY.Present {
		codes = append(codes, CodeTTYPresent)
	}
	if request.Sockets.Availability != model.AvailabilityAvailable {
		codes = append(codes, CodeSocketUnavailable)
	} else {
		if request.Sockets.Listeners != 0 {
			codes = append(codes, CodeListenerPresent)
		}
		if request.Sockets.Established != 0 {
			codes = append(codes, CodeEstablishedSocket)
		}
	}
	if request.WritableActivity.Availability != model.AvailabilityAvailable {
		codes = append(codes, CodeWritableProbeUnavailable)
	} else if request.WritableActivity.Present {
		codes = append(codes, CodeWritableActivity)
	}
	if request.Children.Availability != model.AvailabilityAvailable {
		codes = append(codes, CodeChildrenUnavailable)
	} else if len(request.Children.Children) != 0 {
		codes = append(codes, CodeNewChild)
	}
	if request.LeafProtected || request.ProtectedChildren != 0 {
		codes = append(codes, CodeProtectedIdentity)
	}

	freshMetadata, metadataErr := metadata.Snapshot(ctx, baseline.metadata.RolloutPath)
	if metadataErr != nil {
		codes = append(codes, codeOf(metadataErr, CodeMetadataUnavailable))
	} else {
		availability = append(availability, freshMetadata.Availability)
		if !freshMetadata.actionEqual(baseline.metadata) {
			codes = append(codes, CodeMetadataChanged)
		}
	}
	freshTail, tailErr := tails.Read(ctx, baseline.metadata.RolloutPath, request.Descriptor)
	if tailErr != nil {
		codes = append(codes, codeOf(tailErr, CodeTailUnavailable))
	} else {
		availability = append(availability, freshTail.Availability)
		if !freshTail.actionEqual(baseline.tail) {
			codes = append(codes, CodeTailChanged)
		}
	}

	response.Codes = normalizeCodes(codes)
	response.Availability = aggregateAvailability(availability)
	if response.Availability == model.AvailabilityAvailable {
		response.Availability = availabilityFromCodes(response.Codes)
	}
	if len(response.Codes) == 0 {
		response.Allowed = true
		response.Codes = []Code{CodeActionRecheckExact}
		response.Availability = model.AvailabilityAvailable
	}
	return response
}
