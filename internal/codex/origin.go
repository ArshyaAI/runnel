package codex

import (
	"strings"

	"github.com/ArshyaAI/runnel/internal/model"
)

// SignedArtifact is the normalized result of an identity-bound platform
// signature and digest probe. Runnel does not treat a textual path as proof.
type SignedArtifact struct {
	Availability   model.Availability `json:"availability"`
	ResolvedPath   string             `json:"-"`
	Identifier     string             `json:"identifier"`
	TeamIdentifier string             `json:"team_identifier"`
	SHA256         string             `json:"sha256"`
	SignatureValid bool               `json:"signature_valid"`
}

type HashedArtifact struct {
	Availability model.Availability `json:"availability"`
	ResolvedPath string             `json:"-"`
	SHA256       string             `json:"sha256"`
}

// OriginEvidence is produced by a platform verifier that resolves executable
// paths with the process audit token and checks Security.framework validity.
type OriginEvidence struct {
	Availability model.Availability `json:"availability"`
	Codex        SignedArtifact     `json:"codex"`
	Node         SignedArtifact     `json:"node"`
	Worker       HashedArtifact     `json:"worker"`
	LeafUID      uint32             `json:"leaf_uid"`
	ParentUID    uint32             `json:"parent_uid"`
}

// VerifyOrigin applies the exact immutable v1 origin contract. It cannot
// perform signature checks from path strings; SignatureValid must already be
// established by the platform capability.
func VerifyOrigin(origin OriginEvidence, grammar ProcessGrammar, currentUID uint32) error {
	if origin.Availability != model.AvailabilityAvailable ||
		origin.Codex.Availability != model.AvailabilityAvailable ||
		origin.Node.Availability != model.AvailabilityAvailable ||
		origin.Worker.Availability != model.AvailabilityAvailable {
		return safeError(CodeOriginUnavailable)
	}
	if !origin.Codex.SignatureValid || !origin.Node.SignatureValid {
		return safeError(CodeOriginMismatch)
	}
	if origin.Codex.Identifier != CodexIdentifier ||
		origin.Codex.TeamIdentifier != OpenAITeamIdentifier ||
		!equalDigest(origin.Codex.SHA256, CodexSHA256) ||
		origin.Codex.ResolvedPath != grammar.CodexPath {
		return safeError(CodeOriginMismatch)
	}
	if origin.Node.Identifier != NodeIdentifier ||
		origin.Node.TeamIdentifier != OpenAITeamIdentifier ||
		!equalDigest(origin.Node.SHA256, NodeSHA256) ||
		origin.Node.ResolvedPath != grammar.NodePath {
		return safeError(CodeOriginMismatch)
	}
	if !equalDigest(origin.Worker.SHA256, WorkerSHA256) ||
		origin.Worker.ResolvedPath != grammar.WorkerPath {
		return safeError(CodeOriginMismatch)
	}
	if origin.LeafUID != currentUID || origin.ParentUID != currentUID {
		return safeError(CodeUIDMismatch)
	}
	return nil
}

func equalDigest(actual, expected string) bool {
	return len(actual) == 64 && strings.EqualFold(actual, expected)
}
