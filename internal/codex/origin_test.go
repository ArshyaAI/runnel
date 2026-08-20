package codex

import (
	"testing"

	"github.com/ArshyaAI/runnel/internal/model"
)

func exactOrigin(grammar ProcessGrammar, uid uint32) OriginEvidence {
	return OriginEvidence{
		Availability: model.AvailabilityAvailable,
		Codex: SignedArtifact{
			Availability: model.AvailabilityAvailable, ResolvedPath: grammar.CodexPath,
			Identifier: CodexIdentifier, TeamIdentifier: OpenAITeamIdentifier,
			SHA256: CodexSHA256, SignatureValid: true,
		},
		Node: SignedArtifact{
			Availability: model.AvailabilityAvailable, ResolvedPath: grammar.NodePath,
			Identifier: NodeIdentifier, TeamIdentifier: OpenAITeamIdentifier,
			SHA256: NodeSHA256, SignatureValid: true,
		},
		Worker: HashedArtifact{
			Availability: model.AvailabilityAvailable, ResolvedPath: grammar.WorkerPath,
			SHA256: WorkerSHA256,
		},
		LeafUID: uid, ParentUID: uid,
	}
}

func TestVerifyOriginExactAndNearMisses(t *testing.T) {
	leaf, parent, roots := validArgv()
	grammar, err := NormalizeProcessGrammar(leaf, parent, roots)
	if err != nil {
		t.Fatal(err)
	}
	const uid = 501
	if err := VerifyOrigin(exactOrigin(grammar, uid), grammar, uid); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*OriginEvidence)
		code Code
	}{
		{"unavailable", func(o *OriginEvidence) { o.Availability = model.AvailabilityPermissionDenied }, CodeOriginUnavailable},
		{"unsigned codex", func(o *OriginEvidence) { o.Codex.SignatureValid = false }, CodeOriginMismatch},
		{"resigned team", func(o *OriginEvidence) { o.Codex.TeamIdentifier = "OTHERTEAM" }, CodeOriginMismatch},
		{"wrong codex identifier", func(o *OriginEvidence) { o.Codex.Identifier = "other" }, CodeOriginMismatch},
		{"wrong codex digest", func(o *OriginEvidence) { o.Codex.SHA256 = NodeSHA256 }, CodeOriginMismatch},
		{"wrong codex resolved path", func(o *OriginEvidence) { o.Codex.ResolvedPath += ".copy" }, CodeOriginMismatch},
		{"unsigned node", func(o *OriginEvidence) { o.Node.SignatureValid = false }, CodeOriginMismatch},
		{"wrong node team", func(o *OriginEvidence) { o.Node.TeamIdentifier = "OTHERTEAM" }, CodeOriginMismatch},
		{"wrong node identifier", func(o *OriginEvidence) { o.Node.Identifier = "other" }, CodeOriginMismatch},
		{"wrong node digest", func(o *OriginEvidence) { o.Node.SHA256 = CodexSHA256 }, CodeOriginMismatch},
		{"wrong worker digest", func(o *OriginEvidence) { o.Worker.SHA256 = CodexSHA256 }, CodeOriginMismatch},
		{"wrong worker path", func(o *OriginEvidence) { o.Worker.ResolvedPath += ".copy" }, CodeOriginMismatch},
		{"leaf uid mismatch", func(o *OriginEvidence) { o.LeafUID++ }, CodeUIDMismatch},
		{"parent uid mismatch", func(o *OriginEvidence) { o.ParentUID++ }, CodeUIDMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			origin := exactOrigin(grammar, uid)
			test.edit(&origin)
			err := VerifyOrigin(origin, grammar, uid)
			if err == nil || codeOf(err, "") != test.code {
				t.Fatalf("got %v, want %s", err, test.code)
			}
		})
	}
}
