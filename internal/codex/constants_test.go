package codex

import "testing"

func TestPinnedAdapterConstants(t *testing.T) {
	wants := map[string]string{
		"adapter":          AdapterID,
		"version":          SupportedCodexVersion,
		"team":             OpenAITeamIdentifier,
		"codex identifier": CodexIdentifier,
		"node identifier":  NodeIdentifier,
		"codex digest":     CodexSHA256,
		"node digest":      NodeSHA256,
		"worker digest":    WorkerSHA256,
	}
	exact := map[string]string{
		"adapter":          "codex-chatgpt-trusted-worker/v1",
		"version":          "0.148.0-alpha.15",
		"team":             "2DC432GLL2",
		"codex identifier": "codex",
		"node identifier":  "node",
		"codex digest":     "7645c3caf5607e4528eb3a15b12496c284c2a918939aed34e863c760c1b421e7",
		"node digest":      "e3860ffeda3aaf7203123bd661cae18b478924215048fcfea560fc63950cc95a",
		"worker digest":    "9f936ad8addf558d3de3f415917680ae703bf51b4d63f62d718413a3acb4edb7",
	}
	for name, got := range wants {
		if got != exact[name] {
			t.Fatalf("%s loosened: got %q want %q", name, got, exact[name])
		}
	}
}
