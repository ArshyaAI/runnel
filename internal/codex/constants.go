package codex

// Adapter and origin constants are intentionally exact. Supporting another
// Codex build requires a separately reviewed adapter, not a widened range.
const (
	AdapterID = "codex-chatgpt-trusted-worker/v1"

	SupportedCodexVersion = "0.148.0-alpha.15"
	OpenAITeamIdentifier  = "2DC432GLL2"

	CodexIdentifier = "codex"
	NodeIdentifier  = "node"

	CodexSHA256  = "7645c3caf5607e4528eb3a15b12496c284c2a918939aed34e863c760c1b421e7"
	NodeSHA256   = "e3860ffeda3aaf7203123bd661cae18b478924215048fcfea560fc63950cc95a"
	WorkerSHA256 = "9f936ad8addf558d3de3f415917680ae703bf51b4d63f62d718413a3acb4edb7"

	NodeBundleSuffix = "/ChatGPT.app/Contents/Resources/cua_node/bin/node"
	WorkerFilename   = "trusted-worker.js"

	SupportedStackPredicate = "codex-rollout-read-decoder/v1"
)
