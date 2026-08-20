package codex

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ArshyaAI/runnel/internal/model"
	runnelschema "github.com/ArshyaAI/runnel/schema"
)

type fixtureExpected struct {
	Classification model.Classification `json:"classification"`
	Availability   model.Availability   `json:"availability"`
	Selectable     bool                 `json:"selectable"`
	Evidence       []model.EvidenceCode `json:"evidence"`
}

type fixtureProbes struct {
	Identity         model.Availability `json:"identity"`
	Parent           model.Availability `json:"parent"`
	Origin           model.Availability `json:"origin"`
	Metadata         model.Availability `json:"metadata"`
	Descriptor       model.Availability `json:"descriptor"`
	Tail             model.Availability `json:"tail"`
	TTY              model.Availability `json:"tty"`
	Sockets          model.Availability `json:"sockets"`
	WritableActivity model.Availability `json:"writable_activity"`
	Children         model.Availability `json:"children"`
	Stack            model.Availability `json:"stack"`
}

type fixtureProcess struct {
	Role       string `json:"role"`
	PID        int32  `json:"pid"`
	ParentPID  int32  `json:"parent_pid"`
	StartTick  int64  `json:"start_tick"`
	UID        uint32 `json:"uid"`
	Executable string `json:"executable"`
	PIDVersion uint32 `json:"pid_version"`
	UniqueID   uint64 `json:"unique_id"`
	Origin     string `json:"origin"`
	Argv       string `json:"argv"`
}

type fixtureMetadata struct {
	Schema       string `json:"schema"`
	Version      string `json:"version"`
	DataVersion  string `json:"data_version"`
	Rollout      string `json:"rollout"`
	EdgeStatus   string `json:"edge_status"`
	FileIdentity struct {
		State  string `json:"state"`
		Device uint64 `json:"device"`
		Inode  uint64 `json:"inode"`
	} `json:"file_identity"`
	Descriptor string `json:"descriptor"`
}

type fixtureSample struct {
	Second        int64  `json:"second"`
	CPUTicks      uint64 `json:"cpu_ticks"`
	FileSize      int64  `json:"file_size"`
	FileMtimeTick int64  `json:"file_mtime_tick"`
	Device        uint64 `json:"device"`
	Inode         uint64 `json:"inode"`
	Stack         string `json:"stack"`
	TTY           bool   `json:"tty"`
	Listeners     uint32 `json:"listeners"`
	Established   uint32 `json:"established"`
	Writable      bool   `json:"writable_output"`
	Children      int    `json:"children"`
}

type fixtureCase struct {
	SchemaVersion string           `json:"schema_version"`
	CaseID        string           `json:"case_id"`
	Expected      fixtureExpected  `json:"expected"`
	Probes        fixtureProbes    `json:"probes"`
	ProcessTree   []fixtureProcess `json:"process_tree"`
	Metadata      fixtureMetadata  `json:"metadata"`
	Samples       []fixtureSample  `json:"samples"`
}

func TestGovernedFixtureCorpusThroughDetector(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "fixtures", "codex", "v1", "cases", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 20 {
		t.Fatalf("fixture coverage changed: got %d cases", len(paths))
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := runnelschema.Validate(runnelschema.CodexFixture, data); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		var fixture fixtureCase
		if err := json.Unmarshal(data, &fixture); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		t.Run(fixture.CaseID, func(t *testing.T) {
			result := Evaluate(samplesFromFixture(t, fixture))
			if result.Classification != fixture.Expected.Classification ||
				result.Availability != fixture.Expected.Availability ||
				result.Selectable != fixture.Expected.Selectable {
				t.Fatalf("got classification=%s availability=%s selectable=%t codes=%v; want %s/%s/%t",
					result.Classification, result.Availability, result.Selectable, result.Codes,
					fixture.Expected.Classification, fixture.Expected.Availability, fixture.Expected.Selectable)
			}
			if !slices.Equal(result.Evidence, fixture.Expected.Evidence) {
				t.Fatalf("evidence=%v want %v", result.Evidence, fixture.Expected.Evidence)
			}
		})
	}
}

func samplesFromFixture(t *testing.T, fixture fixtureCase) []DeepSample {
	t.Helper()
	base := validDeepSamples(t)
	if len(fixture.Samples) != len(base) {
		t.Fatalf("fixture samples=%d", len(fixture.Samples))
	}
	parentNode := findFixtureProcess(t, fixture.ProcessTree, "sandbox_parent")
	workerNode, hasWorker := findOptionalFixtureProcess(fixture.ProcessTree, "worker")
	replacementNode, hasReplacement := findOptionalFixtureProcess(fixture.ProcessTree, "replacement")
	if !hasWorker && !hasReplacement {
		t.Fatal("fixture has no worker or replacement")
	}
	leafNode := workerNode
	if !hasWorker {
		leafNode = replacementNode
	}

	leafArgv, parentArgv, roots := validArgv()
	grammar, err := NormalizeProcessGrammar(leafArgv, parentArgv, roots)
	if err != nil {
		t.Fatal(err)
	}
	applyArgvState(leafNode.Argv, parentNode.Argv, &leafArgv, &parentArgv)
	origin := exactOrigin(grammar, leafNode.UID)
	origin.Availability = fixture.Probes.Origin
	origin.Codex.Availability = fixture.Probes.Origin
	origin.Node.Availability = fixture.Probes.Origin
	origin.Worker.Availability = fixture.Probes.Origin
	applyOriginState(leafNode.Origin, parentNode.Origin, &origin)

	parentIdentity := fixtureIdentity(parentNode, grammar.CodexPath)
	leafExecutable := grammar.NodePath
	if leafNode.Role == "replacement" {
		leafExecutable = "/synthetic/replacement-helper"
	}
	leafIdentity := fixtureIdentity(leafNode, leafExecutable)
	initialLeafIdentity := leafIdentity
	replacementIdentity := leafIdentity
	if hasReplacement {
		replacementIdentity = fixtureIdentity(replacementNode, "/synthetic/replacement-helper")
	}
	if !hasWorker && hasReplacement && fixture.Probes.Identity == model.AvailabilityContradictory {
		initialLeafIdentity = replacementIdentity
		initialLeafIdentity.Executable = grammar.NodePath
		if initialLeafIdentity.PIDVersion > 1 {
			initialLeafIdentity.PIDVersion--
		} else {
			initialLeafIdentity.PIDVersion++
		}
	}

	for i := range base {
		raw := fixture.Samples[i]
		sample := &base[i]
		sample.Offset = time.Duration(raw.Second) * time.Second
		sample.IdentityAvailability = fixture.Probes.Identity
		sample.ParentAvailability = fixture.Probes.Parent
		sample.Identity = initialLeafIdentity
		if hasReplacement && fixture.Probes.Identity == model.AvailabilityContradictory && i == len(base)-1 {
			sample.Identity = replacementIdentity
		}
		sample.Parent = parentIdentity
		sample.CurrentUID = leafNode.UID
		sample.LeafArgv = append([]string(nil), leafArgv...)
		sample.ParentArgv = append([]string(nil), parentArgv...)
		sample.TempRoots = append([]string(nil), roots...)
		sample.Origin = origin

		sample.Metadata = MetadataSnapshot{
			Availability:   fixture.Probes.Metadata,
			DataVersion:    7,
			CLIVersion:     SupportedCodexVersion,
			ThreadSource:   "subagent",
			EdgeStatus:     fixture.Metadata.EdgeStatus,
			ThreadID:       "fixture-child",
			ParentThreadID: "fixture-parent",
			RolloutPath:    "/synthetic/fixture-rollout.jsonl",
		}
		if fixture.Metadata.Version != "exact" {
			sample.Metadata.CLIVersion = "unsupported"
		}
		if fixture.Metadata.DataVersion == "changed" {
			sample.Metadata.DataVersion += int64(i)
		}
		if fixture.Metadata.Schema == "incompatible" {
			sample.MetadataFailure = CodeSchemaIncompatible
		}

		sample.Tail = TailSnapshot{
			Availability: fixture.Probes.Tail,
			EnvelopeType: "event_msg",
			EventType:    "task_complete",
			Successful:   true,
			File: FileIdentity{
				Device: raw.Device, Inode: raw.Inode,
				Size: raw.FileSize, ModifiedNS: raw.FileMtimeTick,
			},
			digest: sha256.Sum256([]byte("fixture-envelope")),
		}
		switch fixture.Metadata.Rollout {
		case "truncated":
			sample.TailFailure = CodeTailTruncated
		case "unknown_event":
			sample.TailFailure = CodeTerminalUnknown
		case "contradictory":
			sample.TailFailure = CodeTailChanged
		}

		sample.Descriptor = DescriptorEvidence{
			Availability: fixture.Probes.Descriptor,
			Path:         sample.Metadata.RolloutPath,
			Device:       fixture.Metadata.FileIdentity.Device,
			Inode:        fixture.Metadata.FileIdentity.Inode,
			Access:       DescriptorReadOnly,
		}
		switch fixture.Metadata.Descriptor {
		case "writable":
			sample.Descriptor.Access = DescriptorReadWrite
		case "mismatch":
			sample.Descriptor.Inode++
		case "unknown":
			sample.Descriptor.Access = DescriptorUnknown
		}

		sample.CPUTimeNS = raw.CPUTicks
		sample.TTY = PresenceProbe{Availability: fixture.Probes.TTY, Present: raw.TTY}
		sample.Sockets = SocketProbe{
			Availability: fixture.Probes.Sockets,
			Listeners:    raw.Listeners, Established: raw.Established,
		}
		sample.WritableActivity = PresenceProbe{
			Availability: fixture.Probes.WritableActivity, Present: raw.Writable,
		}
		sample.Children = ChildrenProbe{Availability: fixture.Probes.Children, Children: []model.ProcessIdentity{}}
		for child := 0; child < raw.Children; child++ {
			sample.Children.Children = append(sample.Children.Children, model.ProcessIdentity{
				PID: int32(700 + child), StartTime: time.Unix(int64(700+child), 0).UTC(),
				UID: leafNode.UID, Executable: "/synthetic/child",
			})
		}
		sample.Stack = fixtureStack(raw.Stack, fixture.Probes.Stack)
	}
	return base
}

func findFixtureProcess(t *testing.T, values []fixtureProcess, role string) fixtureProcess {
	t.Helper()
	value, ok := findOptionalFixtureProcess(values, role)
	if !ok {
		t.Fatalf("missing process role %s", role)
	}
	return value
}

func findOptionalFixtureProcess(values []fixtureProcess, role string) (fixtureProcess, bool) {
	for _, value := range values {
		if value.Role == role {
			return value, true
		}
	}
	return fixtureProcess{}, false
}

func fixtureIdentity(value fixtureProcess, executable string) model.DarwinActionIdentity {
	return model.DarwinActionIdentity{
		ProcessIdentity: model.ProcessIdentity{
			PID: value.PID, StartTime: time.Unix(value.StartTick, 0).UTC(),
			UID: value.UID, Executable: executable,
		},
		PIDVersion: value.PIDVersion, UniqueID: value.UniqueID,
	}
}

func applyArgvState(workerState, parentState string, leaf, parent *[]string) {
	switch workerState {
	case "mismatched_worker":
		(*leaf)[2] = "/synthetic/tmp/job/other-worker.js"
	case "replacement":
		(*leaf)[0] = "/synthetic/replacement-helper"
	}
	if workerState != "supported_worker" {
		copy((*parent)[len(*parent)-len(*leaf):], *leaf)
	}
	if parentState == "mismatched_parent" {
		(*parent)[len(*parent)-1] = "/synthetic/other-work"
	}
}

func applyOriginState(workerState, parentState string, origin *OriginEvidence) {
	switch workerState {
	case "unsigned":
		origin.Node.SignatureValid = false
	case "altered", "wrong_digest":
		origin.Worker.SHA256 = CodexSHA256
	case "resigned":
		origin.Node.SignatureValid = false
		origin.Node.TeamIdentifier = "SYNTHETICTEAM"
	case "wrong_team":
		origin.Node.TeamIdentifier = "SYNTHETICTEAM"
	case "wrong_identifier":
		origin.Node.Identifier = "synthetic-node"
	case "mismatched_parent":
		origin.Codex.ResolvedPath = "/synthetic/other-codex"
	}
	if parentState == "mismatched_parent" {
		origin.Codex.ResolvedPath = "/synthetic/other-codex"
	}
}

func fixtureStack(state string, overall model.Availability) StackEvidence {
	switch state {
	case "supported_read":
		return StackEvidence{Availability: model.AvailabilityAvailable, Predicate: SupportedStackPredicate}
	case "changed":
		return StackEvidence{Availability: overall, Predicate: SupportedStackPredicate, Changed: true}
	case "unavailable":
		return StackEvidence{Availability: overall}
	default:
		return StackEvidence{Availability: model.AvailabilityNotApplicable}
	}
}

func TestFixtureManifestMatchesAdapterContract(t *testing.T) {
	path := filepath.Join("..", "..", "fixtures", "codex", "v1", "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := runnelschema.Validate(runnelschema.CodexManifest, data); err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Adapter struct {
			ID                   string `json:"id"`
			EmbeddedCodexVersion string `json:"embedded_codex_version"`
			TeamIdentifier       string `json:"team_identifier"`
			CodexIdentifier      string `json:"codex_identifier"`
			CodexSHA256          string `json:"codex_sha256"`
			NodeIdentifier       string `json:"node_identifier"`
			NodeSHA256           string `json:"node_sha256"`
			WorkerSHA256         string `json:"worker_sha256"`
		} `json:"adapter"`
		SQLite struct {
			RequiredCompletedEdgeStatus string `json:"required_completed_edge_status"`
		} `json:"sqlite"`
		Rollout struct {
			TailLimitBytes       int64  `json:"tail_limit_bytes"`
			MaxTerminalLineBytes int    `json:"max_terminal_line_bytes"`
			TerminalEvent        string `json:"terminal_event"`
			TerminalPayloadType  string `json:"terminal_payload_type"`
		} `json:"rollout"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Adapter.ID != AdapterID ||
		manifest.Adapter.EmbeddedCodexVersion != SupportedCodexVersion ||
		manifest.Adapter.TeamIdentifier != OpenAITeamIdentifier ||
		manifest.Adapter.CodexIdentifier != CodexIdentifier ||
		manifest.Adapter.CodexSHA256 != CodexSHA256 ||
		manifest.Adapter.NodeIdentifier != NodeIdentifier ||
		manifest.Adapter.NodeSHA256 != NodeSHA256 ||
		manifest.Adapter.WorkerSHA256 != WorkerSHA256 ||
		manifest.SQLite.RequiredCompletedEdgeStatus != "closed" ||
		manifest.Rollout.TailLimitBytes != defaultMaxTailBytes ||
		manifest.Rollout.MaxTerminalLineBytes != defaultMaxEventBytes ||
		manifest.Rollout.TerminalEvent != "event_msg" ||
		manifest.Rollout.TerminalPayloadType != "task_complete" {
		t.Fatal("manifest and compiled adapter contract diverged")
	}
}
