package codex

import (
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArshyaAI/runnel/internal/model"
)

func validDeepSamples(t *testing.T) []DeepSample {
	t.Helper()
	leaf, parent, roots := validArgv()
	grammar, err := NormalizeProcessGrammar(leaf, parent, roots)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Unix(1_700_000_000, 0).UTC()
	identity := model.DarwinActionIdentity{
		ProcessIdentity: model.ProcessIdentity{PID: 101, StartTime: start, UID: 501, Executable: grammar.NodePath},
		PIDVersion:      11, UniqueID: 12,
	}
	parentIdentity := model.DarwinActionIdentity{
		ProcessIdentity: model.ProcessIdentity{PID: 100, StartTime: start.Add(-time.Second), UID: 501, Executable: grammar.CodexPath},
		PIDVersion:      9, UniqueID: 10,
	}
	metadata := MetadataSnapshot{
		Availability: model.AvailabilityAvailable, DataVersion: 7,
		CLIVersion: SupportedCodexVersion, ThreadSource: "subagent", EdgeStatus: "closed",
		ThreadID: "synthetic-child", ParentThreadID: "synthetic-parent",
		RolloutPath: "/synthetic/rollout.jsonl",
	}
	file := FileIdentity{Device: 41, Inode: 42, Size: 800, ModifiedNS: 1234}
	tail := TailSnapshot{
		Availability: model.AvailabilityAvailable, EnvelopeType: "event_msg",
		EventType: "task_complete", Successful: true, File: file,
		digest: sha256.Sum256([]byte("synthetic-envelope")),
	}
	descriptor := DescriptorEvidence{
		Availability: model.AvailabilityAvailable, Path: metadata.RolloutPath,
		Device: file.Device, Inode: file.Inode, Access: DescriptorReadOnly,
	}
	samples := make([]DeepSample, 4)
	for i := range samples {
		samples[i] = DeepSample{
			Offset:               requiredSampleOffsets[i],
			IdentityAvailability: model.AvailabilityAvailable, Identity: identity,
			ParentAvailability: model.AvailabilityAvailable, Parent: parentIdentity,
			CurrentUID: 501,
			LeafArgv:   append([]string(nil), leaf...), ParentArgv: append([]string(nil), parent...),
			TempRoots: append([]string(nil), roots...), Origin: exactOrigin(grammar, 501),
			Metadata: metadata, Tail: tail, Descriptor: descriptor,
			CPUTimeNS: uint64((i + 1) * 100), RSSBytes: 1024,
			TTY:              PresenceProbe{Availability: model.AvailabilityAvailable},
			Sockets:          SocketProbe{Availability: model.AvailabilityAvailable},
			WritableActivity: PresenceProbe{Availability: model.AvailabilityAvailable},
			Children:         ChildrenProbe{Availability: model.AvailabilityAvailable, Children: []model.ProcessIdentity{}},
			Stack:            StackEvidence{Availability: model.AvailabilityNotApplicable},
		}
	}
	samples[3].Stack = StackEvidence{Availability: model.AvailabilityAvailable, Predicate: SupportedStackPredicate}
	return samples
}

func TestEvaluateExactFourSampleCandidate(t *testing.T) {
	result := Evaluate(validDeepSamples(t))
	if !result.Selectable || result.Baseline == nil {
		t.Fatalf("candidate refused: %#v", result)
	}
	if result.Classification != model.ClassificationSupportedStaleCandidate || result.Availability != model.AvailabilityAvailable {
		t.Fatalf("unexpected result: %#v", result)
	}
	if !slices.IsSorted(result.Codes) || !slices.IsSorted(result.Evidence) {
		t.Fatal("codes and evidence must be deterministic")
	}
	for _, required := range []Code{
		CodeAdapterExact, CodeIdentityStable, CodeParentIdentityStable, CodeUIDExact,
		CodeOriginExact, CodeVersionExact, CodeArgvExact, CodeParentExact,
		CodeMetadataComplete, CodeRolloutComplete, CodeRolloutUnchanged,
		CodeDescriptorExact, CodeCPUIncreasing, CodeStackSupported, CodeNoTTY,
		CodeNoListener, CodeNoEstablishedSocket, CodeNoWritableOutput,
		CodeChildless, CodeNoProtectedIdentity,
	} {
		if !slices.Contains(result.Codes, required) {
			t.Fatalf("missing required positive %s", required)
		}
	}
	if negatives := negativeCodes(result.Codes); len(negatives) != 0 {
		t.Fatalf("candidate has negative codes: %v", negatives)
	}
}

func TestEvaluateIssuesOpaqueExactActionAuthority(t *testing.T) {
	samples := validDeepSamples(t)
	result := Evaluate(samples)
	authority := result.Authority()
	if authority == nil {
		t.Fatalf("exact result did not issue authority: %#v", result)
	}
	candidate, ok := authority.Candidate()
	if !ok || !candidate.Target.Equal(samples[len(samples)-1].Identity) {
		t.Fatalf("authority candidate mismatch: %#v ok=%v", candidate, ok)
	}
	if !slices.Equal(candidate.Evidence.Availability, candidateAvailability()) ||
		!slices.Equal(candidate.Evidence.Codes, candidateEvidence()) {
		t.Fatalf("authority evidence is not canonical: %#v", candidate.Evidence)
	}
	provenance, ok := authority.Provenance()
	if !ok || provenance == ([sha256.Size]byte{}) {
		t.Fatal("authority has no provenance")
	}

	// Returned candidates are isolated copies, not handles into authority state.
	candidate.Evidence.Codes[0] = model.EvidenceTTYPresent
	fresh, ok := authority.Candidate()
	if !ok || !slices.Equal(fresh.Evidence.Codes, candidateEvidence()) {
		t.Fatal("candidate mutation changed authority state")
	}
	if _, err := json.Marshal(authority); err == nil {
		t.Fatal("authority unexpectedly serialized")
	}
}

func TestAuthorityRejectsNonselectableAndMutatedResults(t *testing.T) {
	nonselectableSamples := validDeepSamples(t)
	nonselectableSamples[0].TTY.Present = true
	if authority := Evaluate(nonselectableSamples).Authority(); authority != nil {
		t.Fatal("nonselectable result issued authority")
	}

	tests := []struct {
		name   string
		mutate func(*DetectorResult)
	}{
		{name: "selectable", mutate: func(result *DetectorResult) { result.Selectable = false }},
		{name: "adapter", mutate: func(result *DetectorResult) { result.AdapterID = "other/v1" }},
		{name: "classification", mutate: func(result *DetectorResult) { result.Classification = model.ClassificationUnknown }},
		{name: "availability", mutate: func(result *DetectorResult) { result.Availability = model.AvailabilityContradictory }},
		{name: "missing code", mutate: func(result *DetectorResult) { result.Codes = slices.Clone(result.Codes[1:]) }},
		{name: "extra negative code", mutate: func(result *DetectorResult) {
			result.Codes = normalizeCodes(append(result.Codes, CodeTTYPresent))
		}},
		{name: "missing evidence", mutate: func(result *DetectorResult) { result.Evidence = slices.Clone(result.Evidence[1:]) }},
		{name: "extra evidence", mutate: func(result *DetectorResult) {
			result.Evidence = append(result.Evidence, model.EvidenceCWDWorktree)
			slices.Sort(result.Evidence)
		}},
		{name: "negative evidence", mutate: func(result *DetectorResult) {
			result.Evidence = append(result.Evidence, model.EvidenceTTYPresent)
			slices.Sort(result.Evidence)
		}},
		{name: "missing baseline", mutate: func(result *DetectorResult) { result.Baseline = nil }},
		{name: "changed baseline", mutate: func(result *DetectorResult) { result.Baseline.identity.PIDVersion++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := Evaluate(validDeepSamples(t))
			test.mutate(&result)
			if authority := result.Authority(); authority != nil {
				t.Fatal("mutated detector result retained authority")
			}
		})
	}
}

func TestActionAuthorityRejectsZeroCopyAndTampering(t *testing.T) {
	var zero ActionAuthority
	if _, ok := zero.Candidate(); ok {
		t.Fatal("zero authority exposed candidate")
	}
	if _, ok := zero.Provenance(); ok {
		t.Fatal("zero authority exposed provenance")
	}

	original := Evaluate(validDeepSamples(t)).Authority()
	if original == nil {
		t.Fatal("exact result did not issue authority")
	}
	copied := *original
	if _, ok := copied.Candidate(); ok {
		t.Fatal("copied authority exposed candidate")
	}

	tests := []struct {
		name   string
		mutate func(*ActionAuthority)
	}{
		{name: "missing evidence", mutate: func(authority *ActionAuthority) {
			authority.state.candidate.Evidence.Codes = slices.Clone(authority.state.candidate.Evidence.Codes[1:])
		}},
		{name: "extra evidence", mutate: func(authority *ActionAuthority) {
			authority.state.candidate.Evidence.Codes = append(authority.state.candidate.Evidence.Codes, model.EvidenceCWDWorktree)
			slices.Sort(authority.state.candidate.Evidence.Codes)
		}},
		{name: "negative evidence", mutate: func(authority *ActionAuthority) {
			authority.state.candidate.Evidence.Codes = append(authority.state.candidate.Evidence.Codes, model.EvidenceTTYPresent)
			slices.Sort(authority.state.candidate.Evidence.Codes)
		}},
		{name: "contradictory evidence", mutate: func(authority *ActionAuthority) {
			authority.state.candidate.Evidence.Availability[0].Status = model.AvailabilityContradictory
		}},
		{name: "candidate target", mutate: func(authority *ActionAuthority) {
			authority.state.candidate.Target.PIDVersion++
		}},
		{name: "baseline", mutate: func(authority *ActionAuthority) {
			authority.state.baseline.metadata.ThreadID += "-changed"
		}},
		{name: "provenance", mutate: func(authority *ActionAuthority) {
			authority.state.provenance[0]++
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority := Evaluate(validDeepSamples(t)).Authority()
			if authority == nil {
				t.Fatal("exact result did not issue authority")
			}
			test.mutate(authority)
			if _, ok := authority.Candidate(); ok {
				t.Fatal("tampered authority exposed candidate")
			}
			if _, ok := authority.Provenance(); ok {
				t.Fatal("tampered authority exposed provenance")
			}
		})
	}
}

func TestEvaluateEveryDisqualifier(t *testing.T) {
	tests := []struct {
		name           string
		edit           func([]DeepSample) []DeepSample
		code           Code
		classification model.Classification
	}{
		{"sample count", func(s []DeepSample) []DeepSample { return s[:3] }, CodeSampleCountInvalid, model.ClassificationUnknown},
		{"sample offset", func(s []DeepSample) []DeepSample { s[2].Offset = 5 * time.Second; return s }, CodeSampleOffsetInvalid, model.ClassificationUnknown},
		{"identity unavailable", func(s []DeepSample) []DeepSample {
			s[1].IdentityAvailability = model.AvailabilityPermissionDenied
			return s
		}, CodeIdentityUnavailable, model.ClassificationUnknown},
		{"identity changed", func(s []DeepSample) []DeepSample { s[3].Identity.PIDVersion++; return s }, CodeIdentityChanged, model.ClassificationUnknown},
		{"parent unavailable", func(s []DeepSample) []DeepSample { s[1].ParentAvailability = model.AvailabilityProcessExited; return s }, CodeParentUnavailable, model.ClassificationUnknown},
		{"parent changed", func(s []DeepSample) []DeepSample { s[3].Parent.UniqueID++; return s }, CodeParentChanged, model.ClassificationUnknown},
		{"uid mismatch", func(s []DeepSample) []DeepSample { s[0].CurrentUID++; return s }, CodeUIDMismatch, model.ClassificationUnknown},
		{"origin unavailable", func(s []DeepSample) []DeepSample {
			s[0].Origin.Node.Availability = model.AvailabilityPermissionDenied
			return s
		}, CodeOriginUnavailable, model.ClassificationUnknown},
		{"origin mismatch", func(s []DeepSample) []DeepSample { s[0].Origin.Worker.SHA256 = CodexSHA256; return s }, CodeOriginMismatch, model.ClassificationUnknown},
		{"argv mismatch", func(s []DeepSample) []DeepSample { s[0].LeafArgv[1] = "--wrong"; return s }, CodeArgvMismatch, model.ClassificationUnknown},
		{"parent mismatch", func(s []DeepSample) []DeepSample { s[0].ParentArgv[1] = "exec"; return s }, CodeParentMismatch, model.ClassificationUnknown},
		{"schema incompatible", func(s []DeepSample) []DeepSample {
			s[0].Metadata.Availability = model.AvailabilitySchemaIncompatible
			s[0].MetadataFailure = CodeSchemaIncompatible
			return s
		}, CodeSchemaIncompatible, model.ClassificationUnknown},
		{"version mismatch", func(s []DeepSample) []DeepSample { s[0].Metadata.CLIVersion = "0.148.0-alpha.16"; return s }, CodeVersionMismatch, model.ClassificationUnknown},
		{"metadata changed", func(s []DeepSample) []DeepSample { s[3].Metadata.DataVersion++; return s }, CodeMetadataChanged, model.ClassificationUnknown},
		{"tail truncated", func(s []DeepSample) []DeepSample {
			s[0].Tail.Availability = model.AvailabilityMalformedOutput
			s[0].TailFailure = CodeTailTruncated
			return s
		}, CodeTailTruncated, model.ClassificationUnknown},
		{"terminal unknown", func(s []DeepSample) []DeepSample { s[0].Tail.EventType = "unknown"; return s }, CodeTerminalUnknown, model.ClassificationUnknown},
		{"terminal failed", func(s []DeepSample) []DeepSample { s[0].Tail.Successful = false; return s }, CodeTerminalFailed, model.ClassificationUnknown},
		{"file changed", func(s []DeepSample) []DeepSample { s[3].Tail.File.Size++; return s }, CodeFileChanged, model.ClassificationRecentlyActive},
		{"tail changed same stat", func(s []DeepSample) []DeepSample { s[3].Tail.digest[0]++; return s }, CodeTailChanged, model.ClassificationUnknown},
		{"descriptor unavailable", func(s []DeepSample) []DeepSample {
			s[0].Descriptor.Availability = model.AvailabilityPermissionDenied
			return s
		}, CodeDescriptorUnavailable, model.ClassificationUnknown},
		{"descriptor writable", func(s []DeepSample) []DeepSample { s[0].Descriptor.Access = DescriptorReadWrite; return s }, CodeDescriptorWritable, model.ClassificationUnknown},
		{"descriptor mismatch", func(s []DeepSample) []DeepSample { s[0].Descriptor.Inode++; return s }, CodeDescriptorMismatch, model.ClassificationUnknown},
		{"cpu not increasing", func(s []DeepSample) []DeepSample { s[2].CPUTimeNS = s[1].CPUTimeNS; return s }, CodeCPUNotIncreasing, model.ClassificationQuietUnclassified},
		{"stack unavailable", func(s []DeepSample) []DeepSample {
			s[3].Stack.Availability = model.AvailabilityPermissionDenied
			return s
		}, CodeStackUnavailable, model.ClassificationUnknown},
		{"stack mismatch", func(s []DeepSample) []DeepSample { s[3].Stack.Predicate = "other"; return s }, CodeStackMismatch, model.ClassificationQuietUnclassified},
		{"stack changed", func(s []DeepSample) []DeepSample { s[3].Stack.Changed = true; return s }, CodeStackChanged, model.ClassificationUnknown},
		{"tty unavailable", func(s []DeepSample) []DeepSample { s[0].TTY.Availability = model.AvailabilityTimeout; return s }, CodeTTYUnavailable, model.ClassificationUnknown},
		{"tty present", func(s []DeepSample) []DeepSample { s[0].TTY.Present = true; return s }, CodeTTYPresent, model.ClassificationProtected},
		{"socket unavailable", func(s []DeepSample) []DeepSample {
			s[0].Sockets.Availability = model.AvailabilityPermissionDenied
			return s
		}, CodeSocketUnavailable, model.ClassificationUnknown},
		{"listener", func(s []DeepSample) []DeepSample { s[0].Sockets.Listeners = 1; return s }, CodeListenerPresent, model.ClassificationUnknown},
		{"established socket", func(s []DeepSample) []DeepSample { s[0].Sockets.Established = 1; return s }, CodeEstablishedSocket, model.ClassificationUnknown},
		{"writable unavailable", func(s []DeepSample) []DeepSample {
			s[0].WritableActivity.Availability = model.AvailabilityPermissionDenied
			return s
		}, CodeWritableProbeUnavailable, model.ClassificationUnknown},
		{"writable activity", func(s []DeepSample) []DeepSample { s[0].WritableActivity.Present = true; return s }, CodeWritableActivity, model.ClassificationRecentlyActive},
		{"children unavailable", func(s []DeepSample) []DeepSample { s[0].Children.Availability = model.AvailabilityTimeout; return s }, CodeChildrenUnavailable, model.ClassificationUnknown},
		{"new child", func(s []DeepSample) []DeepSample {
			s[0].Children.Children = []model.ProcessIdentity{s[0].Identity.ProcessIdentity}
			return s
		}, CodeNewChild, model.ClassificationRecentlyActive},
		{"protected leaf", func(s []DeepSample) []DeepSample { s[0].LeafProtected = true; return s }, CodeProtectedIdentity, model.ClassificationProtected},
		{"protected child", func(s []DeepSample) []DeepSample { s[0].ProtectedChildren = 1; return s }, CodeProtectedIdentity, model.ClassificationProtected},
		{"contradiction", func(s []DeepSample) []DeepSample { s[0].Contradictory = true; return s }, CodeContradictory, model.ClassificationUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := Evaluate(test.edit(validDeepSamples(t)))
			if result.Selectable || result.Baseline != nil {
				t.Fatal("disqualified fixture became selectable")
			}
			if !slices.Contains(result.Codes, test.code) {
				t.Fatalf("codes %v missing %s", result.Codes, test.code)
			}
			if result.Classification != test.classification {
				t.Fatalf("classification=%s want %s, codes=%v", result.Classification, test.classification, result.Codes)
			}
			if !slices.IsSorted(result.Codes) {
				t.Fatal("codes not deterministic")
			}
		})
	}
}

func TestDetectorPublicOutputHasNoPrivateCorrelationMaterial(t *testing.T) {
	result := Evaluate(validDeepSamples(t))
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"synthetic-child", "synthetic-parent", "/synthetic/", "trusted-worker.js",
		"ChatGPT.app", "synthetic-envelope", "turn_id", "last_agent_message",
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("public detector output leaked %q: %s", forbidden, encoded)
		}
	}
}
