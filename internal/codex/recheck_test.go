package codex

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/ArshyaAI/runnel/internal/model"
)

type metadataReaderFunc func(context.Context, string) (MetadataSnapshot, error)

func (f metadataReaderFunc) Snapshot(ctx context.Context, path string) (MetadataSnapshot, error) {
	return f(ctx, path)
}

type tailReaderFunc func(context.Context, string, DescriptorEvidence) (TailSnapshot, error)

func (f tailReaderFunc) Read(ctx context.Context, path string, descriptor DescriptorEvidence) (TailSnapshot, error) {
	return f(ctx, path, descriptor)
}

func validRecheckRequest(t *testing.T, samples []DeepSample) ActionRecheckRequest {
	t.Helper()
	last := samples[len(samples)-1]
	return ActionRecheckRequest{
		IdentityAvailability: last.IdentityAvailability,
		Identity:             last.Identity,
		ParentAvailability:   last.ParentAvailability,
		Parent:               last.Parent,
		CurrentUID:           last.CurrentUID,
		LeafArgv:             append([]string(nil), last.LeafArgv...),
		ParentArgv:           append([]string(nil), last.ParentArgv...),
		TempRoots:            append([]string(nil), last.TempRoots...),
		Origin:               last.Origin,
		Descriptor:           last.Descriptor,
		TTY:                  last.TTY,
		Sockets:              last.Sockets,
		WritableActivity:     last.WritableActivity,
		Children:             last.Children,
		LeafProtected:        last.LeafProtected,
		ProtectedChildren:    last.ProtectedChildren,
	}
}

func TestActionRecheckRepeatsExactReadOnlyEvidence(t *testing.T) {
	samples := validDeepSamples(t)
	detector := Evaluate(samples)
	request := validRecheckRequest(t, samples)
	metadata := metadataReaderFunc(func(_ context.Context, path string) (MetadataSnapshot, error) {
		if path != detector.Baseline.metadata.RolloutPath {
			t.Fatal("wrong canonical rollout path")
		}
		return detector.Baseline.metadata, nil
	})
	tails := tailReaderFunc(func(_ context.Context, path string, descriptor DescriptorEvidence) (TailSnapshot, error) {
		if path != detector.Baseline.metadata.RolloutPath || descriptor != detector.Baseline.descriptor {
			t.Fatal("wrong tail correlation input")
		}
		return detector.Baseline.tail, nil
	})
	result := Recheck(context.Background(), detector, request, metadata, tails)
	if !result.Allowed || !slices.Equal(result.Codes, []Code{CodeActionRecheckExact}) {
		t.Fatalf("recheck refused: %#v", result)
	}
}

func TestActionRecheckRefusesEveryChangedBoundary(t *testing.T) {
	tests := []struct {
		name          string
		editRequest   func(*ActionRecheckRequest)
		editMetadata  func(*MetadataSnapshot)
		editTail      func(*TailSnapshot)
		metadataError error
		tailError     error
		code          Code
	}{
		{name: "identity", editRequest: func(r *ActionRecheckRequest) { r.Identity.PIDVersion++ }, code: CodeIdentityChanged},
		{name: "parent", editRequest: func(r *ActionRecheckRequest) { r.Parent.UniqueID++ }, code: CodeParentChanged},
		{name: "uid", editRequest: func(r *ActionRecheckRequest) { r.CurrentUID++ }, code: CodeUIDMismatch},
		{name: "argv", editRequest: func(r *ActionRecheckRequest) { r.LeafArgv[1] = "--wrong" }, code: CodeArgvMismatch},
		{name: "origin", editRequest: func(r *ActionRecheckRequest) { r.Origin.Worker.SHA256 = CodexSHA256 }, code: CodeOriginMismatch},
		{name: "descriptor inode", editRequest: func(r *ActionRecheckRequest) { r.Descriptor.Inode++ }, code: CodeDescriptorMismatch},
		{name: "descriptor writable", editRequest: func(r *ActionRecheckRequest) { r.Descriptor.Access = DescriptorReadWrite }, code: CodeDescriptorWritable},
		{name: "tty", editRequest: func(r *ActionRecheckRequest) { r.TTY.Present = true }, code: CodeTTYPresent},
		{name: "listener", editRequest: func(r *ActionRecheckRequest) { r.Sockets.Listeners = 1 }, code: CodeListenerPresent},
		{name: "established", editRequest: func(r *ActionRecheckRequest) { r.Sockets.Established = 1 }, code: CodeEstablishedSocket},
		{name: "writable activity", editRequest: func(r *ActionRecheckRequest) { r.WritableActivity.Present = true }, code: CodeWritableActivity},
		{name: "new child", editRequest: func(r *ActionRecheckRequest) {
			r.Children.Children = []model.ProcessIdentity{r.Identity.ProcessIdentity}
		}, code: CodeNewChild},
		{name: "protected", editRequest: func(r *ActionRecheckRequest) { r.LeafProtected = true }, code: CodeProtectedIdentity},
		{name: "data version", editMetadata: func(m *MetadataSnapshot) { m.DataVersion++ }, code: CodeMetadataChanged},
		{name: "row value", editMetadata: func(m *MetadataSnapshot) { m.EdgeStatus = "running" }, code: CodeMetadataChanged},
		{name: "rollout row", editMetadata: func(m *MetadataSnapshot) { m.RolloutPath += ".changed" }, code: CodeMetadataChanged},
		{name: "tail event", editTail: func(t *TailSnapshot) { t.EventType = "other" }, code: CodeTailChanged},
		{name: "tail digest", editTail: func(t *TailSnapshot) { t.digest[0]++ }, code: CodeTailChanged},
		{name: "file inode", editTail: func(t *TailSnapshot) { t.File.Inode++ }, code: CodeTailChanged},
		{name: "file size", editTail: func(t *TailSnapshot) { t.File.Size++ }, code: CodeTailChanged},
		{name: "schema error", metadataError: safeError(CodeSchemaIncompatible), code: CodeSchemaIncompatible},
		{name: "unstable metadata", metadataError: safeError(CodeMetadataUnstable), code: CodeMetadataUnstable},
		{name: "truncated tail", tailError: safeError(CodeTailTruncated), code: CodeTailTruncated},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			samples := validDeepSamples(t)
			detector := Evaluate(samples)
			request := validRecheckRequest(t, samples)
			if test.editRequest != nil {
				test.editRequest(&request)
			}
			freshMetadata := detector.Baseline.metadata
			if test.editMetadata != nil {
				test.editMetadata(&freshMetadata)
			}
			freshTail := detector.Baseline.tail
			if test.editTail != nil {
				test.editTail(&freshTail)
			}
			metadata := metadataReaderFunc(func(context.Context, string) (MetadataSnapshot, error) {
				return freshMetadata, test.metadataError
			})
			tails := tailReaderFunc(func(context.Context, string, DescriptorEvidence) (TailSnapshot, error) {
				return freshTail, test.tailError
			})
			result := Recheck(context.Background(), detector, request, metadata, tails)
			if result.Allowed || !slices.Contains(result.Codes, test.code) {
				t.Fatalf("result=%#v want %s", result, test.code)
			}
		})
	}
}

func TestActionRecheckRejectsNonCandidateAndDoesNotLeak(t *testing.T) {
	result := Recheck(context.Background(), DetectorResult{}, ActionRecheckRequest{}, nil, nil)
	if result.Allowed || result.Availability != model.AvailabilityContradictory {
		t.Fatalf("unexpected result: %#v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"/synthetic/", "trusted-worker.js", "synthetic-child", "last_agent_message"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("recheck output leaked %q", forbidden)
		}
	}
}
