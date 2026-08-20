package codex

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/ArshyaAI/runnel/internal/model"
)

type realRecheckFixture struct {
	sqliteFixture
	store      *Store
	tailReader *TailReader
	descriptor DescriptorEvidence
	detector   DetectorResult
	request    ActionRecheckRequest
}

func newRealRecheckFixture(t *testing.T) realRecheckFixture {
	t.Helper()
	database := newSQLiteFixture(t, "", "")
	if err := os.WriteFile(database.rollout, []byte(completionLine("private completion body")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	database.insert(t, SupportedCodexVersion, "subagent", "closed", "private database body")
	store := openTestStore(t, database, StoreOptions{})
	metadata, err := store.Snapshot(context.Background(), database.rollout)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(database.rollout)
	if err != nil {
		t.Fatal(err)
	}
	file, err := fileIdentity(info)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := DescriptorEvidence{
		Availability: model.AvailabilityAvailable, Path: database.rollout,
		Device: file.Device, Inode: file.Inode, Access: DescriptorReadOnly,
	}
	tailReader := NewTailReader(TailReaderOptions{})
	tail, err := tailReader.Read(context.Background(), database.rollout, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	samples := validDeepSamples(t)
	for i := range samples {
		samples[i].Metadata = metadata
		samples[i].Tail = tail
		samples[i].Descriptor = descriptor
	}
	detector := Evaluate(samples)
	if !detector.Selectable {
		t.Fatalf("real synthetic fixture refused: %#v", detector)
	}
	return realRecheckFixture{
		sqliteFixture: database, store: store, tailReader: tailReader,
		descriptor: descriptor, detector: detector, request: validRecheckRequest(t, samples),
	}
}

func TestRealActionRecheckNoChangeAllowed(t *testing.T) {
	fixture := newRealRecheckFixture(t)
	result := Recheck(context.Background(), fixture.detector, fixture.request, fixture.store, fixture.tailReader)
	if !result.Allowed || !slices.Equal(result.Codes, []Code{CodeActionRecheckExact}) {
		t.Fatalf("result=%#v", result)
	}
}

func TestRealActionRecheckDataVersionRaceRefuses(t *testing.T) {
	fixture := newRealRecheckFixture(t)
	if _, err := fixture.writer.Exec(`UPDATE threads SET private_body = private_body || 'changed' WHERE id = 'synthetic-child'`); err != nil {
		t.Fatal(err)
	}
	result := Recheck(context.Background(), fixture.detector, fixture.request, fixture.store, fixture.tailReader)
	if result.Allowed || !slices.Contains(result.Codes, CodeMetadataChanged) {
		t.Fatalf("result=%#v", result)
	}
}

func TestRealActionRecheckRowValueRefuses(t *testing.T) {
	fixture := newRealRecheckFixture(t)
	if _, err := fixture.writer.Exec(`UPDATE thread_spawn_edges SET status = 'running' WHERE child_thread_id = 'synthetic-child'`); err != nil {
		t.Fatal(err)
	}
	result := Recheck(context.Background(), fixture.detector, fixture.request, fixture.store, fixture.tailReader)
	if result.Allowed || !slices.Contains(result.Codes, CodeMetadataValueInvalid) {
		t.Fatalf("result=%#v", result)
	}
}

func TestRealActionRecheckTerminalTailChangeRefuses(t *testing.T) {
	fixture := newRealRecheckFixture(t)
	file, err := os.OpenFile(fixture.rollout, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString(`{"timestamp":"2026-08-20T00:00:07.000Z","type":"event_msg","payload":{"type":"task_started"}}` + "\n")
	_ = file.Close()
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	result := Recheck(context.Background(), fixture.detector, fixture.request, fixture.store, fixture.tailReader)
	if result.Allowed || !slices.Contains(result.Codes, CodeTerminalUnknown) {
		t.Fatalf("result=%#v", result)
	}
}

func TestRealActionRecheckChangedInodeRefuses(t *testing.T) {
	fixture := newRealRecheckFixture(t)
	old := fixture.rollout + ".old"
	if err := os.Rename(fixture.rollout, old); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.rollout, []byte(completionLine("replacement")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := Recheck(context.Background(), fixture.detector, fixture.request, fixture.store, fixture.tailReader)
	if result.Allowed || !slices.Contains(result.Codes, CodeDescriptorMismatch) {
		t.Fatalf("result=%#v", result)
	}
}
