package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArshyaAI/runnel/internal/model"
	"github.com/ArshyaAI/runnel/internal/receipt"
)

func TestArchiveHistoryPrivateAndShareReceipt(t *testing.T) {
	root := archiveTestRoot(t)
	id := "r-0123456789abcdef0123456789abcdef"
	prepared, result := archiveReceipts(id)
	preparedData, err := receipt.EncodePrepared(prepared)
	if err != nil {
		t.Fatal(err)
	}
	preparedDigest := fmt.Sprintf("%x", sha256.Sum256(preparedData))
	result.PreparedDigest = preparedDigest
	resultData, err := receipt.EncodeResult(result)
	if err != nil {
		t.Fatal(err)
	}
	store, err := receipt.NewModelStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Prepare(context.Background(), id, preparedData); err != nil {
		t.Fatal(err)
	}
	if err := store.ClaimExecution(context.Background(), id, preparedDigest); err != nil {
		t.Fatal(err)
	}
	if err := store.Finalize(context.Background(), id, resultData); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	archive := Archive{Root: root}
	entries, err := archive.History(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ID != id || entries[0].State != receipt.StateResult {
		t.Fatalf("entries = %#v", entries)
	}
	private, err := archive.Receipt(context.Background(), id, false)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(private, resultData) {
		t.Fatal("private receipt changed")
	}
	public, err := archive.Receipt(context.Background(), id, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"receipt_id", "signal_attempts", "pid", "start_time", "executable", "finalized_at"} {
		if strings.Contains(string(public), forbidden) {
			t.Fatalf("share receipt leaked %q: %s", forbidden, public)
		}
	}
	var decoded model.ShareReceipt
	if err := json.Unmarshal(public, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	if decoded.TargetCount != 1 || decoded.TargetExitCount != 1 || decoded.SelectedRSSBytes != result.SelectedRSSBytes {
		t.Fatalf("share reconciliation = %#v", decoded)
	}
}

func TestArchiveRefusesShareOfPreparedTransaction(t *testing.T) {
	root := archiveTestRoot(t)
	id := "r-fedcba9876543210fedcba9876543210"
	prepared, _ := archiveReceipts(id)
	data, err := receipt.EncodePrepared(prepared)
	if err != nil {
		t.Fatal(err)
	}
	store, err := receipt.NewModelStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Prepare(context.Background(), id, data); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = (Archive{Root: root}).Receipt(context.Background(), id, true)
	if !errors.Is(err, ErrShareUnavailable) {
		t.Fatalf("share prepared error = %v", err)
	}
}

func archiveTestRoot(t *testing.T) string {
	t.Helper()
	base, err := os.MkdirTemp("/private/tmp", "runnel-archive-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(base, "receipts")
}

func archiveReceipts(id string) (model.LocalPreparedReceipt, model.LocalResultReceipt) {
	when := time.Date(2026, 8, 20, 1, 2, 3, 0, time.UTC)
	target := model.DarwinActionIdentity{
		ProcessIdentity: model.ProcessIdentity{PID: 42, StartTime: when.Add(-time.Hour), UID: 501, Executable: "/synthetic/bin/node"},
		PIDVersion:      7,
		UniqueID:        9,
	}
	evidence := model.DetectorEvidence{
		Availability: []model.ProbeAvailability{{Probe: model.ProbeOrigin, Status: model.AvailabilityAvailable}},
		Codes:        []model.EvidenceCode{model.EvidenceOriginExact},
	}
	prepared := model.LocalPreparedReceipt{
		SchemaVersion:       model.PreparedReceiptSchemaVersion,
		ToolVersion:         "0.1.0-test",
		ReceiptID:           id,
		PreparedAt:          when,
		DetectorID:          model.CodexV1DetectorID,
		Target:              target,
		Protected:           []model.DarwinActionIdentity{},
		Evidence:            evidence,
		ConfirmationBinding: strings.Repeat("b", 64),
		Outcome:             model.OutcomePrepared,
	}
	result := model.LocalResultReceipt{
		SchemaVersion:        model.ResultReceiptSchemaVersion,
		ToolVersion:          "0.1.0-test",
		ReceiptID:            id,
		PreparedDigest:       strings.Repeat("a", 64),
		FinalizedAt:          when.Add(time.Second),
		Outcome:              model.OutcomeVerified,
		ConfirmationOK:       true,
		Revalidation:         evidence,
		SignalAttempts:       []model.SignalAttempt{{Target: target, Attempted: true, ErrorCode: model.ErrorNone}},
		TargetExitCount:      1,
		ProtectedPresent:     2,
		SelectedRSSBytes:     8192,
		MemoryPressureBefore: model.PressureElevated,
		MemoryPressureAfter:  model.PressureNominal,
		ErrorCodes:           []model.ErrorCode{},
	}
	return prepared, result
}
