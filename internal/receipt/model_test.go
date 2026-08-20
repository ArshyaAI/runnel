package receipt

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArshyaAI/runnel/internal/model"
)

func validModelIdentity() model.DarwinActionIdentity {
	return model.DarwinActionIdentity{
		ProcessIdentity: model.ProcessIdentity{PID: 42, StartTime: time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC), UID: 501, Executable: "/private/synthetic/node"},
		PIDVersion:      7,
		UniqueID:        99,
	}
}

func validModelEvidence() model.DetectorEvidence {
	return model.DetectorEvidence{
		Availability: []model.ProbeAvailability{{Probe: model.ProbeIdentity, Status: model.AvailabilityAvailable}},
		Codes:        []model.EvidenceCode{model.EvidenceChildless},
	}
}

func validPrepared() model.LocalPreparedReceipt {
	return model.LocalPreparedReceipt{
		SchemaVersion:       model.PreparedReceiptSchemaVersion,
		ToolVersion:         "0.1.0-test",
		ReceiptID:           "r-0123456789abcdef0123456789abcdef",
		PreparedAt:          time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC),
		DetectorID:          model.CodexV1DetectorID,
		Target:              validModelIdentity(),
		Protected:           []model.DarwinActionIdentity{},
		Evidence:            validModelEvidence(),
		ConfirmationBinding: strings.Repeat("b", 64),
		Outcome:             model.OutcomePrepared,
	}
}

func validResult() model.LocalResultReceipt {
	return model.LocalResultReceipt{
		SchemaVersion:        model.ResultReceiptSchemaVersion,
		ToolVersion:          "0.1.0-test",
		ReceiptID:            "r-0123456789abcdef0123456789abcdef",
		PreparedDigest:       strings.Repeat("a", 64),
		FinalizedAt:          time.Date(2026, 8, 20, 1, 1, 0, 0, time.UTC),
		Outcome:              model.OutcomeVerified,
		ConfirmationOK:       true,
		Revalidation:         validModelEvidence(),
		SignalAttempts:       []model.SignalAttempt{{Target: validModelIdentity(), Attempted: true, ErrorCode: model.ErrorNone}},
		TargetExitCount:      1,
		ProtectedSignaled:    0,
		ProtectedPresent:     0,
		SelectedRSSBytes:     4096,
		MemoryPressureBefore: model.PressureElevated,
		MemoryPressureAfter:  model.PressureNominal,
		ErrorCodes:           []model.ErrorCode{},
	}
}

func TestModelStoreRoundTrip(t *testing.T) {
	base, err := os.MkdirTemp("/private/tmp", "runnel-model-store-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := NewModelStore(filepath.Join(base, "receipts"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	prepared := validPrepared()
	preparedData, err := EncodePrepared(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Prepare(context.Background(), prepared.ReceiptID, preparedData); err != nil {
		t.Fatal(err)
	}
	if err := store.ClaimExecution(context.Background(), prepared.ReceiptID, digestBytes(preparedData)); err != nil {
		t.Fatal(err)
	}
	duplicateIDResult := validResult()
	duplicateIDResult.PreparedDigest = digestBytes(preparedData)
	duplicateIDData, err := EncodeResult(duplicateIDResult)
	if err != nil {
		t.Fatal(err)
	}
	duplicateIDData = append([]byte(`{"receipt_id":"r-99999999999999999999999999999999",`), duplicateIDData[1:]...)
	if err := store.Finalize(context.Background(), prepared.ReceiptID, duplicateIDData); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("duplicate result receipt_id accepted: %v", err)
	}
	for name, mutate := range map[string]func(*model.LocalResultReceipt){
		"receipt id": func(result *model.LocalResultReceipt) {
			result.ReceiptID = "r-99999999999999999999999999999999"
		},
		"prepared digest": func(result *model.LocalResultReceipt) {
			result.PreparedDigest = strings.Repeat("c", 64)
		},
		"attempt target": func(result *model.LocalResultReceipt) {
			result.SignalAttempts[0].Target.PIDVersion++
		},
	} {
		t.Run("reject mismatched "+name, func(t *testing.T) {
			result := validResult()
			result.PreparedDigest = digestBytes(preparedData)
			mutate(&result)
			data, err := EncodeResult(result)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Finalize(context.Background(), prepared.ReceiptID, data); !errors.Is(err, ErrInvalidState) {
				t.Fatalf("expected linkage rejection, got %v", err)
			}
			if _, err := os.Stat(filepath.Join(store.Root(), prepared.ReceiptID, resultName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("mismatched result mutated final state: %v", err)
			}
		})
	}
	result := validResult()
	result.PreparedDigest = digestBytes(preparedData)
	resultData, err := EncodeResult(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Finalize(context.Background(), prepared.ReceiptID, resultData); err != nil {
		t.Fatal(err)
	}
	state, got, err := store.Read(context.Background(), prepared.ReceiptID)
	if err != nil {
		t.Fatal(err)
	}
	if state != StateResult || !bytes.Equal(got, resultData) {
		t.Fatalf("unexpected stored result: %s %s", state, got)
	}
}

func TestShareEncoderRejectsPrivateAndUnknownFields(t *testing.T) {
	share := model.ShareReceipt{
		SchemaVersion:        model.ShareReceiptSchemaVersion,
		ToolVersion:          "0.1.0-test",
		Platform:             model.Platform{OS: "darwin", Arch: "arm64"},
		DetectorID:           model.CodexV1DetectorID,
		SupportState:         model.SupportSupported,
		Availability:         []model.ProbeAvailability{{Probe: model.ProbeIdentity, Status: model.AvailabilityAvailable}},
		Evidence:             []model.EvidenceCode{model.EvidenceChildless},
		TargetCount:          1,
		DurationBucket:       model.Duration5To10s,
		SelectedRSSBytes:     4096,
		TargetExitCount:      1,
		ProtectedSignaled:    0,
		ProtectedPresent:     1,
		MemoryPressureBefore: model.PressureElevated,
		MemoryPressureAfter:  model.PressureNominal,
		Outcome:              model.OutcomeVerified,
		ErrorCodes:           []model.ErrorCode{},
	}
	data, err := EncodeShareReceipt(share)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"pid", "path", "argv", "cwd", "session", "stack", "port", "username", "hostname", "prepared_digest", "confirmation_binding", "confirmation_token"} {
		if strings.Contains(strings.ToLower(string(data)), `"`+forbidden+`"`) {
			t.Fatalf("share output contains forbidden key %q: %s", forbidden, data)
		}
	}
}

func TestDefaultRootOverridesMustBeAbsolute(t *testing.T) {
	t.Setenv(dataHomeEnv, "relative")
	if _, err := DefaultRoot(); err == nil {
		t.Fatal("expected relative override rejection")
	}
	t.Setenv(dataHomeEnv, "/private/tmp/runnel-data")
	root, err := DefaultRoot()
	if err != nil {
		t.Fatal(err)
	}
	if root != "/private/tmp/runnel-data/receipts" {
		t.Fatalf("unexpected root: %s", root)
	}
}
