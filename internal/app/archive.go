// Package app composes Runnel's user-facing services without granting the UI
// direct process capabilities.
package app

import (
	"context"
	"errors"
	"fmt"
	"runtime"

	"github.com/ArshyaAI/runnel/internal/model"
	"github.com/ArshyaAI/runnel/internal/receipt"
)

var ErrShareUnavailable = errors.New("share receipt is unavailable until a result is durable")

// Archive is a lazy receipt service. Constructing it and running the default
// scan perform no filesystem mutation; the safe receipt root is opened only
// for an explicit history or receipt command.
type Archive struct {
	Root string
}

func (a Archive) root() (string, error) {
	if a.Root != "" {
		return a.Root, nil
	}
	return receipt.DefaultRoot()
}

func (a Archive) open() (*receipt.Store, error) {
	root, err := a.root()
	if err != nil {
		return nil, err
	}
	return receipt.NewModelStore(root)
}

func (a Archive) History(ctx context.Context) ([]receipt.Entry, error) {
	store, err := a.open()
	if err != nil {
		return nil, err
	}
	defer store.Close()
	return store.List(ctx)
}

func (a Archive) Receipt(ctx context.Context, id string, share bool) ([]byte, error) {
	store, err := a.open()
	if err != nil {
		return nil, err
	}
	defer store.Close()
	state, data, err := store.Read(ctx, id)
	if err != nil {
		return nil, err
	}
	if !share {
		return data, nil
	}
	if state != receipt.StateResult {
		return nil, ErrShareUnavailable
	}
	return encodeShareResult(data)
}

func encodeShareResult(data []byte) ([]byte, error) {
	var local model.LocalResultReceipt
	if err := model.DecodeStrict(data, &local); err != nil {
		return nil, fmt.Errorf("decode private result: %w", err)
	}
	share := model.ShareReceipt{
		SchemaVersion:        model.ShareReceiptSchemaVersion,
		ToolVersion:          local.ToolVersion,
		Platform:             model.Platform{OS: runtime.GOOS, Arch: runtime.GOARCH},
		DetectorID:           model.CodexV1DetectorID,
		SupportState:         model.SupportSupported,
		Availability:         append([]model.ProbeAvailability{}, local.Revalidation.Availability...),
		Evidence:             append([]model.EvidenceCode{}, local.Revalidation.Codes...),
		TargetCount:          1,
		DurationBucket:       model.DurationUnknown,
		SelectedRSSBytes:     local.SelectedRSSBytes,
		TargetExitCount:      local.TargetExitCount,
		ProtectedSignaled:    local.ProtectedSignaled,
		ProtectedPresent:     local.ProtectedPresent,
		MemoryPressureBefore: local.MemoryPressureBefore,
		MemoryPressureAfter:  local.MemoryPressureAfter,
		Outcome:              local.Outcome,
		ErrorCodes:           append([]model.ErrorCode{}, local.ErrorCodes...),
	}
	return receipt.EncodeShareReceipt(share)
}
