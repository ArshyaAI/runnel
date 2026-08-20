package receipt

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ArshyaAI/runnel/internal/model"
	"github.com/ArshyaAI/runnel/schema"
)

const dataHomeEnv = "RUNNEL_DATA_HOME"

func DefaultRoot() (string, error) {
	if configured := os.Getenv(dataHomeEnv); configured != "" {
		if !filepath.IsAbs(configured) {
			return "", fmt.Errorf("%w: %s must be absolute", ErrInvalidPath, dataHomeEnv)
		}
		return filepath.Join(filepath.Clean(configured), "receipts"), nil
	}
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		if !filepath.IsAbs(xdg) {
			return "", fmt.Errorf("%w: XDG_DATA_HOME must be absolute", ErrInvalidPath)
		}
		return filepath.Join(filepath.Clean(xdg), "runnel", "receipts"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home: %w", err)
	}
	if !filepath.IsAbs(home) {
		return "", fmt.Errorf("%w: user home is not absolute", ErrInvalidPath)
	}
	return filepath.Join(home, "Library", "Application Support", "Runnel", "receipts"), nil
}

func NewModelStore(root string) (*Store, error) {
	return NewStore(root, validatePreparedReceipt, validateResultReceipt)
}

func EncodePrepared(value model.LocalPreparedReceipt) ([]byte, error) {
	data, err := model.MarshalDeterministic(value)
	if err != nil {
		return nil, err
	}
	if err := schema.Validate(schema.PreparedReceipt, data); err != nil {
		return nil, err
	}
	return data, nil
}

func EncodeResult(value model.LocalResultReceipt) ([]byte, error) {
	data, err := model.MarshalDeterministic(value)
	if err != nil {
		return nil, err
	}
	if err := schema.Validate(schema.ResultReceipt, data); err != nil {
		return nil, err
	}
	return data, nil
}

// EncodeShareReceipt accepts only the already-allowlisted public type. It has no
// overload that accepts either private receipt type.
func EncodeShareReceipt(value model.ShareReceipt) ([]byte, error) {
	data, err := model.MarshalDeterministic(value)
	if err != nil {
		return nil, err
	}
	if err := schema.Validate(schema.ShareReceipt, data); err != nil {
		return nil, err
	}
	return data, nil
}

func EncodeShareSnapshot(value model.ShareSnapshot) ([]byte, error) {
	data, err := model.MarshalDeterministic(value)
	if err != nil {
		return nil, err
	}
	if err := schema.Validate(schema.ShareSnapshot, data); err != nil {
		return nil, err
	}
	return data, nil
}

func validatePreparedReceipt(data []byte) error {
	if err := schema.Validate(schema.PreparedReceipt, data); err != nil {
		return err
	}
	var value model.LocalPreparedReceipt
	return model.DecodeStrict(data, &value)
}

func validateResultReceipt(data []byte) error {
	if err := schema.Validate(schema.ResultReceipt, data); err != nil {
		return err
	}
	var value model.LocalResultReceipt
	return model.DecodeStrict(data, &value)
}
