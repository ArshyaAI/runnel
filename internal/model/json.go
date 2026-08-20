package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

type Validatable interface{ Validate() error }

// MarshalDeterministic validates the value, then emits compact JSON. Public
// model types contain no maps, so struct field and slice order define the exact
// byte order.
func MarshalDeterministic(value Validatable) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("model: nil value")
	}
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

// DecodeStrict rejects unknown properties, trailing documents, and invalid
// enum/model states.
func DecodeStrict(data []byte, dst Validatable) error {
	if dst == nil {
		return fmt.Errorf("model: nil destination")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("model: decode: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("model: trailing JSON document")
		}
		return fmt.Errorf("model: trailing JSON: %w", err)
	}
	if err := dst.Validate(); err != nil {
		return err
	}
	return nil
}
