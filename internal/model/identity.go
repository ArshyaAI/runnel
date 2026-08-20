package model

import (
	"fmt"
	"time"
)

// ProcessIdentity is the portable identity used for attribution and display.
// PID alone is never identity.
type ProcessIdentity struct {
	PID        int32     `json:"pid"`
	StartTime  time.Time `json:"start_time"`
	UID        uint32    `json:"uid"`
	Executable string    `json:"executable"`
}

func (id ProcessIdentity) Complete() bool {
	return id.PID > 0 && !id.StartTime.IsZero() && id.Executable != ""
}

func (id ProcessIdentity) Equal(other ProcessIdentity) bool {
	return id.PID == other.PID &&
		id.StartTime.Equal(other.StartTime) &&
		id.UID == other.UID &&
		id.Executable == other.Executable
}

func (id ProcessIdentity) Validate() error {
	if id.PID <= 0 {
		return fmt.Errorf("model: pid must be positive")
	}
	if !id.StartTime.IsZero() && id.StartTime.Location() != time.UTC {
		return fmt.Errorf("model: start_time must use UTC")
	}
	return nil
}

// DarwinActionIdentity adds the kernel identity components required by the
// identity-bound Darwin signal primitive. A zero component is incomplete.
type DarwinActionIdentity struct {
	ProcessIdentity
	PIDVersion uint32 `json:"pid_version"`
	UniqueID   uint64 `json:"unique_id"`
}

func (id DarwinActionIdentity) Complete() bool {
	return id.ProcessIdentity.Complete() && id.PIDVersion != 0 && id.UniqueID != 0
}

func (id DarwinActionIdentity) Equal(other DarwinActionIdentity) bool {
	return id.ProcessIdentity.Equal(other.ProcessIdentity) &&
		id.PIDVersion == other.PIDVersion &&
		id.UniqueID == other.UniqueID
}

func (id DarwinActionIdentity) Validate() error {
	if err := id.ProcessIdentity.Validate(); err != nil {
		return err
	}
	if !id.ProcessIdentity.Complete() {
		return fmt.Errorf("model: portable action identity is incomplete")
	}
	if id.PIDVersion == 0 {
		return fmt.Errorf("model: pid_version is required")
	}
	if id.UniqueID == 0 {
		return fmt.Errorf("model: unique_id is required")
	}
	return nil
}
