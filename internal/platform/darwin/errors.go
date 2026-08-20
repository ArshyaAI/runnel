package darwin

import (
	"errors"
	"fmt"
)

var (
	// ErrUnsupported is returned when the current build or Darwin runtime does
	// not expose a required primitive. Callers must treat it as fail-closed.
	ErrUnsupported = errors.New("darwin primitive unsupported")
	// ErrIdentityMismatch means the process no longer has the exact identity
	// supplied by the caller. It deliberately unwraps to the platform ESRCH
	// value on Darwin.
	ErrIdentityMismatch  = errors.New("process identity changed")
	ErrOutputLimit       = errors.New("probe output limit exceeded")
	ErrEscapedChild      = errors.New("probe descendant escaped its process group")
	ErrOriginMismatch    = errors.New("executable origin mismatch")
	ErrProtectedIdentity = errors.New("protected process identity")
)

// OperationError preserves a stable operation name and availability code
// without forcing renderers to expose a raw platform error.
type OperationError struct {
	Op           string
	Availability Availability
	Err          error
}

func (e *OperationError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Err == nil {
		return fmt.Sprintf("%s: %s", e.Op, e.Availability)
	}
	return fmt.Sprintf("%s: %s: %v", e.Op, e.Availability, e.Err)
}

func (e *OperationError) Unwrap() error { return e.Err }
