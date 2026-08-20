package darwin

import (
	"context"
	"errors"
	"os"
	"syscall"

	"github.com/ArshyaAI/runnel/internal/model"
)

type signalBackend interface {
	Capability() Capability
	ReadIdentity(int32) (model.DarwinActionIdentity, error)
	SignalTERM(int32, uint32) error
}

type systemSignalBackend struct{}

func (systemSignalBackend) Capability() Capability { return nativeSignalCapability() }
func (systemSignalBackend) ReadIdentity(pid int32) (model.DarwinActionIdentity, error) {
	value, err := nativeReadIdentity(pid)
	if err != nil {
		return model.DarwinActionIdentity{}, err
	}
	return actionIdentityFromNative(value), nil
}
func (systemSignalBackend) SignalTERM(pid int32, version uint32) error {
	return nativeSignalTERM(pid, version)
}

// AuditTokenSignaler exposes one operation: identity-bound SIGTERM. It has no
// raw-PID or arbitrary-signal method.
type AuditTokenSignaler struct{ backend signalBackend }

func NewAuditTokenSignaler() *AuditTokenSignaler {
	return &AuditTokenSignaler{backend: systemSignalBackend{}}
}

func (s *AuditTokenSignaler) Capability() Capability {
	if s == nil || s.backend == nil {
		return Capability{Availability: UnsupportedVersion, Reason: "signal backend unavailable"}
	}
	return s.backend.Capability()
}

func (s *AuditTokenSignaler) SignalTERM(ctx context.Context, identity model.DarwinActionIdentity) error {
	if err := identity.Validate(); err != nil {
		return err
	}
	if identity.PID == int32(os.Getpid()) {
		return ErrProtectedIdentity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	capability := s.Capability()
	if !capability.Supported() {
		return &OperationError{Op: "signal_capability", Availability: capability.Availability, Err: ErrUnsupported}
	}
	current, err := s.backend.ReadIdentity(identity.PID)
	if err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return identityMismatch("signal_revalidate")
		}
		return &OperationError{Op: "signal_revalidate", Availability: availabilityForError(err), Err: err}
	}
	if !current.Equal(identity) {
		return identityMismatch("signal_revalidate")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// The native backend dynamically resolves proc_signal_with_audittoken and
	// hardcodes SIGTERM. A reused PID or successful exec after revalidation is
	// rejected by the kernel's pidversion lookup with ESRCH.
	if err := s.backend.SignalTERM(identity.PID, identity.PIDVersion); err != nil {
		availability := availabilityForError(err)
		if errors.Is(err, syscall.ESRCH) {
			availability = model.AvailabilityProcessExited
		}
		return &OperationError{Op: "signal_term_audittoken", Availability: availability, Err: err}
	}
	return nil
}
