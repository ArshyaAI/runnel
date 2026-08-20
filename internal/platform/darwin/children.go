package darwin

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"syscall"

	"github.com/ArshyaAI/runnel/internal/model"
)

const (
	defaultMaxChildren = 1024
	hardMaxChildren    = 16_384
)

// ChildSnapshot is an identity-bound, direct-child view of one Darwin
// process. Only an Available, untruncated snapshot with no Failures is a
// complete answer; in particular, only such an empty snapshot proves that the
// selected process has no direct children.
type ChildSnapshot struct {
	Identity     model.DarwinActionIdentity
	Children     []ProcessRecord
	Failures     []ProcessFailure
	Truncated    bool
	Availability model.Availability
}

type childPIDLister interface {
	Capability() Capability
	List(parentPID int32, capacity int) ([]int32, error)
}

type nativeChildPIDLister struct{}

func (nativeChildPIDLister) Capability() Capability { return nativeChildCapability() }
func (nativeChildPIDLister) List(parentPID int32, capacity int) ([]int32, error) {
	return nativeListChildPIDs(parentPID, capacity)
}

// Children returns the bounded direct children of one exact Darwin process.
// It uses proc_listchildpids rather than inferring parentage from a host-wide
// process scan. The supplied parent identity is checked before and after the
// query, and every returned PID is resolved to a complete exact identity and
// ProcessObservation.
func (c *Collector) Children(ctx context.Context, identity model.DarwinActionIdentity, maxChildren int) (ChildSnapshot, error) {
	return c.children(ctx, identity, maxChildren, nativeChildPIDLister{})
}

func (c *Collector) children(ctx context.Context, identity model.DarwinActionIdentity, maxChildren int, lister childPIDLister) (ChildSnapshot, error) {
	snapshot := ChildSnapshot{
		Identity:     identity,
		Children:     []ProcessRecord{},
		Failures:     []ProcessFailure{},
		Availability: model.AvailabilityAvailable,
	}
	if err := identity.Validate(); err != nil {
		snapshot.Availability = model.AvailabilityMalformedOutput
		return snapshot, err
	}
	if err := ctx.Err(); err != nil {
		snapshot.Availability = childContextAvailability(err)
		return snapshot, err
	}
	capability := lister.Capability()
	if !capability.Supported() {
		snapshot.Availability = capability.Availability
		return snapshot, &OperationError{Op: "child_list", Availability: capability.Availability, Err: ErrUnsupported}
	}
	if maxChildren <= 0 {
		maxChildren = defaultMaxChildren
	}
	maxChildren = min(maxChildren, hardMaxChildren)

	before, err := nativeReadIdentity(identity.PID)
	if err != nil {
		snapshot.Availability = availabilityForError(err)
		return snapshot, identityReadError("child_parent_identity_before", err)
	}
	if !actionIdentityFromNative(before).Equal(identity) {
		snapshot.Availability = model.AvailabilityProcessExited
		return snapshot, identityMismatch("child_parent_identity_before")
	}

	// One extra PID distinguishes exactly maxChildren results from a result
	// that exceeds the caller's ceiling, while bounding native bytes to
	// (hardMaxChildren+1)*sizeof(pid_t).
	pids, err := lister.List(identity.PID, maxChildren+1)
	if err != nil {
		availability := availabilityForError(err)
		snapshot.Availability = availability
		return snapshot, &OperationError{Op: "child_list", Availability: availability, Err: err}
	}
	if err := ctx.Err(); err != nil {
		snapshot.Availability = childContextAvailability(err)
		return snapshot, err
	}
	slices.Sort(pids)
	if len(pids) > maxChildren {
		snapshot.Truncated = true
		snapshot.Availability = model.AvailabilityContradictory
		if err := c.verifyChildParentAfter(identity); err != nil {
			snapshot.Availability = availabilityForError(err)
			return snapshot, err
		}
		return snapshot, &OperationError{Op: "child_list", Availability: model.AvailabilityContradictory, Err: ErrOutputLimit}
	}
	for i, pid := range pids {
		if i > 0 && pid == pids[i-1] {
			snapshot.Availability = model.AvailabilityMalformedOutput
			return snapshot, &OperationError{Op: "child_list", Availability: snapshot.Availability, Err: fmt.Errorf("duplicate child pid %d", pid)}
		}
		if err := ctx.Err(); err != nil {
			snapshot.Availability = childContextAvailability(err)
			return snapshot, err
		}
		record, readErr := readProcessRecord(pid)
		failureAvailability := model.AvailabilityAvailable
		if readErr == nil && record.Observation.ParentPID != identity.PID {
			readErr = errors.Join(ErrIdentityMismatch, syscall.ESRCH)
		}
		if readErr == nil && !record.ActionIdentity.Complete() {
			failureAvailability = record.ActionAvailable
			if failureAvailability == model.AvailabilityAvailable {
				failureAvailability = model.AvailabilityUnsupportedVersion
			}
			readErr = &OperationError{Op: "child_identity", Availability: failureAvailability, Err: ErrUnsupported}
		}
		if readErr == nil {
			readErr = record.Observation.Validate()
		}
		if readErr != nil {
			availability := failureAvailability
			if availability == model.AvailabilityAvailable {
				availability = availabilityForError(readErr)
			}
			snapshot.Failures = append(snapshot.Failures, ProcessFailure{PID: pid, Availability: availability, Err: readErr})
			continue
		}
		snapshot.Children = append(snapshot.Children, record)
	}

	if err := ctx.Err(); err != nil {
		snapshot.Availability = childContextAvailability(err)
		return snapshot, err
	}
	if err := c.verifyChildParentAfter(identity); err != nil {
		snapshot.Availability = availabilityForError(err)
		return snapshot, err
	}
	if len(snapshot.Failures) != 0 {
		snapshot.Availability = childFailureAvailability(snapshot.Failures)
		joined := make([]error, 0, len(snapshot.Failures))
		for _, failure := range snapshot.Failures {
			joined = append(joined, fmt.Errorf("pid %d: %w", failure.PID, failure.Err))
		}
		return snapshot, &OperationError{Op: "child_resolve", Availability: snapshot.Availability, Err: errors.Join(joined...)}
	}
	return snapshot, nil
}

func (c *Collector) verifyChildParentAfter(identity model.DarwinActionIdentity) error {
	after, err := nativeReadIdentity(identity.PID)
	if err != nil {
		return identityReadError("child_parent_identity_after", err)
	}
	if !actionIdentityFromNative(after).Equal(identity) {
		return identityMismatch("child_parent_identity_after")
	}
	return nil
}

func childFailureAvailability(failures []ProcessFailure) model.Availability {
	availability := failures[0].Availability
	for _, failure := range failures[1:] {
		if failure.Availability != availability {
			return model.AvailabilityContradictory
		}
	}
	return availability
}

func childContextAvailability(err error) model.Availability {
	if errors.Is(err, context.DeadlineExceeded) {
		return model.AvailabilityTimeout
	}
	return model.AvailabilityContradictory
}
