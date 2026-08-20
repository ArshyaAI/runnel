package darwin

import (
	"context"
	"errors"
	"sort"
	"syscall"
	"time"

	"github.com/ArshyaAI/runnel/internal/model"
)

type DescriptorKind string

const (
	DescriptorUnknown DescriptorKind = "unknown"
	DescriptorVnode   DescriptorKind = "vnode"
	DescriptorSocket  DescriptorKind = "socket"
	DescriptorPipe    DescriptorKind = "pipe"
	DescriptorKqueue  DescriptorKind = "kqueue"
	DescriptorOther   DescriptorKind = "other"
)

type FileDescriptorStat struct {
	Path       string
	Device     uint64
	Inode      uint64
	Size       uint64
	ModifiedAt time.Time
	OpenFlags  uint32
	Offset     int64
	Writable   bool
}

type SocketDescriptorStat struct {
	Family      int32
	Type        int32
	Protocol    int32
	State       int32
	LocalPort   uint16
	RemotePort  uint16
	Listening   bool
	Established bool
}

type Descriptor struct {
	FD           int32
	Kind         DescriptorKind
	File         *FileDescriptorStat
	Socket       *SocketDescriptorStat
	Availability model.Availability
}

type DescriptorSnapshot struct {
	Identity     model.DarwinActionIdentity
	Descriptors  []Descriptor
	Listening    uint32
	Established  uint32
	Truncated    bool
	Availability model.Availability
}

// Descriptors returns a bounded per-process descriptor snapshot. The exact
// action identity is checked before and after all PID-addressed read-only calls;
// any PID reuse or exec invalidates the complete result.
func (c *Collector) Descriptors(ctx context.Context, identity model.DarwinActionIdentity, maxFDs int) (DescriptorSnapshot, error) {
	if err := identity.Validate(); err != nil {
		return DescriptorSnapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return DescriptorSnapshot{}, err
	}
	if maxFDs <= 0 {
		maxFDs = c.config.withDefaults().MaxFDs
	}
	maxFDs = min(maxFDs, hardMaxFDs)
	before, err := nativeReadIdentity(identity.PID)
	if err != nil {
		return DescriptorSnapshot{}, identityReadError("descriptor_identity_before", err)
	}
	if !actionIdentityFromNative(before).Equal(identity) {
		return DescriptorSnapshot{}, identityMismatch("descriptor_identity_before")
	}
	entries, truncated, err := nativeListFDs(identity.PID, maxFDs)
	if err != nil {
		availability := availabilityForError(err)
		return DescriptorSnapshot{}, &OperationError{Op: "descriptor_list", Availability: availability, Err: err}
	}
	after, err := nativeReadIdentity(identity.PID)
	if err != nil {
		return DescriptorSnapshot{}, identityReadError("descriptor_identity_after", err)
	}
	if !actionIdentityFromNative(after).Equal(identity) {
		return DescriptorSnapshot{}, identityMismatch("descriptor_identity_after")
	}
	if err := ctx.Err(); err != nil {
		return DescriptorSnapshot{}, err
	}

	snapshot := DescriptorSnapshot{
		Identity:     identity,
		Truncated:    truncated,
		Availability: model.AvailabilityAvailable,
	}
	if truncated {
		snapshot.Availability = model.AvailabilityContradictory
	}
	for _, entry := range entries {
		descriptor := convertDescriptor(entry)
		if descriptor.Availability != model.AvailabilityAvailable {
			if snapshot.Availability == model.AvailabilityAvailable {
				snapshot.Availability = descriptor.Availability
			} else if snapshot.Availability != descriptor.Availability {
				snapshot.Availability = model.AvailabilityContradictory
			}
		}
		if descriptor.Socket != nil {
			if descriptor.Socket.Listening {
				snapshot.Listening++
			}
			if descriptor.Socket.Established {
				snapshot.Established++
			}
		}
		snapshot.Descriptors = append(snapshot.Descriptors, descriptor)
	}
	sort.Slice(snapshot.Descriptors, func(i, j int) bool { return snapshot.Descriptors[i].FD < snapshot.Descriptors[j].FD })
	return snapshot, nil
}

func convertDescriptor(entry nativeFD) Descriptor {
	descriptor := Descriptor{FD: entry.FD, Kind: descriptorKind(entry.Kind), Availability: availabilityForErrno(entry.DetailErrno)}
	if entry.Kind == 1 && entry.DetailErrno == 0 {
		if entry.Path == "" {
			descriptor.Availability = model.AvailabilityMalformedOutput
			return descriptor
		}
		accessMode := entry.OpenFlags & 0x3
		descriptor.File = &FileDescriptorStat{
			Path:       entry.Path,
			Device:     entry.Device,
			Inode:      entry.Inode,
			Size:       entry.Size,
			ModifiedAt: time.Unix(entry.MTimeSec, entry.MTimeNS).UTC(),
			OpenFlags:  entry.OpenFlags,
			Offset:     entry.Offset,
			Writable:   accessMode == 1 || accessMode == 2,
		}
	}
	if entry.Kind == 2 && entry.DetailErrno == 0 {
		descriptor.Socket = &SocketDescriptorStat{
			Family:      entry.SocketFamily,
			Type:        entry.SocketType,
			Protocol:    entry.SocketProtocol,
			State:       entry.SocketState,
			LocalPort:   entry.LocalPort,
			RemotePort:  entry.RemotePort,
			Listening:   entry.SocketState == 1,
			Established: entry.SocketState == 4,
		}
	}
	return descriptor
}

func descriptorKind(kind uint32) DescriptorKind {
	switch kind {
	case 1:
		return DescriptorVnode
	case 2:
		return DescriptorSocket
	case 5:
		return DescriptorKqueue
	case 6:
		return DescriptorPipe
	case 0:
		return DescriptorUnknown
	default:
		return DescriptorOther
	}
}

func identityMismatch(op string) error {
	return &OperationError{Op: op, Availability: model.AvailabilityProcessExited, Err: errors.Join(ErrIdentityMismatch, syscall.ESRCH)}
}

func identityReadError(op string, err error) error {
	if errors.Is(err, syscall.ESRCH) {
		return identityMismatch(op)
	}
	return &OperationError{Op: op, Availability: availabilityForError(err), Err: err}
}
