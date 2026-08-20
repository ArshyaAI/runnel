package darwin

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"syscall"
	"unicode/utf8"

	"github.com/ArshyaAI/runnel/internal/model"
)

const (
	defaultArgvBytes = 256 << 10
	hardArgvBytes    = 1 << 20
	hardArgvCount    = 4096
)

// Argv reads KERN_PROCARGS2 directly and binds the result to the complete
// Darwin action identity on both sides. It never invokes ps or a shell.
func (c *Collector) Argv(ctx context.Context, identity model.DarwinActionIdentity, maxBytes int) ([]string, model.Availability, error) {
	if err := identity.Validate(); err != nil {
		return nil, model.AvailabilityMalformedOutput, err
	}
	if maxBytes <= 0 {
		maxBytes = defaultArgvBytes
	}
	maxBytes = min(maxBytes, hardArgvBytes)
	if err := ctx.Err(); err != nil {
		return nil, availabilityForError(err), err
	}
	before, err := nativeReadIdentity(identity.PID)
	if err != nil {
		return nil, availabilityForError(err), identityReadError("argv_identity_before", err)
	}
	if !actionIdentityFromNative(before).Equal(identity) {
		return nil, model.AvailabilityProcessExited, identityMismatch("argv_identity_before")
	}
	raw, err := nativeArgv(identity.PID, maxBytes)
	if err != nil {
		if errors.Is(err, syscall.ENOMEM) || errors.Is(err, syscall.EOVERFLOW) {
			return nil, model.AvailabilityContradictory, &OperationError{Op: "argv_read", Availability: model.AvailabilityContradictory, Err: ErrOutputLimit}
		}
		availability := availabilityForError(err)
		return nil, availability, &OperationError{Op: "argv_read", Availability: availability, Err: err}
	}
	if len(raw) >= maxBytes {
		return nil, model.AvailabilityContradictory, &OperationError{Op: "argv_read", Availability: model.AvailabilityContradictory, Err: ErrOutputLimit}
	}
	argv, err := ParseKERNProcArgs2(raw, hardArgvCount)
	if err != nil {
		return nil, model.AvailabilityMalformedOutput, &OperationError{Op: "argv_parse", Availability: model.AvailabilityMalformedOutput, Err: err}
	}
	after, err := nativeReadIdentity(identity.PID)
	if err != nil {
		return nil, availabilityForError(err), identityReadError("argv_identity_after", err)
	}
	if !actionIdentityFromNative(after).Equal(identity) {
		return nil, model.AvailabilityProcessExited, identityMismatch("argv_identity_after")
	}
	if err := ctx.Err(); err != nil {
		return nil, availabilityForError(err), err
	}
	return argv, model.AvailabilityAvailable, nil
}

// ParseKERNProcArgs2 parses the Darwin KERN_PROCARGS2 layout: native-endian
// argc, executable path, alignment NULs, then exactly argc NUL-terminated argv
// values. Environment strings after argv are ignored.
func ParseKERNProcArgs2(data []byte, maxArgs int) ([]string, error) {
	if maxArgs <= 0 || maxArgs > hardArgvCount {
		maxArgs = hardArgvCount
	}
	if len(data) < 4 || len(data) > hardArgvBytes {
		return nil, ErrOutputLimit
	}
	argc32 := int32(binary.NativeEndian.Uint32(data[:4]))
	if argc32 < 0 || int(argc32) > maxArgs {
		return nil, errors.New("KERN_PROCARGS2 argc exceeds ceiling")
	}
	argc := int(argc32)
	cursor := 4
	executableEnd := bytes.IndexByte(data[cursor:], 0)
	if executableEnd <= 0 {
		return nil, errors.New("KERN_PROCARGS2 executable path missing")
	}
	if !utf8.Valid(data[cursor : cursor+executableEnd]) {
		return nil, errors.New("KERN_PROCARGS2 executable path is not UTF-8")
	}
	cursor += executableEnd + 1
	for cursor < len(data) && data[cursor] == 0 {
		cursor++
	}
	argv := make([]string, 0, argc)
	for i := 0; i < argc; i++ {
		if cursor > len(data) {
			return nil, errors.New("KERN_PROCARGS2 argv truncated")
		}
		end := bytes.IndexByte(data[cursor:], 0)
		if end < 0 {
			return nil, errors.New("KERN_PROCARGS2 argv terminator missing")
		}
		argument := data[cursor : cursor+end]
		if !utf8.Valid(argument) {
			return nil, errors.New("KERN_PROCARGS2 argument is not UTF-8")
		}
		argv = append(argv, string(argument))
		cursor += end + 1
	}
	return argv, nil
}
