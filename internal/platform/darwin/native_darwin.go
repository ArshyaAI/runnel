//go:build darwin && cgo

package darwin

/*
#cgo LDFLAGS: -lproc -framework Security -framework CoreFoundation
#include <stdlib.h>
#include "native_darwin.h"
*/
import "C"

import (
	"errors"
	"syscall"
	"unsafe"
)

type nativeProcess struct {
	PID             int32
	PPID            int32
	UID             uint32
	TTYDevice       uint32
	TTYProcessGroup int32
	HasTTY          bool
	TTYPath         string
	StartSec        uint64
	StartUsec       uint64
	CPUUserNS       uint64
	CPUSystemNS     uint64
	RSSBytes        uint64
	VMSBytes        uint64
	PIDVersion      uint32
	UniqueID        uint64
	Executable      string
	ExecutableErrno syscall.Errno
	CWD             string
	CWDErrno        syscall.Errno
}

type nativeFD struct {
	FD             int32
	Kind           uint32
	OpenFlags      uint32
	Offset         int64
	Device         uint64
	Inode          uint64
	Size           uint64
	MTimeSec       int64
	MTimeNS        int64
	SocketFamily   int32
	SocketType     int32
	SocketProtocol int32
	SocketState    int32
	LocalPort      uint16
	RemotePort     uint16
	DetailErrno    syscall.Errno
	Path           string
}

func nativeListPIDs(max int) ([]int32, bool, error) {
	if max <= 0 {
		return nil, false, syscall.EINVAL
	}
	pids := make([]C.int32_t, max)
	var truncated C.int
	count := int(C.runnel_list_pids(&pids[0], C.int(max), &truncated))
	if count < 0 {
		return nil, false, syscall.Errno(-count)
	}
	out := make([]int32, 0, count)
	for _, pid := range pids[:count] {
		if pid > 0 {
			out = append(out, int32(pid))
		}
	}
	return out, truncated != 0, nil
}

func nativeChildCapability() Capability {
	if C.runnel_have_listchildpids_symbol() == 0 {
		return Capability{Availability: UnsupportedVersion, Reason: "proc_listchildpids missing"}
	}
	return Capability{Availability: Available}
}

func nativeListChildPIDs(parentPID int32, capacity int) ([]int32, error) {
	if parentPID <= 0 || capacity <= 0 {
		return nil, syscall.EINVAL
	}
	pids := make([]C.int32_t, capacity)
	var count C.int
	code := C.runnel_list_child_pids(C.int32_t(parentPID), &pids[0], C.int(capacity), &count)
	if code != 0 {
		return nil, syscall.Errno(code)
	}
	if count < 0 || int(count) > len(pids) {
		return nil, syscall.EOVERFLOW
	}
	out := make([]int32, int(count))
	for i, pid := range pids[:int(count)] {
		if pid <= 0 {
			return nil, syscall.EIO
		}
		out[i] = int32(pid)
	}
	return out, nil
}

func nativeReadProcess(pid int32) (nativeProcess, error) {
	var value C.struct_runnel_process_info
	if code := C.runnel_read_process(C.int32_t(pid), &value); code != 0 {
		return nativeProcess{}, syscall.Errno(code)
	}
	return convertNativeProcess(value), nil
}

func nativeReadIdentity(pid int32) (nativeProcess, error) {
	var value C.struct_runnel_process_info
	if code := C.runnel_read_identity(C.int32_t(pid), &value); code != 0 {
		return nativeProcess{}, syscall.Errno(code)
	}
	return convertNativeProcess(value), nil
}

func nativeArgv(pid int32, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, syscall.EINVAL
	}
	buffer := make([]byte, maxBytes)
	var used C.int
	code := C.runnel_procargs(C.int32_t(pid), unsafe.Pointer(&buffer[0]), C.int(maxBytes), &used)
	if code != 0 {
		return nil, syscall.Errno(code)
	}
	if used < 0 || int(used) > len(buffer) {
		return nil, syscall.EOVERFLOW
	}
	return buffer[:int(used)], nil
}

func convertNativeProcess(value C.struct_runnel_process_info) nativeProcess {
	return nativeProcess{
		PID:             int32(value.pid),
		PPID:            int32(value.ppid),
		UID:             uint32(value.uid),
		TTYDevice:       uint32(value.tty_device),
		TTYProcessGroup: int32(value.tty_pgid),
		HasTTY:          value.has_tty != 0,
		TTYPath:         C.GoString(&value.tty_path[0]),
		StartSec:        uint64(value.start_sec),
		StartUsec:       uint64(value.start_usec),
		CPUUserNS:       uint64(value.cpu_user_ns),
		CPUSystemNS:     uint64(value.cpu_system_ns),
		RSSBytes:        uint64(value.rss_bytes),
		VMSBytes:        uint64(value.vms_bytes),
		PIDVersion:      uint32(value.pidversion),
		UniqueID:        uint64(value.uniqueid),
		Executable:      C.GoString(&value.executable[0]),
		ExecutableErrno: syscall.Errno(value.executable_errno),
		CWD:             C.GoString(&value.cwd[0]),
		CWDErrno:        syscall.Errno(value.cwd_errno),
	}
}

func nativeListFDs(pid int32, max int) ([]nativeFD, bool, error) {
	if max <= 0 {
		return nil, false, syscall.EINVAL
	}
	values := make([]C.struct_runnel_fd_entry, max)
	var count, truncated C.int
	code := C.runnel_list_fds(C.int32_t(pid), &values[0], C.int(max), &count, &truncated)
	if code != 0 {
		return nil, false, syscall.Errno(code)
	}
	out := make([]nativeFD, 0, int(count))
	for i := 0; i < int(count); i++ {
		value := values[i]
		out = append(out, nativeFD{
			FD:             int32(value.fd),
			Kind:           uint32(value.kind),
			OpenFlags:      uint32(value.open_flags),
			Offset:         int64(value.offset),
			Device:         uint64(value.device),
			Inode:          uint64(value.inode),
			Size:           uint64(value.size),
			MTimeSec:       int64(value.mtime_sec),
			MTimeNS:        int64(value.mtime_nsec),
			SocketFamily:   int32(value.socket_family),
			SocketType:     int32(value.socket_type),
			SocketProtocol: int32(value.socket_protocol),
			SocketState:    int32(value.socket_state),
			LocalPort:      uint16(value.local_port),
			RemotePort:     uint16(value.remote_port),
			DetailErrno:    syscall.Errno(value.detail_errno),
			Path:           C.GoString(&value.path[0]),
		})
	}
	return out, truncated != 0, nil
}

func nativeSignalCapability() Capability {
	if C.runnel_have_signal_symbol() == 0 {
		return Capability{Availability: UnsupportedVersion, Reason: "proc_signal_with_audittoken missing"}
	}
	return Capability{Availability: Available}
}

func nativeSignalTERM(pid int32, pidversion uint32) error {
	if code := C.runnel_signal_term(C.int32_t(pid), C.uint32_t(pidversion)); code != 0 {
		return syscall.Errno(code)
	}
	return nil
}

func nativePIDPath(pid int32, pidversion uint32) (string, error) {
	path := make([]C.char, C.RUNNEL_PATH_MAX)
	if code := C.runnel_pidpath_token(C.int32_t(pid), C.uint32_t(pidversion), &path[0], C.int(len(path))); code != 0 {
		return "", syscall.Errno(code)
	}
	return C.GoString(&path[0]), nil
}

type nativeCodeResult struct {
	Identifier string
	Team       string
	Status     int32
}

func nativeCheckStaticCode(path, requirement string) (nativeCodeResult, error) {
	cPath := C.CString(path)
	cRequirement := C.CString(requirement)
	defer C.free(unsafe.Pointer(cPath))
	defer C.free(unsafe.Pointer(cRequirement))
	identifier := make([]C.char, 512)
	team := make([]C.char, 128)
	var status C.int32_t
	code := C.runnel_verify_static_code(cPath, cRequirement, &identifier[0], C.int(len(identifier)), &team[0], C.int(len(team)), &status)
	if code != 0 {
		return nativeCodeResult{}, syscall.Errno(code)
	}
	result := nativeCodeResult{Identifier: C.GoString(&identifier[0]), Team: C.GoString(&team[0]), Status: int32(status)}
	if result.Status != 0 {
		return result, errors.Join(ErrOriginMismatch, securityStatusError(result.Status))
	}
	return result, nil
}

type securityStatusError int32

func (e securityStatusError) Error() string { return "Security.framework rejected static code" }
