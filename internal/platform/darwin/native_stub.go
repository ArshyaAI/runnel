//go:build !darwin || !cgo

package darwin

import "syscall"

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

type nativeCodeResult struct {
	Identifier string
	Team       string
	Status     int32
}

func nativeListPIDs(_ int) ([]int32, bool, error) { return nil, false, ErrUnsupported }
func nativeChildCapability() Capability {
	return Capability{Availability: UnsupportedPlatform, Reason: "requires Darwin with CGO"}
}
func nativeListChildPIDs(_ int32, _ int) ([]int32, error) { return nil, ErrUnsupported }
func nativeReadProcess(_ int32) (nativeProcess, error)    { return nativeProcess{}, ErrUnsupported }
func nativeReadIdentity(_ int32) (nativeProcess, error)   { return nativeProcess{}, ErrUnsupported }
func nativeArgv(_ int32, _ int) ([]byte, error)           { return nil, ErrUnsupported }
func nativeListFDs(_ int32, _ int) ([]nativeFD, bool, error) {
	return nil, false, ErrUnsupported
}
func nativeSignalCapability() Capability {
	return Capability{Availability: UnsupportedPlatform, Reason: "requires Darwin with CGO"}
}
func nativeSignalTERM(_ int32, _ uint32) error        { return ErrUnsupported }
func nativePIDPath(_ int32, _ uint32) (string, error) { return "", ErrUnsupported }
func nativeCheckStaticCode(_, _ string) (nativeCodeResult, error) {
	return nativeCodeResult{}, ErrUnsupported
}
