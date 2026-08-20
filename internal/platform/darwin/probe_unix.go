//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package darwin

import (
	"errors"
	"os/exec"
	"syscall"
)

type probeSignal int

const (
	probeSignalTerm probeSignal = probeSignal(syscall.SIGTERM)
	probeSignalKill probeSignal = probeSignal(syscall.SIGKILL)
)

func configureIsolatedProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func verifyIsolatedProcessGroup(pid int) error {
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		return err
	}
	if pgid != pid {
		return errors.New("probe process group is not isolated")
	}
	return nil
}

func signalOwnedProcessGroup(pid int, signal probeSignal) error {
	pgid, err := syscall.Getpgid(pid)
	if err != nil {
		return err
	}
	if pgid != pid {
		return errors.New("refusing to signal non-isolated process group")
	}
	return syscall.Kill(-pgid, syscall.Signal(signal))
}
