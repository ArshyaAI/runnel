//go:build windows

package darwin

import (
	"errors"
	"os/exec"
)

type probeSignal int

const (
	probeSignalTerm probeSignal = iota + 1
	probeSignalKill
)

func configureIsolatedProcessGroup(_ *exec.Cmd) {}
func verifyIsolatedProcessGroup(_ int) error    { return ErrUnsupported }
func signalOwnedProcessGroup(_ int, _ probeSignal) error {
	return errors.New("probe process groups unsupported on windows")
}
