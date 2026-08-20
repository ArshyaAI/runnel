package darwin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// ProbeLauncher is the only child-command launcher used by Darwin adapters.
// It never invokes a shell and never targets the caller's process group.
type ProbeLauncher struct {
	Limits ProbeLimits
}

type waitResult struct {
	err  error
	code int
}

func (p ProbeLauncher) Run(ctx context.Context, argv ...string) (ProbeResult, error) {
	started := time.Now()
	limits := p.Limits.withDefaults()
	if err := validateProbeArgv(argv); err != nil {
		return ProbeResult{}, &OperationError{Op: "probe_start", Availability: MalformedOutput, Err: err}
	}
	if err := ctx.Err(); err != nil {
		return ProbeResult{}, err
	}

	deadlineCtx, cancel := context.WithTimeout(ctx, limits.Timeout)
	defer cancel()

	readSentinel, writeSentinel, err := os.Pipe()
	if err != nil {
		return ProbeResult{}, fmt.Errorf("probe sentinel: %w", err)
	}
	defer readSentinel.Close()

	limitHit := make(chan struct{})
	sink := newCeilingWriter(limits.MaxBytes, limits.MaxLines, limitHit)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout = sink
	cmd.Stderr = sink
	cmd.Stdin = nil
	cmd.WaitDelay = max(10*time.Millisecond, limits.KillGrace/2)
	cmd.ExtraFiles = []*os.File{writeSentinel}
	cmd.Env = []string{
		"LC_ALL=C",
		"LANG=C",
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"RUNNEL_PROBE_SENTINEL_FD=3",
	}
	configureIsolatedProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		writeSentinel.Close()
		return ProbeResult{}, &OperationError{Op: "probe_start", Availability: classifyProbeError(err), Err: err}
	}
	// Only descendants retain the write end. EOF therefore proves that no
	// descendant still holds the inherited sentinel descriptor.
	_ = writeSentinel.Close()

	pid := cmd.Process.Pid
	if err := verifyIsolatedProcessGroup(pid); err != nil {
		result := ProbeResult{Duration: time.Since(started)}
		wait := make(chan waitResult, 1)
		go waitCommand(cmd, wait)
		terminateAndWait(pid, wait, limits, &result)
		return result, &OperationError{Op: "probe_group", Availability: Contradictory, Err: err}
	}

	wait := make(chan waitResult, 1)
	go waitCommand(cmd, wait)
	var wr waitResult
	var runErr error
	result := ProbeResult{ExitCode: -1}
	select {
	case wr = <-wait:
	case <-limitHit:
		runErr = ErrOutputLimit
		wr = terminateAndWait(pid, wait, limits, &result)
	case <-deadlineCtx.Done():
		runErr = deadlineCtx.Err()
		wr = terminateAndWait(pid, wait, limits, &result)
	}
	result.ExitCode = wr.code
	result.Output = sink.Bytes()
	result.Duration = time.Since(started)

	escaped, escapeErr := awaitSentinelEOF(readSentinel, limits.EscapeGrace)
	if escaped {
		result.EscapedChild = true
		if runErr == nil {
			runErr = escapeErr
		}
	}
	if runErr != nil {
		return result, runErr
	}
	if wr.err != nil {
		return result, &ProbeExitError{Code: wr.code}
	}
	return result, nil
}

func validateProbeArgv(argv []string) error {
	if len(argv) == 0 || argv[0] == "" {
		return errors.New("empty argv")
	}
	if len(argv) > 256 {
		return errors.New("probe argv count exceeds ceiling")
	}
	if !filepath.IsAbs(argv[0]) {
		return errors.New("probe executable must be an absolute path")
	}
	total := 0
	for _, arg := range argv {
		total += len(arg)
		if total > 1<<20 {
			return errors.New("probe argv bytes exceed ceiling")
		}
	}
	return nil
}

func waitCommand(cmd *exec.Cmd, out chan<- waitResult) {
	err := cmd.Wait()
	code := 0
	if err != nil {
		code = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		}
	}
	out <- waitResult{err: err, code: code}
}

func terminateAndWait(pid int, wait <-chan waitResult, limits ProbeLimits, result *ProbeResult) waitResult {
	if err := signalOwnedProcessGroup(pid, probeSignalTerm); err == nil {
		result.TermSent = true
	}
	select {
	case wr := <-wait:
		return wr
	case <-time.After(limits.TermGrace):
	}
	if err := signalOwnedProcessGroup(pid, probeSignalKill); err == nil {
		result.KillSent = true
	}
	select {
	case wr := <-wait:
		return wr
	case <-time.After(limits.KillGrace):
		// KILL is uncatchable and cmd.WaitDelay bounds inherited output-pipe
		// closure after the leader exits. Still consume the one and only Wait
		// result: returning without it would leak child state.
		return <-wait
	}
}

func awaitSentinelEOF(r *os.File, grace time.Duration) (bool, error) {
	done := make(chan error, 1)
	go func() {
		var one [1]byte
		_, err := r.Read(one[:])
		if errors.Is(err, io.EOF) {
			err = nil
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			return false, fmt.Errorf("probe sentinel: %w", err)
		}
		return false, nil
	case <-time.After(grace):
		_ = r.Close()
		return true, ErrEscapedChild
	}
}

type ceilingWriter struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	maxBytes int
	maxLines int
	bytes    int
	lines    int
	hit      chan struct{}
	once     sync.Once
}

func newCeilingWriter(maxBytes, maxLines int, hit chan struct{}) *ceilingWriter {
	return &ceilingWriter{maxBytes: maxBytes, maxLines: maxLines, hit: hit}
}

func (w *ceilingWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	original := len(data)
	remaining := w.maxBytes - w.bytes
	if remaining < 0 {
		remaining = 0
	}
	accepted := data
	if len(accepted) > remaining {
		accepted = accepted[:remaining]
	}
	if room := w.maxLines - w.lines; room >= 0 {
		if n := bytes.Count(accepted, []byte{'\n'}); n > room {
			cut := nthNewline(accepted, room)
			accepted = accepted[:cut]
		}
	}
	_, _ = w.buf.Write(accepted)
	w.bytes += len(accepted)
	w.lines += bytes.Count(accepted, []byte{'\n'})
	if len(accepted) < original {
		w.once.Do(func() { close(w.hit) })
	}
	// os/exec treats short writes as errors and may stop draining a pipe. Claim
	// the full input while retaining only the bounded prefix.
	return original, nil
}

func (w *ceilingWriter) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return bytes.Clone(w.buf.Bytes())
}

func nthNewline(data []byte, allowed int) int {
	if allowed <= 0 {
		return 0
	}
	from := 0
	for i := 0; i < allowed; i++ {
		at := bytes.IndexByte(data[from:], '\n')
		if at < 0 {
			return len(data)
		}
		from += at + 1
	}
	return from
}

func classifyProbeError(err error) Availability {
	if errors.Is(err, context.DeadlineExceeded) {
		return TimedOut
	}
	if errors.Is(err, os.ErrPermission) {
		return PermissionDenied
	}
	return MalformedOutput
}
