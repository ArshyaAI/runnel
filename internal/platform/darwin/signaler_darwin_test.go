//go:build darwin && cgo

package darwin

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ArshyaAI/runnel/internal/model"
	"golang.org/x/sys/unix"
)

func TestOwnedHelper(t *testing.T) {
	mode, rest := helperModeAndArgs(os.Args)
	if mode == "" {
		return
	}
	switch mode {
	case "exec-initial":
		fmt.Fprintln(os.Stdout, "READY initial")
		if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
			os.Exit(81)
		}
		executable, err := os.Executable()
		if err != nil {
			os.Exit(82)
		}
		err = syscall.Exec(executable, []string{executable, "-test.run=^TestOwnedHelper$", "--", "wait-term"}, []string{"LC_ALL=C", "LANG=C"})
		if err != nil {
			os.Exit(83)
		}
	case "fd-wait":
		if len(rest) != 1 {
			fmt.Fprintf(os.Stderr, "fd-wait args: %#v\n", rest)
			os.Exit(84)
		}
		file, err := os.Open(rest[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "open fd fixture: %v\n", err)
			os.Exit(85)
		}
		defer file.Close()
		sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "socketpair fixture: %v\n", err)
			os.Exit(86)
		}
		defer unix.Close(sockets[0])
		defer unix.Close(sockets[1])
		waitForOwnedTERM("READY fd")
	case "wait-term":
		waitForOwnedTERM("READY replacement")
	default:
		os.Exit(87)
	}
}

func waitForOwnedTERM(ready string) {
	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM)
	defer signal.Stop(term)
	fmt.Fprintln(os.Stdout, ready)
	<-term
}

func TestAuditTokenSignalWrongPIDVersionReturnsESRCHAndChildSurvives(t *testing.T) {
	requireSignalCapability(t)
	child := startOwnedChild(t, "wait-term")
	defer child.cleanup(t)
	identity := readOwnedIdentity(t, child.cmd.Process.Pid)
	wrong := identity
	wrong.PIDVersion++
	if wrong.PIDVersion == 0 {
		wrong.PIDVersion = 1
	}
	err := nativeSignalTERM(wrong.PID, wrong.PIDVersion)
	if !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("wrong pidversion must return ESRCH, got %v", err)
	}
	assertOwnedAlive(t, child.cmd)
	if err := nativeSignalTERM(identity.PID, identity.PIDVersion); err != nil {
		t.Fatalf("exact token SIGTERM: %v", err)
	}
	child.wait(t)
}

func TestAuditTokenPreExecTokenReturnsESRCHAndReplacementSurvives(t *testing.T) {
	requireSignalCapability(t)
	child := startOwnedChild(t, "exec-initial")
	defer child.cleanup(t)
	before := readOwnedIdentity(t, child.cmd.Process.Pid)
	if _, err := child.stdin.Write([]byte("exec\n")); err != nil {
		t.Fatal(err)
	}
	child.waitReady(t)
	after := readOwnedIdentity(t, child.cmd.Process.Pid)
	if before.PIDVersion == after.PIDVersion {
		t.Fatalf("exec did not change pidversion: %d", before.PIDVersion)
	}
	if err := nativeSignalTERM(before.PID, before.PIDVersion); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("pre-exec token must return ESRCH, got %v", err)
	}
	assertOwnedAlive(t, child.cmd)
	if err := nativeSignalTERM(after.PID, after.PIDVersion); err != nil {
		t.Fatalf("fresh token SIGTERM: %v", err)
	}
	child.wait(t)
}

func TestAuditTokenFreshExactTerminatesOnlyTargetAndProtectedChildSurvives(t *testing.T) {
	requireSignalCapability(t)
	callerPID := os.Getpid()
	target := startOwnedChild(t, "wait-term")
	defer target.cleanup(t)
	protected := startOwnedChild(t, "wait-term")
	defer protected.cleanup(t)
	targetIdentity := readOwnedIdentity(t, target.cmd.Process.Pid)
	protectedIdentity := readOwnedIdentity(t, protected.cmd.Process.Pid)
	if err := nativeSignalTERM(targetIdentity.PID, targetIdentity.PIDVersion); err != nil {
		t.Fatalf("target SIGTERM: %v", err)
	}
	target.wait(t)
	assertOwnedAlive(t, protected.cmd)
	if os.Getpid() != callerPID {
		t.Fatal("caller identity changed")
	}
	if err := nativeSignalTERM(protectedIdentity.PID, protectedIdentity.PIDVersion); err != nil {
		t.Fatalf("protected child cleanup SIGTERM: %v", err)
	}
	protected.wait(t)
}

func TestAuditTokenSignalerMissingSymbolFailsClosed(t *testing.T) {
	backend := &fakeSignalBackend{capability: Capability{Availability: UnsupportedVersion, Reason: "test missing symbol"}}
	signaler := &AuditTokenSignaler{backend: backend}
	identity := model.DarwinActionIdentity{
		ProcessIdentity: model.ProcessIdentity{PID: 424242, StartTime: time.Unix(10, 0).UTC(), UID: 501, Executable: "/test/owned"},
		PIDVersion:      7,
		UniqueID:        9,
	}
	err := signaler.SignalTERM(context.Background(), identity)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("missing symbol did not fail unsupported: %v", err)
	}
	if backend.readCalls != 0 || backend.signalCalls != 0 {
		t.Fatalf("unsupported backend was touched: %#v", backend)
	}
}

func TestOwnedProcessDetailsExposeExactKernelFacts(t *testing.T) {
	requireSignalCapability(t)
	child := startOwnedChild(t, "wait-term")
	defer child.cleanup(t)
	value, err := nativeReadProcess(int32(child.cmd.Process.Pid))
	if err != nil {
		t.Fatalf("nativeReadProcess: %v", err)
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if value.PID != int32(child.cmd.Process.Pid) || value.PPID != int32(os.Getpid()) {
		t.Fatalf("PID/PPID mismatch: %#v", value)
	}
	if value.UID != uint32(os.Getuid()) || value.Executable == "" || value.CWD != workingDirectory {
		t.Fatalf("UID/executable/CWD mismatch: %#v cwd=%q", value, workingDirectory)
	}
	if value.StartSec == 0 || value.RSSBytes == 0 || value.VMSBytes == 0 || value.PIDVersion == 0 || value.UniqueID == 0 {
		t.Fatalf("incomplete native facts: %#v", value)
	}
	record, err := readProcessRecord(int32(child.cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Observation.Validate(); err != nil {
		t.Fatalf("model observation validation: %v", err)
	}
	identity := actionIdentityFromNative(value)
	if err := NewAuditTokenSignaler().SignalTERM(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	child.wait(t)
}

func TestOwnedArgvUsesBoundedKERNPROCARGS2AndPreservesChild(t *testing.T) {
	requireSignalCapability(t)
	child := startOwnedChild(t, "wait-term")
	defer child.cleanup(t)
	identity := readOwnedIdentity(t, child.cmd.Process.Pid)
	collector := NewCollector(CollectorConfig{})
	argv, availability, err := collector.Argv(context.Background(), identity, 64<<10)
	if err != nil || availability != model.AvailabilityAvailable {
		t.Fatalf("Argv: argv=%#v availability=%s err=%v", argv, availability, err)
	}
	if !slices.Contains(argv, "-test.run=^TestOwnedHelper$") || !slices.Contains(argv, "wait-term") {
		t.Fatalf("owned argv missing exact helper grammar: %#v", argv)
	}
	_, availability, err = collector.Argv(context.Background(), identity, 8)
	if err == nil || availability != model.AvailabilityContradictory || !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("argv ceiling did not fail closed: availability=%s err=%v", availability, err)
	}
	assertOwnedAlive(t, child.cmd)
	if err := NewAuditTokenSignaler().SignalTERM(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	child.wait(t)
}

func TestOwnedDescriptorSnapshotIsBoundedAndIdentityChecked(t *testing.T) {
	requireSignalCapability(t)
	path := filepath.Join(t.TempDir(), "owned-rollout.jsonl")
	if err := os.WriteFile(path, []byte("synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Darwin reports the kernel-canonical vnode path. On macOS /var is a
	// symlink to /private/var, while testing.T.TempDir may retain the /var
	// spelling. Canonicalize the fixture before the exact path assertion so
	// this remains an identity test rather than a pathname-alias test.
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	child := startOwnedChild(t, "fd-wait", path)
	defer child.cleanup(t)
	identity := readOwnedIdentity(t, child.cmd.Process.Pid)
	collector := NewCollector(CollectorConfig{MaxFDs: 128})
	snapshot, err := collector.Descriptors(context.Background(), identity, 128)
	if err != nil {
		t.Fatalf("Descriptors: %v", err)
	}
	var foundFile, foundSocket bool
	for _, descriptor := range snapshot.Descriptors {
		if descriptor.File != nil && descriptor.File.Path == path {
			foundFile = true
			if descriptor.File.Inode == 0 || descriptor.File.Size != uint64(len("synthetic\n")) {
				t.Fatalf("incorrect file stat: %#v", descriptor.File)
			}
		}
		if descriptor.Socket != nil {
			foundSocket = true
		}
	}
	if !foundFile || !foundSocket {
		t.Fatalf("missing owned descriptors: file=%v socket=%v snapshot=%#v", foundFile, foundSocket, snapshot)
	}
	if err := NewAuditTokenSignaler().SignalTERM(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	child.wait(t)
}

type fakeSignalBackend struct {
	capability  Capability
	identity    model.DarwinActionIdentity
	readCalls   int
	signalCalls int
}

func (f *fakeSignalBackend) Capability() Capability { return f.capability }
func (f *fakeSignalBackend) ReadIdentity(_ int32) (model.DarwinActionIdentity, error) {
	f.readCalls++
	return f.identity, nil
}
func (f *fakeSignalBackend) SignalTERM(_ int32, _ uint32) error {
	f.signalCalls++
	return nil
}

func requireSignalCapability(t *testing.T) {
	t.Helper()
	capability := NewAuditTokenSignaler().Capability()
	if !capability.Supported() {
		t.Skipf("identity-bound signal unavailable: %s", capability.Reason)
	}
}

type ownedChild struct {
	cmd      *exec.Cmd
	stdin    ioWriteCloser
	reader   *bufio.Reader
	waitOnce sync.Once
	waitErr  error
}

type ioWriteCloser interface {
	Write([]byte) (int, error)
	Close() error
}

func startOwnedChild(t *testing.T, mode string, args ...string) *ownedChild {
	t.Helper()
	argv := []string{"-test.run=^TestOwnedHelper$", "--", mode}
	argv = append(argv, args...)
	cmd := exec.Command(testExecutable(t), argv...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Env = []string{"LC_ALL=C", "LANG=C"}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	child := &ownedChild{cmd: cmd, stdin: stdin, reader: bufio.NewReader(stdout)}
	child.waitReady(t)
	return child
}

func (c *ownedChild) waitReady(t *testing.T) {
	t.Helper()
	done := make(chan struct {
		line string
		err  error
	}, 1)
	go func() {
		line, err := c.reader.ReadString('\n')
		done <- struct {
			line string
			err  error
		}{line: line, err: err}
	}()
	select {
	case got := <-done:
		if got.err != nil || !strings.HasPrefix(got.line, "READY ") {
			t.Fatalf("owned helper readiness: line=%q err=%v", got.line, got.err)
		}
	case <-time.After(5 * time.Second):
		_ = c.cmd.Process.Kill()
		t.Fatal("owned helper readiness timeout")
	}
}

func (c *ownedChild) wait(t *testing.T) {
	t.Helper()
	done := make(chan error, 1)
	c.waitOnce.Do(func() {
		go func() {
			c.waitErr = c.cmd.Wait()
			done <- c.waitErr
		}()
	})
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("owned helper Wait: %v", err)
		}
	case <-time.After(5 * time.Second):
		_ = c.cmd.Process.Kill()
		t.Fatal("owned helper Wait timeout")
	}
}

func (c *ownedChild) cleanup(t *testing.T) {
	t.Helper()
	if c.cmd.ProcessState != nil {
		return
	}
	_ = c.cmd.Process.Kill()
	_ = c.cmd.Wait()
}

func readOwnedIdentity(t *testing.T, pid int) model.DarwinActionIdentity {
	t.Helper()
	identity, err := NewCollector(CollectorConfig{}).ActionIdentity(context.Background(), int32(pid))
	if err != nil {
		t.Fatalf("owned ActionIdentity: %v", err)
	}
	return identity
}

func assertOwnedAlive(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("owned child did not survive: %v", err)
	}
}

func helperModeAndArgs(args []string) (string, []string) {
	for i, arg := range args {
		if arg == "--" && i+1 < len(args) {
			return args[i+1], args[i+2:]
		}
	}
	return "", nil
}
