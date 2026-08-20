//go:build darwin && cgo

package darwin

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArshyaAI/runnel/internal/model"
)

func TestChildrenProcessHelper(t *testing.T) {
	mode, rest := helperModeAndArgs(os.Args)
	if mode == "" {
		return
	}
	switch mode {
	case "leaf":
		fmt.Fprintln(os.Stdout, "READY leaf")
		time.Sleep(10 * time.Minute)
	case "parent":
		if len(rest) != 1 {
			os.Exit(101)
		}
		count, err := strconv.Atoi(rest[0])
		if err != nil || count < 0 || count > 8 {
			os.Exit(102)
		}
		runChildrenParentHelper(count)
	default:
		os.Exit(103)
	}
}

func runChildrenParentHelper(count int) {
	children := make(map[int]*exec.Cmd, count)
	defer func() {
		for _, child := range children {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	for range count {
		child := exec.Command(os.Args[0], "-test.run=^TestChildrenProcessHelper$", "--", "leaf")
		stdout, err := child.StdoutPipe()
		if err != nil {
			os.Exit(104)
		}
		child.Stderr = child.Stdout
		child.Env = []string{"LC_ALL=C", "LANG=C"}
		if err := child.Start(); err != nil {
			os.Exit(105)
		}
		line, err := bufio.NewReader(stdout).ReadString('\n')
		if err != nil || line != "READY leaf\n" {
			_ = child.Process.Kill()
			_ = child.Wait()
			os.Exit(106)
		}
		children[child.Process.Pid] = child
	}
	pids := make([]int, 0, len(children))
	for pid := range children {
		pids = append(pids, pid)
	}
	slices.Sort(pids)
	fmt.Fprint(os.Stdout, "READY parent")
	for _, pid := range pids {
		fmt.Fprintf(os.Stdout, " %d", pid)
	}
	fmt.Fprintln(os.Stdout)

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 1 && fields[0] == "exit" {
			return
		}
		if len(fields) != 2 || fields[0] != "drop" {
			os.Exit(107)
		}
		pid, err := strconv.Atoi(fields[1])
		if err != nil {
			os.Exit(108)
		}
		child, ok := children[pid]
		if !ok {
			os.Exit(109)
		}
		if err := child.Process.Kill(); err != nil {
			os.Exit(110)
		}
		if err := child.Wait(); err == nil {
			os.Exit(111)
		}
		delete(children, pid)
		fmt.Fprintf(os.Stdout, "DROPPED %d\n", pid)
	}
}

func TestChildrenListsExactDirectChildAndExcludesUnrelatedChild(t *testing.T) {
	requireChildCapability(t)
	callerPID := os.Getpid()
	selected := startOwnedChildrenParent(t, 1)
	defer selected.cleanup(t)
	unrelated := startOwnedChild(t, "wait-term")
	defer unrelated.cleanup(t)

	identity := readOwnedIdentity(t, selected.cmd.Process.Pid)
	snapshot, err := NewCollector(CollectorConfig{}).Children(context.Background(), identity, 8)
	if err != nil {
		t.Fatalf("Children: %v", err)
	}
	if snapshot.Availability != model.AvailabilityAvailable || snapshot.Truncated || len(snapshot.Failures) != 0 {
		t.Fatalf("incomplete child snapshot: %#v", snapshot)
	}
	if len(snapshot.Children) != 1 || snapshot.Children[0].Observation.Identity.PID != int32(selected.childPIDs[0]) {
		t.Fatalf("wrong direct children: %#v", snapshot.Children)
	}
	child := snapshot.Children[0]
	if !child.ActionIdentity.Complete() || child.Observation.ParentPID != identity.PID {
		t.Fatalf("incomplete exact child: %#v", child)
	}
	if err := child.Observation.Validate(); err != nil {
		t.Fatalf("child observation: %v", err)
	}
	if child.Observation.Identity.PID == int32(unrelated.cmd.Process.Pid) {
		t.Fatal("unrelated caller child leaked into selected parent's children")
	}
	assertChildrenFixtureSurvives(t, selected, callerPID)
	assertOwnedAlive(t, unrelated.cmd)
}

func TestChildrenEmptyAvailableSnapshotProvesOwnedParentChildless(t *testing.T) {
	requireChildCapability(t)
	callerPID := os.Getpid()
	selected := startOwnedChildrenParent(t, 0)
	defer selected.cleanup(t)
	identity := readOwnedIdentity(t, selected.cmd.Process.Pid)

	snapshot, err := NewCollector(CollectorConfig{}).Children(context.Background(), identity, 8)
	if err != nil {
		t.Fatalf("Children: %v", err)
	}
	if snapshot.Availability != model.AvailabilityAvailable || snapshot.Truncated ||
		len(snapshot.Children) != 0 || len(snapshot.Failures) != 0 {
		t.Fatalf("childless result is not a complete proof: %#v", snapshot)
	}
	if snapshot.Children == nil || snapshot.Failures == nil {
		t.Fatalf("childless repeated fields must be explicit: %#v", snapshot)
	}
	assertChildrenFixtureSurvives(t, selected, callerPID)
}

func TestChildrenRejectsWrongParentPIDVersionWithoutListing(t *testing.T) {
	requireChildCapability(t)
	callerPID := os.Getpid()
	selected := startOwnedChildrenParent(t, 1)
	defer selected.cleanup(t)
	identity := readOwnedIdentity(t, selected.cmd.Process.Pid)
	wrong := identity
	wrong.PIDVersion++
	if wrong.PIDVersion == 0 {
		wrong.PIDVersion = 1
	}

	snapshot, err := NewCollector(CollectorConfig{}).Children(context.Background(), wrong, 8)
	if !errors.Is(err, ErrIdentityMismatch) || !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("wrong pidversion did not fail as exited: snapshot=%#v err=%v", snapshot, err)
	}
	if snapshot.Availability != model.AvailabilityProcessExited || len(snapshot.Children) != 0 {
		t.Fatalf("wrong pidversion returned usable children: %#v", snapshot)
	}
	assertChildrenFixtureSurvives(t, selected, callerPID)
}

func TestChildrenRejectsPreExecParentIdentity(t *testing.T) {
	requireChildCapability(t)
	callerPID := os.Getpid()
	selected := startOwnedChild(t, "exec-initial")
	defer selected.cleanup(t)
	before := readOwnedIdentity(t, selected.cmd.Process.Pid)
	if _, err := selected.stdin.Write([]byte("exec\n")); err != nil {
		t.Fatal(err)
	}
	selected.waitReady(t)
	after := readOwnedIdentity(t, selected.cmd.Process.Pid)
	if before.PIDVersion == after.PIDVersion {
		t.Fatalf("exec did not change pidversion: %d", before.PIDVersion)
	}

	snapshot, err := NewCollector(CollectorConfig{}).Children(context.Background(), before, 8)
	if !errors.Is(err, ErrIdentityMismatch) || snapshot.Availability != model.AvailabilityProcessExited {
		t.Fatalf("pre-exec identity did not fail closed: snapshot=%#v err=%v", snapshot, err)
	}
	assertOwnedAlive(t, selected.cmd)
	if os.Getpid() != callerPID {
		t.Fatal("caller changed during pre-exec identity query")
	}
}

func TestChildrenRejectsParentExecDuringQuery(t *testing.T) {
	requireChildCapability(t)
	callerPID := os.Getpid()
	selected := startOwnedChild(t, "exec-initial")
	defer selected.cleanup(t)
	identity := readOwnedIdentity(t, selected.cmd.Process.Pid)
	lister := callbackChildPIDLister{afterList: func(_ []int32) {
		if _, err := selected.stdin.Write([]byte("exec\n")); err != nil {
			t.Fatalf("trigger owned parent exec: %v", err)
		}
		selected.waitReady(t)
	}}

	snapshot, err := NewCollector(CollectorConfig{}).children(context.Background(), identity, 8, lister)
	if !errors.Is(err, ErrIdentityMismatch) || !errors.Is(err, syscall.ESRCH) ||
		snapshot.Availability != model.AvailabilityProcessExited {
		t.Fatalf("mid-query parent exec did not fail after identity check: snapshot=%#v err=%v", snapshot, err)
	}
	assertOwnedAlive(t, selected.cmd)
	if os.Getpid() != callerPID {
		t.Fatal("caller changed during mid-query parent exec")
	}
}

func TestChildrenExitRaceIsExplicit(t *testing.T) {
	requireChildCapability(t)
	callerPID := os.Getpid()
	selected := startOwnedChildrenParent(t, 1)
	defer selected.cleanup(t)
	identity := readOwnedIdentity(t, selected.cmd.Process.Pid)
	targetPID := int32(selected.childPIDs[0])
	lister := callbackChildPIDLister{afterList: func(pids []int32) {
		if !slices.Contains(pids, targetPID) {
			t.Fatalf("native child list omitted owned target %d: %#v", targetPID, pids)
		}
		selected.drop(t, int(targetPID))
	}}

	snapshot, err := NewCollector(CollectorConfig{}).children(context.Background(), identity, 8, lister)
	if err == nil || snapshot.Availability != model.AvailabilityProcessExited {
		t.Fatalf("child exit race was not explicit: snapshot=%#v err=%v", snapshot, err)
	}
	if len(snapshot.Children) != 0 || len(snapshot.Failures) != 1 || snapshot.Failures[0].PID != targetPID ||
		snapshot.Failures[0].Availability != model.AvailabilityProcessExited {
		t.Fatalf("wrong child exit failure: %#v", snapshot)
	}
	if !errors.Is(snapshot.Failures[0].Err, syscall.ESRCH) {
		t.Fatalf("child exit failure lost ESRCH: %v", snapshot.Failures[0].Err)
	}
	assertChildrenFixtureSurvives(t, selected, callerPID)
}

func TestChildrenTruncationFailsClosed(t *testing.T) {
	requireChildCapability(t)
	callerPID := os.Getpid()
	selected := startOwnedChildrenParent(t, 2)
	defer selected.cleanup(t)
	identity := readOwnedIdentity(t, selected.cmd.Process.Pid)

	snapshot, err := NewCollector(CollectorConfig{}).Children(context.Background(), identity, 1)
	if !errors.Is(err, ErrOutputLimit) || !snapshot.Truncated || snapshot.Availability != model.AvailabilityContradictory {
		t.Fatalf("truncation did not fail closed: snapshot=%#v err=%v", snapshot, err)
	}
	if len(snapshot.Children) != 0 || len(snapshot.Failures) != 0 {
		t.Fatalf("truncated snapshot exposed partial results: %#v", snapshot)
	}
	assertChildrenFixtureSurvives(t, selected, callerPID)
}

func TestChildrenCancellationFailsClosed(t *testing.T) {
	requireChildCapability(t)
	callerPID := os.Getpid()
	selected := startOwnedChildrenParent(t, 1)
	defer selected.cleanup(t)
	identity := readOwnedIdentity(t, selected.cmd.Process.Pid)
	ctx, cancel := context.WithCancel(context.Background())
	lister := callbackChildPIDLister{afterList: func(_ []int32) { cancel() }}

	snapshot, err := NewCollector(CollectorConfig{}).children(ctx, identity, 8, lister)
	if !errors.Is(err, context.Canceled) || snapshot.Availability != model.AvailabilityContradictory {
		t.Fatalf("cancellation did not fail closed: snapshot=%#v err=%v", snapshot, err)
	}
	if len(snapshot.Children) != 0 || len(snapshot.Failures) != 0 {
		t.Fatalf("cancelled snapshot exposed results: %#v", snapshot)
	}
	assertChildrenFixtureSurvives(t, selected, callerPID)
}

func TestChildrenMissingPrimitiveFailsUnsupported(t *testing.T) {
	selected := startOwnedChildrenParent(t, 0)
	defer selected.cleanup(t)
	identity := readOwnedIdentity(t, selected.cmd.Process.Pid)
	lister := &unsupportedChildPIDLister{}

	snapshot, err := NewCollector(CollectorConfig{}).children(context.Background(), identity, 8, lister)
	if !errors.Is(err, ErrUnsupported) || snapshot.Availability != model.AvailabilityUnsupportedVersion {
		t.Fatalf("missing primitive did not fail unsupported: snapshot=%#v err=%v", snapshot, err)
	}
	if lister.listCalls != 0 {
		t.Fatalf("unsupported primitive list called %d times", lister.listCalls)
	}
}

type callbackChildPIDLister struct {
	afterList func([]int32)
}

func (callbackChildPIDLister) Capability() Capability {
	return Capability{Availability: model.AvailabilityAvailable}
}

func (l callbackChildPIDLister) List(parentPID int32, capacity int) ([]int32, error) {
	pids, err := nativeListChildPIDs(parentPID, capacity)
	if err == nil && l.afterList != nil {
		l.afterList(slices.Clone(pids))
	}
	return pids, err
}

type unsupportedChildPIDLister struct{ listCalls int }

func (*unsupportedChildPIDLister) Capability() Capability {
	return Capability{Availability: model.AvailabilityUnsupportedVersion, Reason: "test symbol missing"}
}

func (l *unsupportedChildPIDLister) List(_ int32, _ int) ([]int32, error) {
	l.listCalls++
	return nil, ErrUnsupported
}

type ownedChildrenParent struct {
	cmd       *exec.Cmd
	stdin     ioWriteCloser
	reader    *bufio.Reader
	childPIDs []int
	waited    bool
}

func startOwnedChildrenParent(t *testing.T, childCount int) *ownedChildrenParent {
	t.Helper()
	cmd := exec.Command(testExecutable(t), "-test.run=^TestChildrenProcessHelper$", "--", "parent", strconv.Itoa(childCount))
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
	fixture := &ownedChildrenParent{cmd: cmd, stdin: stdin, reader: bufio.NewReader(stdout)}
	line := fixture.readLine(t)
	fields := strings.Fields(line)
	if len(fields) != childCount+2 || fields[0] != "READY" || fields[1] != "parent" {
		fixture.cleanup(t)
		t.Fatalf("owned parent readiness: %q", line)
	}
	for _, field := range fields[2:] {
		pid, err := strconv.Atoi(field)
		if err != nil || pid <= 0 {
			fixture.cleanup(t)
			t.Fatalf("owned child pid %q", field)
		}
		fixture.childPIDs = append(fixture.childPIDs, pid)
	}
	return fixture
}

func (p *ownedChildrenParent) drop(t *testing.T, pid int) {
	t.Helper()
	if _, err := fmt.Fprintf(p.stdin, "drop %d\n", pid); err != nil {
		t.Fatalf("drop owned child: %v", err)
	}
	if line := p.readLine(t); line != fmt.Sprintf("DROPPED %d", pid) {
		t.Fatalf("drop owned child acknowledgment: %q", line)
	}
	p.childPIDs = slices.DeleteFunc(p.childPIDs, func(candidate int) bool { return candidate == pid })
}

func (p *ownedChildrenParent) readLine(t *testing.T) string {
	t.Helper()
	type result struct {
		line string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		line, err := p.reader.ReadString('\n')
		done <- result{line: strings.TrimSpace(line), err: err}
	}()
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("owned parent output: line=%q err=%v", got.line, got.err)
		}
		return got.line
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		t.Fatal("owned parent output timeout")
		return ""
	}
}

func (p *ownedChildrenParent) cleanup(t *testing.T) {
	t.Helper()
	if p.waited {
		return
	}
	p.waited = true
	_, _ = p.stdin.Write([]byte("exit\n"))
	_ = p.stdin.Close()
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("owned parent Wait: %v", err)
		}
	case <-time.After(5 * time.Second):
		_ = p.cmd.Process.Kill()
		<-done
		t.Errorf("owned parent cleanup timeout")
	}
}

func assertChildrenFixtureSurvives(t *testing.T, fixture *ownedChildrenParent, callerPID int) {
	t.Helper()
	if os.Getpid() != callerPID {
		t.Fatal("caller identity changed during child query")
	}
	if _, err := nativeReadProcess(int32(fixture.cmd.Process.Pid)); err != nil {
		t.Fatalf("selected parent did not survive child query: %v", err)
	}
	for _, pid := range fixture.childPIDs {
		if _, err := nativeReadProcess(int32(pid)); err != nil {
			t.Fatalf("owned direct child %d did not survive child query: %v", pid, err)
		}
	}
}

func requireChildCapability(t *testing.T) {
	t.Helper()
	capability := nativeChildCapability()
	if !capability.Supported() {
		t.Skipf("direct-child primitive unavailable: %s", capability.Reason)
	}
}
