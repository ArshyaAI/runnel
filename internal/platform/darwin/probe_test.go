//go:build darwin

package darwin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestProbeHelper(t *testing.T) {
	mode := helperMode(os.Args)
	if mode == "" {
		return
	}
	switch mode {
	case "echo":
		fmt.Fprint(os.Stdout, "alpha\nbeta\n")
	case "large":
		fmt.Fprint(os.Stdout, strings.Repeat("0123456789\n", 10_000))
	case "env":
		if os.Getenv("RUNNEL_TEST_SECRET") != "" {
			fmt.Fprintln(os.Stdout, "secret inherited")
			os.Exit(95)
		}
		fmt.Fprintln(os.Stdout, "minimal environment")
	case "ignore-term":
		signal.Ignore(syscall.SIGTERM)
		time.Sleep(5 * time.Second)
	case "escape":
		executable, err := os.Executable()
		if err != nil {
			os.Exit(91)
		}
		sentinel := os.NewFile(3, "runnel-probe-sentinel")
		if sentinel == nil {
			os.Exit(92)
		}
		child := exec.Command(executable, "-test.run=^TestProbeHelper$", "--", "escaped-grandchild")
		child.ExtraFiles = []*os.File{sentinel}
		child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := child.Start(); err != nil {
			os.Exit(93)
		}
		fmt.Fprintln(os.Stdout, "probe parent exited")
	case "escaped-grandchild":
		time.Sleep(300 * time.Millisecond)
	default:
		os.Exit(94)
	}
}

func TestProbeLauncherDirectArgv(t *testing.T) {
	launcher := ProbeLauncher{Limits: ProbeLimits{Timeout: 5 * time.Second, MaxBytes: 1024, MaxLines: 20}}
	result, err := launcher.Run(context.Background(), testExecutable(t), "-test.run=^TestProbeHelper$", "--", "echo")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.HasPrefix(string(result.Output), "alpha\nbeta\n") || result.ExitCode != 0 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.TermSent || result.KillSent || result.EscapedChild {
		t.Fatalf("normal probe used cleanup: %#v", result)
	}
}

func TestProbeLauncherRejectsPATHLookup(t *testing.T) {
	_, err := (ProbeLauncher{}).Run(context.Background(), "sample", "1")
	var operation *OperationError
	if !errors.As(err, &operation) || operation.Availability != MalformedOutput {
		t.Fatalf("relative executable did not fail closed: %v", err)
	}
}

func TestProbeLauncherDoesNotForwardCallerSecrets(t *testing.T) {
	t.Setenv("RUNNEL_TEST_SECRET", "must-not-cross-probe-boundary")
	launcher := ProbeLauncher{Limits: ProbeLimits{Timeout: 5 * time.Second, MaxBytes: 1024, MaxLines: 20}}
	result, err := launcher.Run(context.Background(), testExecutable(t), "-test.run=^TestProbeHelper$", "--", "env")
	if err != nil {
		t.Fatalf("Run: %v output=%q", err, result.Output)
	}
	if !strings.HasPrefix(string(result.Output), "minimal environment\n") {
		t.Fatalf("unexpected environment result: %q", result.Output)
	}
}

func TestProbeLauncherOutputCeiling(t *testing.T) {
	launcher := ProbeLauncher{Limits: ProbeLimits{
		Timeout:   2 * time.Second,
		TermGrace: 100 * time.Millisecond,
		KillGrace: 500 * time.Millisecond,
		MaxBytes:  128,
		MaxLines:  8,
	}}
	result, err := launcher.Run(context.Background(), testExecutable(t), "-test.run=^TestProbeHelper$", "--", "large")
	if !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("expected output limit, got %v", err)
	}
	if len(result.Output) > 128 || strings.Count(string(result.Output), "\n") > 8 {
		t.Fatalf("output escaped ceiling: bytes=%d lines=%d", len(result.Output), strings.Count(string(result.Output), "\n"))
	}
}

func TestProbeLauncherTERMThenKILLPreservesCallerGroup(t *testing.T) {
	callerGroup := syscall.Getpgrp()
	launcher := ProbeLauncher{Limits: ProbeLimits{
		Timeout:   80 * time.Millisecond,
		TermGrace: 80 * time.Millisecond,
		KillGrace: time.Second,
		MaxBytes:  1024,
		MaxLines:  20,
	}}
	result, err := launcher.Run(context.Background(), testExecutable(t), "-test.run=^TestProbeHelper$", "--", "ignore-term")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got %v", err)
	}
	if !result.TermSent || !result.KillSent {
		t.Fatalf("expected bounded TERM/KILL cleanup: %#v", result)
	}
	if syscall.Getpgrp() != callerGroup {
		t.Fatalf("caller process group changed")
	}
}

func TestProbeLauncherDetectsEscapedDescendant(t *testing.T) {
	launcher := ProbeLauncher{Limits: ProbeLimits{
		Timeout:     5 * time.Second,
		EscapeGrace: 30 * time.Millisecond,
		MaxBytes:    1024,
		MaxLines:    20,
	}}
	result, err := launcher.Run(context.Background(), testExecutable(t), "-test.run=^TestProbeHelper$", "--", "escape")
	if !errors.Is(err, ErrEscapedChild) {
		t.Fatalf("expected escaped-child error, got %v", err)
	}
	if !result.EscapedChild {
		t.Fatalf("escaped descendant was not recorded")
	}
	// The owned grandchild self-terminates; the launcher deliberately does not
	// widen its signal target beyond the process group it created.
	time.Sleep(350 * time.Millisecond)
}

func testExecutable(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return executable
}

func helperMode(args []string) string {
	for i, arg := range args {
		if arg == "--" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
