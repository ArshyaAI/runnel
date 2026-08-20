package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ArshyaAI/runnel/internal/model"
	"github.com/creack/pty"
)

type fakeScan struct {
	snapshot model.Snapshot
	err      error
	calls    int
}

func (f *fakeScan) Snapshot(context.Context) (model.Snapshot, error) {
	f.calls++
	return f.snapshot, f.err
}

func validEmptySnapshot() model.Snapshot {
	return model.Snapshot{SchemaVersion: model.SnapshotSchemaVersion, ToolVersion: "test", ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Platform: model.Platform{OS: "darwin", Arch: "arm64"}, Availability: []model.ProbeAvailability{{Probe: model.ProbeCWD, Status: model.AvailabilityAvailable}, {Probe: model.ProbeExecutable, Status: model.AvailabilityAvailable}, {Probe: model.ProbeIdentity, Status: model.AvailabilityAvailable}, {Probe: model.ProbeSockets, Status: model.AvailabilityAvailable}, {Probe: model.ProbeTTY, Status: model.AvailabilityAvailable}}, Groups: []model.WorkflowGroup{}}
}

func TestScanJSONIsStrictAndPropagatesPartialExit(t *testing.T) {
	var out, errOut bytes.Buffer
	fake := &fakeScan{snapshot: validEmptySnapshot(), err: ErrPartial}
	root := NewRoot(Options{In: strings.NewReader(""), Out: &out, ErrOut: &errOut, Scan: fake})
	root.SetArgs([]string{"scan", "--json"})
	err := root.Execute()
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != ExitPartial {
		t.Fatalf("error=%v", err)
	}
	if fake.calls != 1 {
		t.Fatalf("calls=%d", fake.calls)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Fatal("JSON contains ANSI")
	}
	if !strings.Contains(out.String(), `"schema_version":"runnel.snapshot/v1"`) {
		t.Fatalf("unexpected JSON: %s", out.String())
	}
}

func TestRecoverRefusesNonTTY(t *testing.T) {
	var out bytes.Buffer
	root := NewRoot(Options{Out: &out, ErrOut: &out, In: strings.NewReader("")})
	root.SetArgs([]string{"recover"})
	err := root.Execute()
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != ExitRecoveryLocked || !strings.Contains(err.Error(), "requires interactive input and output terminals") {
		t.Fatalf("error=%v", err)
	}
}

type fakeCLIRecovery struct {
	calls int
	in    io.Reader
	out   io.Writer
	err   error
}

func (f *fakeCLIRecovery) Recover(_ context.Context, in io.Reader, out io.Writer) error {
	f.calls++
	f.in = in
	f.out = out
	return f.err
}

func TestRecoverRequiresBothTTYsAndInjectsThem(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()

	for _, test := range []struct {
		name string
		in   io.Reader
		out  io.Writer
	}{
		{name: "input is not a tty", in: strings.NewReader(""), out: slave},
		{name: "output is not a tty", in: slave, out: &bytes.Buffer{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &fakeCLIRecovery{}
			root := NewRoot(Options{In: test.in, Out: test.out, ErrOut: &bytes.Buffer{}, Recovery: service})
			root.SetArgs([]string{"recover"})
			var exit *ExitError
			if err := root.Execute(); !errors.As(err, &exit) || exit.Code != ExitRecoveryLocked {
				t.Fatalf("error = %v", err)
			}
			if service.calls != 0 {
				t.Fatalf("recovery calls = %d", service.calls)
			}
		})
	}

	service := &fakeCLIRecovery{}
	root := NewRoot(Options{In: slave, Out: slave, ErrOut: &bytes.Buffer{}, Recovery: service})
	root.SetArgs([]string{"recover"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if service.calls != 1 || service.in != slave || service.out != slave {
		t.Fatalf("injected recovery = calls:%d in:%T out:%T", service.calls, service.in, service.out)
	}

	unavailable := NewRoot(Options{In: slave, Out: slave, ErrOut: &bytes.Buffer{}})
	unavailable.SetArgs([]string{"recover"})
	var exit *ExitError
	if err := unavailable.Execute(); !errors.As(err, &exit) || exit.Code != ExitRecoveryLocked {
		t.Fatalf("unavailable recovery error = %v", err)
	}

	noPID := &fakeCLIRecovery{}
	withPID := NewRoot(Options{In: slave, Out: slave, ErrOut: &bytes.Buffer{}, Recovery: noPID})
	withPID.SetArgs([]string{"recover", "12345"})
	if err := withPID.Execute(); err == nil || noPID.calls != 0 {
		t.Fatalf("recover accepted PID argument: err=%v calls=%d", err, noPID.calls)
	}
}

func TestRecoverRejectsCharacterDevicesThatAreNotTTYs(t *testing.T) {
	device, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()
	service := &fakeCLIRecovery{}
	root := NewRoot(Options{In: device, Out: device, ErrOut: &bytes.Buffer{}, Recovery: service})
	root.SetArgs([]string{"recover"})
	var exit *ExitError
	if err := root.Execute(); !errors.As(err, &exit) || exit.Code != ExitRecoveryLocked {
		t.Fatalf("error = %v", err)
	}
	if service.calls != 0 {
		t.Fatalf("recovery calls = %d", service.calls)
	}
}

type codedRecoveryError struct{ code int }

func (e codedRecoveryError) Error() string { return "coded recovery" }
func (e codedRecoveryError) ExitCode() int { return e.code }

func TestRecoverPreservesBoundedRecoveryExitOutcomes(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer slave.Close()
	for _, code := range []int{ExitRecoveryLocked, ExitRecoveryPartial, ExitRecoveryFailed, ExitReceiptIntegrity, ExitRecoveryCancelled} {
		service := &fakeCLIRecovery{err: codedRecoveryError{code: code}}
		root := NewRoot(Options{In: slave, Out: slave, ErrOut: &bytes.Buffer{}, Recovery: service})
		root.SetArgs([]string{"recover"})
		var exit *ExitError
		if err := root.Execute(); !errors.As(err, &exit) || exit.Code != code {
			t.Fatalf("code %d: error = %v", code, err)
		}
	}
}

func TestCommandSurface(t *testing.T) {
	root := NewRoot(Options{Out: &bytes.Buffer{}, ErrOut: &bytes.Buffer{}})
	want := map[string]bool{"scan": true, "explain": true, "recover": true, "history": true, "receipt": true, "doctor": true, "completion": true, "version": true}
	for _, c := range root.Commands() {
		if c.Name() == "help" {
			continue
		}
		delete(want, c.Name())
	}
	for missing := range want {
		t.Errorf("missing command %q", missing)
	}
}

func TestDefaultDoctorRunsSelfTestWithoutClaimingRecoveryReady(t *testing.T) {
	data, err := (localDoctor{}).Doctor(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		RecoveryService string `json:"recovery_service"`
		SelfTest        string `json:"self_test"`
		Status          string `json:"status"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.RecoveryService != "disabled" || report.SelfTest != "passed" {
		t.Fatalf("doctor report = %#v", report)
	}
	if report.Status == "ready" {
		t.Fatal("doctor claimed recovery readiness without a configured service")
	}
}
