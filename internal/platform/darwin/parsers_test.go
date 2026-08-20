package darwin

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/ArshyaAI/runnel/internal/model"
)

func TestParseLSOFFieldMode(t *testing.T) {
	data, err := os.ReadFile("testdata/lsof_fields.txt")
	if err != nil {
		t.Fatal(err)
	}
	sockets, truncated, err := ParseLSOF(data, 10)
	if err != nil {
		t.Fatalf("ParseLSOF: %v", err)
	}
	if truncated || len(sockets) != 3 {
		t.Fatalf("unexpected parse: len=%d truncated=%v", len(sockets), truncated)
	}
	if sockets[0].PID != 55 || sockets[0].State != "LISTEN" || sockets[1].PID != 101 || sockets[2].State != "ESTABLISHED" {
		t.Fatalf("unexpected deterministic order/content: %#v", sockets)
	}
}

func TestParseLSOFBoundedAndMalformed(t *testing.T) {
	data, err := os.ReadFile("testdata/lsof_fields.txt")
	if err != nil {
		t.Fatal(err)
	}
	sockets, truncated, err := ParseLSOF(data, 1)
	if err != nil || !truncated || len(sockets) != 1 {
		t.Fatalf("bounded parse: sockets=%#v truncated=%v err=%v", sockets, truncated, err)
	}
	if _, _, err := ParseLSOF([]byte("pnot-a-pid\n"), 10); err == nil {
		t.Fatal("malformed PID accepted")
	}
	if _, _, err := ParseLSOF([]byte("p1\nf3\nPTCP\n"), 10); err == nil {
		t.Fatal("incomplete socket record accepted")
	}
}

func TestParseSampleNormalizesWithoutRawFrames(t *testing.T) {
	data, err := os.ReadFile("testdata/sample_read_decode.txt")
	if err != nil {
		t.Fatal(err)
	}
	report, err := ParseSample(data)
	if err != nil {
		t.Fatalf("ParseSample: %v", err)
	}
	if report.Availability != model.AvailabilityAvailable || report.FrameCount == 0 {
		t.Fatalf("unexpected report: %#v", report)
	}
	for _, expected := range []StackPredicate{
		StackPredicateFileRead,
		StackPredicateJSONDecoder,
		StackPredicateNodeEventLoop,
		StackPredicateReadDecodeChain,
		StackPredicateReadSyscall,
	} {
		if !slices.Contains(report.Predicates, expected) {
			t.Errorf("missing predicate %q in %#v", expected, report.Predicates)
		}
	}
}

func TestParseSampleRejectsMissingCallGraphAndCeiling(t *testing.T) {
	if _, err := ParseSample([]byte("not sample output\n")); err == nil {
		t.Fatal("missing call graph accepted")
	}
	if _, err := ParseSample(make([]byte, (8<<20)+1)); !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("expected output limit, got %v", err)
	}
}

func TestAncestryDetectsCyclesAndMissingParents(t *testing.T) {
	record := func(pid, ppid int32) ProcessRecord {
		return ProcessRecord{Observation: model.ProcessObservation{Identity: model.ProcessIdentity{
			PID: pid, StartTime: time.Unix(int64(pid), 0).UTC(), UID: 501, Executable: "/test/process",
		}, ParentPID: ppid}}
	}
	cycle := ProcessSnapshot{Processes: []ProcessRecord{record(10, 11), record(11, 10)}}
	if got := cycle.AncestryFrom(10, 10); got.Availability != model.AvailabilityContradictory || len(got.Chain) != 2 {
		t.Fatalf("cycle not detected: %#v", got)
	}
	missing := ProcessSnapshot{Processes: []ProcessRecord{record(10, 99)}}
	if got := missing.AncestryFrom(10, 10); got.Availability != model.AvailabilityProcessExited || len(got.Chain) != 1 {
		t.Fatalf("missing parent not explicit: %#v", got)
	}
	complete := ProcessSnapshot{Processes: []ProcessRecord{record(1, 0), record(10, 1)}}
	if got := complete.AncestryFrom(10, 10); got.Availability != model.AvailabilityAvailable || len(got.Chain) != 2 {
		t.Fatalf("complete ancestry failed: %#v", got)
	}
}

func TestDescriptorConversionClassifiesFileAndSocket(t *testing.T) {
	file := convertDescriptor(nativeFD{FD: 3, Kind: 1, OpenFlags: 2, Inode: 4, Size: 5, MTimeSec: 6, Path: "/synthetic"})
	if file.Kind != DescriptorVnode || file.File == nil || !file.File.Writable {
		t.Fatalf("file conversion: %#v", file)
	}
	socket := convertDescriptor(nativeFD{FD: 4, Kind: 2, SocketState: 1, LocalPort: 8080})
	if socket.Kind != DescriptorSocket || socket.Socket == nil || !socket.Socket.Listening || socket.Socket.Established {
		t.Fatalf("socket conversion: %#v", socket)
	}
}

func TestConfigurationHardCeilings(t *testing.T) {
	limits := (ProbeLimits{
		Timeout:     time.Hour,
		TermGrace:   time.Hour,
		KillGrace:   time.Hour,
		EscapeGrace: time.Hour,
		MaxBytes:    1 << 30,
		MaxLines:    1 << 30,
	}).withDefaults()
	if limits.Timeout != hardProbeTimeout || limits.TermGrace != hardProbeGrace ||
		limits.KillGrace != hardProbeGrace || limits.EscapeGrace != hardProbeEscapeGrace ||
		limits.MaxBytes != hardProbeBytes || limits.MaxLines != hardProbeLines {
		t.Fatalf("probe hard ceilings not enforced: %#v", limits)
	}
	config := (CollectorConfig{MaxProcesses: 1 << 30, Workers: 1 << 20, MaxFDs: 1 << 30}).withDefaults()
	if config.MaxProcesses != hardMaxProcesses || config.Workers != 128 || config.MaxFDs != hardMaxFDs {
		t.Fatalf("collector hard ceilings not enforced: %#v", config)
	}
}

func TestParseKERNProcArgs2ExactArgc(t *testing.T) {
	var fixture bytes.Buffer
	if err := binary.Write(&fixture, binary.NativeEndian, int32(3)); err != nil {
		t.Fatal(err)
	}
	fixture.WriteString("/test/helper\x00\x00")
	fixture.WriteString("/test/helper\x00--flag\x00\x00")
	fixture.WriteString("SECRET_ENV=not-argv\x00")
	argv, err := ParseKERNProcArgs2(fixture.Bytes(), 10)
	if err != nil {
		t.Fatalf("ParseKERNProcArgs2: %v", err)
	}
	want := []string{"/test/helper", "--flag", ""}
	if !slices.Equal(argv, want) {
		t.Fatalf("argv mismatch: got %#v want %#v", argv, want)
	}
}

func TestParseKERNProcArgs2RejectsMalformedAndCountCeiling(t *testing.T) {
	var excessive bytes.Buffer
	if err := binary.Write(&excessive, binary.NativeEndian, int32(11)); err != nil {
		t.Fatal(err)
	}
	excessive.WriteString("/test/helper\x00\x00")
	if _, err := ParseKERNProcArgs2(excessive.Bytes(), 10); err == nil {
		t.Fatal("excessive argc accepted")
	}
	invalid := make([]byte, 4)
	binary.NativeEndian.PutUint32(invalid, 1)
	invalid = append(invalid, []byte("/test/helper\x00\x00\xff\x00")...)
	if _, err := ParseKERNProcArgs2(invalid, 10); err == nil {
		t.Fatal("non-UTF-8 argv accepted")
	}
}
