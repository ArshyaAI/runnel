package darwin

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/ArshyaAI/runnel/internal/model"
)

type StackPredicate string

const (
	StackPredicateReadSyscall     StackPredicate = "read_syscall"
	StackPredicateFileRead        StackPredicate = "file_read"
	StackPredicateJSONDecoder     StackPredicate = "json_decoder"
	StackPredicateNodeEventLoop   StackPredicate = "node_event_loop"
	StackPredicateReadDecodeChain StackPredicate = "read_decode_chain"
)

type SampleReport struct {
	ThreadCount  uint32
	FrameCount   uint32
	Predicates   []StackPredicate
	Availability model.Availability
}

type SampleOptions struct {
	DurationSeconds      int
	IntervalMilliseconds int
}

func (o SampleOptions) withDefaults() (SampleOptions, error) {
	if o.DurationSeconds == 0 {
		o.DurationSeconds = 1
	}
	if o.IntervalMilliseconds == 0 {
		o.IntervalMilliseconds = 10
	}
	if o.DurationSeconds < 1 || o.DurationSeconds > 5 || o.IntervalMilliseconds < 1 || o.IntervalMilliseconds > 1000 {
		return SampleOptions{}, errors.New("sample options exceed bounded range")
	}
	return o, nil
}

// Sample validates the exact identity on both sides of the PID-addressed
// sample command. It returns normalized predicates only, never raw stack text.
func (c *Collector) Sample(ctx context.Context, launcher ProbeLauncher, identity model.DarwinActionIdentity, options SampleOptions) (SampleReport, error) {
	if err := identity.Validate(); err != nil {
		return SampleReport{}, err
	}
	options, err := options.withDefaults()
	if err != nil {
		return SampleReport{}, err
	}
	before, err := nativeReadIdentity(identity.PID)
	if err != nil {
		return SampleReport{}, identityReadError("sample_identity_before", err)
	}
	if !actionIdentityFromNative(before).Equal(identity) {
		return SampleReport{}, identityMismatch("sample_identity_before")
	}
	result, runErr := launcher.Run(ctx,
		"/usr/bin/sample",
		strconv.FormatInt(int64(identity.PID), 10),
		strconv.Itoa(options.DurationSeconds),
		strconv.Itoa(options.IntervalMilliseconds),
		"-mayDie",
	)
	after, identityErr := nativeReadIdentity(identity.PID)
	if identityErr != nil {
		return SampleReport{}, identityReadError("sample_identity_after", identityErr)
	}
	if !actionIdentityFromNative(after).Equal(identity) {
		return SampleReport{}, identityMismatch("sample_identity_after")
	}
	if runErr != nil {
		availability := availabilityForError(runErr)
		if errors.Is(runErr, ErrOutputLimit) {
			availability = model.AvailabilityContradictory
		}
		return SampleReport{Availability: availability}, &OperationError{Op: "sample", Availability: availability, Err: runErr}
	}
	report, err := ParseSample(result.Output)
	if err != nil {
		return SampleReport{Availability: model.AvailabilityMalformedOutput}, &OperationError{Op: "sample_parse", Availability: model.AvailabilityMalformedOutput, Err: err}
	}
	return report, nil
}

func ParseSample(data []byte) (SampleReport, error) {
	if len(data) == 0 {
		return SampleReport{}, errors.New("empty sample output")
	}
	if len(data) > 8<<20 {
		return SampleReport{}, ErrOutputLimit
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 256<<10)
	var report SampleReport
	seenCallGraph := false
	seen := make(map[StackPredicate]bool)
	threadRead := false
	threadDecode := false
	finishThread := func() {
		if threadRead && threadDecode {
			seen[StackPredicateReadDecodeChain] = true
		}
		threadRead = false
		threadDecode = false
	}
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		if lineCount > 100_000 {
			return SampleReport{}, ErrOutputLimit
		}
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "call graph:") {
			seenCallGraph = true
			continue
		}
		if strings.HasPrefix(lower, "thread_") || strings.HasPrefix(lower, "thread ") || strings.Contains(lower, " thread_") {
			finishThread()
			report.ThreadCount++
		}
		if !seenCallGraph || trimmed == "" {
			continue
		}
		if looksLikeSampleFrame(trimmed) {
			report.FrameCount++
		}
		switch {
		case containsAny(lower, " read(", " pread(", " readv(", "__read_nocancel"):
			seen[StackPredicateReadSyscall] = true
			threadRead = true
		case containsAny(lower, "fs.read", "uv__fs_work", "filehandle::read"):
			seen[StackPredicateFileRead] = true
			threadRead = true
		}
		if containsAny(lower, "json.parse", "jsonparser", "json_parser", "builtin_jsonparse", "simdjson", "serde_json") {
			seen[StackPredicateJSONDecoder] = true
			threadDecode = true
		}
		if containsAny(lower, "uv_run", "node::spin", "eventloop", "kevent") {
			seen[StackPredicateNodeEventLoop] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return SampleReport{}, err
	}
	finishThread()
	if !seenCallGraph {
		return SampleReport{}, errors.New("sample call graph missing")
	}
	for _, predicate := range []StackPredicate{
		StackPredicateFileRead,
		StackPredicateJSONDecoder,
		StackPredicateNodeEventLoop,
		StackPredicateReadDecodeChain,
		StackPredicateReadSyscall,
	} {
		if seen[predicate] {
			report.Predicates = append(report.Predicates, predicate)
		}
	}
	report.Availability = model.AvailabilityAvailable
	return report, nil
}

func looksLikeSampleFrame(line string) bool {
	if line == "" || strings.HasSuffix(line, ":") {
		return false
	}
	// sample frames begin with a numeric sample count or a '+' continuation.
	return (line[0] >= '0' && line[0] <= '9') || line[0] == '+'
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}
