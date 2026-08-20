package darwin

import (
	"time"

	"github.com/ArshyaAI/runnel/internal/model"
)

const (
	hardProbeTimeout     = 30 * time.Second
	hardProbeGrace       = 5 * time.Second
	hardProbeEscapeGrace = 2 * time.Second
	hardProbeBytes       = 16 << 20
	hardProbeLines       = 100_000
)

// Availability mirrors the versioned model vocabulary. These aliases remain
// local to the adapter so low-level helpers can compile on unsupported hosts.
// Public model-bearing records use model.Availability once the domain package
// is available.
type Availability = model.Availability

const (
	Available           = model.AvailabilityAvailable
	NotApplicable       = model.AvailabilityNotApplicable
	PermissionDenied    = model.AvailabilityPermissionDenied
	UnsupportedPlatform = model.AvailabilityUnsupportedPlatform
	UnsupportedVersion  = model.AvailabilityUnsupportedVersion
	ProcessExited       = model.AvailabilityProcessExited
	TimedOut            = model.AvailabilityTimeout
	MalformedOutput     = model.AvailabilityMalformedOutput
	SchemaIncompatible  = model.AvailabilitySchemaIncompatible
	Contradictory       = model.AvailabilityContradictory
)

// Capability describes a dynamically detected platform primitive.
type Capability struct {
	Availability Availability
	Reason       string
}

func (c Capability) Supported() bool { return c.Availability == Available }

// ProbeLimits bound a single direct-argv child probe.
type ProbeLimits struct {
	Timeout     time.Duration
	TermGrace   time.Duration
	KillGrace   time.Duration
	EscapeGrace time.Duration
	MaxBytes    int
	MaxLines    int
}

func (l ProbeLimits) withDefaults() ProbeLimits {
	if l.Timeout <= 0 {
		l.Timeout = 5 * time.Second
	}
	l.Timeout = min(l.Timeout, hardProbeTimeout)
	if l.TermGrace <= 0 {
		l.TermGrace = 250 * time.Millisecond
	}
	l.TermGrace = min(l.TermGrace, hardProbeGrace)
	if l.KillGrace <= 0 {
		l.KillGrace = time.Second
	}
	l.KillGrace = min(l.KillGrace, hardProbeGrace)
	if l.EscapeGrace <= 0 {
		l.EscapeGrace = 100 * time.Millisecond
	}
	l.EscapeGrace = min(l.EscapeGrace, hardProbeEscapeGrace)
	if l.MaxBytes <= 0 {
		l.MaxBytes = 1 << 20
	}
	l.MaxBytes = min(l.MaxBytes, hardProbeBytes)
	if l.MaxLines <= 0 {
		l.MaxLines = 20_000
	}
	l.MaxLines = min(l.MaxLines, hardProbeLines)
	return l
}

type ProbeResult struct {
	Output       []byte
	ExitCode     int
	Duration     time.Duration
	TermSent     bool
	KillSent     bool
	EscapedChild bool
}

type ProbeExitError struct{ Code int }

func (e *ProbeExitError) Error() string { return "probe exited unsuccessfully" }
