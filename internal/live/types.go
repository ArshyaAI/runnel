package live

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/ArshyaAI/runnel/internal/codex"
	"github.com/ArshyaAI/runnel/internal/model"
	"github.com/ArshyaAI/runnel/internal/platform/darwin"
)

// Code is a privacy-safe live-composition outcome. It never contains an argv
// value, path, PID, session identifier, raw error, or stack frame.
type Code string

const (
	CodeOK                     Code = "ok"
	CodeInvalidConfig          Code = "invalid_config"
	CodeInvalidCandidate       Code = "invalid_candidate"
	CodeDiscoveryUnavailable   Code = "discovery_unavailable"
	CodeDiscoveryAmbiguous     Code = "discovery_ambiguous"
	CodeStatePathUnavailable   Code = "state_path_unavailable"
	CodeStateStoreUnavailable  Code = "state_store_unavailable"
	CodeScheduleUnavailable    Code = "schedule_unavailable"
	CodeProcessTreeUnavailable Code = "process_tree_unavailable"
	CodeIdentityUnavailable    Code = "identity_unavailable"
	CodeOriginUnavailable      Code = "origin_unavailable"
	CodeDescriptorUnavailable  Code = "descriptor_unavailable"
	CodeDescriptorAmbiguous    Code = "descriptor_ambiguous"
	CodeMetadataUnavailable    Code = "metadata_unavailable"
	CodeTailUnavailable        Code = "tail_unavailable"
	CodeProtectionUnavailable  Code = "protection_unavailable"
	CodeStackSkipped           Code = "stack_skipped"
	CodeStackUnavailable       Code = "stack_unavailable"
	CodeContextCancelled       Code = "context_cancelled"
	CodeContradictory          Code = "contradictory"
)

// Error deliberately hides its cause. Causes are retained only for local
// errors.Is/errors.As decisions inside this package.
type Error struct {
	Code  Code
	cause error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return "live inspector: " + string(e.Code)
}

func (e *Error) Unwrap() error { return e.cause }

func safeError(code Code, cause error) error { return &Error{Code: code, cause: cause} }

// Candidate is an opaque pair minted only by Discover. Its process identities
// are unavailable to renderers and callers cannot construct a valid value from
// a raw PID.
type Candidate struct {
	leaf   model.DarwinActionIdentity
	parent model.DarwinActionIdentity
	proof  [32]byte
}

func (c Candidate) valid() bool {
	return c.leaf.Validate() == nil && c.parent.Validate() == nil &&
		c.proof == candidateProof(c.leaf, c.parent)
}

// Matches reports whether identity is the candidate's exact portable leaf
// identity. It supports mapping an opaque candidate to an already-held radar
// group without exposing a PID, path, parent, or raw selector.
func (c Candidate) Matches(identity model.ProcessIdentity) bool {
	return c.valid() && identity.Complete() && c.leaf.ProcessIdentity.Equal(identity)
}

// MarshalJSON prevents even same-package additions from accidentally exposing
// candidate correlation material through the default encoder.
func (Candidate) MarshalJSON() ([]byte, error) { return []byte(`{}`), nil }

// Discovery is the privacy-safe result of inspecting one immutable process
// snapshot. Candidates are available only through Candidates.
type Discovery struct {
	Availability model.Availability `json:"availability"`
	Code         Code               `json:"code"`
	Count        int                `json:"candidate_count"`
	candidates   []Candidate
}

// Candidates returns independent opaque values. The returned slice cannot
// mutate the discovery result.
func (d Discovery) Candidates() []Candidate { return slices.Clone(d.candidates) }

// PairObservation is an exact identity refresh returned by an injected
// read-only platform. Methods accept Candidate rather than a raw PID.
type PairObservation struct {
	Leaf   model.DarwinActionIdentity
	Parent model.DarwinActionIdentity
}

func (PairObservation) MarshalJSON() ([]byte, error) { return []byte(`{}`), nil }

// Platform is the complete read-only Darwin/Codex surface used by Inspector.
// It contains no signaler and no method accepts a raw PID.
type Platform interface {
	Processes(context.Context) (darwin.ProcessSnapshot, error)
	Pair(context.Context, Candidate) (PairObservation, error)
	Origin(context.Context, Candidate, PairObservation, uint32, []string) (codex.DarwinOriginObservation, error)
	Children(context.Context, Candidate, PairObservation) (darwin.ChildSnapshot, error)
	Descriptors(context.Context, Candidate, PairObservation) (darwin.DescriptorSnapshot, error)
	DescriptorEvidence(context.Context, Candidate, PairObservation, string) (codex.DarwinDescriptorObservation, error)
	Stack(context.Context, Candidate, PairObservation) (darwin.SampleReport, error)
}

// MetadataStore is a read-only stable SQLite snapshot capability.
type MetadataStore interface {
	codex.MetadataReader
	Close() error
}

// StateStoreOpener opens an exact state path in read-only mode.
type StateStoreOpener interface {
	Open(context.Context, string) (MetadataStore, error)
}

type StateStoreOpenFunc func(context.Context, string) (MetadataStore, error)

func (f StateStoreOpenFunc) Open(ctx context.Context, path string) (MetadataStore, error) {
	return f(ctx, path)
}

// StatePathResolver is intentionally lazy: Inspector calls it only when an
// opaque candidate is inspected, never during construction or fast discovery.
type StatePathResolver interface {
	Resolve() (string, error)
}

type StatePathResolveFunc func() (string, error)

func (f StatePathResolveFunc) Resolve() (string, error) { return f() }

type Clock interface{ Now() time.Time }

type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

type Sleeper interface {
	Sleep(context.Context, time.Duration) error
}

type SleepFunc func(context.Context, time.Duration) error

func (f SleepFunc) Sleep(ctx context.Context, d time.Duration) error { return f(ctx, d) }

// ProtectionObservation is exact, immutable evidence for the selected leaf
// and its direct children. Exact identities remain outside JSON.
type ProtectionObservation struct {
	Availability      model.Availability           `json:"availability"`
	LeafProtected     bool                         `json:"leaf_protected"`
	ProtectedChildren uint32                       `json:"protected_children"`
	Protected         []model.DarwinActionIdentity `json:"-"`
}

// ProtectionPolicy refreshes structural protection from the same process
// snapshot used for the sample. It cannot receive a raw PID.
type ProtectionPolicy interface {
	Observe(darwin.ProcessSnapshot, Candidate, PairObservation, []darwin.ProcessRecord) (ProtectionObservation, error)
}

type ProtectionFunc func(darwin.ProcessSnapshot, Candidate, PairObservation, []darwin.ProcessRecord) (ProtectionObservation, error)

func (f ProtectionFunc) Observe(snapshot darwin.ProcessSnapshot, candidate Candidate, pair PairObservation, children []darwin.ProcessRecord) (ProtectionObservation, error) {
	return f(snapshot, candidate, pair, children)
}

type Options struct {
	CurrentUID uint32
	TempRoots  []string
	StatePath  StatePathResolver
	Protected  []model.DarwinActionIdentity
}

type Dependencies struct {
	Platform   Platform
	State      StateStoreOpener
	Tail       codex.CompletionTailReader
	Clock      Clock
	Sleeper    Sleeper
	Protection ProtectionPolicy
}

// Report is the complete privacy-safe live result. DetectorResult's Baseline
// and all Codex correlation fields are already excluded from JSON by codex.
type Report struct {
	Availability     model.Availability   `json:"availability"`
	Code             Code                 `json:"code"`
	CompletedSamples int                  `json:"completed_samples"`
	StackAttempted   bool                 `json:"stack_attempted"`
	Detector         codex.DetectorResult `json:"detector"`
}

// Finding carries the safe report plus explicit access to immutable private
// context. Default JSON encoding emits only Report.
type Finding struct {
	report  Report
	context *RecoveryContext
}

func (f Finding) Report() Report { return cloneReport(f.report) }

// DetectorResult is the neutral authority-bearing handoff. The inspector does
// not manufacture a model.ActionCandidate.
func (f Finding) DetectorResult() codex.DetectorResult {
	return cloneDetectorResult(f.report.Detector)
}

func (f Finding) MarshalJSON() ([]byte, error) { return json.Marshal(f.report) }

// RecoveryContext contains the immutable read-only facts needed by a
// higher-level action-time revalidator. Access is explicit and it has no
// signaling method.
type RecoveryContext struct {
	candidate   Candidate
	detector    codex.DetectorResult
	leaf        model.DarwinActionIdentity
	parent      model.DarwinActionIdentity
	currentUID  uint32
	tempRoots   []string
	statePath   string
	rolloutPath string
	protected   []model.DarwinActionIdentity
	rssBytes    uint64
}

// RecoveryContext is issued only for a selectable detector result.
func (f Finding) RecoveryContext() (RecoveryContext, bool) {
	if f.context == nil || !f.report.Detector.Selectable {
		return RecoveryContext{}, false
	}
	return f.context.clone(), true
}

func (c RecoveryContext) DetectorResult() codex.DetectorResult {
	return cloneDetectorResult(c.detector)
}
func (c RecoveryContext) Candidate() Candidate { return c.candidate }
func (c RecoveryContext) Identities() (model.DarwinActionIdentity, model.DarwinActionIdentity) {
	return c.leaf, c.parent
}
func (c RecoveryContext) CurrentUID() uint32                      { return c.currentUID }
func (c RecoveryContext) TempRoots() []string                     { return slices.Clone(c.tempRoots) }
func (c RecoveryContext) StatePath() string                       { return c.statePath }
func (c RecoveryContext) RolloutPath() string                     { return c.rolloutPath }
func (c RecoveryContext) Protected() []model.DarwinActionIdentity { return slices.Clone(c.protected) }
func (c RecoveryContext) RSSBytes() uint64                        { return c.rssBytes }
func (RecoveryContext) MarshalJSON() ([]byte, error)              { return []byte(`{}`), nil }

func (c RecoveryContext) clone() RecoveryContext {
	c.detector = cloneDetectorResult(c.detector)
	c.tempRoots = slices.Clone(c.tempRoots)
	c.protected = slices.Clone(c.protected)
	return c
}

func cloneReport(value Report) Report {
	value.Detector = cloneDetectorResult(value.Detector)
	return value
}

func cloneDetectorResult(value codex.DetectorResult) codex.DetectorResult {
	value.Evidence = slices.Clone(value.Evidence)
	value.Codes = slices.Clone(value.Codes)
	return value
}

func contextCode(err error) Code {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return CodeContextCancelled
	}
	return CodeContradictory
}
