package model

import (
	"fmt"
	"slices"
	"time"
)

const (
	SnapshotSchemaVersion      = "runnel.snapshot/v1"
	ShareSnapshotSchemaVersion = "runnel.share-snapshot/v1"
)

// ProbeAvailability preserves partial and unavailable observations explicitly.
type ProbeAvailability struct {
	Probe  ProbeKind    `json:"probe"`
	Status Availability `json:"status"`
}

func (p ProbeAvailability) Validate() error {
	if !p.Probe.Valid() {
		return fmt.Errorf("model: invalid probe %q", p.Probe)
	}
	if !p.Status.Valid() {
		return fmt.Errorf("model: invalid availability %q", p.Status)
	}
	return nil
}

// ProcessObservation contains read-only scanner facts. It deliberately has no
// DarwinActionIdentity, detector result, selection, or confirmation fields.
type ProcessObservation struct {
	Identity               ProcessIdentity     `json:"identity"`
	ParentPID              int32               `json:"parent_pid"`
	CPUTimeNS              uint64              `json:"cpu_time_ns"`
	CPUTimeDeltaNS         uint64              `json:"cpu_time_delta_ns"`
	RSSBytes               uint64              `json:"rss_bytes"`
	TTY                    string              `json:"tty,omitempty"`
	CWD                    string              `json:"cwd,omitempty"`
	Argv                   []string            `json:"argv"`
	ListeningConnections   uint32              `json:"listening_connections"`
	EstablishedConnections uint32              `json:"established_connections"`
	Availability           []ProbeAvailability `json:"availability"`
	Evidence               []EvidenceCode      `json:"evidence"`
}

func (p ProcessObservation) Validate() error {
	if err := p.Identity.Validate(); err != nil {
		return fmt.Errorf("process identity: %w", err)
	}
	for i, availability := range p.Availability {
		if err := availability.Validate(); err != nil {
			return fmt.Errorf("availability[%d]: %w", i, err)
		}
	}
	if !sortedUniqueAvailability(p.Availability) {
		return fmt.Errorf("model: availability must be sorted by probe with unique probes")
	}
	if !sortedUniqueEvidence(p.Evidence) {
		return fmt.Errorf("model: evidence must be sorted and unique")
	}
	if p.Argv == nil || p.Availability == nil || p.Evidence == nil {
		return fmt.Errorf("model: repeated fields must be non-nil")
	}
	return nil
}

type ResourceAggregate struct {
	ProcessCount uint32 `json:"process_count"`
	CPUTimeNS    uint64 `json:"cpu_time_ns"`
	RSSBytes     uint64 `json:"rss_bytes"`
}

type WorkflowGroup struct {
	ID             string               `json:"id"`
	Root           ProcessIdentity      `json:"root"`
	Family         WorkflowFamily       `json:"family"`
	Classification Classification       `json:"classification"`
	Attribution    []EvidenceCode       `json:"attribution"`
	Protection     []EvidenceCode       `json:"protection"`
	Processes      []ProcessObservation `json:"processes"`
	Aggregate      ResourceAggregate    `json:"aggregate"`
}

func (g WorkflowGroup) Protected() bool {
	return g.Classification == ClassificationProtected || len(g.Protection) != 0
}

func (g WorkflowGroup) Validate() error {
	if g.ID == "" {
		return fmt.Errorf("model: group id is required")
	}
	if err := g.Root.Validate(); err != nil {
		return fmt.Errorf("group root: %w", err)
	}
	if !g.Family.Valid() {
		return fmt.Errorf("model: invalid workflow family %q", g.Family)
	}
	if !g.Classification.Valid() {
		return fmt.Errorf("model: invalid classification %q", g.Classification)
	}
	if g.Attribution == nil || g.Protection == nil || g.Processes == nil {
		return fmt.Errorf("model: repeated fields must be non-nil")
	}
	if !sortedUniqueEvidence(g.Attribution) || !sortedUniqueEvidence(g.Protection) {
		return fmt.Errorf("model: evidence must be sorted and unique")
	}
	if len(g.Protection) > 0 && g.Classification != ClassificationProtected {
		return fmt.Errorf("model: protected group must have protected classification")
	}
	if g.Classification == ClassificationSupportedStaleCandidate && len(g.Protection) > 0 {
		return fmt.Errorf("model: protected group cannot be a candidate")
	}
	var aggregate ResourceAggregate
	for i, process := range g.Processes {
		if err := process.Validate(); err != nil {
			return fmt.Errorf("processes[%d]: %w", i, err)
		}
		if i > 0 && compareIdentity(g.Processes[i-1].Identity, process.Identity) >= 0 {
			return fmt.Errorf("model: processes must be strictly sorted")
		}
		aggregate.ProcessCount++
		aggregate.CPUTimeNS += process.CPUTimeNS
		aggregate.RSSBytes += process.RSSBytes
	}
	if aggregate != g.Aggregate {
		return fmt.Errorf("model: aggregate does not exactly match processes")
	}
	if len(g.Processes) == 0 || !g.Root.Equal(g.Processes[0].Identity) && !containsIdentity(g.Processes, g.Root) {
		return fmt.Errorf("model: group root must be present in processes")
	}
	return nil
}

type Platform struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

func (p Platform) Validate() error {
	if p.OS == "" || p.Arch == "" {
		return fmt.Errorf("model: platform os and arch are required")
	}
	return nil
}

type Snapshot struct {
	SchemaVersion string              `json:"schema_version"`
	ToolVersion   string              `json:"tool_version"`
	ObservedAt    time.Time           `json:"observed_at"`
	Platform      Platform            `json:"platform"`
	Availability  []ProbeAvailability `json:"availability"`
	Groups        []WorkflowGroup     `json:"groups"`
}

func (s Snapshot) Validate() error {
	if s.SchemaVersion != SnapshotSchemaVersion {
		return fmt.Errorf("model: unsupported snapshot schema %q", s.SchemaVersion)
	}
	if s.ToolVersion == "" {
		return fmt.Errorf("model: tool_version is required")
	}
	if s.ObservedAt.IsZero() || s.ObservedAt.Location() != time.UTC {
		return fmt.Errorf("model: observed_at must be a non-zero UTC time")
	}
	if err := s.Platform.Validate(); err != nil {
		return err
	}
	if s.Availability == nil || s.Groups == nil {
		return fmt.Errorf("model: repeated fields must be non-nil")
	}
	if !sortedUniqueAvailability(s.Availability) {
		return fmt.Errorf("model: availability must be sorted by probe with unique probes")
	}
	for i, availability := range s.Availability {
		if err := availability.Validate(); err != nil {
			return fmt.Errorf("availability[%d]: %w", i, err)
		}
	}
	for i, group := range s.Groups {
		if err := group.Validate(); err != nil {
			return fmt.Errorf("groups[%d]: %w", i, err)
		}
		if i > 0 && s.Groups[i-1].ID >= group.ID {
			return fmt.Errorf("model: groups must be strictly sorted by id")
		}
	}
	return nil
}

// ShareSnapshot is built independently from aggregate inputs. It has no process
// identity, time, path, argv, cwd, port, session, raw stack, or raw error fields.
type ShareSnapshot struct {
	SchemaVersion string               `json:"schema_version"`
	ToolVersion   string               `json:"tool_version"`
	Platform      Platform             `json:"platform"`
	Availability  []ProbeAvailability  `json:"availability"`
	Groups        []ShareWorkflowGroup `json:"groups"`
}

type ShareWorkflowGroup struct {
	Family         WorkflowFamily `json:"family"`
	Classification Classification `json:"classification"`
	Attribution    []EvidenceCode `json:"attribution"`
	Protection     []EvidenceCode `json:"protection"`
	ProcessCount   uint32         `json:"process_count"`
	CPUTimeBucket  CPUTimeBucket  `json:"cpu_time_bucket"`
	RSSBucket      SizeBucket     `json:"rss_bucket"`
}

func (s ShareSnapshot) Validate() error {
	if s.SchemaVersion != ShareSnapshotSchemaVersion {
		return fmt.Errorf("model: unsupported share snapshot schema %q", s.SchemaVersion)
	}
	if s.ToolVersion == "" {
		return fmt.Errorf("model: tool_version is required")
	}
	if err := s.Platform.Validate(); err != nil {
		return err
	}
	if s.Availability == nil || s.Groups == nil {
		return fmt.Errorf("model: repeated fields must be non-nil")
	}
	if !sortedUniqueAvailability(s.Availability) {
		return fmt.Errorf("model: availability must be sorted by probe with unique probes")
	}
	for i, availability := range s.Availability {
		if err := availability.Validate(); err != nil {
			return fmt.Errorf("availability[%d]: %w", i, err)
		}
	}
	for i, group := range s.Groups {
		if !group.Family.Valid() || !group.Classification.Valid() {
			return fmt.Errorf("model: groups[%d] has invalid enum", i)
		}
		if !sortedUniqueEvidence(group.Attribution) || !sortedUniqueEvidence(group.Protection) {
			return fmt.Errorf("model: groups[%d] evidence must be sorted and unique", i)
		}
		if group.Attribution == nil || group.Protection == nil || !group.CPUTimeBucket.Valid() || !group.RSSBucket.Valid() {
			return fmt.Errorf("model: groups[%d] is incomplete", i)
		}
		if i > 0 && compareShareGroup(s.Groups[i-1], group) >= 0 {
			return fmt.Errorf("model: share groups must be strictly sorted")
		}
	}
	return nil
}

func sortedUniqueEvidence(values []EvidenceCode) bool {
	return slices.IsSortedFunc(values, func(a, b EvidenceCode) int { return compareString(string(a), string(b)) }) &&
		!hasAdjacentDuplicate(values)
}

func sortedUniqueAvailability(values []ProbeAvailability) bool {
	return slices.IsSortedFunc(values, func(a, b ProbeAvailability) int { return compareString(string(a.Probe), string(b.Probe)) }) &&
		!hasAdjacentDuplicateFunc(values, func(a, b ProbeAvailability) bool { return a.Probe == b.Probe })
}

func hasAdjacentDuplicate[T comparable](values []T) bool {
	for i := 1; i < len(values); i++ {
		if values[i] == values[i-1] {
			return true
		}
	}
	return false
}

func hasAdjacentDuplicateFunc[T any](values []T, equal func(T, T) bool) bool {
	for i := 1; i < len(values); i++ {
		if equal(values[i], values[i-1]) {
			return true
		}
	}
	return false
}

func compareIdentity(a, b ProcessIdentity) int {
	if a.PID != b.PID {
		if a.PID < b.PID {
			return -1
		}
		return 1
	}
	if c := a.StartTime.Compare(b.StartTime); c != 0 {
		return c
	}
	if a.UID != b.UID {
		if a.UID < b.UID {
			return -1
		}
		return 1
	}
	return compareString(a.Executable, b.Executable)
}

func compareShareGroup(a, b ShareWorkflowGroup) int {
	if c := compareString(string(a.Family), string(b.Family)); c != 0 {
		return c
	}
	return compareString(string(a.Classification), string(b.Classification))
}

func compareString(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func containsIdentity(processes []ProcessObservation, identity ProcessIdentity) bool {
	for _, process := range processes {
		if process.Identity.Equal(identity) {
			return true
		}
	}
	return false
}
