package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"time"

	"github.com/ArshyaAI/runnel/internal/buildinfo"
	"github.com/ArshyaAI/runnel/internal/model"
	"github.com/ArshyaAI/runnel/internal/platform/darwin"
	"github.com/ArshyaAI/runnel/internal/workflow"
)

// ErrPartial indicates a valid snapshot with incomplete probe evidence. It is
// mapped to exit status 3 by the command layer.
var ErrPartial = errors.New("snapshot is partial or unavailable")

// SnapshotService is the sole read-only capability needed by scan. Keeping it
// narrow lets callers inject fixture scanners without importing Darwin code.
type SnapshotService interface {
	Snapshot(context.Context) (model.Snapshot, error)
}

type LocalScanner struct {
	Collector *darwin.Collector
	Clock     func() time.Time
}

func NewLocalScanner() *LocalScanner {
	return &LocalScanner{Collector: darwin.NewCollector(darwin.CollectorConfig{}), Clock: time.Now}
}

func (s *LocalScanner) Snapshot(ctx context.Context) (model.Snapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if s == nil || s.Collector == nil {
		return emptySnapshot(model.AvailabilityUnsupportedPlatform)
	}
	clock := s.Clock
	if clock == nil {
		clock = time.Now
	}
	// Keep the fast radar bounded even if the caller supplied a context without
	// a deadline. Deep evidence is intentionally not part of this path.
	probeCtx, cancel := context.WithTimeout(ctx, 1800*time.Millisecond)
	defer cancel()
	// The two cheap process samples are deliberately close together. CPU deltas
	// are accepted only when portable identity matches exactly.
	first, firstErr := s.Collector.Processes(probeCtx)
	second, secondErr := s.Collector.Processes(probeCtx)
	base := second
	if len(base.Processes) == 0 && len(first.Processes) > 0 {
		base = first
	}
	// One bounded global socket map avoids per-process lsof calls. Socket data
	// is correlation-only and remains explicitly unavailable when the probe is
	// not permitted or unsupported.
	socketCtx, socketCancel := context.WithTimeout(probeCtx, 250*time.Millisecond)
	sockets, socketErr := darwin.GlobalSockets(socketCtx, darwin.ProbeLauncher{}, 65536)
	socketCancel()
	byPID := sockets.ByPID
	previous := make(map[string]darwin.ProcessRecord, len(first.Processes))
	for _, p := range first.Processes {
		previous[processKey(p.Observation.Identity)] = p
	}
	observations := make([]model.ProcessObservation, 0, len(base.Processes))
	for _, record := range base.Processes {
		o := record.Observation
		if counts, ok := byPID[o.Identity.PID]; ok {
			o.ListeningConnections = counts.Listening
			o.EstablishedConnections = counts.Established
		}
		if prior, ok := previous[processKey(o.Identity)]; ok && o.Identity.Equal(prior.Observation.Identity) && o.CPUTimeNS >= prior.Observation.CPUTimeNS {
			o.CPUTimeDeltaNS = o.CPUTimeNS - prior.Observation.CPUTimeNS
		}
		observations = append(observations, o)
	}
	currentPID := int32(os.Getpid())
	currentUID := uint32(os.Getuid())
	ttyOwners := make([]int32, 0)
	for _, p := range base.Processes {
		if p.Observation.TTY != "" {
			ttyOwners = append(ttyOwners, p.Observation.Identity.PID)
		}
	}
	groups, groupErr := workflow.Group(observations, workflow.Options{CurrentPID: currentPID, CurrentUID: currentUID, TTYOwnerPIDs: ttyOwners})
	if groupErr != nil {
		empty, _ := emptySnapshot(model.AvailabilityContradictory)
		return empty, fmt.Errorf("%w: group: %v", ErrPartial, groupErr)
	}
	socketAvailability := sockets.Availability
	if socketErr != nil && socketAvailability == model.AvailabilityAvailable {
		socketAvailability = model.AvailabilityMalformedOutput
	}
	snapshot := model.Snapshot{SchemaVersion: model.SnapshotSchemaVersion, ToolVersion: buildinfo.Current().Version, ObservedAt: clock().UTC(), Platform: model.Platform{OS: runtime.GOOS, Arch: runtime.GOARCH}, Groups: groups,
		Availability: []model.ProbeAvailability{{Probe: model.ProbeCWD, Status: baseAvailability(model.ProbeCWD, first, second)}, {Probe: model.ProbeExecutable, Status: baseAvailability(model.ProbeExecutable, first, second)}, {Probe: model.ProbeIdentity, Status: baseAvailability(model.ProbeIdentity, first, second)}, {Probe: model.ProbeSockets, Status: socketAvailability}, {Probe: model.ProbeTTY, Status: baseAvailability(model.ProbeTTY, first, second)}}}
	sort.Slice(snapshot.Availability, func(i, j int) bool { return snapshot.Availability[i].Probe < snapshot.Availability[j].Probe })
	if err := snapshot.Validate(); err != nil {
		return snapshot, fmt.Errorf("%w: validate: %v", ErrPartial, err)
	}
	// Socket correlation is optional for the radar. Its availability is already
	// preserved in the snapshot; a permission-denied or malformed socket probe
	// must not turn an otherwise complete process snapshot into a misleading
	// partial result. Only process enumeration/detail failures affect the exit.
	if firstErr != nil || secondErr != nil || base.Availability != model.AvailabilityAvailable || len(base.Failures) > 0 {
		return snapshot, fmt.Errorf("%w: process probe incomplete", ErrPartial)
	}
	return snapshot, nil
}

func processKey(id model.ProcessIdentity) string {
	return fmt.Sprintf("%d|%d|%s", id.PID, id.UID, id.StartTime.UTC().Format(time.RFC3339Nano)) + "|" + id.Executable
}
func baseAvailability(_ model.ProbeKind, snapshots ...darwin.ProcessSnapshot) model.Availability {
	for _, s := range snapshots {
		if s.Availability != model.AvailabilityAvailable {
			return s.Availability
		}
		if len(s.Failures) > 0 {
			return s.Failures[0].Availability
		}
	}
	return model.AvailabilityAvailable
}
func emptySnapshot(status model.Availability) (model.Snapshot, error) {
	s := model.Snapshot{SchemaVersion: model.SnapshotSchemaVersion, ToolVersion: buildinfo.Current().Version, ObservedAt: time.Now().UTC(), Platform: model.Platform{OS: runtime.GOOS, Arch: runtime.GOARCH}, Availability: []model.ProbeAvailability{{Probe: model.ProbeIdentity, Status: status}}, Groups: []model.WorkflowGroup{}}
	return s, ErrPartial
}
