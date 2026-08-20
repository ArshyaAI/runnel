package darwin

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"slices"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/ArshyaAI/runnel/internal/model"
)

const (
	hardMaxProcesses = 65_536
	hardMaxFDs       = 16_384
)

type CollectorConfig struct {
	MaxProcesses int
	Workers      int
	MaxFDs       int
}

func (c CollectorConfig) withDefaults() CollectorConfig {
	if c.MaxProcesses <= 0 {
		c.MaxProcesses = 8192
	}
	c.MaxProcesses = min(c.MaxProcesses, hardMaxProcesses)
	if c.Workers <= 0 {
		c.Workers = min(64, max(4, runtime.GOMAXPROCS(0)*2))
	}
	if c.Workers > 128 {
		c.Workers = 128
	}
	if c.MaxFDs <= 0 {
		c.MaxFDs = 4096
	}
	c.MaxFDs = min(c.MaxFDs, hardMaxFDs)
	return c
}

type Collector struct{ config CollectorConfig }

func NewCollector(config CollectorConfig) *Collector {
	return &Collector{config: config.withDefaults()}
}

type ProcessRecord struct {
	Observation     model.ProcessObservation
	ActionIdentity  model.DarwinActionIdentity
	CPUUserNS       uint64
	CPUSystemNS     uint64
	VMSBytes        uint64
	TTYDevice       uint32
	TTYProcessGroup int32
	ActionAvailable model.Availability
}

type ProcessFailure struct {
	PID          int32
	Availability model.Availability
	Err          error
}

type ProcessSnapshot struct {
	Processes    []ProcessRecord
	Failures     []ProcessFailure
	Truncated    bool
	Availability model.Availability
}

type processReadResult struct {
	record  ProcessRecord
	failure ProcessFailure
	ok      bool
}

// Processes performs exactly one full-list enumeration and then reads details
// through a bounded worker pool. It never calls a per-process Children method.
func (c *Collector) Processes(ctx context.Context) (ProcessSnapshot, error) {
	config := c.config.withDefaults()
	pids, truncated, err := nativeListPIDs(config.MaxProcesses)
	if err != nil {
		availability := availabilityForError(err)
		return ProcessSnapshot{Availability: availability}, &OperationError{Op: "process_list", Availability: availability, Err: err}
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })

	jobs := make(chan int32)
	results := make(chan processReadResult, config.Workers)
	var workers sync.WaitGroup
	workers.Add(config.Workers)
	for i := 0; i < config.Workers; i++ {
		go func() {
			defer workers.Done()
			for pid := range jobs {
				if ctx.Err() != nil {
					continue
				}
				record, readErr := readProcessRecord(pid)
				if readErr != nil {
					results <- processReadResult{failure: ProcessFailure{PID: pid, Availability: availabilityForError(readErr), Err: readErr}}
					continue
				}
				results <- processReadResult{record: record, ok: true}
			}
		}()
	}
	go func() {
		for _, pid := range pids {
			select {
			case jobs <- pid:
			case <-ctx.Done():
				close(jobs)
				return
			}
		}
		close(jobs)
	}()
	go func() {
		workers.Wait()
		close(results)
	}()

	snapshot := ProcessSnapshot{Truncated: truncated, Availability: model.AvailabilityAvailable}
	for result := range results {
		if result.ok {
			snapshot.Processes = append(snapshot.Processes, result.record)
		} else {
			snapshot.Failures = append(snapshot.Failures, result.failure)
		}
	}
	sort.Slice(snapshot.Processes, func(i, j int) bool {
		return snapshot.Processes[i].Observation.Identity.PID < snapshot.Processes[j].Observation.Identity.PID
	})
	sort.Slice(snapshot.Failures, func(i, j int) bool { return snapshot.Failures[i].PID < snapshot.Failures[j].PID })
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			snapshot.Availability = model.AvailabilityTimeout
		}
		return snapshot, err
	}
	if truncated {
		snapshot.Availability = model.AvailabilityContradictory
	}
	return snapshot, nil
}

func readProcessRecord(pid int32) (ProcessRecord, error) {
	value, err := nativeReadProcess(pid)
	if err != nil {
		return ProcessRecord{}, err
	}
	action := actionIdentityFromNative(value)
	identity := action.ProcessIdentity
	actionAvailable := model.AvailabilityAvailable
	if !action.Complete() {
		actionAvailable = availabilityForErrno(value.ExecutableErrno)
		if actionAvailable == model.AvailabilityAvailable {
			actionAvailable = model.AvailabilityUnsupportedVersion
		}
	}
	executableStatus := model.AvailabilityAvailable
	if identity.Executable == "" {
		executableStatus = availabilityForErrno(value.ExecutableErrno)
	}
	tty := ""
	if value.HasTTY {
		tty = value.TTYPath
		if tty == "" {
			tty = fmt.Sprintf("dev:%d", value.TTYDevice)
		}
	}
	availability := []model.ProbeAvailability{
		{Probe: model.ProbeCWD, Status: availabilityForErrno(value.CWDErrno)},
		{Probe: model.ProbeExecutable, Status: executableStatus},
		{Probe: model.ProbeIdentity, Status: actionAvailable},
		{Probe: model.ProbeTTY, Status: model.AvailabilityAvailable},
	}
	slices.SortFunc(availability, func(a, b model.ProbeAvailability) int {
		if a.Probe < b.Probe {
			return -1
		}
		if a.Probe > b.Probe {
			return 1
		}
		return 0
	})
	observation := model.ProcessObservation{
		Identity:     identity,
		ParentPID:    value.PPID,
		CPUTimeNS:    saturatedAdd(value.CPUUserNS, value.CPUSystemNS),
		RSSBytes:     value.RSSBytes,
		TTY:          tty,
		CWD:          value.CWD,
		Argv:         []string{},
		Availability: availability,
		Evidence:     []model.EvidenceCode{},
	}
	return ProcessRecord{
		Observation:     observation,
		ActionIdentity:  action,
		CPUUserNS:       value.CPUUserNS,
		CPUSystemNS:     value.CPUSystemNS,
		VMSBytes:        value.VMSBytes,
		TTYDevice:       value.TTYDevice,
		TTYProcessGroup: value.TTYProcessGroup,
		ActionAvailable: actionAvailable,
	}, nil
}

func actionIdentityFromNative(value nativeProcess) model.DarwinActionIdentity {
	return model.DarwinActionIdentity{
		ProcessIdentity: model.ProcessIdentity{
			PID:        value.PID,
			StartTime:  time.Unix(int64(value.StartSec), int64(value.StartUsec)*1_000).UTC(),
			UID:        value.UID,
			Executable: value.Executable,
		},
		PIDVersion: value.PIDVersion,
		UniqueID:   value.UniqueID,
	}
}

func saturatedAdd(a, b uint64) uint64 {
	if math.MaxUint64-a < b {
		return math.MaxUint64
	}
	return a + b
}

func availabilityForErrno(errno syscall.Errno) model.Availability {
	if errno == 0 {
		return model.AvailabilityAvailable
	}
	return availabilityForError(errno)
}

func availabilityForError(err error) model.Availability {
	switch {
	case err == nil:
		return model.AvailabilityAvailable
	case errors.Is(err, ErrUnsupported), errors.Is(err, syscall.ENOTSUP), errors.Is(err, syscall.ENOSYS):
		return model.AvailabilityUnsupportedPlatform
	case errors.Is(err, context.DeadlineExceeded):
		return model.AvailabilityTimeout
	case errors.Is(err, syscall.ESRCH), errors.Is(err, os.ErrNotExist):
		return model.AvailabilityProcessExited
	case errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EACCES), errors.Is(err, os.ErrPermission):
		return model.AvailabilityPermissionDenied
	default:
		return model.AvailabilityMalformedOutput
	}
}

// ActionIdentity re-reads and returns the exact Darwin action identity.
func (c *Collector) ActionIdentity(ctx context.Context, pid int32) (model.DarwinActionIdentity, error) {
	if err := ctx.Err(); err != nil {
		return model.DarwinActionIdentity{}, err
	}
	record, err := readProcessRecord(pid)
	if err != nil {
		return model.DarwinActionIdentity{}, err
	}
	if !record.ActionIdentity.Complete() {
		return model.DarwinActionIdentity{}, &OperationError{Op: "action_identity", Availability: record.ActionAvailable, Err: ErrUnsupported}
	}
	return record.ActionIdentity, nil
}

type Ancestry struct {
	Chain        []ProcessRecord
	Availability model.Availability
}

func (snapshot ProcessSnapshot) CurrentAncestry(maxDepth int) Ancestry {
	return snapshot.AncestryFrom(int32(os.Getpid()), maxDepth)
}

func (snapshot ProcessSnapshot) AncestryFrom(startPID int32, maxDepth int) Ancestry {
	if maxDepth <= 0 {
		maxDepth = 256
	}
	byPID := make(map[int32]ProcessRecord, len(snapshot.Processes))
	for _, process := range snapshot.Processes {
		byPID[process.Observation.Identity.PID] = process
	}
	chain := make([]ProcessRecord, 0, min(maxDepth, 16))
	seen := make(map[int32]struct{}, min(maxDepth, 16))
	pid := startPID
	for pid > 0 && len(chain) < maxDepth {
		if _, exists := seen[pid]; exists {
			return Ancestry{Chain: chain, Availability: model.AvailabilityContradictory}
		}
		seen[pid] = struct{}{}
		process, exists := byPID[pid]
		if !exists {
			return Ancestry{Chain: chain, Availability: model.AvailabilityProcessExited}
		}
		chain = append(chain, process)
		if process.Observation.ParentPID == 0 || process.Observation.ParentPID == pid {
			return Ancestry{Chain: chain, Availability: model.AvailabilityAvailable}
		}
		pid = process.Observation.ParentPID
	}
	if pid > 0 {
		return Ancestry{Chain: chain, Availability: model.AvailabilityContradictory}
	}
	return Ancestry{Chain: chain, Availability: model.AvailabilityAvailable}
}
