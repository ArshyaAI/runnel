package live

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ArshyaAI/runnel/internal/codex"
	"github.com/ArshyaAI/runnel/internal/model"
	"github.com/ArshyaAI/runnel/internal/platform/darwin"
)

type productionPlatform struct {
	collector *darwin.Collector
	adapter   *codex.DarwinAdapter
	launcher  darwin.ProbeLauncher
}

func (p *productionPlatform) Processes(ctx context.Context) (darwin.ProcessSnapshot, error) {
	return p.collector.Processes(ctx)
}

func (p *productionPlatform) Pair(ctx context.Context, candidate Candidate) (PairObservation, error) {
	if !candidate.valid() {
		return PairObservation{}, safeError(CodeInvalidCandidate, nil)
	}
	leaf, err := p.collector.ActionIdentity(ctx, candidate.leaf.PID)
	if err != nil {
		return PairObservation{}, err
	}
	parent, err := p.collector.ActionIdentity(ctx, candidate.parent.PID)
	if err != nil {
		return PairObservation{}, err
	}
	return PairObservation{Leaf: leaf, Parent: parent}, nil
}

func (p *productionPlatform) Origin(ctx context.Context, candidate Candidate, pair PairObservation, uid uint32, roots []string) (codex.DarwinOriginObservation, error) {
	if !candidate.valid() {
		return codex.DarwinOriginObservation{}, safeError(CodeInvalidCandidate, nil)
	}
	return p.adapter.ObserveOrigin(ctx, pair.Leaf, pair.Parent, uid, roots)
}

func (p *productionPlatform) Children(ctx context.Context, candidate Candidate, pair PairObservation) (darwin.ChildSnapshot, error) {
	if !candidate.valid() {
		return darwin.ChildSnapshot{}, safeError(CodeInvalidCandidate, nil)
	}
	return p.collector.Children(ctx, pair.Leaf, 0)
}

func (p *productionPlatform) Descriptors(ctx context.Context, candidate Candidate, pair PairObservation) (darwin.DescriptorSnapshot, error) {
	if !candidate.valid() {
		return darwin.DescriptorSnapshot{}, safeError(CodeInvalidCandidate, nil)
	}
	return p.collector.Descriptors(ctx, pair.Leaf, 0)
}

func (p *productionPlatform) DescriptorEvidence(ctx context.Context, candidate Candidate, pair PairObservation, rolloutPath string) (codex.DarwinDescriptorObservation, error) {
	if !candidate.valid() {
		return codex.DarwinDescriptorObservation{}, safeError(CodeInvalidCandidate, nil)
	}
	return p.adapter.ObserveDescriptors(ctx, pair.Leaf, rolloutPath)
}

func (p *productionPlatform) Stack(ctx context.Context, candidate Candidate, pair PairObservation) (darwin.SampleReport, error) {
	if !candidate.valid() {
		return darwin.SampleReport{}, safeError(CodeInvalidCandidate, nil)
	}
	return p.collector.Sample(ctx, p.launcher, pair.Leaf, darwin.SampleOptions{})
}

type readOnlyStateOpener struct{}

func (readOnlyStateOpener) Open(ctx context.Context, path string) (MetadataStore, error) {
	return codex.OpenStore(ctx, path, codex.StoreOptions{})
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

type timerSleeper struct{}

func (timerSleeper) Sleep(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// DefaultStatePathResolver lazily resolves only ~/.codex/state_5.sqlite.
func DefaultStatePathResolver() StatePathResolver {
	return StatePathResolveFunc(func() (string, error) {
		home, err := os.UserHomeDir()
		if err != nil || !canonicalAbsolute(home) {
			return "", safeError(CodeStatePathUnavailable, err)
		}
		return filepath.Join(home, ".codex", "state_5.sqlite"), nil
	})
}

// NewProduction builds the real read-only inspector. It deliberately does not
// resolve the state path or probe a process until Inspect is called.
func NewProduction(options Options) (*Inspector, error) {
	collector := darwin.NewCollector(darwin.CollectorConfig{})
	if options.CurrentUID == 0 {
		options.CurrentUID = uint32(os.Getuid())
	}
	if options.StatePath == nil {
		options.StatePath = DefaultStatePathResolver()
	}
	return New(options, Dependencies{
		Platform: &productionPlatform{
			collector: collector,
			adapter:   codex.NewDarwinAdapter(collector, darwin.NewOriginVerifier()),
			launcher:  darwin.ProbeLauncher{},
		},
		State:      readOnlyStateOpener{},
		Tail:       codex.NewTailReader(codex.TailReaderOptions{}),
		Clock:      systemClock{},
		Sleeper:    timerSleeper{},
		Protection: newStructuralProtection(int32(os.Getpid()), options.Protected),
	})
}

type structuralProtection struct {
	currentPID int32
	explicit   []model.DarwinActionIdentity
}

func newStructuralProtection(currentPID int32, explicit []model.DarwinActionIdentity) *structuralProtection {
	return &structuralProtection{currentPID: currentPID, explicit: slices.Clone(explicit)}
}

func (p *structuralProtection) Observe(snapshot darwin.ProcessSnapshot, _ Candidate, pair PairObservation, children []darwin.ProcessRecord) (ProtectionObservation, error) {
	if snapshot.Availability != model.AvailabilityAvailable || snapshot.Truncated {
		return ProtectionObservation{Availability: model.AvailabilityContradictory}, safeError(CodeProtectionUnavailable, nil)
	}
	failures := failurePIDs(snapshot.Failures)
	protected := slices.Clone(p.explicit)
	for _, identity := range protected {
		if identity.Validate() != nil {
			return ProtectionObservation{Availability: model.AvailabilityContradictory}, safeError(CodeProtectionUnavailable, nil)
		}
		if failures[identity.PID] {
			return ProtectionObservation{Availability: model.AvailabilityPermissionDenied}, safeError(CodeProtectionUnavailable, nil)
		}
	}

	ancestry, ancestryErr := exactAncestry(snapshot, p.currentPID, 256)
	if ancestryErr != nil {
		return ProtectionObservation{Availability: model.AvailabilityContradictory}, safeError(CodeProtectionUnavailable, ancestryErr)
	}
	for _, record := range ancestry {
		protected = append(protected, record.ActionIdentity)
	}
	for _, record := range snapshot.Processes {
		if record.Observation.TTY == "" && !intrinsicallyProtected(record.Observation.Identity.Executable) {
			continue
		}
		if !exactActionRecord(record) {
			continue
		}
		protected = append(protected, record.ActionIdentity)
	}
	for _, child := range children {
		if !exactActionRecord(child) || child.Observation.ParentPID != pair.Leaf.PID {
			return ProtectionObservation{Availability: model.AvailabilityContradictory}, safeError(CodeProtectionUnavailable, nil)
		}
		if child.Observation.TTY != "" || intrinsicallyProtected(child.Observation.Identity.Executable) {
			protected = append(protected, child.ActionIdentity)
		}
	}
	protected = normalizeIdentities(protected)

	result := ProtectionObservation{
		Availability:  model.AvailabilityAvailable,
		Protected:     protected,
		LeafProtected: containsIdentity(protected, pair.Leaf),
	}
	for _, child := range children {
		if containsIdentity(protected, child.ActionIdentity) {
			result.ProtectedChildren++
		}
	}
	return result, nil
}

func exactAncestry(snapshot darwin.ProcessSnapshot, startPID int32, maxDepth int) ([]darwin.ProcessRecord, error) {
	if startPID <= 0 || maxDepth <= 0 {
		return nil, errors.New("invalid ancestry root")
	}
	chain := make([]darwin.ProcessRecord, 0, 16)
	seen := make(map[int32]bool, 16)
	pid := startPID
	for pid > 0 && len(chain) < maxDepth {
		if seen[pid] {
			return nil, errors.New("ancestry cycle")
		}
		seen[pid] = true
		record, err := uniqueExactRecord(snapshot, pid)
		if err != nil {
			return nil, err
		}
		chain = append(chain, record)
		parent := record.Observation.ParentPID
		if parent == 0 {
			return chain, nil
		}
		if parent == pid {
			return nil, errors.New("ancestry self-cycle")
		}
		pid = parent
	}
	if pid > 0 {
		return nil, errors.New("ancestry depth exceeded")
	}
	return chain, nil
}

func intrinsicallyProtected(path string) bool {
	name := strings.ToLower(filepath.Base(filepath.Clean(path)))
	for _, fragment := range []string{
		"cmux", "code", "cursor", "xcode", "postgres", "mysqld", "redis-server",
		"dropbox", "drivefs", "fileproviderd", "wireguard", "tailscale", "little snitch",
		"1password", "securityagent",
	} {
		if name == fragment || strings.Contains(name, fragment) {
			return true
		}
	}
	return false
}

func normalizeIdentities(values []model.DarwinActionIdentity) []model.DarwinActionIdentity {
	result := slices.Clone(values)
	sort.Slice(result, func(i, j int) bool {
		if result[i].PID != result[j].PID {
			return result[i].PID < result[j].PID
		}
		if !result[i].StartTime.Equal(result[j].StartTime) {
			return result[i].StartTime.Before(result[j].StartTime)
		}
		if result[i].PIDVersion != result[j].PIDVersion {
			return result[i].PIDVersion < result[j].PIDVersion
		}
		return result[i].UniqueID < result[j].UniqueID
	})
	return slices.CompactFunc(result, func(a, b model.DarwinActionIdentity) bool { return a.Equal(b) })
}

func containsIdentity(values []model.DarwinActionIdentity, identity model.DarwinActionIdentity) bool {
	return slices.ContainsFunc(values, func(value model.DarwinActionIdentity) bool { return value.Equal(identity) })
}

func validateProtected(values []model.DarwinActionIdentity) error {
	for _, identity := range values {
		if err := identity.Validate(); err != nil {
			return err
		}
	}
	normalized := normalizeIdentities(values)
	if len(normalized) != len(values) {
		return errors.New("duplicate protected identity")
	}
	return nil
}
