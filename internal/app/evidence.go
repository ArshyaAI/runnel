package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/ArshyaAI/runnel/internal/live"
	"github.com/ArshyaAI/runnel/internal/model"
)

var (
	ErrFindingUnavailable = errors.New("finding is unavailable or no longer exact")
	findingIDPattern      = regexp.MustCompile(`^wf-[0-9a-f]{16}$`)
)

type Snapshotter interface {
	Snapshot(context.Context) (model.Snapshot, error)
}

type EvidenceBackend interface {
	Discover(context.Context) (live.Discovery, error)
	InspectReport(context.Context, live.Candidate) (live.Report, error)
}

type productionEvidenceBackend struct{ inspector *live.Inspector }

func (b productionEvidenceBackend) Discover(ctx context.Context) (live.Discovery, error) {
	return b.inspector.Discover(ctx)
}

func (b productionEvidenceBackend) InspectReport(ctx context.Context, candidate live.Candidate) (live.Report, error) {
	finding, err := b.inspector.Inspect(ctx, candidate)
	return finding.Report(), err
}

// EvidenceService maps a privacy-safe radar group to one opaque live
// candidate, then returns only normalized detector evidence.
type EvidenceService struct {
	Radar   Snapshotter
	Backend EvidenceBackend
}

func NewProductionEvidence(radar Snapshotter) (*EvidenceService, error) {
	inspector, err := live.NewProduction(live.Options{
		CurrentUID: uint32(os.Getuid()),
		TempRoots:  defaultTempRoots(),
	})
	if err != nil {
		return nil, err
	}
	return &EvidenceService{Radar: radar, Backend: productionEvidenceBackend{inspector: inspector}}, nil
}

func (s *EvidenceService) Explain(ctx context.Context, findingID string) (string, error) {
	if s == nil || s.Radar == nil || s.Backend == nil || !findingIDPattern.MatchString(findingID) {
		return "", ErrFindingUnavailable
	}
	snapshot, scanErr := s.Radar.Snapshot(ctx)
	if err := snapshot.Validate(); err != nil {
		return "", ErrFindingUnavailable
	}
	group, ok := groupByID(snapshot.Groups, findingID)
	if !ok {
		return "", ErrFindingUnavailable
	}
	discovery, err := s.Backend.Discover(ctx)
	if err != nil || discovery.Availability != model.AvailabilityAvailable {
		return "", fmt.Errorf("%w: discovery %s", ErrFindingUnavailable, discovery.Code)
	}
	matches := matchingCandidates(discovery.Candidates(), group)
	if len(matches) != 1 {
		return "", fmt.Errorf("%w: group maps to %d exact workers", ErrFindingUnavailable, len(matches))
	}
	report, err := s.Backend.InspectReport(ctx, matches[0])
	if err != nil {
		return "", err
	}
	var out strings.Builder
	fmt.Fprintf(&out, "Finding %s\n", findingID)
	fmt.Fprintf(&out, "Family: %s\n", group.Family)
	fmt.Fprintf(&out, "Live evidence: %s (%s)\n", report.Code, report.Availability)
	fmt.Fprintf(&out, "Samples: %d/4 | stack attempted: %t\n", report.CompletedSamples, report.StackAttempted)
	fmt.Fprintf(&out, "Classification: %s | selectable: %t\n", report.Detector.Classification, report.Detector.Selectable)
	fmt.Fprintf(&out, "Detector codes: %s\n", joinDetectorCodes(report))
	if scanErr != nil {
		out.WriteString("Radar note: partial host metadata; target evidence was evaluated separately.\n")
	}
	if report.Detector.Selectable {
		out.WriteString("Next safe action: run `runnel recover` and re-confirm the freshly revalidated token.\n")
	} else {
		out.WriteString("Action: locked. Runnel will not signal this workflow.\n")
	}
	return out.String(), nil
}

func groupByID(groups []model.WorkflowGroup, id string) (model.WorkflowGroup, bool) {
	index, found := slices.BinarySearchFunc(groups, id, func(group model.WorkflowGroup, target string) int {
		return strings.Compare(group.ID, target)
	})
	if !found {
		return model.WorkflowGroup{}, false
	}
	return groups[index], true
}

func matchingCandidates(candidates []live.Candidate, group model.WorkflowGroup) []live.Candidate {
	result := make([]live.Candidate, 0, 1)
	for _, candidate := range candidates {
		for _, process := range group.Processes {
			if candidate.Matches(process.Identity) {
				result = append(result, candidate)
				break
			}
		}
	}
	return result
}

func joinDetectorCodes(report live.Report) string {
	if len(report.Detector.Codes) == 0 {
		return "none"
	}
	parts := make([]string, len(report.Detector.Codes))
	for index, code := range report.Detector.Codes {
		parts[index] = string(code)
	}
	return strings.Join(parts, ", ")
}

func defaultTempRoots() []string {
	root := filepath.Clean(os.TempDir())
	values := []string{}
	if filepath.IsAbs(root) && root != string(filepath.Separator) {
		values = append(values, root)
	}
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		resolved = filepath.Clean(resolved)
		if filepath.IsAbs(resolved) && resolved != string(filepath.Separator) && !slices.Contains(values, resolved) {
			values = append(values, resolved)
		}
	}
	if len(values) == 0 && runtime.GOOS != "darwin" {
		// Non-Darwin production construction remains explicitly unsupported by
		// the platform adapter; this root only keeps configuration deterministic.
		values = []string{"/tmp"}
	}
	return values
}
