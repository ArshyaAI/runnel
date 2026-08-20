// Package ui contains the deliberately capability-free Runnel renderers and
// Bubble Tea model. It accepts observations; it cannot select or signal a PID.
package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/ArshyaAI/runnel/internal/model"
	tea "github.com/charmbracelet/bubbletea"
)

// plainGroupLimit keeps the default human-facing scan useful when a host has
// thousands of unrelated processes. JSON remains the complete local snapshot.
const plainGroupLimit = 24

// JSON renders strict deterministic JSON. MarshalIndent is intentionally used
// so snapshots are useful in logs while remaining byte-stable.
func JSON(snapshot model.Snapshot) ([]byte, error) {
	if err := snapshot.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// Plain writes a deterministic, human-readable snapshot without terminal
// control sequences. Unknown/partial states are always spelled out.
func Plain(w io.Writer, snapshot model.Snapshot) error {
	if err := snapshot.Validate(); err != nil {
		return err
	}
	fmt.Fprintf(w, "Runnel %s | %s/%s | %s\n", snapshot.ToolVersion, snapshot.Platform.OS, snapshot.Platform.Arch, snapshot.ObservedAt.UTC().Format("2006-01-02 15:04:05Z"))
	groups := rankedGroups(snapshot.Groups)
	shown := len(groups)
	if shown > plainGroupLimit {
		shown = plainGroupLimit
	}
	fmt.Fprintf(w, "Snapshot: %d workflow group(s) | showing %d, omitted %d low-signal group(s)\n", len(groups), shown, len(groups)-shown)
	for _, a := range snapshot.Availability {
		if a.Status != model.AvailabilityAvailable && a.Status != model.AvailabilityNotApplicable {
			fmt.Fprintf(w, "Probe: %s (%s)\n", a.Probe, a.Status)
		}
	}
	for _, g := range groups[:shown] {
		label := ClassificationLabel(g.Classification)
		fmt.Fprintf(w, "\n%s %s [%s] — %d process(es), %s RSS, %s CPU\n", label, g.ID, g.Family, g.Aggregate.ProcessCount, bytesLabel(g.Aggregate.RSSBytes), durationLabel(g.Aggregate.CPUTimeNS))
		if len(g.Protection) > 0 {
			fmt.Fprintf(w, "  protected: %s\n", joinEvidence(g.Protection))
		}
		if len(g.Attribution) > 0 {
			fmt.Fprintf(w, "  evidence: %s\n", joinEvidence(g.Attribution))
		}
	}
	return nil
}

// rankedGroups returns a display-only copy. It deliberately does not change
// snapshot order: model snapshots and JSON remain stable, complete contracts.
func rankedGroups(groups []model.WorkflowGroup) []model.WorkflowGroup {
	ranked := append([]model.WorkflowGroup(nil), groups...)
	sort.SliceStable(ranked, func(i, j int) bool {
		a, b := ranked[i], ranked[j]
		if rank := radarRank(a); rank != radarRank(b) {
			return rank < radarRank(b)
		}
		if a.Aggregate.RSSBytes != b.Aggregate.RSSBytes {
			return a.Aggregate.RSSBytes > b.Aggregate.RSSBytes
		}
		if a.Aggregate.ProcessCount != b.Aggregate.ProcessCount {
			return a.Aggregate.ProcessCount > b.Aggregate.ProcessCount
		}
		if a.Aggregate.CPUTimeNS != b.Aggregate.CPUTimeNS {
			return a.Aggregate.CPUTimeNS > b.Aggregate.CPUTimeNS
		}
		return a.ID < b.ID
	})
	return ranked
}

func radarRank(g model.WorkflowGroup) int {
	if g.Protected() {
		return 0
	}
	known := g.Family != model.WorkflowFamilyUnclassified
	switch g.Classification {
	case model.ClassificationRecentlyActive:
		if known {
			return 1
		}
		return 3
	case model.ClassificationSupportedStaleCandidate:
		if known {
			return 1
		}
		return 3
	case model.ClassificationUnknown:
		if known {
			return 1
		}
		return 2
	default:
		if known {
			return 1
		}
		return 4
	}
}

func ClassificationLabel(c model.Classification) string {
	switch c {
	case model.ClassificationProtected:
		return "PROTECTED"
	case model.ClassificationRecentlyActive:
		return "RECENT"
	case model.ClassificationQuietUnclassified:
		return "QUIET"
	case model.ClassificationSupportedStaleCandidate:
		return "CANDIDATE"
	default:
		return "UNKNOWN"
	}
}

func bytesLabel(n uint64) string {
	if n < 1024 {
		return strconv.FormatUint(n, 10) + " B"
	}
	units := []string{"KiB", "MiB", "GiB"}
	v := float64(n)
	for _, unit := range units {
		v /= 1024
		if v < 1024 || unit == "GiB" {
			return fmt.Sprintf("%.1f %s", v, unit)
		}
	}
	return "unknown"
}

func durationLabel(n uint64) string {
	if n < 1_000_000_000 {
		return fmt.Sprintf("%d ms", n/1_000_000)
	}
	return fmt.Sprintf("%.1f s", float64(n)/1_000_000_000)
}

func joinEvidence(values []model.EvidenceCode) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = string(v)
	}
	return strings.Join(parts, ", ")
}

// TUIModel is a small, testable Bubble Tea state machine. It never owns a
// scanner or a recovery capability; callers inject a completed snapshot.
type TUIModel struct {
	Snapshot        model.Snapshot
	Width, Height   int
	Done, Cancelled bool
	Drilldown       string
}

func NewTUIModel(snapshot model.Snapshot) TUIModel {
	return TUIModel{Snapshot: snapshot, Width: 80, Height: 24}
}
func (m TUIModel) Init() tea.Cmd { return nil }
func (m TUIModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.Width, m.Height = msg.Width, msg.Height
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.Done = true
			m.Cancelled = msg.String() == "ctrl+c"
			return m, tea.Quit
		case "esc":
			if m.Drilldown != "" {
				m.Drilldown = ""
				break
			}
			m.Done = true
			return m, tea.Quit
		case "enter", "e":
			m.Drilldown = "evidence"
		}
	}
	return m, nil
}
func (m TUIModel) View() string {
	var b strings.Builder
	b.WriteString("READY  Runnel workflow radar\n")
	b.WriteString(fmt.Sprintf("Snapshot: %d group(s)  [%s]\n\n", len(m.Snapshot.Groups), m.Snapshot.ObservedAt.UTC().Format("15:04:05Z")))
	max := m.Height - 6
	if max < 1 {
		max = 1
	}
	nameWidth := m.Width - 43
	if nameWidth < 10 {
		nameWidth = 10
	}
	if nameWidth > 32 {
		nameWidth = 32
	}
	groups := rankedGroups(m.Snapshot.Groups)
	for i, g := range groups {
		if i >= max {
			break
		}
		b.WriteString(fmt.Sprintf("%-9s %-*s %-18s %d proc  %s\n", ClassificationLabel(g.Classification), nameWidth, truncate(g.ID, nameWidth), g.Family, g.Aggregate.ProcessCount, bytesLabel(g.Aggregate.RSSBytes)))
	}
	if len(groups) > max {
		b.WriteString(fmt.Sprintf("… %d more group(s)\n", len(groups)-max))
	}
	if m.Drilldown != "" {
		b.WriteString("\nEvidence drilldown: press Esc to close\n")
	}
	b.WriteString("\nq quit  Enter/e evidence  Ctrl-C cancel\n")
	return b.String()
}
func truncate(s string, n int) string {
	if n < 2 || len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// NoColor reports the conventional opt-out used by scripts and CI.
func NoColor() bool { return os.Getenv("NO_COLOR") != "" }
