// Package workflow implements deterministic, read-only process grouping,
// workflow attribution, aggregation, and structural protection.
package workflow

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/bits"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/ArshyaAI/runnel/internal/model"
)

// Options contains caller-owned protection facts. It contains no default based
// solely on CurrentUID: same-UID ownership is never workflow attribution.
type Options struct {
	CurrentPID        int32
	CurrentUID        uint32
	TTYOwnerPIDs      []int32
	ExplicitProtected []model.ProcessIdentity
}

// Grouper is a pure classifier. Its zero value is ready for use.
type Grouper struct{}

// Group is a convenience wrapper around Grouper.Group.
func Group(processes []model.ProcessObservation, options Options) ([]model.WorkflowGroup, error) {
	return (Grouper{}).Group(processes, options)
}

type node struct {
	process         model.ProcessObservation
	parent          int
	parentAmbiguous bool
	duplicatePID    bool
	rawFamily       model.WorkflowFamily
	family          model.WorkflowFamily
	attribution     []model.EvidenceCode
	protection      []model.EvidenceCode
}

func (Grouper) Group(processes []model.ProcessObservation, options Options) ([]model.WorkflowGroup, error) {
	nodes, err := buildNodes(processes)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return []model.WorkflowGroup{}, nil
	}
	linkParents(nodes)
	currentAncestors := ancestorSet(nodes, options.CurrentPID)
	ttyOwners := int32Set(options.TTYOwnerPIDs)
	explicit := identitySet(options.ExplicitProtected)

	for i := range nodes {
		nodes[i].rawFamily = recognizeFamily(nodes[i].process)
	}
	for i := range nodes {
		var parent *node
		if nodes[i].parent >= 0 {
			parent = &nodes[nodes[i].parent]
		}
		nodes[i].family, nodes[i].attribution = attribute(nodes[i], parent, ttyOwners)
		nodes[i].protection = protect(nodes[i], i, options.CurrentPID, currentAncestors, ttyOwners, explicit)
	}

	roots := assignRoots(nodes)
	groupsByRoot := make(map[int][]int, len(nodes))
	for i, root := range roots {
		groupsByRoot[root] = append(groupsByRoot[root], i)
	}
	rootIndexes := make([]int, 0, len(groupsByRoot))
	for root := range groupsByRoot {
		rootIndexes = append(rootIndexes, root)
	}
	sort.Slice(rootIndexes, func(i, j int) bool {
		return identityKey(nodes[rootIndexes[i]].process.Identity) < identityKey(nodes[rootIndexes[j]].process.Identity)
	})

	groups := make([]model.WorkflowGroup, 0, len(rootIndexes))
	for _, root := range rootIndexes {
		group, err := makeGroup(nodes, root, groupsByRoot[root])
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })
	return groups, nil
}

func buildNodes(processes []model.ProcessObservation) ([]node, error) {
	nodes := make([]node, len(processes))
	for i, process := range processes {
		process.Argv = slices.Clone(process.Argv)
		process.Availability = slices.Clone(process.Availability)
		process.Evidence = slices.Clone(process.Evidence)
		if process.Argv == nil {
			process.Argv = []string{}
		}
		if process.Availability == nil {
			process.Availability = []model.ProbeAvailability{}
		}
		if process.Evidence == nil {
			process.Evidence = []model.EvidenceCode{}
		}
		sort.Slice(process.Availability, func(i, j int) bool { return process.Availability[i].Probe < process.Availability[j].Probe })
		slices.Sort(process.Evidence)
		process.Evidence = slices.Compact(process.Evidence)
		if err := process.Validate(); err != nil {
			return nil, fmt.Errorf("workflow: processes[%d]: %w", i, err)
		}
		nodes[i] = node{process: process, parent: -1, family: model.WorkflowFamilyUnclassified}
	}
	sort.Slice(nodes, func(i, j int) bool {
		return identityKey(nodes[i].process.Identity) < identityKey(nodes[j].process.Identity)
	})
	return nodes, nil
}

func linkParents(nodes []node) {
	byPID := make(map[int32][]int, len(nodes))
	for i := range nodes {
		byPID[nodes[i].process.Identity.PID] = append(byPID[nodes[i].process.Identity.PID], i)
	}
	for _, indexes := range byPID {
		if len(indexes) > 1 {
			for _, index := range indexes {
				nodes[index].duplicatePID = true
			}
		}
	}
	for i := range nodes {
		parents := byPID[nodes[i].process.ParentPID]
		if len(parents) == 1 && parents[0] != i {
			nodes[i].parent = parents[0]
		} else if len(parents) > 1 || len(parents) == 1 && parents[0] == i {
			nodes[i].parentAmbiguous = true
		}
	}
}

func ancestorSet(nodes []node, currentPID int32) map[int]bool {
	result := make(map[int]bool)
	if currentPID <= 0 {
		return result
	}
	current := -1
	for i := range nodes {
		if nodes[i].process.Identity.PID == currentPID {
			if current != -1 {
				return result
			}
			current = i
		}
	}
	seen := make(map[int]bool)
	for current >= 0 && !seen[current] {
		seen[current] = true
		result[current] = true
		current = nodes[current].parent
	}
	return result
}

func attribute(n node, parent *node, ttyOwners map[int32]bool) (model.WorkflowFamily, []model.EvidenceCode) {
	if n.rawFamily == model.WorkflowFamilyUnclassified {
		return model.WorkflowFamilyUnclassified, []model.EvidenceCode{}
	}
	evidence := []model.EvidenceCode{model.EvidenceExecutableFamily}
	if worktreeLike(n.process.CWD) {
		evidence = append(evidence, model.EvidenceCWDWorktree)
	}
	if n.process.TTY != "" || ttyOwners[n.process.Identity.PID] {
		evidence = append(evidence, model.EvidenceTTYOwner)
	}
	if parent != nil && compatibleParent(n.rawFamily, parent.rawFamily) {
		evidence = append(evidence, model.EvidenceKnownParentGrammar)
	}
	if n.rawFamily == model.WorkflowFamilyLocalDatabase {
		return n.rawFamily, normalizeEvidence(evidence)
	}
	if independentAttributionCount(evidence) < 2 {
		return model.WorkflowFamilyUnclassified, normalizeEvidence(evidence)
	}
	return n.rawFamily, normalizeEvidence(evidence)
}

func independentAttributionCount(evidence []model.EvidenceCode) int {
	count := 0
	for _, code := range evidence {
		switch code {
		case model.EvidenceExecutableFamily, model.EvidenceCWDWorktree, model.EvidenceTTYOwner, model.EvidenceKnownParentGrammar:
			count++
		}
	}
	return count
}

func compatibleParent(child, parent model.WorkflowFamily) bool {
	if child == parent && child != model.WorkflowFamilyUnclassified {
		return true
	}
	return child == model.WorkflowFamilyCodex && (parent == model.WorkflowFamilyNodeDev || parent == model.WorkflowFamilyCodex)
}

func protect(n node, index int, currentPID int32, currentAncestors map[int]bool, ttyOwners map[int32]bool, explicit map[string]bool) []model.EvidenceCode {
	reasons := make([]model.EvidenceCode, 0, 4)
	if currentAncestors[index] {
		if n.process.Identity.PID == currentPID {
			reasons = append(reasons, model.EvidenceCurrentProcess)
		} else {
			reasons = append(reasons, model.EvidenceAncestor)
		}
	}
	if ttyOwners[n.process.Identity.PID] || n.process.TTY != "" {
		reasons = append(reasons, model.EvidenceTTYOwner)
	}
	if explicit[identityKey(n.process.Identity)] {
		reasons = append(reasons, model.EvidenceUserAllowlist)
	}
	name := executableName(n.process.Identity.Executable)
	switch {
	case isCMUX(name):
		reasons = append(reasons, model.EvidenceCMUXOwner)
	case isEditor(name):
		reasons = append(reasons, model.EvidenceEditorOwner)
	}
	if n.rawFamily == model.WorkflowFamilyLocalDatabase {
		reasons = append(reasons, model.EvidenceDatabaseProcess)
	}
	if isSync(name) {
		reasons = append(reasons, model.EvidenceSyncProcess)
	}
	if isVPN(name) {
		reasons = append(reasons, model.EvidenceVPNProcess)
	}
	if isSecurity(name) {
		reasons = append(reasons, model.EvidenceSecurityProcess)
	}
	if !n.process.Identity.Complete() || n.parentAmbiguous || n.duplicatePID || ownershipUnavailable(n.process) {
		reasons = append(reasons, model.EvidenceIncompleteOwnership)
	}
	if hasAvailability(n.process.Availability, model.AvailabilityContradictory) {
		reasons = append(reasons, model.EvidenceContradictoryOwnership)
	}
	return normalizeEvidence(reasons)
}

func assignRoots(nodes []node) []int {
	roots := make([]int, len(nodes))
	for i := range roots {
		roots[i] = -1
	}
	for start := range nodes {
		if roots[start] >= 0 {
			continue
		}
		path := make([]int, 0, 8)
		position := make(map[int]int)
		current := start
		root := -1
		for {
			if roots[current] >= 0 {
				root = roots[current]
				break
			}
			if pos, exists := position[current]; exists {
				cycle := path[pos:]
				root = cycle[0]
				for _, candidate := range cycle[1:] {
					if identityKey(nodes[candidate].process.Identity) < identityKey(nodes[root].process.Identity) {
						root = candidate
					}
				}
				for _, member := range cycle {
					roots[member] = root
				}
				nodes[root].process.Evidence = normalizeEvidence(append(nodes[root].process.Evidence, model.EvidenceRootlessCycle))
				break
			}
			position[current] = len(path)
			path = append(path, current)
			parent := nodes[current].parent
			if parent < 0 || boundary(nodes[current], nodes[parent]) {
				root = current
				break
			}
			current = parent
		}
		for _, member := range path {
			if roots[member] < 0 {
				roots[member] = root
			}
		}
	}
	return roots
}

func boundary(child, parent node) bool {
	if child.process.Identity.UID != parent.process.Identity.UID {
		return true
	}
	if child.family != model.WorkflowFamilyUnclassified && child.family != parent.family {
		return true
	}
	if child.rawFamily == model.WorkflowFamilyLocalDatabase {
		return true
	}
	if worktreeLike(child.process.CWD) && worktreeLike(parent.process.CWD) && filepath.Clean(child.process.CWD) != filepath.Clean(parent.process.CWD) && child.family != model.WorkflowFamilyUnclassified {
		return true
	}
	return false
}

func makeGroup(nodes []node, root int, indexes []int) (model.WorkflowGroup, error) {
	processes := make([]model.ProcessObservation, 0, len(indexes))
	attribution := []model.EvidenceCode{}
	protection := []model.EvidenceCode{}
	family := nodes[root].family
	recent := false
	unknown := false
	var aggregate model.ResourceAggregate
	for _, index := range indexes {
		n := nodes[index]
		processes = append(processes, n.process)
		attribution = append(attribution, n.attribution...)
		protection = append(protection, n.protection...)
		if family == model.WorkflowFamilyUnclassified && n.family != model.WorkflowFamilyUnclassified {
			family = n.family
		}
		if n.process.CPUTimeDeltaNS > 0 {
			recent = true
		}
		if observationUnknown(n.process) {
			unknown = true
		}
		var carry uint64
		aggregate.CPUTimeNS, carry = bits.Add64(aggregate.CPUTimeNS, n.process.CPUTimeNS, 0)
		if carry != 0 {
			return model.WorkflowGroup{}, fmt.Errorf("workflow: cpu aggregation overflow")
		}
		aggregate.RSSBytes, carry = bits.Add64(aggregate.RSSBytes, n.process.RSSBytes, 0)
		if carry != 0 {
			return model.WorkflowGroup{}, fmt.Errorf("workflow: rss aggregation overflow")
		}
	}
	if uint64(len(processes)) > uint64(^uint32(0)) {
		return model.WorkflowGroup{}, fmt.Errorf("workflow: process count overflow")
	}
	aggregate.ProcessCount = uint32(len(processes))
	sort.Slice(processes, func(i, j int) bool { return identityKey(processes[i].Identity) < identityKey(processes[j].Identity) })
	attribution = normalizeEvidence(attribution)
	protection = normalizeEvidence(protection)
	classification := model.ClassificationQuietUnclassified
	switch {
	case len(protection) > 0:
		classification = model.ClassificationProtected
	case unknown:
		classification = model.ClassificationUnknown
	case recent:
		classification = model.ClassificationRecentlyActive
	}
	key := identityKey(nodes[root].process.Identity)
	hash := sha256.Sum256([]byte(key))
	group := model.WorkflowGroup{
		ID: "wf-" + hex.EncodeToString(hash[:8]), Root: nodes[root].process.Identity,
		Family: family, Classification: classification, Attribution: attribution,
		Protection: protection, Processes: processes, Aggregate: aggregate,
	}
	if err := group.Validate(); err != nil {
		return model.WorkflowGroup{}, fmt.Errorf("workflow: group: %w", err)
	}
	return group, nil
}

func recognizeFamily(process model.ProcessObservation) model.WorkflowFamily {
	name := executableName(process.Identity.Executable)
	argv := strings.ToLower(strings.Join(process.Argv, " "))
	switch {
	case name == "codex" || strings.Contains(name, "trusted-worker") || name == "node" && strings.Contains(argv, "trusted-worker.js"):
		return model.WorkflowFamilyCodex
	case name == "claude" || strings.Contains(name, "claude"):
		return model.WorkflowFamilyClaude
	case strings.Contains(name, "mcp") || strings.Contains(argv, "mcp-server"):
		return model.WorkflowFamilyMCP
	case name == "playwright" || strings.Contains(name, "chromium") || strings.Contains(argv, "playwright"):
		return model.WorkflowFamilyPlaywrightChromium
	case isDatabase(name):
		return model.WorkflowFamilyLocalDatabase
	case name == "docker" || strings.Contains(name, "colima") || strings.Contains(name, "virtualization") || strings.Contains(name, "qemu"):
		return model.WorkflowFamilyDockerVM
	case isBrowser(name):
		return model.WorkflowFamilyBrowser
	case isNodeDev(name, argv):
		return model.WorkflowFamilyNodeDev
	default:
		return model.WorkflowFamilyUnclassified
	}
}

func executableName(path string) string { return strings.ToLower(filepath.Base(filepath.Clean(path))) }
func worktreeLike(cwd string) bool {
	if cwd == "" {
		return false
	}
	clean := filepath.Clean(cwd)
	return clean != "/" && clean != "." && clean != "/tmp" && !strings.HasPrefix(clean, "/System/") && !strings.HasPrefix(clean, "/usr/")
}
func isNodeDev(name, argv string) bool {
	if name == "vite" || name == "next" || name == "bun" {
		return true
	}
	if name != "node" && name != "npm" && name != "pnpm" && name != "yarn" {
		return false
	}
	return strings.Contains(argv, " dev") || strings.Contains(argv, "vite") || strings.Contains(argv, "next")
}
func isDatabase(name string) bool {
	return stringIn(name, "postgres", "postmaster", "mysqld", "redis-server", "mongod", "sqlite3")
}
func isBrowser(name string) bool {
	return stringIn(name, "chrome", "google chrome", "safari", "firefox", "arc", "brave browser")
}
func isCMUX(name string) bool { return name == "cmux" || strings.HasPrefix(name, "cmux-") }
func isEditor(name string) bool {
	return stringIn(name, "code", "cursor", "zed", "nvim", "vim", "emacs", "idea", "xcode")
}
func isSync(name string) bool {
	return stringIn(name, "dropbox", "onedrive", "fileproviderd", "bird", "drivefs", "googledrive")
}
func isVPN(name string) bool {
	return stringIn(name, "tailscaled", "tailscale", "wireguard-go", "openvpn", "nordvpn", "mullvad-daemon")
}
func isSecurity(name string) bool {
	return stringIn(name, "securityd", "syspolicyd", "trustd", "1password", "op-daemon", "littlesnitch", "keychain-circle-notification")
}
func stringIn(value string, candidates ...string) bool { return slices.Contains(candidates, value) }

func ownershipUnavailable(process model.ProcessObservation) bool {
	for _, p := range process.Availability {
		if p.Probe != model.ProbeIdentity && p.Probe != model.ProbeExecutable {
			continue
		}
		if p.Status != model.AvailabilityAvailable && p.Status != model.AvailabilityNotApplicable {
			return true
		}
	}
	return false
}
func observationUnknown(process model.ProcessObservation) bool {
	if !process.Identity.Complete() {
		return true
	}
	for _, p := range process.Availability {
		switch p.Status {
		case model.AvailabilityAvailable, model.AvailabilityNotApplicable:
		default:
			return true
		}
	}
	return false
}
func hasAvailability(values []model.ProbeAvailability, wanted model.Availability) bool {
	for _, value := range values {
		if value.Status == wanted {
			return true
		}
	}
	return false
}
func normalizeEvidence(values []model.EvidenceCode) []model.EvidenceCode {
	if values == nil {
		return []model.EvidenceCode{}
	}
	result := slices.Clone(values)
	slices.Sort(result)
	return slices.Compact(result)
}
func int32Set(values []int32) map[int32]bool {
	result := make(map[int32]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}
func identitySet(values []model.ProcessIdentity) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[identityKey(value)] = true
	}
	return result
}
func identityKey(id model.ProcessIdentity) string {
	return fmt.Sprintf("%011d|%s|%010d|%s", id.PID, id.StartTime.UTC().Format("20060102T150405.000000000Z"), id.UID, id.Executable)
}
