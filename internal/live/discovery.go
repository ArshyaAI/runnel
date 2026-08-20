package live

import (
	"crypto/sha256"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"

	"github.com/ArshyaAI/runnel/internal/codex"
	"github.com/ArshyaAI/runnel/internal/model"
	"github.com/ArshyaAI/runnel/internal/platform/darwin"
)

const nodeResourcesSuffix = "/cua_node/bin/node"

// Discover derives plausible v1 pairs from exactly one ProcessSnapshot. It
// requires the pinned ChatGPT node location, the adjacent embedded codex
// parent, a direct parent edge, matching non-inferred UIDs, and complete Darwin
// identities. Same-UID ownership by itself is never attribution.
func Discover(snapshot darwin.ProcessSnapshot) Discovery {
	result := Discovery{
		Availability: snapshot.Availability,
		Code:         CodeOK,
		candidates:   []Candidate{},
	}
	if snapshot.Availability != model.AvailabilityAvailable || snapshot.Truncated {
		result.Code = CodeDiscoveryUnavailable
		if !result.Availability.Valid() || result.Availability == model.AvailabilityAvailable {
			result.Availability = model.AvailabilityContradictory
		}
		return result
	}

	byPID := make(map[int32][]darwin.ProcessRecord, len(snapshot.Processes))
	for _, record := range snapshot.Processes {
		pid := record.Observation.Identity.PID
		if pid <= 0 {
			continue
		}
		byPID[pid] = append(byPID[pid], record)
	}
	failures := failurePIDs(snapshot.Failures)
	ambiguousPlausible := false

	for _, leafRecord := range snapshot.Processes {
		if !exactActionRecord(leafRecord) || !plausibleNodePath(leafRecord.ActionIdentity.Executable) {
			continue
		}
		leafPID := leafRecord.ActionIdentity.PID
		if len(byPID[leafPID]) != 1 || failures[leafPID] {
			ambiguousPlausible = true
			continue
		}
		parents := byPID[leafRecord.Observation.ParentPID]
		if len(parents) != 1 || failures[leafRecord.Observation.ParentPID] || !exactActionRecord(parents[0]) {
			if len(parents) > 1 || failures[leafRecord.Observation.ParentPID] {
				ambiguousPlausible = true
			}
			continue
		}
		parentRecord := parents[0]
		leaf := leafRecord.ActionIdentity
		parent := parentRecord.ActionIdentity
		if leaf.PID == parent.PID || leaf.UID != parent.UID ||
			!plausibleParentPath(leaf.Executable, parent.Executable) {
			continue
		}
		result.candidates = append(result.candidates, Candidate{
			leaf: leaf, parent: parent, proof: candidateProof(leaf, parent),
		})
	}
	slices.SortFunc(result.candidates, func(a, b Candidate) int {
		if a.leaf.PID < b.leaf.PID {
			return -1
		}
		if a.leaf.PID > b.leaf.PID {
			return 1
		}
		return 0
	})
	result.Count = len(result.candidates)
	if result.Count == 0 && ambiguousPlausible {
		result.Availability = model.AvailabilityContradictory
		result.Code = CodeDiscoveryAmbiguous
		return result
	}
	result.Availability = model.AvailabilityAvailable
	return result
}

func failurePIDs(failures []darwin.ProcessFailure) map[int32]bool {
	result := make(map[int32]bool, len(failures))
	for _, failure := range failures {
		if failure.PID > 0 {
			result[failure.PID] = true
		}
	}
	return result
}

func exactActionRecord(record darwin.ProcessRecord) bool {
	return record.ActionAvailable == model.AvailabilityAvailable &&
		record.ActionIdentity.Validate() == nil &&
		record.ActionIdentity.ProcessIdentity.Equal(record.Observation.Identity)
}

func plausibleNodePath(path string) bool {
	slashed := filepath.ToSlash(path)
	return canonicalAbsolute(path) && strings.HasSuffix(slashed, codex.NodeBundleSuffix)
}

func plausibleParentPath(nodePath, parentPath string) bool {
	if !canonicalAbsolute(parentPath) {
		return false
	}
	slashedNode := filepath.ToSlash(nodePath)
	if !strings.HasSuffix(slashedNode, nodeResourcesSuffix) {
		return false
	}
	resources := strings.TrimSuffix(slashedNode, nodeResourcesSuffix)
	expected := resources + "/" + codex.CodexIdentifier
	return filepath.ToSlash(parentPath) == expected
}

func canonicalAbsolute(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func candidateProof(leaf, parent model.DarwinActionIdentity) [sha256.Size]byte {
	encoded, err := json.Marshal(struct {
		Leaf   model.DarwinActionIdentity `json:"leaf"`
		Parent model.DarwinActionIdentity `json:"parent"`
	}{Leaf: leaf, Parent: parent})
	if err != nil {
		return [sha256.Size]byte{}
	}
	return sha256.Sum256(encoded)
}
