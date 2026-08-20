package schema_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ArshyaAI/runnel/internal/model"
	runnelschema "github.com/ArshyaAI/runnel/schema"
)

func TestAllSchemasCompile(t *testing.T) {
	if err := runnelschema.CompileAll(); err != nil {
		t.Fatal(err)
	}
	for _, name := range runnelschema.Names() {
		if _, err := runnelschema.Compile(name); err != nil {
			t.Errorf("Compile(%s): %v", name, err)
		}
	}
}

func TestClosedShareSchemasRejectUnknownAndForbiddenFields(t *testing.T) {
	values := []struct {
		name  runnelschema.Name
		value model.Validatable
	}{
		{runnelschema.ShareSnapshot, validShareSnapshot()},
		{runnelschema.ShareReceipt, validShareReceipt()},
	}
	for _, tt := range values {
		t.Run(string(tt.name), func(t *testing.T) {
			data, err := model.MarshalDeterministic(tt.value)
			if err != nil {
				t.Fatal(err)
			}
			if err := runnelschema.Validate(tt.name, data); err != nil {
				t.Fatalf("valid value rejected: %v", err)
			}
			for _, field := range []string{"pid", "path", "argv", "cwd", "session_id", "raw_error", "stack", "port"} {
				var object map[string]any
				if err := json.Unmarshal(data, &object); err != nil {
					t.Fatal(err)
				}
				object[field] = "private"
				mutated, _ := json.Marshal(object)
				if err := runnelschema.Validate(tt.name, mutated); err == nil {
					t.Errorf("field %q accepted", field)
				}
			}
		})
	}
}

func TestFixtureCorpusValidAndComplete(t *testing.T) {
	root := filepath.Join("..", "fixtures", "codex", "v1")
	entries, err := os.ReadDir(filepath.Join(root, "cases"))
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]bool{"active": false, "paused": false, "supported-stale": false, "pid-reuse": false, "exec-changed": false, "permission-denied": false, "truncated-tail": false, "unknown-tail": false, "stack-changed": false, "socket-present": false, "tty-present": false, "contradictory": false, "origin-unsigned": false, "origin-altered": false, "origin-resigned": false, "origin-wrong-team": false, "origin-wrong-identifier": false, "origin-wrong-digest": false, "origin-mismatched-parent": false}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, "cases", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := runnelschema.Validate(runnelschema.CodexFixture, data); err != nil {
			t.Errorf("%s: %v", entry.Name(), err)
			continue
		}
		var fixture struct {
			CaseID   string `json:"case_id"`
			Expected struct {
				Selectable     bool                 `json:"selectable"`
				Classification model.Classification `json:"classification"`
			} `json:"expected"`
			Samples []struct {
				Second int `json:"second"`
			} `json:"samples"`
		}
		if err := json.Unmarshal(data, &fixture); err != nil {
			t.Fatal(err)
		}
		if _, ok := required[fixture.CaseID]; ok {
			required[fixture.CaseID] = true
		}
		seconds := []int{fixture.Samples[0].Second, fixture.Samples[1].Second, fixture.Samples[2].Second, fixture.Samples[3].Second}
		if !reflect.DeepEqual(seconds, []int{0, 2, 4, 6}) {
			t.Errorf("%s sample seconds = %v", entry.Name(), seconds)
		}
		if fixture.Expected.Selectable != (fixture.Expected.Classification == model.ClassificationSupportedStaleCandidate) {
			t.Errorf("%s selectable/classification mismatch", entry.Name())
		}
		lower := strings.ToLower(string(data))
		for _, forbidden := range []string{"/users/", "/home/", "arshya", "session_id", "thread_id", "prompt", "response", "conversation"} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("%s contains forbidden private marker %q", entry.Name(), forbidden)
			}
		}
	}
	missing := make([]string, 0)
	for name, found := range required {
		if !found {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) != 0 {
		t.Fatalf("missing required cases: %v", missing)
	}
}

func TestFixtureManifestHashes(t *testing.T) {
	root := filepath.Join("..", "fixtures", "codex", "v1")
	data, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := runnelschema.Validate(runnelschema.CodexManifest, data); err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		CorpusRoot string                          `json:"corpus_root"`
		Files      []struct{ Path, SHA256 string } `json:"files"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "cases"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(manifest.Files) {
		t.Fatalf("manifest files = %d, directory entries = %d", len(manifest.Files), len(entries))
	}
	var corpus bytes.Buffer
	previous := ""
	for _, entry := range manifest.Files {
		if previous != "" && previous >= entry.Path {
			t.Fatalf("manifest paths not strictly sorted: %q then %q", previous, entry.Path)
		}
		previous = entry.Path
		contents, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(entry.Path)))
		if err != nil {
			t.Fatal(err)
		}
		digest := fmt.Sprintf("%x", sha256.Sum256(contents))
		if digest != entry.SHA256 {
			t.Errorf("%s hash = %s, want %s", entry.Path, digest, entry.SHA256)
		}
		corpus.WriteString(entry.Path)
		corpus.WriteByte(0)
		corpus.WriteString(digest)
		corpus.WriteByte('\n')
	}
	rootDigest := fmt.Sprintf("%x", sha256.Sum256(corpus.Bytes()))
	if rootDigest != manifest.CorpusRoot {
		t.Fatalf("corpus root = %s, want %s", rootDigest, manifest.CorpusRoot)
	}
}

func validShareSnapshot() model.ShareSnapshot {
	return model.ShareSnapshot{SchemaVersion: model.ShareSnapshotSchemaVersion, ToolVersion: "0.1.0", Platform: model.Platform{OS: "darwin", Arch: "arm64"}, Availability: []model.ProbeAvailability{}, Groups: []model.ShareWorkflowGroup{}}
}
func validShareReceipt() model.ShareReceipt {
	return model.ShareReceipt{SchemaVersion: model.ShareReceiptSchemaVersion, ToolVersion: "0.1.0", Platform: model.Platform{OS: "darwin", Arch: "arm64"}, DetectorID: model.CodexV1DetectorID, SupportState: model.SupportSupported, Availability: []model.ProbeAvailability{}, Evidence: []model.EvidenceCode{}, DurationBucket: model.Duration5To10s, MemoryPressureBefore: model.PressureUnknown, MemoryPressureAfter: model.PressureUnknown, Outcome: model.OutcomeRefused, ErrorCodes: []model.ErrorCode{}}
}
