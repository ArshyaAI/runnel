package codex

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArshyaAI/runnel/internal/model"
)

func completionLine(message string) string {
	payload := map[string]any{
		"timestamp": "2026-08-20T00:00:06.000Z",
		"ordinal":   7,
		"type":      "event_msg",
		"payload": map[string]any{
			"type":                   "task_complete",
			"turn_id":                "synthetic-turn",
			"last_agent_message":     message,
			"started_at":             100,
			"completed_at":           106,
			"duration_ms":            6000,
			"time_to_first_token_ms": 100,
		},
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func tailFixture(t *testing.T, content string) (string, DescriptorEvidence) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rollout.jsonl")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := fileIdentity(info)
	if err != nil {
		t.Fatal(err)
	}
	return path, DescriptorEvidence{
		Availability: model.AvailabilityAvailable,
		Path:         path, Device: identity.Device, Inode: identity.Inode, Access: DescriptorReadOnly,
	}
}

func TestTailReaderAcceptsOnlyFinalCompletionEnvelope(t *testing.T) {
	privateMessage := "secret prompt response must never be returned"
	path, descriptor := tailFixture(t,
		`{"timestamp":"2026-08-20T00:00:00Z","type":"event_msg","payload":{"type":"task_started"}}`+"\n"+
			completionLine(privateMessage)+"\n",
	)
	snapshot, err := NewTailReader(TailReaderOptions{}).Read(context.Background(), path, descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.EnvelopeType != "event_msg" || snapshot.EventType != "task_complete" || !snapshot.Successful {
		t.Fatalf("unexpected envelope: %#v", snapshot)
	}
	public, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{privateMessage, path, "synthetic-turn"} {
		if strings.Contains(string(public), forbidden) {
			t.Fatalf("tail output leaked %q", forbidden)
		}
	}
}

func TestTailReaderBoundedLargeFile(t *testing.T) {
	prefix := strings.Repeat("x", 1<<20) + "\n"
	path, descriptor := tailFixture(t, prefix+completionLine("done")+"\n")
	reader := NewTailReader(TailReaderOptions{MaxTailBytes: 4096, MaxEventBytes: 2048})
	if _, err := reader.Read(context.Background(), path, descriptor); err != nil {
		t.Fatal(err)
	}
}

func TestTailReaderRejectsTruncatedHugeMalformedAndUnknown(t *testing.T) {
	tests := []struct {
		name    string
		content string
		options TailReaderOptions
		code    Code
	}{
		{"missing final newline", completionLine("done"), TailReaderOptions{}, CodeTailTruncated},
		{"blank trailing line", completionLine("done") + "\n\n", TailReaderOptions{}, CodeTailMalformed},
		{"huge final event", completionLine(strings.Repeat("x", 4096)) + "\n", TailReaderOptions{MaxTailBytes: 1024, MaxEventBytes: 512}, CodeTailTooLarge},
		{"malformed json", "{malformed}\n", TailReaderOptions{}, CodeTailMalformed},
		{"unknown envelope", `{"timestamp":"2026-08-20T00:00:00.000Z","type":"response_item","payload":{}}` + "\n", TailReaderOptions{}, CodeTerminalUnknown},
		{"unknown event", `{"timestamp":"2026-08-20T00:00:00.000Z","type":"event_msg","payload":{"type":"turn_complete","turn_id":"x","last_agent_message":null}}` + "\n", TailReaderOptions{}, CodeTerminalUnknown},
		{"missing last message", `{"timestamp":"2026-08-20T00:00:00.000Z","type":"event_msg","payload":{"type":"task_complete","turn_id":"x"}}` + "\n", TailReaderOptions{}, CodeTailMalformed},
		{"unknown payload field", `{"timestamp":"2026-08-20T00:00:00.000Z","type":"event_msg","payload":{"type":"task_complete","turn_id":"x","last_agent_message":null,"future":true}}` + "\n", TailReaderOptions{}, CodeTailMalformed},
		{"unknown envelope field", `{"timestamp":"2026-08-20T00:00:00.000Z","type":"event_msg","payload":{"type":"task_complete","turn_id":"x","last_agent_message":null},"future":true}` + "\n", TailReaderOptions{}, CodeTailMalformed},
		{"bad timestamp", `{"timestamp":"today","type":"event_msg","payload":{"type":"task_complete","turn_id":"x","last_agent_message":null}}` + "\n", TailReaderOptions{}, CodeTailMalformed},
		{"noncanonical timestamp offset", `{"timestamp":"2026-08-20T02:00:00+02:00","type":"event_msg","payload":{"type":"task_complete","turn_id":"x","last_agent_message":null}}` + "\n", TailReaderOptions{}, CodeTailMalformed},
		{"missing timestamp milliseconds", `{"timestamp":"2026-08-20T00:00:00Z","type":"event_msg","payload":{"type":"task_complete","turn_id":"x","last_agent_message":null}}` + "\n", TailReaderOptions{}, CodeTailMalformed},
		{"failed completion", `{"timestamp":"2026-08-20T00:00:00.000Z","type":"event_msg","payload":{"type":"task_complete","turn_id":"x","last_agent_message":null,"error":{"message":"private failure"}}}` + "\n", TailReaderOptions{}, CodeTerminalFailed},
		{"explicit null error", `{"timestamp":"2026-08-20T00:00:00.000Z","type":"event_msg","payload":{"type":"task_complete","turn_id":"x","last_agent_message":null,"error":null}}` + "\n", TailReaderOptions{}, CodeTerminalFailed},
		{"negative duration", `{"timestamp":"2026-08-20T00:00:00.000Z","type":"event_msg","payload":{"type":"task_complete","turn_id":"x","last_agent_message":null,"duration_ms":-1}}` + "\n", TailReaderOptions{}, CodeTailMalformed},
		{"null duration", `{"timestamp":"2026-08-20T00:00:00.000Z","type":"event_msg","payload":{"type":"task_complete","turn_id":"x","last_agent_message":null,"duration_ms":null}}` + "\n", TailReaderOptions{}, CodeTailMalformed},
		{"reversed times", `{"timestamp":"2026-08-20T00:00:00.000Z","type":"event_msg","payload":{"type":"task_complete","turn_id":"x","last_agent_message":null,"started_at":2,"completed_at":1}}` + "\n", TailReaderOptions{}, CodeTailMalformed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path, descriptor := tailFixture(t, test.content)
			_, err := NewTailReader(test.options).Read(context.Background(), path, descriptor)
			if err == nil || codeOf(err, "") != test.code {
				t.Fatalf("got %v want %s", err, test.code)
			}
			if strings.Contains(err.Error(), "private failure") || strings.Contains(err.Error(), path) {
				t.Fatal("private tail data leaked in error")
			}
		})
	}
}

func TestTailReaderDescriptorAndInodeCorrelation(t *testing.T) {
	content := completionLine("done") + "\n"
	path, descriptor := tailFixture(t, content)
	tests := []struct {
		name string
		edit func(*DescriptorEvidence)
		code Code
	}{
		{"unavailable", func(d *DescriptorEvidence) { d.Availability = model.AvailabilityPermissionDenied }, CodeDescriptorUnavailable},
		{"writable", func(d *DescriptorEvidence) { d.Access = DescriptorReadWrite }, CodeDescriptorWritable},
		{"path mismatch", func(d *DescriptorEvidence) { d.Path += ".other" }, CodeDescriptorMismatch},
		{"device mismatch", func(d *DescriptorEvidence) { d.Device++ }, CodeDescriptorMismatch},
		{"inode mismatch", func(d *DescriptorEvidence) { d.Inode++ }, CodeDescriptorMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := descriptor
			test.edit(&changed)
			_, err := NewTailReader(TailReaderOptions{}).Read(context.Background(), path, changed)
			if err == nil || codeOf(err, "") != test.code {
				t.Fatalf("got %v want %s", err, test.code)
			}
		})
	}

	old := path + ".old"
	if err := os.Rename(path, old); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewTailReader(TailReaderOptions{}).Read(context.Background(), path, descriptor)
	if err == nil || codeOf(err, "") != CodeDescriptorMismatch {
		t.Fatalf("changed inode got %v", err)
	}
}

func TestTailReaderDetectsMutationDuringBoundedRead(t *testing.T) {
	path, descriptor := tailFixture(t, completionLine("done")+"\n")
	reader := NewTailReader(TailReaderOptions{})
	reader.testHook = func(file *os.File) {
		if _, err := file.WriteAt([]byte("x"), 0); err == nil {
			t.Error("read-only file unexpectedly writable")
		}
		other, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Error(err)
			return
		}
		_, err = fmt.Fprintln(other, "changed")
		_ = other.Close()
		if err != nil {
			t.Error(err)
		}
	}
	_, err := reader.Read(context.Background(), path, descriptor)
	if err == nil || codeOf(err, "") != CodeTailChanged {
		t.Fatalf("got %v", err)
	}
}

func FuzzParseCompletionEnvelope(f *testing.F) {
	f.Add([]byte(completionLine("synthetic")))
	f.Add([]byte(`{"type":"event_msg"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseCompletionEnvelope(data)
	})
}

func FuzzFinalCompleteLine(f *testing.F) {
	f.Add([]byte(completionLine("synthetic")+"\n"), false)
	f.Add([]byte("partial"), true)
	f.Fuzz(func(t *testing.T, data []byte, midFile bool) {
		_, _ = finalCompleteLine(data, midFile, 4096)
	})
}
