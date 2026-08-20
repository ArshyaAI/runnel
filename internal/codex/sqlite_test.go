package codex

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const testThreadSchema = `
CREATE TABLE threads (
    id TEXT PRIMARY KEY,
    rollout_path TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    cli_version TEXT NOT NULL DEFAULT '',
    thread_source TEXT,
    private_body TEXT
);`

const testEdgeSchema = `
CREATE TABLE thread_spawn_edges (
    parent_thread_id TEXT NOT NULL,
    child_thread_id TEXT NOT NULL PRIMARY KEY,
    status TEXT NOT NULL
);`

type sqliteFixture struct {
	path    string
	rollout string
	writer  *sql.DB
}

func newSQLiteFixture(t *testing.T, threadSchema, edgeSchema string) sqliteFixture {
	t.Helper()
	if threadSchema == "" {
		threadSchema = testThreadSchema
	}
	if edgeSchema == "" {
		edgeSchema = testEdgeSchema
	}
	path := filepath.Join(t.TempDir(), "state.sqlite")
	writer, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	if _, err := writer.Exec(threadSchema + edgeSchema); err != nil {
		t.Fatal(err)
	}
	rollout := filepath.Join(t.TempDir(), "rollout.jsonl")
	return sqliteFixture{path: path, rollout: rollout, writer: writer}
}

func (f sqliteFixture) insert(t *testing.T, version, source, status, body string) {
	t.Helper()
	if _, err := f.writer.Exec(
		`INSERT INTO threads (id, rollout_path, updated_at, cli_version, thread_source, private_body) VALUES (?, ?, ?, ?, ?, ?)`,
		"synthetic-child", f.rollout, 100, version, source, body,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := f.writer.Exec(
		`INSERT INTO thread_spawn_edges (parent_thread_id, child_thread_id, status) VALUES (?, ?, ?)`,
		"synthetic-parent", "synthetic-child", status,
	); err != nil {
		t.Fatal(err)
	}
}

func openTestStore(t *testing.T, fixture sqliteFixture, options StoreOptions) *Store {
	t.Helper()
	store, err := OpenStore(context.Background(), fixture.path, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestStoreReadOnlyQueryOnlyStableSnapshot(t *testing.T) {
	fixture := newSQLiteFixture(t, "", "")
	fixture.insert(t, SupportedCodexVersion, "subagent", "closed", "private prompt and response body")
	store := openTestStore(t, fixture, StoreOptions{})

	snapshot, err := store.Snapshot(context.Background(), fixture.rollout)
	if err != nil {
		t.Fatal(err)
	}
	if !validMetadataSample(snapshot) || snapshot.DataVersion < 0 {
		t.Fatalf("invalid normalized snapshot: %#v", snapshot)
	}
	if _, err := store.conn.ExecContext(context.Background(), "CREATE TABLE forbidden_write (id INTEGER)"); err == nil {
		t.Fatal("query-only connection accepted a write")
	}

	public, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"private prompt", fixture.path, fixture.rollout, "synthetic-child", "synthetic-parent",
	} {
		if strings.Contains(string(public), forbidden) {
			t.Fatalf("private value leaked in public snapshot JSON: %q", forbidden)
		}
	}
}

func TestReadOnlyDSNIsLiveWALAwareAndBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state with space.sqlite")
	dsn := readOnlyDSN(path, 250*time.Millisecond)
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "file" || filepath.FromSlash(parsed.Path) != path {
		t.Fatalf("path was not URI escaped exactly: %q", dsn)
	}
	query := parsed.Query()
	wants := map[string]string{
		"mode": "ro", "_query_only": "1", "_busy_timeout": "250", "_trusted_schema": "0",
	}
	for key, want := range wants {
		if got := query.Get(key); got != want {
			t.Fatalf("%s=%q want %q", key, got, want)
		}
	}
	if _, present := query["immutable"]; present {
		t.Fatal("immutable mode would hide concurrent Codex WAL writes")
	}
}

func TestStoreRequiresExistingCanonicalPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.sqlite")
	_, err := OpenStore(context.Background(), missing, StoreOptions{})
	if err == nil || codeOf(err, "") != CodeMetadataUnavailable {
		t.Fatalf("got %v", err)
	}
	if _, statErr := os.Stat(missing); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("read-only open created missing database: %v", statErr)
	}
	if strings.Contains(err.Error(), missing) {
		t.Fatal("database path leaked in error")
	}
}

func TestStoreSchemaGate(t *testing.T) {
	tests := []struct {
		name         string
		threadSchema string
		edgeSchema   string
	}{
		{"missing rollout path", strings.Replace(testThreadSchema, "    rollout_path TEXT NOT NULL,\n", "", 1), testEdgeSchema},
		{"wrong rollout affinity", strings.Replace(testThreadSchema, "rollout_path TEXT", "rollout_path INTEGER", 1), testEdgeSchema},
		{"missing updated at", strings.Replace(testThreadSchema, "    updated_at INTEGER NOT NULL,\n", "", 1), testEdgeSchema},
		{"wrong updated affinity", strings.Replace(testThreadSchema, "updated_at INTEGER", "updated_at TEXT", 1), testEdgeSchema},
		{"nullable cli version", strings.Replace(testThreadSchema, "cli_version TEXT NOT NULL", "cli_version TEXT", 1), testEdgeSchema},
		{"missing thread source", strings.Replace(testThreadSchema, "    thread_source TEXT,\n", "", 1), testEdgeSchema},
		{"missing edge table", testThreadSchema, `CREATE TABLE another (id INTEGER);`},
		{"edge child not primary key", testThreadSchema, strings.Replace(testEdgeSchema, "child_thread_id TEXT NOT NULL PRIMARY KEY", "child_thread_id TEXT NOT NULL", 1)},
		{"edge child nullable", testThreadSchema, strings.Replace(testEdgeSchema, "child_thread_id TEXT NOT NULL PRIMARY KEY", "child_thread_id TEXT PRIMARY KEY", 1)},
		{"edge status nullable", testThreadSchema, strings.Replace(testEdgeSchema, "status TEXT NOT NULL", "status TEXT", 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSQLiteFixture(t, test.threadSchema, test.edgeSchema)
			store := openTestStore(t, fixture, StoreOptions{})
			_, err := store.Snapshot(context.Background(), fixture.rollout)
			if err == nil || codeOf(err, "") != CodeSchemaIncompatible {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestStoreValueGate(t *testing.T) {
	tests := []struct {
		name, version, source, status string
	}{
		{"wrong exact version", "0.148.0-alpha.16", "subagent", "closed"},
		{"empty version", "", "subagent", "closed"},
		{"root thread", SupportedCodexVersion, "user", "closed"},
		{"open edge", SupportedCodexVersion, "subagent", "open"},
		{"empty edge", SupportedCodexVersion, "subagent", ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSQLiteFixture(t, "", "")
			fixture.insert(t, test.version, test.source, test.status, "do not leak this body")
			store := openTestStore(t, fixture, StoreOptions{})
			_, err := store.Snapshot(context.Background(), fixture.rollout)
			if err == nil || codeOf(err, "") != CodeMetadataValueInvalid {
				t.Fatalf("got %v", err)
			}
			if strings.Contains(err.Error(), "do not leak") {
				t.Fatal("private row value leaked")
			}
		})
	}
}

func TestStoreDataVersionWALRaceRetriesWholeRead(t *testing.T) {
	fixture := newSQLiteFixture(t, "", "")
	if _, err := fixture.writer.Exec("PRAGMA journal_mode=WAL"); err != nil {
		t.Fatal(err)
	}
	fixture.insert(t, SupportedCodexVersion, "subagent", "closed", "a")
	store := openTestStore(t, fixture, StoreOptions{Attempts: 3})
	calls := 0
	store.testHook = func(attempt int, phase readPhase) {
		if attempt != 0 || phase != phaseAfterRows {
			return
		}
		calls++
		if _, err := fixture.writer.Exec(`UPDATE threads SET private_body = private_body || 'b' WHERE id = 'synthetic-child'`); err != nil {
			t.Error(err)
		}
	}
	if _, err := store.Snapshot(context.Background(), fixture.rollout); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("hook calls=%d", calls)
	}
}

func TestStoreContinuousWALRaceIsUnavailable(t *testing.T) {
	fixture := newSQLiteFixture(t, "", "")
	if _, err := fixture.writer.Exec("PRAGMA journal_mode=WAL"); err != nil {
		t.Fatal(err)
	}
	fixture.insert(t, SupportedCodexVersion, "subagent", "closed", "a")
	store := openTestStore(t, fixture, StoreOptions{Attempts: 3})
	store.testHook = func(_ int, _ readPhase) {
		if _, err := fixture.writer.Exec(`UPDATE threads SET private_body = private_body || 'b' WHERE id = 'synthetic-child'`); err != nil {
			t.Error(err)
		}
	}
	_, err := store.Snapshot(context.Background(), fixture.rollout)
	if err == nil || codeOf(err, "") != CodeMetadataUnstable {
		t.Fatalf("got %v", err)
	}
}

func TestStoreRevalidatesSchemaOnEverySnapshot(t *testing.T) {
	fixture := newSQLiteFixture(t, "", "")
	fixture.insert(t, SupportedCodexVersion, "subagent", "closed", "private")
	store := openTestStore(t, fixture, StoreOptions{})
	if _, err := store.Snapshot(context.Background(), fixture.rollout); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.writer.Exec("ALTER TABLE threads RENAME TO incompatible_threads"); err != nil {
		t.Fatal(err)
	}
	_, err := store.Snapshot(context.Background(), fixture.rollout)
	if err == nil || codeOf(err, "") != CodeSchemaIncompatible {
		t.Fatalf("got %v", err)
	}
}

func TestStoreContextBound(t *testing.T) {
	fixture := newSQLiteFixture(t, "", "")
	fixture.insert(t, SupportedCodexVersion, "subagent", "closed", "private")
	store := openTestStore(t, fixture, StoreOptions{ReadTimeout: 50 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := store.Snapshot(ctx, fixture.rollout)
	if err == nil || !errors.Is(err, context.Canceled) || codeOf(err, "") != CodeContextCancelled {
		t.Fatalf("got %v", err)
	}
}
