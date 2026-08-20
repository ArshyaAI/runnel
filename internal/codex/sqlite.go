package codex

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ArshyaAI/runnel/internal/model"
	_ "github.com/mattn/go-sqlite3"
)

const (
	defaultBusyTimeout  = 250 * time.Millisecond
	defaultReadTimeout  = 900 * time.Millisecond
	defaultReadAttempts = 3
)

type StoreOptions struct {
	BusyTimeout time.Duration
	ReadTimeout time.Duration
	Attempts    int
}

func (o StoreOptions) withDefaults() StoreOptions {
	if o.BusyTimeout <= 0 {
		o.BusyTimeout = defaultBusyTimeout
	}
	if o.ReadTimeout <= 0 {
		o.ReadTimeout = defaultReadTimeout
	}
	if o.Attempts <= 0 {
		o.Attempts = defaultReadAttempts
	}
	if o.BusyTimeout > 2*time.Second {
		o.BusyTimeout = 2 * time.Second
	}
	if o.ReadTimeout > 5*time.Second {
		o.ReadTimeout = 5 * time.Second
	}
	if o.Attempts > 5 {
		o.Attempts = 5
	}
	return o
}

// MetadataSnapshot contains only the row fields needed to correlate one
// completed subagent rollout. Private identifiers and paths cannot be JSON
// encoded accidentally.
type MetadataSnapshot struct {
	Availability   model.Availability `json:"availability"`
	DataVersion    int64              `json:"data_version"`
	CLIVersion     string             `json:"cli_version"`
	ThreadSource   string             `json:"thread_source"`
	EdgeStatus     string             `json:"edge_status"`
	ThreadID       string             `json:"-"`
	ParentThreadID string             `json:"-"`
	RolloutPath    string             `json:"-"`
}

func (s MetadataSnapshot) actionEqual(other MetadataSnapshot) bool {
	return s.Availability == other.Availability &&
		s.DataVersion == other.DataVersion &&
		s.CLIVersion == other.CLIVersion &&
		s.ThreadSource == other.ThreadSource &&
		s.EdgeStatus == other.EdgeStatus &&
		s.ThreadID == other.ThreadID &&
		s.ParentThreadID == other.ParentThreadID &&
		s.RolloutPath == other.RolloutPath
}

type readPhase uint8

const phaseAfterRows readPhase = 1

// Store owns one connection because PRAGMA data_version is connection-local.
// Every operation is serialized and bounded.
type Store struct {
	db       *sql.DB
	conn     *sql.Conn
	options  StoreOptions
	mu       sync.Mutex
	testHook func(attempt int, phase readPhase)
}

func OpenStore(ctx context.Context, databasePath string, options StoreOptions) (*Store, error) {
	if _, err := exactAbsolutePath(databasePath); err != nil {
		return nil, safeError(CodeMetadataUnavailable)
	}
	options = options.withDefaults()
	dsn := readOnlyDSN(databasePath, options.BusyTimeout)
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, safeWrap(CodeMetadataUnavailable, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	openCtx, cancel := context.WithTimeout(ctx, options.ReadTimeout)
	defer cancel()
	conn, err := db.Conn(openCtx)
	if err != nil {
		db.Close()
		return nil, normalizeSQLiteError(openCtx, err)
	}
	store := &Store{db: db, conn: conn, options: options}
	if err := store.verifyConnection(openCtx); err != nil {
		store.Close()
		return nil, err
	}
	return store, nil
}

func readOnlyDSN(path string, busyTimeout time.Duration) string {
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	query := u.Query()
	query.Set("mode", "ro")
	query.Set("cache", "private")
	query.Set("_query_only", "1")
	query.Set("_busy_timeout", fmt.Sprintf("%d", busyTimeout.Milliseconds()))
	query.Set("_trusted_schema", "0")
	u.RawQuery = query.Encode()
	return u.String()
}

func (s *Store) verifyConnection(ctx context.Context) error {
	// go-sqlite3 preserves the requested _trusted_schema URI parameter, but
	// SQLite does not interpret unknown URI keys itself. Apply the pragma on the
	// already mode=ro/query-only connection and verify it below.
	if _, err := s.conn.ExecContext(ctx, "PRAGMA trusted_schema = OFF"); err != nil {
		return normalizeSQLiteError(ctx, err)
	}
	checks := []struct {
		query string
		want  int64
	}{
		{"PRAGMA query_only", 1},
		{"PRAGMA trusted_schema", 0},
		{"PRAGMA busy_timeout", s.options.BusyTimeout.Milliseconds()},
	}
	for _, check := range checks {
		var actual int64
		if err := s.conn.QueryRowContext(ctx, check.query).Scan(&actual); err != nil {
			return normalizeSQLiteError(ctx, err)
		}
		if actual != check.want {
			return safeError(CodeMetadataUnavailable)
		}
	}
	return nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var first error
	if s.conn != nil {
		if err := s.conn.Close(); err != nil {
			first = err
		}
		s.conn = nil
	}
	if s.db != nil {
		if err := s.db.Close(); first == nil && err != nil {
			first = err
		}
		s.db = nil
	}
	return first
}

// Snapshot retries only complete before/query/after observations. Continuous
// WAL churn is unavailable; no hybrid or earlier-baseline result is returned.
func (s *Store) Snapshot(ctx context.Context, rolloutPath string) (MetadataSnapshot, error) {
	if _, err := exactAbsolutePath(rolloutPath); err != nil {
		return MetadataSnapshot{}, safeError(CodeMetadataValueInvalid)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return MetadataSnapshot{}, safeError(CodeMetadataUnavailable)
	}

	readCtx, cancel := context.WithTimeout(ctx, s.options.ReadTimeout)
	defer cancel()
	for attempt := 0; attempt < s.options.Attempts; attempt++ {
		before, err := s.dataVersion(readCtx)
		if err != nil {
			return MetadataSnapshot{}, err
		}
		row, err := s.readRow(readCtx, rolloutPath)
		if err != nil {
			return MetadataSnapshot{}, err
		}
		if s.testHook != nil {
			s.testHook(attempt, phaseAfterRows)
		}
		after, err := s.dataVersion(readCtx)
		if err != nil {
			return MetadataSnapshot{}, err
		}
		if before != after {
			continue
		}
		row.DataVersion = after
		return row, nil
	}
	return MetadataSnapshot{}, safeError(CodeMetadataUnstable)
}

func (s *Store) dataVersion(ctx context.Context) (int64, error) {
	var version int64
	if err := s.conn.QueryRowContext(ctx, "PRAGMA data_version").Scan(&version); err != nil {
		return 0, normalizeSQLiteError(ctx, err)
	}
	if version < 0 {
		return 0, safeError(CodeMetadataValueInvalid)
	}
	return version, nil
}

func (s *Store) readRow(ctx context.Context, rolloutPath string) (MetadataSnapshot, error) {
	tx, err := s.conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return MetadataSnapshot{}, normalizeSQLiteError(ctx, err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := validateSchema(ctx, tx); err != nil {
		return MetadataSnapshot{}, err
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT
			t.id,
			t.rollout_path,
			t.cli_version,
			t.thread_source,
			e.parent_thread_id,
			e.status
		FROM threads AS t
		JOIN thread_spawn_edges AS e ON e.child_thread_id = t.id
		WHERE t.rollout_path = ? COLLATE BINARY
		ORDER BY t.id COLLATE BINARY
		LIMIT 2`, rolloutPath)
	if err != nil {
		return MetadataSnapshot{}, normalizeSQLiteError(ctx, err)
	}
	defer rows.Close()

	var results []MetadataSnapshot
	for rows.Next() {
		var source sql.NullString
		var row MetadataSnapshot
		if err := rows.Scan(
			&row.ThreadID,
			&row.RolloutPath,
			&row.CLIVersion,
			&source,
			&row.ParentThreadID,
			&row.EdgeStatus,
		); err != nil {
			return MetadataSnapshot{}, normalizeSQLiteError(ctx, err)
		}
		if !source.Valid {
			return MetadataSnapshot{}, safeError(CodeMetadataValueInvalid)
		}
		row.ThreadSource = source.String
		results = append(results, row)
	}
	if err := rows.Err(); err != nil {
		return MetadataSnapshot{}, normalizeSQLiteError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return MetadataSnapshot{}, normalizeSQLiteError(ctx, err)
	}
	if len(results) == 0 {
		return MetadataSnapshot{}, safeError(CodeMetadataUnavailable)
	}
	if len(results) != 1 {
		return MetadataSnapshot{}, safeError(CodeMetadataContradictory)
	}
	row := results[0]
	if row.ThreadID == "" || row.ParentThreadID == "" || row.ThreadID == row.ParentThreadID ||
		row.RolloutPath != rolloutPath || row.CLIVersion != SupportedCodexVersion ||
		row.ThreadSource != "subagent" || row.EdgeStatus != "closed" {
		return MetadataSnapshot{}, safeError(CodeMetadataValueInvalid)
	}
	row.Availability = model.AvailabilityAvailable
	return row, nil
}

type queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

type expectedColumn struct {
	affinity string
	notNull  *bool
	pk       *int64
}

func validateSchema(ctx context.Context, q queryer) error {
	threadColumns := map[string]expectedColumn{
		"id":            {affinity: "TEXT", notNull: boolPtr(false), pk: int64Ptr(1)},
		"rollout_path":  {affinity: "TEXT", notNull: boolPtr(true)},
		"updated_at":    {affinity: "INTEGER", notNull: boolPtr(true)},
		"cli_version":   {affinity: "TEXT", notNull: boolPtr(true)},
		"thread_source": {affinity: "TEXT", notNull: boolPtr(false)},
	}
	edgeColumns := map[string]expectedColumn{
		"parent_thread_id": {affinity: "TEXT", notNull: boolPtr(true)},
		"child_thread_id":  {affinity: "TEXT", notNull: boolPtr(true), pk: int64Ptr(1)},
		"status":           {affinity: "TEXT", notNull: boolPtr(true)},
	}
	if err := validateTable(ctx, q, "threads", threadColumns); err != nil {
		return err
	}
	return validateTable(ctx, q, "thread_spawn_edges", edgeColumns)
}

func validateTable(ctx context.Context, q queryer, table string, expected map[string]expectedColumn) error {
	statement := `PRAGMA table_info("` + table + `")`
	rows, err := q.QueryContext(ctx, statement)
	if err != nil {
		return safeWrap(CodeSchemaIncompatible, err)
	}
	defer rows.Close()
	found := make(map[string]expectedColumn)
	for rows.Next() {
		var cid, notNull, pk int64
		var name, declaredType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &declaredType, &notNull, &defaultValue, &pk); err != nil {
			return safeWrap(CodeSchemaIncompatible, err)
		}
		if want, ok := expected[name]; ok {
			if sqliteAffinity(declaredType) != want.affinity ||
				(want.notNull != nil && (notNull != 0) != *want.notNull) ||
				(want.pk != nil && pk != *want.pk) {
				return safeError(CodeSchemaIncompatible)
			}
			found[name] = want
		}
	}
	if err := rows.Err(); err != nil {
		return safeWrap(CodeSchemaIncompatible, err)
	}
	if len(found) != len(expected) {
		return safeError(CodeSchemaIncompatible)
	}
	return nil
}

func sqliteAffinity(declared string) string {
	upper := strings.ToUpper(declared)
	switch {
	case strings.Contains(upper, "INT"):
		return "INTEGER"
	case strings.Contains(upper, "CHAR"), strings.Contains(upper, "CLOB"), strings.Contains(upper, "TEXT"):
		return "TEXT"
	case upper == "", strings.Contains(upper, "BLOB"):
		return "BLOB"
	case strings.Contains(upper, "REAL"), strings.Contains(upper, "FLOA"), strings.Contains(upper, "DOUB"):
		return "REAL"
	default:
		return "NUMERIC"
	}
}

func normalizeSQLiteError(ctx context.Context, err error) error {
	if ctx.Err() == context.DeadlineExceeded {
		return safeWrap(CodeReadTimeout, err)
	}
	if ctx.Err() == context.Canceled {
		return safeWrap(CodeContextCancelled, err)
	}
	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "busy") || strings.Contains(lower, "locked") {
		return safeWrap(CodeMetadataUnavailable, err)
	}
	return safeWrap(CodeMetadataUnavailable, err)
}

func boolPtr(value bool) *bool    { return &value }
func int64Ptr(value int64) *int64 { return &value }
