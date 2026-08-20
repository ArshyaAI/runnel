package receipt

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/ArshyaAI/runnel/internal/model"
	"golang.org/x/sys/unix"
)

const (
	preparedName   = "prepared.json"
	executingName  = "executing.json"
	resultName     = "result.json"
	maxReceiptSize = 4 << 20
)

var receiptIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{15,63}$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

var (
	ErrClosed       = errors.New("receipt store is closed")
	ErrCollision    = errors.New("receipt already exists")
	ErrInvalidID    = errors.New("invalid receipt id")
	ErrInvalidPath  = errors.New("unsafe receipt path")
	ErrInvalidState = errors.New("invalid receipt state")
	ErrTooLarge     = errors.New("receipt exceeds size limit")
)

// Validator validates one encoded receipt before any durable filesystem mutation.
// Schema validators are injected so the store has no knowledge of private/public fields.
type Validator func([]byte) error

type State string

const (
	StatePrepared  State = "prepared"
	StateExecuting State = "executing"
	StateResult    State = "result"
)

type Entry struct {
	ID    string
	State State
}

// Store owns an open descriptor to a verified receipt root. Every transaction is an
// immutable directory containing prepared.json and, at most once, result.json.
// All operations are relative to held directory descriptors to prevent path swapping.
type Store struct {
	root     string
	rootFD   int
	uid      uint32
	prepared Validator
	result   Validator

	mu     sync.RWMutex
	closed bool
}

func NewStore(root string, prepared, result Validator) (*Store, error) {
	if prepared == nil || result == nil {
		return nil, fmt.Errorf("%w: validators are required", ErrInvalidState)
	}
	fd, clean, err := openOrCreateSafeRoot(root, uint32(os.Getuid()))
	if err != nil {
		return nil, err
	}
	return &Store{
		root:     clean,
		rootFD:   fd,
		uid:      uint32(os.Getuid()),
		prepared: prepared,
		result:   result,
	}, nil
}

func (s *Store) Root() string { return s.root }

func NewID() (string, error) {
	var raw [16]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return "", fmt.Errorf("receipt id: %w", err)
	}
	return "r-" + hex.EncodeToString(raw[:]), nil
}

func (s *Store) Prepare(ctx context.Context, id string, data []byte) error {
	if err := validateID(id); err != nil {
		return err
	}
	data = bytes.Clone(data)
	if err := validatePayload(data, s.prepared); err != nil {
		return fmt.Errorf("prepared receipt: %w", err)
	}
	payloadID, err := decodeReceiptID(data)
	if err != nil || payloadID != id {
		return fmt.Errorf("prepared receipt: %w: payload receipt_id does not match directory id", ErrInvalidState)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	if err := unix.Mkdirat(s.rootFD, id, 0o700); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("%w: %s", ErrCollision, id)
		}
		return fmt.Errorf("create transaction directory: %w", err)
	}
	txFD, err := openVerifiedDirAt(s.rootFD, id, s.uid, 0o700)
	if err != nil {
		_ = unix.Unlinkat(s.rootFD, id, unix.AT_REMOVEDIR)
		return err
	}
	defer unix.Close(txFD)

	if err := writeImmutableAt(ctx, txFD, preparedName, data, s.uid); err != nil {
		_ = unix.Unlinkat(s.rootFD, id, unix.AT_REMOVEDIR)
		return fmt.Errorf("write prepared receipt: %w", err)
	}
	if err := unix.Fsync(txFD); err != nil {
		return fmt.Errorf("sync transaction directory: %w", err)
	}
	if err := unix.Fsync(s.rootFD); err != nil {
		return fmt.Errorf("sync receipt root: %w", err)
	}
	return nil
}

// ClaimExecution durably and exclusively consumes a prepared transaction for
// one execution attempt. The immutable marker is intentionally retained after
// finalization so a crash or completed action remains auditable. A claim is
// never leased or automatically retried.
func (s *Store) ClaimExecution(ctx context.Context, id, expectedPreparedDigest string) error {
	if err := validateID(id); err != nil {
		return err
	}
	if !digestPattern.MatchString(expectedPreparedDigest) {
		return fmt.Errorf("%w: malformed prepared digest", ErrInvalidState)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	txFD, err := openVerifiedDirAt(s.rootFD, id, s.uid, 0o700)
	if err != nil {
		return err
	}
	defer unix.Close(txFD)

	_, _, preparedDigest, err := s.readPreparedBoundAt(txFD, id)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(preparedDigest), []byte(expectedPreparedDigest)) != 1 {
		return fmt.Errorf("%w: prepared digest mismatch", ErrInvalidState)
	}
	if err := verifyAbsentAt(txFD, resultName); err != nil {
		return fmt.Errorf("%w: transaction is already final", ErrInvalidState)
	}
	claimData, err := json.Marshal(executionClaim{
		State:          StateExecuting,
		ReceiptID:      id,
		PreparedDigest: preparedDigest,
	})
	if err != nil {
		return fmt.Errorf("encode execution claim: %w", err)
	}
	if err := writeImmutableAt(ctx, txFD, executingName, claimData, s.uid); err != nil {
		return fmt.Errorf("claim execution: %w", err)
	}
	if err := unix.Fsync(txFD); err != nil {
		return fmt.Errorf("sync execution claim: %w", err)
	}
	return nil
}

func (s *Store) Finalize(ctx context.Context, id string, data []byte) error {
	if err := validateID(id); err != nil {
		return err
	}
	data = bytes.Clone(data)
	if err := validatePayload(data, s.result); err != nil {
		return fmt.Errorf("result receipt: %w", err)
	}
	resultBinding, err := decodeResultBinding(data)
	if err != nil || resultBinding.ReceiptID != id {
		return fmt.Errorf("result receipt: %w: payload receipt_id does not match directory id", ErrInvalidState)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrClosed
	}
	txFD, err := openVerifiedDirAt(s.rootFD, id, s.uid, 0o700)
	if err != nil {
		return err
	}
	defer unix.Close(txFD)
	_, preparedBinding, preparedDigest, err := s.readPreparedBoundAt(txFD, id)
	if err != nil {
		return err
	}
	claim, err := readExecutionClaimAt(txFD, s.uid)
	if err != nil {
		return fmt.Errorf("execution claim missing or unsafe: %w", err)
	}
	if err := validateExecutionClaim(claim, id, preparedDigest); err != nil {
		return err
	}
	if err := validateResultLink(resultBinding, id, preparedDigest, preparedBinding.Target); err != nil {
		return err
	}
	if err := writeImmutableAt(ctx, txFD, resultName, data, s.uid); err != nil {
		return fmt.Errorf("write result receipt: %w", err)
	}
	if err := unix.Fsync(txFD); err != nil {
		return fmt.Errorf("sync transaction directory: %w", err)
	}
	return nil
}

func (s *Store) Read(ctx context.Context, id string) (State, []byte, error) {
	if err := validateID(id); err != nil {
		return "", nil, err
	}
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return "", nil, ErrClosed
	}
	txFD, err := openVerifiedDirAt(s.rootFD, id, s.uid, 0o700)
	if err != nil {
		return "", nil, err
	}
	defer unix.Close(txFD)
	preparedData, preparedBinding, preparedDigest, err := s.readPreparedBoundAt(txFD, id)
	if err != nil {
		return "", nil, err
	}
	if resultData, readErr := readVerifiedAt(txFD, resultName, s.uid); readErr == nil {
		if err := validatePayload(resultData, s.result); err != nil {
			return "", nil, fmt.Errorf("stored result receipt: %w", err)
		}
		resultBinding, err := decodeResultBinding(resultData)
		if err != nil {
			return "", nil, fmt.Errorf("stored result receipt: %w", err)
		}
		claim, err := readExecutionClaimAt(txFD, s.uid)
		if err != nil {
			return "", nil, fmt.Errorf("stored execution claim: %w", err)
		}
		if err := validateExecutionClaim(claim, id, preparedDigest); err != nil {
			return "", nil, err
		}
		if err := validateResultLink(resultBinding, id, preparedDigest, preparedBinding.Target); err != nil {
			return "", nil, err
		}
		return StateResult, resultData, nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", nil, readErr
	}
	if claim, readErr := readExecutionClaimAt(txFD, s.uid); readErr == nil {
		if err := validateExecutionClaim(claim, id, preparedDigest); err != nil {
			return "", nil, err
		}
		return StateExecuting, preparedData, nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", nil, readErr
	}
	return StatePrepared, preparedData, nil
}

func (s *Store) List(ctx context.Context) ([]Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dupFD, err := unix.Openat(s.rootFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("duplicate receipt root: %w", err)
	}
	dir := os.NewFile(uintptr(dupFD), s.root)
	if dir == nil {
		_ = unix.Close(dupFD)
		return nil, errors.New("open receipt root stream")
	}
	defer dir.Close()
	items, err := dir.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("list receipt root: %w", err)
	}
	entries := make([]Entry, 0, len(items))
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		id := item.Name()
		if !receiptIDPattern.MatchString(id) {
			continue
		}
		txFD, err := openVerifiedDirAt(s.rootFD, id, s.uid, 0o700)
		if err != nil {
			continue
		}
		state, err := s.stateAt(txFD, id)
		if err != nil {
			_ = unix.Close(txFD)
			continue
		}
		_ = unix.Close(txFD)
		entries = append(entries, Entry{ID: id, State: state})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID > entries[j].ID })
	return entries, nil
}

type preparedBinding struct {
	ReceiptID string
	Target    json.RawMessage
}

type resultAttemptBinding struct {
	Target    json.RawMessage
	Attempted bool
}

type resultBinding struct {
	ReceiptID      string
	PreparedDigest string
	Attempts       []resultAttemptBinding
}

type executionClaim struct {
	State          State  `json:"state"`
	ReceiptID      string `json:"receipt_id"`
	PreparedDigest string `json:"prepared_digest"`
}

func (s *Store) readPreparedBoundAt(txFD int, id string) ([]byte, preparedBinding, string, error) {
	data, err := readVerifiedAt(txFD, preparedName, s.uid)
	if err != nil {
		return nil, preparedBinding{}, "", fmt.Errorf("prepared receipt missing or unsafe: %w", err)
	}
	if err := validatePayload(data, s.prepared); err != nil {
		return nil, preparedBinding{}, "", fmt.Errorf("stored prepared receipt: %w", err)
	}
	binding, err := decodePreparedBinding(data)
	if err != nil {
		return nil, preparedBinding{}, "", fmt.Errorf("stored prepared receipt: %w", err)
	}
	if binding.ReceiptID != id {
		return nil, preparedBinding{}, "", fmt.Errorf("%w: stored prepared receipt_id does not match directory id", ErrInvalidState)
	}
	return data, binding, digestBytes(data), nil
}

func (s *Store) stateAt(txFD int, id string) (State, error) {
	_, prepared, digest, err := s.readPreparedBoundAt(txFD, id)
	if err != nil {
		return "", err
	}
	if resultData, readErr := readVerifiedAt(txFD, resultName, s.uid); readErr == nil {
		if err := validatePayload(resultData, s.result); err != nil {
			return "", err
		}
		result, err := decodeResultBinding(resultData)
		if err != nil {
			return "", err
		}
		claim, err := readExecutionClaimAt(txFD, s.uid)
		if err != nil {
			return "", err
		}
		if err := validateExecutionClaim(claim, id, digest); err != nil {
			return "", err
		}
		if err := validateResultLink(result, id, digest, prepared.Target); err != nil {
			return "", err
		}
		return StateResult, nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", readErr
	}
	if claim, readErr := readExecutionClaimAt(txFD, s.uid); readErr == nil {
		if err := validateExecutionClaim(claim, id, digest); err != nil {
			return "", err
		}
		return StateExecuting, nil
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return "", readErr
	}
	return StatePrepared, nil
}

func decodeReceiptID(data []byte) (string, error) {
	fields, err := decodeJSONObject(data)
	if err != nil {
		return "", err
	}
	var id string
	if raw, ok := fields["receipt_id"]; !ok || json.Unmarshal(raw, &id) != nil || id == "" {
		return "", fmt.Errorf("%w: receipt_id must be one non-empty string", ErrInvalidState)
	}
	return id, nil
}

func decodePreparedBinding(data []byte) (preparedBinding, error) {
	fields, err := decodeJSONObject(data)
	if err != nil {
		return preparedBinding{}, err
	}
	id, err := decodeStringField(fields, "receipt_id")
	if err != nil {
		return preparedBinding{}, err
	}
	return preparedBinding{ReceiptID: id, Target: fields["target"]}, nil
}

func decodeResultBinding(data []byte) (resultBinding, error) {
	fields, err := decodeJSONObject(data)
	if err != nil {
		return resultBinding{}, err
	}
	id, err := decodeStringField(fields, "receipt_id")
	if err != nil {
		return resultBinding{}, err
	}
	digest, err := decodeStringField(fields, "prepared_digest")
	if err != nil || !digestPattern.MatchString(digest) {
		return resultBinding{}, fmt.Errorf("%w: prepared_digest must be a lowercase SHA-256 digest", ErrInvalidState)
	}
	var rawAttempts []json.RawMessage
	if raw, ok := fields["signal_attempts"]; ok {
		if err := json.Unmarshal(raw, &rawAttempts); err != nil {
			return resultBinding{}, fmt.Errorf("%w: signal_attempts must be an array", ErrInvalidState)
		}
	}
	attempts := make([]resultAttemptBinding, 0, len(rawAttempts))
	for _, raw := range rawAttempts {
		attemptFields, err := decodeJSONObject(raw)
		if err != nil {
			return resultBinding{}, fmt.Errorf("%w: malformed signal attempt", ErrInvalidState)
		}
		var attempted bool
		if rawAttempted, ok := attemptFields["attempted"]; !ok || json.Unmarshal(rawAttempted, &attempted) != nil {
			return resultBinding{}, fmt.Errorf("%w: signal attempt has no boolean attempted field", ErrInvalidState)
		}
		attempts = append(attempts, resultAttemptBinding{Target: attemptFields["target"], Attempted: attempted})
	}
	return resultBinding{ReceiptID: id, PreparedDigest: digest, Attempts: attempts}, nil
}

func readExecutionClaimAt(txFD int, uid uint32) (executionClaim, error) {
	data, err := readVerifiedAt(txFD, executingName, uid)
	if err != nil {
		return executionClaim{}, err
	}
	fields, err := decodeJSONObject(data)
	if err != nil || len(fields) != 3 {
		return executionClaim{}, fmt.Errorf("%w: malformed execution claim", ErrInvalidState)
	}
	stateValue, err := decodeStringField(fields, "state")
	if err != nil {
		return executionClaim{}, err
	}
	id, err := decodeStringField(fields, "receipt_id")
	if err != nil {
		return executionClaim{}, err
	}
	digest, err := decodeStringField(fields, "prepared_digest")
	if err != nil {
		return executionClaim{}, err
	}
	return executionClaim{State: State(stateValue), ReceiptID: id, PreparedDigest: digest}, nil
}

func validateExecutionClaim(claim executionClaim, id, preparedDigest string) error {
	if claim.State != StateExecuting || claim.ReceiptID != id || claim.PreparedDigest != preparedDigest || !digestPattern.MatchString(claim.PreparedDigest) {
		return fmt.Errorf("%w: execution claim does not bind the prepared receipt", ErrInvalidState)
	}
	return nil
}

func validateResultLink(result resultBinding, id, preparedDigest string, preparedTarget json.RawMessage) error {
	if result.ReceiptID != id || result.PreparedDigest != preparedDigest {
		return fmt.Errorf("%w: result does not bind the prepared receipt", ErrInvalidState)
	}
	for _, attempt := range result.Attempts {
		if !attempt.Attempted {
			continue
		}
		var preparedIdentity, attemptedIdentity model.DarwinActionIdentity
		if len(preparedTarget) == 0 || len(attempt.Target) == 0 ||
			json.Unmarshal(preparedTarget, &preparedIdentity) != nil ||
			json.Unmarshal(attempt.Target, &attemptedIdentity) != nil ||
			preparedIdentity.Validate() != nil || attemptedIdentity.Validate() != nil ||
			!preparedIdentity.Equal(attemptedIdentity) {
			return fmt.Errorf("%w: attempted target does not match prepared target", ErrInvalidState)
		}
	}
	return nil
}

func decodeJSONObject(data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("%w: receipt must be one JSON object", ErrInvalidState)
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: malformed object key", ErrInvalidState)
		}
		key, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("%w: non-string object key", ErrInvalidState)
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, fmt.Errorf("%w: duplicate object key %q", ErrInvalidState, key)
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, fmt.Errorf("%w: malformed value for %q", ErrInvalidState, key)
		}
		fields[key] = raw
	}
	if _, err := decoder.Token(); err != nil {
		return nil, fmt.Errorf("%w: unterminated object", ErrInvalidState)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, fmt.Errorf("%w: trailing JSON document", ErrInvalidState)
	}
	return fields, nil
}

func decodeStringField(fields map[string]json.RawMessage, name string) (string, error) {
	raw, ok := fields[name]
	if !ok {
		return "", fmt.Errorf("%w: missing %s", ErrInvalidState, name)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || value == "" {
		return "", fmt.Errorf("%w: %s must be a non-empty string", ErrInvalidState, name)
	}
	return value, nil
}

func digestBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if err := unix.Close(s.rootFD); err != nil {
		return fmt.Errorf("close receipt root: %w", err)
	}
	return nil
}

func validateID(id string) error {
	if !receiptIDPattern.MatchString(id) || strings.Contains(id, "..") {
		return fmt.Errorf("%w: %q", ErrInvalidID, id)
	}
	return nil
}

func validatePayload(data []byte, validator Validator) error {
	if len(data) == 0 {
		return fmt.Errorf("%w: empty payload", ErrInvalidState)
	}
	if len(data) > maxReceiptSize {
		return ErrTooLarge
	}
	if err := validator(data); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidState, err)
	}
	return nil
}

func openOrCreateSafeRoot(path string, uid uint32) (int, string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return -1, "", fmt.Errorf("%w: root must be a non-root absolute path", ErrInvalidPath)
	}
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", fmt.Errorf("open filesystem root: %w", err)
	}
	for index, part := range parts {
		if part == "" || part == "." || part == ".." {
			_ = unix.Close(fd)
			return -1, "", fmt.Errorf("%w: invalid path component", ErrInvalidPath)
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(openErr, unix.ENOENT) {
			if mkErr := unix.Mkdirat(fd, part, 0o700); mkErr != nil && !errors.Is(mkErr, unix.EEXIST) {
				_ = unix.Close(fd)
				return -1, "", fmt.Errorf("create %q: %w", part, mkErr)
			}
			next, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if openErr != nil {
			_ = unix.Close(fd)
			return -1, "", fmt.Errorf("%w: open %q: %v", ErrInvalidPath, part, openErr)
		}
		_ = unix.Close(fd)
		fd = next
		if index == len(parts)-1 {
			if err := verifyOpenDir(fd, uid, 0o700); err != nil {
				_ = unix.Close(fd)
				return -1, "", err
			}
		}
	}
	return fd, clean, nil
}

func openVerifiedDirAt(parentFD int, name string, uid uint32, mode uint16) (int, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return -1, os.ErrNotExist
		}
		return -1, fmt.Errorf("%w: open directory %q: %v", ErrInvalidPath, name, err)
	}
	if err := verifyOpenDir(fd, uid, mode); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func verifyOpenDir(fd int, uid uint32, mode uint16) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("stat directory: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uid || stat.Mode&0o777 != mode {
		return fmt.Errorf("%w: directory owner/mode mismatch", ErrInvalidPath)
	}
	return nil
}

func writeImmutableAt(ctx context.Context, dirFD int, name string, data []byte, uid uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := verifyAbsentAt(dirFD, name); err != nil {
		return err
	}
	tmp, err := randomTempName(name)
	if err != nil {
		return err
	}
	fd, err := unix.Openat(dirFD, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("exclusive temp create: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = unix.Unlinkat(dirFD, tmp, 0)
		}
	}()
	file := os.NewFile(uintptr(fd), tmp)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("wrap receipt temp file")
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := verifyRegularAt(dirFD, tmp, uid, 0o600); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := unix.RenameatxNp(dirFD, tmp, dirFD, name, unix.RENAME_EXCL); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("%w: %s", ErrCollision, name)
		}
		return fmt.Errorf("exclusive rename: %w", err)
	}
	cleanup = false
	if err := verifyRegularAt(dirFD, name, uid, 0o600); err != nil {
		return err
	}
	return nil
}

func verifyAbsentAt(dirFD int, name string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(dirFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return fmt.Errorf("%w: %s", ErrCollision, name)
	}
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return fmt.Errorf("check destination: %w", err)
}

func verifyRegularAt(dirFD int, name string, uid uint32, mode uint16) error {
	var stat unix.Stat_t
	err := unix.Fstatat(dirFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return os.ErrNotExist
	}
	if err != nil {
		return fmt.Errorf("stat %q: %w", name, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uid || stat.Mode&0o777 != mode {
		return fmt.Errorf("%w: file %q owner/type/mode mismatch", ErrInvalidPath, name)
	}
	return nil
}

func readVerifiedAt(dirFD int, name string, uid uint32) ([]byte, error) {
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, fmt.Errorf("%w: open %q: %v", ErrInvalidPath, name, err)
	}
	if err := verifyOpenRegular(fd, uid, 0o600); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("wrap receipt file")
	}
	defer file.Close()
	limited := io.LimitReader(file, maxReceiptSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", name, err)
	}
	if len(data) > maxReceiptSize {
		return nil, ErrTooLarge
	}
	return data, nil
}

func verifyOpenRegular(fd int, uid uint32, mode uint16) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("stat opened receipt: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uid || stat.Mode&0o777 != mode {
		return fmt.Errorf("%w: opened receipt owner/type/mode mismatch", ErrInvalidPath)
	}
	return nil
}

func randomTempName(final string) (string, error) {
	var raw [12]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return "", fmt.Errorf("temp name: %w", err)
	}
	return "." + final + "." + hex.EncodeToString(raw[:]) + ".tmp", nil
}
