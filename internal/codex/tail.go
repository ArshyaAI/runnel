package codex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/ArshyaAI/runnel/internal/model"
)

const (
	defaultMaxTailBytes  int64 = 256 << 10
	defaultMaxEventBytes       = 64 << 10
)

type DescriptorAccess string

const (
	DescriptorReadOnly  DescriptorAccess = "read_only"
	DescriptorWriteOnly DescriptorAccess = "write_only"
	DescriptorReadWrite DescriptorAccess = "read_write"
	DescriptorUnknown   DescriptorAccess = "unknown"
)

type DescriptorEvidence struct {
	Availability model.Availability `json:"availability"`
	Path         string             `json:"-"`
	Device       uint64             `json:"-"`
	Inode        uint64             `json:"-"`
	Access       DescriptorAccess   `json:"access"`
}

type FileIdentity struct {
	Device     uint64 `json:"-"`
	Inode      uint64 `json:"-"`
	Size       int64  `json:"size"`
	ModifiedNS int64  `json:"modified_ns"`
}

func (f FileIdentity) Equal(other FileIdentity) bool {
	return f == other
}

type TailSnapshot struct {
	Availability model.Availability `json:"availability"`
	EnvelopeType string             `json:"envelope_type"`
	EventType    string             `json:"event_type"`
	Successful   bool               `json:"successful"`
	File         FileIdentity       `json:"file"`
	digest       [sha256.Size]byte
}

func (t TailSnapshot) actionEqual(other TailSnapshot) bool {
	return t.Availability == other.Availability &&
		t.EnvelopeType == other.EnvelopeType &&
		t.EventType == other.EventType &&
		t.Successful == other.Successful &&
		t.File.Equal(other.File) &&
		t.digest == other.digest
}

type TailReaderOptions struct {
	MaxTailBytes  int64
	MaxEventBytes int
}

type TailReader struct {
	maxTailBytes  int64
	maxEventBytes int
	testHook      func(*os.File)
}

func NewTailReader(options TailReaderOptions) *TailReader {
	if options.MaxTailBytes <= 0 {
		options.MaxTailBytes = defaultMaxTailBytes
	}
	if options.MaxEventBytes <= 0 {
		options.MaxEventBytes = defaultMaxEventBytes
	}
	if options.MaxTailBytes > 4<<20 {
		options.MaxTailBytes = 4 << 20
	}
	if options.MaxEventBytes > int(options.MaxTailBytes) {
		options.MaxEventBytes = int(options.MaxTailBytes)
	}
	return &TailReader{maxTailBytes: options.MaxTailBytes, maxEventBytes: options.MaxEventBytes}
}

// Read opens the canonical rollout read-only, binds it to the descriptor's
// device/inode, and reads at most the configured tail. It never returns event
// payload text.
func (r *TailReader) Read(ctx context.Context, canonicalPath string, descriptor DescriptorEvidence) (TailSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return TailSnapshot{}, contextCode(err)
	}
	if descriptor.Availability != model.AvailabilityAvailable {
		return TailSnapshot{}, safeError(CodeDescriptorUnavailable)
	}
	if descriptor.Access != DescriptorReadOnly {
		return TailSnapshot{}, safeError(CodeDescriptorWritable)
	}
	if descriptor.Path != canonicalPath || descriptor.Device == 0 || descriptor.Inode == 0 {
		return TailSnapshot{}, safeError(CodeDescriptorMismatch)
	}
	if _, err := exactAbsolutePath(canonicalPath); err != nil {
		return TailSnapshot{}, safeError(CodeDescriptorMismatch)
	}

	file, err := os.Open(canonicalPath)
	if err != nil {
		return TailSnapshot{}, safeWrap(CodeTailUnavailable, err)
	}
	defer file.Close()
	beforeInfo, err := file.Stat()
	if err != nil {
		return TailSnapshot{}, safeWrap(CodeTailUnavailable, err)
	}
	before, err := fileIdentity(beforeInfo)
	if err != nil {
		return TailSnapshot{}, err
	}
	if before.Device != descriptor.Device || before.Inode != descriptor.Inode {
		return TailSnapshot{}, safeError(CodeDescriptorMismatch)
	}
	if before.Size <= 0 {
		return TailSnapshot{}, safeError(CodeTailTruncated)
	}

	readSize := before.Size
	offset := int64(0)
	if readSize > r.maxTailBytes {
		readSize = r.maxTailBytes
		offset = before.Size - readSize
	}
	buffer := make([]byte, readSize)
	n, readErr := file.ReadAt(buffer, offset)
	if readErr != nil && readErr != io.EOF {
		return TailSnapshot{}, safeWrap(CodeTailUnavailable, readErr)
	}
	if int64(n) != readSize {
		return TailSnapshot{}, safeError(CodeTailChanged)
	}
	buffer = buffer[:n]
	if r.testHook != nil {
		r.testHook(file)
	}
	if err := ctx.Err(); err != nil {
		return TailSnapshot{}, contextCode(err)
	}
	afterInfo, err := file.Stat()
	if err != nil {
		return TailSnapshot{}, safeWrap(CodeTailUnavailable, err)
	}
	after, err := fileIdentity(afterInfo)
	if err != nil {
		return TailSnapshot{}, err
	}
	if !before.Equal(after) {
		return TailSnapshot{}, safeError(CodeTailChanged)
	}

	line, err := finalCompleteLine(buffer, offset > 0, r.maxEventBytes)
	if err != nil {
		return TailSnapshot{}, err
	}
	envelope, err := parseCompletionEnvelope(line)
	if err != nil {
		return TailSnapshot{}, err
	}
	envelope.File = after
	envelope.digest = sha256.Sum256(line)
	return envelope, nil
}

func finalCompleteLine(tail []byte, startsMidFile bool, maxEventBytes int) ([]byte, error) {
	if len(tail) == 0 || tail[len(tail)-1] != '\n' {
		return nil, safeError(CodeTailTruncated)
	}
	if startsMidFile {
		firstNewline := bytes.IndexByte(tail, '\n')
		if firstNewline < 0 || firstNewline == len(tail)-1 {
			return nil, safeError(CodeTailTooLarge)
		}
		tail = tail[firstNewline+1:]
	}
	withoutFinalNewline := tail[:len(tail)-1]
	if len(withoutFinalNewline) == 0 || withoutFinalNewline[len(withoutFinalNewline)-1] == '\n' {
		return nil, safeError(CodeTailMalformed)
	}
	start := bytes.LastIndexByte(withoutFinalNewline, '\n') + 1
	line := withoutFinalNewline[start:]
	if len(line) == 0 || len(line) > maxEventBytes {
		return nil, safeError(CodeTailTooLarge)
	}
	if !bytes.Equal(bytes.TrimSpace(line), line) {
		return nil, safeError(CodeTailMalformed)
	}
	return line, nil
}

type rawRolloutEnvelope struct {
	Timestamp string          `json:"timestamp"`
	Ordinal   *uint64         `json:"ordinal,omitempty"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
}

type rawTaskComplete struct {
	Type               string          `json:"type"`
	TurnID             string          `json:"turn_id"`
	LastAgentMessage   json.RawMessage `json:"last_agent_message"`
	Error              json.RawMessage `json:"error,omitempty"`
	StartedAt          json.RawMessage `json:"started_at,omitempty"`
	CompletedAt        json.RawMessage `json:"completed_at,omitempty"`
	DurationMS         json.RawMessage `json:"duration_ms,omitempty"`
	TimeToFirstTokenMS json.RawMessage `json:"time_to_first_token_ms,omitempty"`
}

func parseCompletionEnvelope(line []byte) (TailSnapshot, error) {
	var envelope rawRolloutEnvelope
	if err := decodeStrictJSON(line, &envelope); err != nil {
		return TailSnapshot{}, safeWrap(CodeTailMalformed, err)
	}
	if len(envelope.Timestamp) != len("2006-01-02T15:04:05.000Z") ||
		len(envelope.Payload) == 0 {
		return TailSnapshot{}, safeError(CodeTailMalformed)
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000Z", envelope.Timestamp); err != nil {
		return TailSnapshot{}, safeError(CodeTailMalformed)
	}
	if envelope.Type != "event_msg" {
		return TailSnapshot{}, safeError(CodeTerminalUnknown)
	}
	var payload rawTaskComplete
	if err := decodeStrictJSON(envelope.Payload, &payload); err != nil {
		return TailSnapshot{}, safeWrap(CodeTailMalformed, err)
	}
	if payload.Type != "task_complete" {
		return TailSnapshot{}, safeError(CodeTerminalUnknown)
	}
	if payload.TurnID == "" || !validOptionalMessage(payload.LastAgentMessage) {
		return TailSnapshot{}, safeError(CodeTailMalformed)
	}
	// A successful persisted TurnComplete omits error entirely because the
	// upstream field uses skip_serializing_if. An explicit null is not the exact
	// output grammar and is rejected rather than normalized.
	if len(payload.Error) != 0 {
		return TailSnapshot{}, safeError(CodeTerminalFailed)
	}
	startedAt, startedOK := optionalNonNegativeInt(payload.StartedAt)
	completedAt, completedOK := optionalNonNegativeInt(payload.CompletedAt)
	_, durationOK := optionalNonNegativeInt(payload.DurationMS)
	_, firstTokenOK := optionalNonNegativeInt(payload.TimeToFirstTokenMS)
	if !startedOK || !completedOK || !durationOK || !firstTokenOK {
		return TailSnapshot{}, safeError(CodeTailMalformed)
	}
	if startedAt != nil && completedAt != nil && *completedAt < *startedAt {
		return TailSnapshot{}, safeError(CodeTailMalformed)
	}
	return TailSnapshot{
		Availability: model.AvailabilityAvailable,
		EnvelopeType: "event_msg",
		EventType:    "task_complete",
		Successful:   true,
	}, nil
}

func decodeStrictJSON(data []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	return nil
}

func validOptionalMessage(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	if bytes.Equal(raw, []byte("null")) {
		return true
	}
	return raw[0] == '"' && raw[len(raw)-1] == '"' && json.Valid(raw)
}

func optionalNonNegativeInt(raw json.RawMessage) (*int64, bool) {
	if len(raw) == 0 {
		return nil, true
	}
	if bytes.Equal(raw, []byte("null")) {
		return nil, false
	}
	var value int64
	if err := decodeStrictJSON(raw, &value); err != nil || value < 0 {
		return nil, false
	}
	return &value, true
}

func contextCode(err error) error {
	if err == context.DeadlineExceeded {
		return safeWrap(CodeReadTimeout, err)
	}
	return safeWrap(CodeContextCancelled, err)
}
