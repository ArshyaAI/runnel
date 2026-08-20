package model

import (
	"fmt"
	"regexp"
	"time"
)

const (
	PreparedReceiptSchemaVersion = "runnel.prepared-receipt/v1"
	ResultReceiptSchemaVersion   = "runnel.result-receipt/v1"
	ShareReceiptSchemaVersion    = "runnel.share-receipt/v1"
	CodexV1DetectorID            = "codex-chatgpt-trusted-worker/v1"
)

var sha256HexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type DetectorEvidence struct {
	Availability []ProbeAvailability `json:"availability"`
	Codes        []EvidenceCode      `json:"codes"`
}

func (e DetectorEvidence) Validate() error {
	if e.Availability == nil || e.Codes == nil {
		return fmt.Errorf("model: detector evidence fields must be non-nil")
	}
	if !sortedUniqueAvailability(e.Availability) || !sortedUniqueEvidence(e.Codes) {
		return fmt.Errorf("model: detector evidence must be sorted and unique")
	}
	for i, availability := range e.Availability {
		if err := availability.Validate(); err != nil {
			return fmt.Errorf("availability[%d]: %w", i, err)
		}
	}
	return nil
}

// ActionCandidate is the separate action-grade object. Scanner observations
// cannot be converted into it without the detector supplying a complete Darwin
// identity and a fully passing supported classification.
type ActionCandidate struct {
	DetectorID     string               `json:"detector_id"`
	Classification Classification       `json:"classification"`
	Target         DarwinActionIdentity `json:"target"`
	Evidence       DetectorEvidence     `json:"evidence"`
}

func (c ActionCandidate) Validate() error {
	if c.DetectorID != CodexV1DetectorID {
		return fmt.Errorf("model: unsupported detector %q", c.DetectorID)
	}
	if c.Classification != ClassificationSupportedStaleCandidate {
		return fmt.Errorf("model: action candidate requires supported stale classification")
	}
	if err := c.Target.Validate(); err != nil {
		return fmt.Errorf("target: %w", err)
	}
	if err := c.Evidence.Validate(); err != nil {
		return fmt.Errorf("evidence: %w", err)
	}
	for _, availability := range c.Evidence.Availability {
		if availability.Status != AvailabilityAvailable && availability.Status != AvailabilityNotApplicable {
			return fmt.Errorf("model: action candidate contains unavailable evidence")
		}
	}
	return nil
}

type LocalPreparedReceipt struct {
	SchemaVersion string                 `json:"schema_version"`
	ToolVersion   string                 `json:"tool_version"`
	ReceiptID     string                 `json:"receipt_id"`
	PreparedAt    time.Time              `json:"prepared_at"`
	DetectorID    string                 `json:"detector_id"`
	Target        DarwinActionIdentity   `json:"target"`
	Protected     []DarwinActionIdentity `json:"protected"`
	Evidence      DetectorEvidence       `json:"evidence"`
	// ConfirmationBinding is SHA-256(domain || receipt_id || token). The
	// displayed confirmation token is never persisted.
	ConfirmationBinding string  `json:"confirmation_binding"`
	ConfirmationOK      bool    `json:"confirmation_ok"`
	Outcome             Outcome `json:"outcome"`
}

func (r LocalPreparedReceipt) Validate() error {
	if r.SchemaVersion != PreparedReceiptSchemaVersion || r.ToolVersion == "" || r.ReceiptID == "" {
		return fmt.Errorf("model: invalid prepared receipt header")
	}
	if r.PreparedAt.IsZero() || r.PreparedAt.Location() != time.UTC {
		return fmt.Errorf("model: prepared_at must be a non-zero UTC time")
	}
	if r.DetectorID != CodexV1DetectorID || r.Outcome != OutcomePrepared {
		return fmt.Errorf("model: invalid prepared receipt detector or outcome")
	}
	if !sha256HexPattern.MatchString(r.ConfirmationBinding) {
		return fmt.Errorf("model: confirmation binding must be a lowercase SHA-256 digest")
	}
	if err := r.Target.Validate(); err != nil {
		return fmt.Errorf("target: %w", err)
	}
	if r.Protected == nil {
		return fmt.Errorf("model: protected must be non-nil")
	}
	for i, protected := range r.Protected {
		if err := protected.Validate(); err != nil {
			return fmt.Errorf("protected[%d]: %w", i, err)
		}
		if i > 0 && compareDarwinIdentity(r.Protected[i-1], protected) >= 0 {
			return fmt.Errorf("model: protected identities must be strictly sorted")
		}
		if r.Target.Equal(protected) {
			return fmt.Errorf("model: target cannot be protected")
		}
	}
	return r.Evidence.Validate()
}

type SignalAttempt struct {
	Target    DarwinActionIdentity `json:"target"`
	Attempted bool                 `json:"attempted"`
	ErrorCode ErrorCode            `json:"error_code"`
}

type LocalResultReceipt struct {
	SchemaVersion string `json:"schema_version"`
	ToolVersion   string `json:"tool_version"`
	ReceiptID     string `json:"receipt_id"`
	// PreparedDigest binds the result to the exact immutable prepared bytes.
	PreparedDigest       string           `json:"prepared_digest"`
	FinalizedAt          time.Time        `json:"finalized_at"`
	Outcome              Outcome          `json:"outcome"`
	ConfirmationOK       bool             `json:"confirmation_ok"`
	Revalidation         DetectorEvidence `json:"revalidation"`
	SignalAttempts       []SignalAttempt  `json:"signal_attempts"`
	TargetExitCount      uint32           `json:"target_exit_count"`
	ProtectedSignaled    uint32           `json:"protected_signaled_count"`
	ProtectedPresent     uint32           `json:"protected_present_count"`
	SelectedRSSBytes     uint64           `json:"selected_rss_bytes"`
	MemoryPressureBefore PressureLevel    `json:"memory_pressure_before"`
	MemoryPressureAfter  PressureLevel    `json:"memory_pressure_after"`
	ErrorCodes           []ErrorCode      `json:"error_codes"`
}

func (r LocalResultReceipt) Validate() error {
	if r.SchemaVersion != ResultReceiptSchemaVersion || r.ToolVersion == "" || r.ReceiptID == "" {
		return fmt.Errorf("model: invalid result receipt header")
	}
	if !sha256HexPattern.MatchString(r.PreparedDigest) {
		return fmt.Errorf("model: prepared digest must be a lowercase SHA-256 digest")
	}
	if r.FinalizedAt.IsZero() || r.FinalizedAt.Location() != time.UTC {
		return fmt.Errorf("model: finalized_at must be a non-zero UTC time")
	}
	if !r.Outcome.Valid() || r.Outcome == OutcomePrepared {
		return fmt.Errorf("model: invalid final outcome")
	}
	if err := r.Revalidation.Validate(); err != nil {
		return fmt.Errorf("revalidation: %w", err)
	}
	if r.SignalAttempts == nil || r.ErrorCodes == nil {
		return fmt.Errorf("model: repeated fields must be non-nil")
	}
	for i, attempt := range r.SignalAttempts {
		if err := attempt.Target.Validate(); err != nil {
			return fmt.Errorf("signal_attempts[%d]: %w", i, err)
		}
		if !attempt.ErrorCode.Valid() {
			return fmt.Errorf("signal_attempts[%d]: invalid error code", i)
		}
		if i > 0 && compareDarwinIdentity(r.SignalAttempts[i-1].Target, attempt.Target) >= 0 {
			return fmt.Errorf("model: signal attempts must be strictly sorted")
		}
	}
	if !sortedUniqueErrorCodes(r.ErrorCodes) {
		return fmt.Errorf("model: error codes must be sorted and unique")
	}
	if !r.MemoryPressureBefore.Valid() || !r.MemoryPressureAfter.Valid() {
		return fmt.Errorf("model: invalid pressure level")
	}
	if r.Outcome == OutcomeVerified && (r.ProtectedSignaled != 0 || r.TargetExitCount != uint32(len(r.SignalAttempts))) {
		return fmt.Errorf("model: verified outcome does not reconcile")
	}
	if r.Outcome == OutcomeRefused && anyAttempted(r.SignalAttempts) {
		return fmt.Errorf("model: refused outcome cannot contain a signal attempt")
	}
	if (r.Outcome == OutcomeVerified || r.Outcome == OutcomePartial) && !r.ConfirmationOK {
		return fmt.Errorf("model: post-signal outcome requires confirmed token")
	}
	return nil
}

// ShareReceipt has only aggregate, enumerated data and is not derived by
// redacting either private receipt type.
type ShareReceipt struct {
	SchemaVersion        string              `json:"schema_version"`
	ToolVersion          string              `json:"tool_version"`
	Platform             Platform            `json:"platform"`
	DetectorID           string              `json:"detector_id"`
	SupportState         SupportState        `json:"support_state"`
	Availability         []ProbeAvailability `json:"availability"`
	Evidence             []EvidenceCode      `json:"evidence"`
	TargetCount          uint32              `json:"target_count"`
	DurationBucket       DurationBucket      `json:"duration_bucket"`
	SelectedRSSBytes     uint64              `json:"selected_rss_bytes"`
	TargetExitCount      uint32              `json:"target_exit_count"`
	ProtectedSignaled    uint32              `json:"protected_signaled_count"`
	ProtectedPresent     uint32              `json:"protected_present_count"`
	MemoryPressureBefore PressureLevel       `json:"memory_pressure_before"`
	MemoryPressureAfter  PressureLevel       `json:"memory_pressure_after"`
	Outcome              Outcome             `json:"outcome"`
	ErrorCodes           []ErrorCode         `json:"error_codes"`
}

func (r ShareReceipt) Validate() error {
	if r.SchemaVersion != ShareReceiptSchemaVersion || r.ToolVersion == "" {
		return fmt.Errorf("model: invalid share receipt header")
	}
	if err := r.Platform.Validate(); err != nil {
		return err
	}
	if r.DetectorID != CodexV1DetectorID || !r.SupportState.Valid() || !r.Outcome.Valid() {
		return fmt.Errorf("model: invalid share receipt enums")
	}
	if !r.DurationBucket.Valid() || r.Availability == nil || r.Evidence == nil || r.ErrorCodes == nil {
		return fmt.Errorf("model: share receipt fields must be non-empty/non-nil")
	}
	if !sortedUniqueAvailability(r.Availability) || !sortedUniqueEvidence(r.Evidence) || !sortedUniqueErrorCodes(r.ErrorCodes) {
		return fmt.Errorf("model: share receipt arrays must be sorted and unique")
	}
	for i, availability := range r.Availability {
		if err := availability.Validate(); err != nil {
			return fmt.Errorf("availability[%d]: %w", i, err)
		}
	}
	if !r.MemoryPressureBefore.Valid() || !r.MemoryPressureAfter.Valid() {
		return fmt.Errorf("model: invalid pressure level")
	}
	if r.Outcome == OutcomeVerified && (r.ProtectedSignaled != 0 || r.TargetExitCount != r.TargetCount) {
		return fmt.Errorf("model: verified share receipt does not reconcile")
	}
	if r.Outcome == OutcomeRefused && (r.TargetExitCount != 0 || r.ProtectedSignaled != 0) {
		return fmt.Errorf("model: refused share receipt contains action effects")
	}
	return nil
}

func compareDarwinIdentity(a, b DarwinActionIdentity) int {
	if c := compareIdentity(a.ProcessIdentity, b.ProcessIdentity); c != 0 {
		return c
	}
	if a.PIDVersion != b.PIDVersion {
		if a.PIDVersion < b.PIDVersion {
			return -1
		}
		return 1
	}
	if a.UniqueID != b.UniqueID {
		if a.UniqueID < b.UniqueID {
			return -1
		}
		return 1
	}
	return 0
}

func sortedUniqueErrorCodes(values []ErrorCode) bool {
	for i, value := range values {
		if !value.Valid() {
			return false
		}
		if i > 0 && string(values[i-1]) >= string(value) {
			return false
		}
	}
	return true
}

func anyAttempted(attempts []SignalAttempt) bool {
	for _, attempt := range attempts {
		if attempt.Attempted {
			return true
		}
	}
	return false
}
