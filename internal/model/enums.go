package model

import (
	"encoding/json"
	"fmt"
)

// Availability records the result of a probe. Missing evidence is data and must
// never be inferred to mean available.
type Availability string

const (
	AvailabilityAvailable           Availability = "available"
	AvailabilityNotApplicable       Availability = "not_applicable"
	AvailabilityPermissionDenied    Availability = "permission_denied"
	AvailabilityUnsupportedPlatform Availability = "unsupported_platform"
	AvailabilityUnsupportedVersion  Availability = "unsupported_version"
	AvailabilityProcessExited       Availability = "process_exited"
	AvailabilityTimeout             Availability = "timeout"
	AvailabilityMalformedOutput     Availability = "malformed_output"
	AvailabilitySchemaIncompatible  Availability = "schema_incompatible"
	AvailabilityContradictory       Availability = "contradictory"
)

var availabilityValues = enumSet(
	AvailabilityAvailable,
	AvailabilityNotApplicable,
	AvailabilityPermissionDenied,
	AvailabilityUnsupportedPlatform,
	AvailabilityUnsupportedVersion,
	AvailabilityProcessExited,
	AvailabilityTimeout,
	AvailabilityMalformedOutput,
	AvailabilitySchemaIncompatible,
	AvailabilityContradictory,
)

func (v Availability) Valid() bool { return availabilityValues[v] }
func (v Availability) MarshalJSON() ([]byte, error) {
	return marshalEnum("availability", v, v.Valid())
}
func (v *Availability) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "availability", v, availabilityValues)
}

// Classification is a workflow observation state. Only
// ClassificationSupportedStaleCandidate may be passed to an action gate.
type Classification string

const (
	ClassificationProtected               Classification = "protected"
	ClassificationRecentlyActive          Classification = "recently_active"
	ClassificationQuietUnclassified       Classification = "quiet_unclassified"
	ClassificationUnknown                 Classification = "unknown"
	ClassificationSupportedStaleCandidate Classification = "supported_stale_candidate"
)

var classificationValues = enumSet(
	ClassificationProtected,
	ClassificationRecentlyActive,
	ClassificationQuietUnclassified,
	ClassificationUnknown,
	ClassificationSupportedStaleCandidate,
)

func (v Classification) Valid() bool { return classificationValues[v] }
func (v Classification) MarshalJSON() ([]byte, error) {
	return marshalEnum("classification", v, v.Valid())
}
func (v *Classification) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "classification", v, classificationValues)
}

// EvidenceCode is a normalized, privacy-safe fact. Raw command output, paths,
// stack text, and errors are deliberately not evidence codes.
type EvidenceCode string

const (
	EvidenceExecutableFamily       EvidenceCode = "executable_family"
	EvidenceCWDWorktree            EvidenceCode = "cwd_worktree"
	EvidenceTTYOwner               EvidenceCode = "tty_owner"
	EvidenceKnownParentGrammar     EvidenceCode = "known_parent_grammar"
	EvidenceCurrentUIDOnly         EvidenceCode = "current_uid_only"
	EvidenceCurrentProcess         EvidenceCode = "current_process"
	EvidenceAncestor               EvidenceCode = "ancestor"
	EvidenceCMUXOwner              EvidenceCode = "cmux_owner"
	EvidenceEditorOwner            EvidenceCode = "editor_owner"
	EvidenceDatabaseProcess        EvidenceCode = "database_process"
	EvidenceSyncProcess            EvidenceCode = "sync_process"
	EvidenceVPNProcess             EvidenceCode = "vpn_process"
	EvidenceSecurityProcess        EvidenceCode = "security_process"
	EvidenceUserAllowlist          EvidenceCode = "user_allowlist"
	EvidenceIncompleteOwnership    EvidenceCode = "incomplete_ownership"
	EvidenceContradictoryOwnership EvidenceCode = "contradictory_ownership"
	EvidenceControllingTTY         EvidenceCode = "controlling_tty"
	EvidenceOriginExact            EvidenceCode = "origin_exact"
	EvidenceVersionExact           EvidenceCode = "version_exact"
	EvidenceArgvExact              EvidenceCode = "argv_exact"
	EvidenceParentExact            EvidenceCode = "parent_exact"
	EvidenceRolloutComplete        EvidenceCode = "rollout_complete"
	EvidenceRolloutUnchanged       EvidenceCode = "rollout_unchanged"
	EvidenceCPUIncreasing          EvidenceCode = "cpu_increasing"
	EvidenceSupportedReadStack     EvidenceCode = "supported_read_stack"
	EvidenceNoTTY                  EvidenceCode = "no_tty"
	EvidenceNoListener             EvidenceCode = "no_listener"
	EvidenceNoEstablishedSocket    EvidenceCode = "no_established_socket"
	EvidenceNoWritableOutput       EvidenceCode = "no_writable_output"
	EvidenceChildless              EvidenceCode = "childless"
	EvidencePIDReused              EvidenceCode = "pid_reused"
	EvidenceExecChanged            EvidenceCode = "exec_changed"
	EvidenceTailTruncated          EvidenceCode = "tail_truncated"
	EvidenceUnknownTerminalEvent   EvidenceCode = "unknown_terminal_event"
	EvidenceStackChanged           EvidenceCode = "stack_changed"
	EvidenceSocketPresent          EvidenceCode = "socket_present"
	EvidenceTTYPresent             EvidenceCode = "tty_present"
	EvidenceDescriptorMismatch     EvidenceCode = "descriptor_mismatch"
	EvidenceRootlessCycle          EvidenceCode = "rootless_cycle"
	EvidenceOrphanedParent         EvidenceCode = "orphaned_parent"
)

var evidenceCodeValues = enumSet(
	EvidenceExecutableFamily,
	EvidenceCWDWorktree,
	EvidenceTTYOwner,
	EvidenceKnownParentGrammar,
	EvidenceCurrentUIDOnly,
	EvidenceCurrentProcess,
	EvidenceAncestor,
	EvidenceCMUXOwner,
	EvidenceEditorOwner,
	EvidenceDatabaseProcess,
	EvidenceSyncProcess,
	EvidenceVPNProcess,
	EvidenceSecurityProcess,
	EvidenceUserAllowlist,
	EvidenceIncompleteOwnership,
	EvidenceContradictoryOwnership,
	EvidenceControllingTTY,
	EvidenceOriginExact,
	EvidenceVersionExact,
	EvidenceArgvExact,
	EvidenceParentExact,
	EvidenceRolloutComplete,
	EvidenceRolloutUnchanged,
	EvidenceCPUIncreasing,
	EvidenceSupportedReadStack,
	EvidenceNoTTY,
	EvidenceNoListener,
	EvidenceNoEstablishedSocket,
	EvidenceNoWritableOutput,
	EvidenceChildless,
	EvidencePIDReused,
	EvidenceExecChanged,
	EvidenceTailTruncated,
	EvidenceUnknownTerminalEvent,
	EvidenceStackChanged,
	EvidenceSocketPresent,
	EvidenceTTYPresent,
	EvidenceDescriptorMismatch,
	EvidenceRootlessCycle,
	EvidenceOrphanedParent,
)

func (v EvidenceCode) Valid() bool { return evidenceCodeValues[v] }
func (v EvidenceCode) MarshalJSON() ([]byte, error) {
	return marshalEnum("evidence code", v, v.Valid())
}
func (v *EvidenceCode) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "evidence code", v, evidenceCodeValues)
}

// Outcome is a durable recovery outcome. Prepared is an intent state, not a
// claim that a signal was sent.
type Outcome string

const (
	OutcomePrepared  Outcome = "prepared"
	OutcomeVerified  Outcome = "verified"
	OutcomePartial   Outcome = "partial"
	OutcomeRefused   Outcome = "refused"
	OutcomeFailed    Outcome = "failed"
	OutcomeCancelled Outcome = "cancelled"
)

var outcomeValues = enumSet(
	OutcomePrepared,
	OutcomeVerified,
	OutcomePartial,
	OutcomeRefused,
	OutcomeFailed,
	OutcomeCancelled,
)

func (v Outcome) Valid() bool                  { return outcomeValues[v] }
func (v Outcome) MarshalJSON() ([]byte, error) { return marshalEnum("outcome", v, v.Valid()) }
func (v *Outcome) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "outcome", v, outcomeValues)
}

type WorkflowFamily string

const (
	WorkflowFamilyUnclassified       WorkflowFamily = "unclassified"
	WorkflowFamilyCodex              WorkflowFamily = "codex"
	WorkflowFamilyClaude             WorkflowFamily = "claude"
	WorkflowFamilyMCP                WorkflowFamily = "mcp"
	WorkflowFamilyNodeDev            WorkflowFamily = "node_dev"
	WorkflowFamilyPlaywrightChromium WorkflowFamily = "playwright_chromium"
	WorkflowFamilyDockerVM           WorkflowFamily = "docker_vm"
	WorkflowFamilyBrowser            WorkflowFamily = "browser"
	WorkflowFamilyLocalDatabase      WorkflowFamily = "local_database"
	WorkflowFamilyOther              WorkflowFamily = "other"
)

var workflowFamilyValues = enumSet(
	WorkflowFamilyUnclassified,
	WorkflowFamilyCodex,
	WorkflowFamilyClaude,
	WorkflowFamilyMCP,
	WorkflowFamilyNodeDev,
	WorkflowFamilyPlaywrightChromium,
	WorkflowFamilyDockerVM,
	WorkflowFamilyBrowser,
	WorkflowFamilyLocalDatabase,
	WorkflowFamilyOther,
)

func (v WorkflowFamily) Valid() bool { return workflowFamilyValues[v] }
func (v WorkflowFamily) MarshalJSON() ([]byte, error) {
	return marshalEnum("workflow family", v, v.Valid())
}
func (v *WorkflowFamily) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "workflow family", v, workflowFamilyValues)
}

type ProbeKind string

const (
	ProbeIdentity    ProbeKind = "identity"
	ProbeExecutable  ProbeKind = "executable"
	ProbeCWD         ProbeKind = "cwd"
	ProbeTTY         ProbeKind = "tty"
	ProbeSockets     ProbeKind = "sockets"
	ProbeDescriptors ProbeKind = "descriptors"
	ProbeStack       ProbeKind = "stack"
	ProbeMetadata    ProbeKind = "metadata"
	ProbeRolloutTail ProbeKind = "rollout_tail"
	ProbeOrigin      ProbeKind = "origin"
)

var probeKindValues = enumSet(
	ProbeIdentity,
	ProbeExecutable,
	ProbeCWD,
	ProbeTTY,
	ProbeSockets,
	ProbeDescriptors,
	ProbeStack,
	ProbeMetadata,
	ProbeRolloutTail,
	ProbeOrigin,
)

func (v ProbeKind) Valid() bool                  { return probeKindValues[v] }
func (v ProbeKind) MarshalJSON() ([]byte, error) { return marshalEnum("probe kind", v, v.Valid()) }
func (v *ProbeKind) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "probe kind", v, probeKindValues)
}

type SupportState string

const (
	SupportSupported   SupportState = "supported"
	SupportUnsupported SupportState = "unsupported"
	SupportUnavailable SupportState = "unavailable"
	SupportUnknown     SupportState = "unknown"
)

var supportStateValues = enumSet(SupportSupported, SupportUnsupported, SupportUnavailable, SupportUnknown)

func (v SupportState) Valid() bool { return supportStateValues[v] }
func (v SupportState) MarshalJSON() ([]byte, error) {
	return marshalEnum("support state", v, v.Valid())
}
func (v *SupportState) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "support state", v, supportStateValues)
}

type PressureLevel string

const (
	PressureUnknown  PressureLevel = "unknown"
	PressureNominal  PressureLevel = "nominal"
	PressureElevated PressureLevel = "elevated"
	PressureCritical PressureLevel = "critical"
)

var pressureLevelValues = enumSet(PressureUnknown, PressureNominal, PressureElevated, PressureCritical)

func (v PressureLevel) Valid() bool { return pressureLevelValues[v] }
func (v PressureLevel) MarshalJSON() ([]byte, error) {
	return marshalEnum("pressure level", v, v.Valid())
}
func (v *PressureLevel) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "pressure level", v, pressureLevelValues)
}

type DurationBucket string

const (
	DurationUnknown DurationBucket = "unknown"
	DurationUnder1s DurationBucket = "under_1s"
	Duration1To5s   DurationBucket = "1_5s"
	Duration5To10s  DurationBucket = "5_10s"
	Duration10To30s DurationBucket = "10_30s"
	Duration30sPlus DurationBucket = "30s_plus"
)

var durationBucketValues = enumSet(DurationUnknown, DurationUnder1s, Duration1To5s, Duration5To10s, Duration10To30s, Duration30sPlus)

func (v DurationBucket) Valid() bool { return durationBucketValues[v] }
func (v DurationBucket) MarshalJSON() ([]byte, error) {
	return marshalEnum("duration bucket", v, v.Valid())
}
func (v *DurationBucket) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "duration bucket", v, durationBucketValues)
}

type CPUTimeBucket string

const (
	CPUTimeUnknown CPUTimeBucket = "unknown"
	CPUTimeZero    CPUTimeBucket = "zero"
	CPUTimeUnder1s CPUTimeBucket = "under_1s"
	CPUTime1To10s  CPUTimeBucket = "1_10s"
	CPUTime10To60s CPUTimeBucket = "10_60s"
	CPUTime1To10m  CPUTimeBucket = "1_10m"
	CPUTime10mPlus CPUTimeBucket = "10m_plus"
)

var cpuTimeBucketValues = enumSet(CPUTimeUnknown, CPUTimeZero, CPUTimeUnder1s, CPUTime1To10s, CPUTime10To60s, CPUTime1To10m, CPUTime10mPlus)

func (v CPUTimeBucket) Valid() bool { return cpuTimeBucketValues[v] }
func (v CPUTimeBucket) MarshalJSON() ([]byte, error) {
	return marshalEnum("cpu time bucket", v, v.Valid())
}
func (v *CPUTimeBucket) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "cpu time bucket", v, cpuTimeBucketValues)
}

type SizeBucket string

const (
	SizeUnknown    SizeBucket = "unknown"
	SizeZero       SizeBucket = "zero"
	SizeUnder100MB SizeBucket = "under_100mb"
	Size100To500MB SizeBucket = "100_500mb"
	Size500MBTo1GB SizeBucket = "500mb_1gb"
	Size1To5GB     SizeBucket = "1_5gb"
	Size5GBPlus    SizeBucket = "5gb_plus"
)

var sizeBucketValues = enumSet(SizeUnknown, SizeZero, SizeUnder100MB, Size100To500MB, Size500MBTo1GB, Size1To5GB, Size5GBPlus)

func (v SizeBucket) Valid() bool { return sizeBucketValues[v] }
func (v SizeBucket) MarshalJSON() ([]byte, error) {
	return marshalEnum("size bucket", v, v.Valid())
}
func (v *SizeBucket) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "size bucket", v, sizeBucketValues)
}

type ErrorCode string

const (
	ErrorNone                 ErrorCode = "none"
	ErrorIdentityChanged      ErrorCode = "identity_changed"
	ErrorEvidenceChanged      ErrorCode = "evidence_changed"
	ErrorProtectedTarget      ErrorCode = "protected_target"
	ErrorCandidateUnavailable ErrorCode = "candidate_unavailable"
	ErrorConfirmationMismatch ErrorCode = "confirmation_mismatch"
	ErrorSignalFailed         ErrorCode = "signal_failed"
	ErrorVerificationFailed   ErrorCode = "verification_failed"
	ErrorReceiptStoreFailed   ErrorCode = "receipt_store_failed"
	ErrorInternal             ErrorCode = "internal"
)

var errorCodeValues = enumSet(
	ErrorNone,
	ErrorIdentityChanged,
	ErrorEvidenceChanged,
	ErrorProtectedTarget,
	ErrorCandidateUnavailable,
	ErrorConfirmationMismatch,
	ErrorSignalFailed,
	ErrorVerificationFailed,
	ErrorReceiptStoreFailed,
	ErrorInternal,
)

func (v ErrorCode) Valid() bool                  { return errorCodeValues[v] }
func (v ErrorCode) MarshalJSON() ([]byte, error) { return marshalEnum("error code", v, v.Valid()) }
func (v *ErrorCode) UnmarshalJSON(data []byte) error {
	return unmarshalEnum(data, "error code", v, errorCodeValues)
}

func enumSet[T comparable](values ...T) map[T]bool {
	set := make(map[T]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func marshalEnum[T ~string](name string, value T, valid bool) ([]byte, error) {
	if !valid {
		return nil, fmt.Errorf("model: invalid %s %q", name, value)
	}
	return json.Marshal(string(value))
}

func unmarshalEnum[T ~string](data []byte, name string, dst *T, valid map[T]bool) error {
	if dst == nil {
		return fmt.Errorf("model: nil %s destination", name)
	}
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("model: decode %s: %w", name, err)
	}
	value := T(raw)
	if !valid[value] {
		return fmt.Errorf("model: invalid %s %q", name, raw)
	}
	*dst = value
	return nil
}
