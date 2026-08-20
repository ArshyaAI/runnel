package codex

import (
	"slices"
)

// Code is a deterministic, privacy-safe detector or adapter fact. It must
// never contain a path, argv value, thread identifier, raw error, or stack.
type Code string

const (
	CodeAdapterExact         Code = "adapter_exact"
	CodeIdentityStable       Code = "identity_stable"
	CodeParentIdentityStable Code = "parent_identity_stable"
	CodeUIDExact             Code = "uid_exact"
	CodeOriginExact          Code = "origin_exact"
	CodeVersionExact         Code = "version_exact"
	CodeArgvExact            Code = "argv_exact"
	CodeParentExact          Code = "parent_exact"
	CodeMetadataComplete     Code = "metadata_complete"
	CodeRolloutComplete      Code = "rollout_complete"
	CodeRolloutUnchanged     Code = "rollout_unchanged"
	CodeDescriptorExact      Code = "descriptor_exact"
	CodeCPUIncreasing        Code = "cpu_increasing"
	CodeStackSupported       Code = "stack_supported"
	CodeNoTTY                Code = "no_tty"
	CodeNoListener           Code = "no_listener"
	CodeNoEstablishedSocket  Code = "no_established_socket"
	CodeNoWritableOutput     Code = "no_writable_output"
	CodeChildless            Code = "childless"
	CodeNoProtectedIdentity  Code = "no_protected_identity"
	CodeActionRecheckExact   Code = "action_recheck_exact"

	CodeSampleCountInvalid       Code = "sample_count_invalid"
	CodeSampleOffsetInvalid      Code = "sample_offset_invalid"
	CodeIdentityUnavailable      Code = "identity_unavailable"
	CodeIdentityChanged          Code = "identity_changed"
	CodePIDReused                Code = "pid_reused"
	CodeExecChanged              Code = "exec_changed"
	CodeParentUnavailable        Code = "parent_unavailable"
	CodeParentChanged            Code = "parent_changed"
	CodeUIDMismatch              Code = "uid_mismatch"
	CodeOriginUnavailable        Code = "origin_unavailable"
	CodeOriginContradictory      Code = "origin_contradictory"
	CodeOriginMismatch           Code = "origin_mismatch"
	CodeVersionMismatch          Code = "version_mismatch"
	CodeArgvMismatch             Code = "argv_mismatch"
	CodeParentMismatch           Code = "parent_mismatch"
	CodeMetadataUnavailable      Code = "metadata_unavailable"
	CodeSchemaIncompatible       Code = "schema_incompatible"
	CodeMetadataValueInvalid     Code = "metadata_value_incompatible"
	CodeMetadataContradictory    Code = "metadata_contradictory"
	CodeMetadataUnstable         Code = "metadata_unstable"
	CodeMetadataChanged          Code = "metadata_changed"
	CodeTailUnavailable          Code = "tail_unavailable"
	CodeTailTruncated            Code = "tail_truncated"
	CodeTailTooLarge             Code = "tail_too_large"
	CodeTailMalformed            Code = "tail_malformed"
	CodeTerminalUnknown          Code = "terminal_event_unknown"
	CodeTerminalFailed           Code = "terminal_event_failed"
	CodeTailChanged              Code = "tail_changed"
	CodeFileChanged              Code = "rollout_file_changed"
	CodeDescriptorUnavailable    Code = "descriptor_unavailable"
	CodeDescriptorMismatch       Code = "descriptor_mismatch"
	CodeDescriptorWritable       Code = "descriptor_writable"
	CodeCPUNotIncreasing         Code = "cpu_not_increasing"
	CodeStackUnavailable         Code = "stack_unavailable"
	CodeStackMismatch            Code = "stack_mismatch"
	CodeStackChanged             Code = "stack_changed"
	CodeTTYUnavailable           Code = "tty_unavailable"
	CodeTTYPresent               Code = "tty_present"
	CodeSocketUnavailable        Code = "socket_unavailable"
	CodeListenerPresent          Code = "listener_present"
	CodeEstablishedSocket        Code = "established_socket_present"
	CodeWritableProbeUnavailable Code = "writable_activity_unavailable"
	CodeWritableActivity         Code = "writable_activity_present"
	CodeChildrenUnavailable      Code = "children_unavailable"
	CodeNewChild                 Code = "new_child_present"
	CodeProtectedIdentity        Code = "protected_identity_present"
	CodeContradictory            Code = "contradictory"
	CodeContextCancelled         Code = "context_cancelled"
	CodeReadTimeout              Code = "read_timeout"
)

func normalizeCodes(values []Code) []Code {
	if len(values) == 0 {
		return []Code{}
	}
	result := append([]Code(nil), values...)
	slices.Sort(result)
	result = slices.Compact(result)
	return result
}
