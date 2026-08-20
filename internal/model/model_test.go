package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

var testTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func TestEnumRoundTripAndRejectUnknown(t *testing.T) {
	tests := []struct {
		name  string
		value any
		fresh func() any
	}{
		{"availability", AvailabilityAvailable, func() any { return new(Availability) }},
		{"classification", ClassificationProtected, func() any { return new(Classification) }},
		{"evidence", EvidenceAncestor, func() any { return new(EvidenceCode) }},
		{"outcome", OutcomeVerified, func() any { return new(Outcome) }},
		{"family", WorkflowFamilyCodex, func() any { return new(WorkflowFamily) }},
		{"probe", ProbeIdentity, func() any { return new(ProbeKind) }},
		{"support", SupportSupported, func() any { return new(SupportState) }},
		{"pressure", PressureNominal, func() any { return new(PressureLevel) }},
		{"error", ErrorNone, func() any { return new(ErrorCode) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.value)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			dst := tt.fresh()
			if err := json.Unmarshal(data, dst); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if got := reflect.ValueOf(dst).Elem().Interface(); got != tt.value {
				t.Fatalf("round trip = %v, want %v", got, tt.value)
			}
			if err := json.Unmarshal([]byte(`"future_value"`), dst); err == nil {
				t.Fatal("unknown enum accepted")
			}
			if err := json.Unmarshal([]byte(`null`), dst); err == nil {
				t.Fatal("null enum accepted")
			}
		})
	}
	if _, err := json.Marshal(Availability("future_value")); err == nil {
		t.Fatal("invalid availability marshaled")
	}
}

func TestProcessAndDarwinIdentityCompleteness(t *testing.T) {
	partial := ProcessIdentity{PID: 12, UID: 501}
	if err := partial.Validate(); err != nil {
		t.Fatalf("partial observation identity should validate: %v", err)
	}
	if partial.Complete() {
		t.Fatal("partial identity reported complete")
	}
	complete := ProcessIdentity{PID: 12, StartTime: testTime, UID: 501, Executable: "/synthetic/bin/tool"}
	if !complete.Complete() || !complete.Equal(complete) {
		t.Fatal("complete identity failed")
	}
	action := DarwinActionIdentity{ProcessIdentity: complete, PIDVersion: 9, UniqueID: 19}
	if err := action.Validate(); err != nil || !action.Complete() {
		t.Fatalf("action identity invalid: %v", err)
	}
	action.PIDVersion = 0
	if err := action.Validate(); err == nil {
		t.Fatal("incomplete Darwin identity accepted")
	}
}

func TestMarshalDecodeStrictDeterministic(t *testing.T) {
	share := validShareReceipt()
	first, err := MarshalDeterministic(share)
	if err != nil {
		t.Fatalf("MarshalDeterministic: %v", err)
	}
	second, err := MarshalDeterministic(share)
	if err != nil {
		t.Fatalf("MarshalDeterministic second: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("non-deterministic output:\n%s\n%s", first, second)
	}
	var decoded ShareReceipt
	if err := DecodeStrict(first, &decoded); err != nil {
		t.Fatalf("DecodeStrict: %v", err)
	}
	withUnknown := append(first[:len(first)-1], []byte(`,"pid":42}`)...)
	if err := DecodeStrict(withUnknown, &decoded); err == nil {
		t.Fatal("unknown property accepted")
	}
	if err := DecodeStrict(append(first, []byte(` {}`)...), &decoded); err == nil {
		t.Fatal("trailing document accepted")
	}
}

func TestActionCandidateFailsClosed(t *testing.T) {
	candidate := validCandidate()
	if err := candidate.Validate(); err != nil {
		t.Fatalf("valid candidate: %v", err)
	}
	for _, mutate := range []func(*ActionCandidate){
		func(c *ActionCandidate) { c.DetectorID = "other/v1" },
		func(c *ActionCandidate) { c.Classification = ClassificationRecentlyActive },
		func(c *ActionCandidate) { c.Target.PIDVersion = 0 },
		func(c *ActionCandidate) { c.Evidence.Availability[0].Status = AvailabilityContradictory },
	} {
		copy := validCandidate()
		mutate(&copy)
		if err := copy.Validate(); err == nil {
			t.Fatalf("unsafe candidate accepted: %#v", copy)
		}
	}
}

func TestReceiptReconciliation(t *testing.T) {
	share := validShareReceipt()
	if err := share.Validate(); err != nil {
		t.Fatalf("valid share receipt: %v", err)
	}
	share.ProtectedSignaled = 1
	if err := share.Validate(); err == nil {
		t.Fatal("verified protected signal accepted")
	}
	share = validShareReceipt()
	share.Outcome = OutcomeRefused
	share.TargetExitCount = 1
	if err := share.Validate(); err == nil {
		t.Fatal("refused action effect accepted")
	}

	result := LocalResultReceipt{
		SchemaVersion: ResultReceiptSchemaVersion, ToolVersion: "0.1.0", ReceiptID: "synthetic-receipt",
		PreparedDigest: strings.Repeat("a", 64),
		FinalizedAt:    testTime, Outcome: OutcomeRefused,
		Revalidation:   DetectorEvidence{Availability: []ProbeAvailability{}, Codes: []EvidenceCode{}},
		SignalAttempts: []SignalAttempt{}, MemoryPressureBefore: PressureUnknown,
		MemoryPressureAfter: PressureUnknown, ErrorCodes: []ErrorCode{ErrorEvidenceChanged},
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("valid refused result: %v", err)
	}
	result.SignalAttempts = []SignalAttempt{{Target: validCandidate().Target, Attempted: true, ErrorCode: ErrorNone}}
	if err := result.Validate(); err == nil {
		t.Fatal("refused result with attempted signal accepted")
	}
	result.Outcome, result.ConfirmationOK = OutcomePartial, false
	if err := result.Validate(); err == nil {
		t.Fatal("partial result without confirmation accepted")
	}
}

func TestWorkflowGroupSnapshotAndShareSnapshotValidation(t *testing.T) {
	group := validWorkflowGroup()
	if err := group.Validate(); err != nil {
		t.Fatalf("valid group: %v", err)
	}
	if group.Protected() {
		t.Fatal("unprotected group reported protected")
	}
	protected := validWorkflowGroup()
	protected.Classification = ClassificationProtected
	protected.Protection = []EvidenceCode{EvidenceAncestor}
	if !protected.Protected() || protected.Validate() != nil {
		t.Fatalf("protected group invalid: %v", protected.Validate())
	}

	groupMutations := []func(*WorkflowGroup){
		func(g *WorkflowGroup) { g.ID = "" },
		func(g *WorkflowGroup) { g.Root.PID = 0 },
		func(g *WorkflowGroup) { g.Family = WorkflowFamily("future") },
		func(g *WorkflowGroup) { g.Classification = Classification("future") },
		func(g *WorkflowGroup) { g.Attribution = nil },
		func(g *WorkflowGroup) { g.Attribution = []EvidenceCode{EvidenceTTYOwner, EvidenceAncestor} },
		func(g *WorkflowGroup) { g.Protection = []EvidenceCode{EvidenceAncestor} },
		func(g *WorkflowGroup) {
			g.Classification = ClassificationSupportedStaleCandidate
			g.Protection = []EvidenceCode{EvidenceAncestor}
		},
		func(g *WorkflowGroup) { g.Processes[0].Argv = nil },
		func(g *WorkflowGroup) { g.Aggregate.RSSBytes++ },
		func(g *WorkflowGroup) { g.Root.PID = 999 },
	}
	for i, mutate := range groupMutations {
		copy := validWorkflowGroup()
		mutate(&copy)
		if err := copy.Validate(); err == nil {
			t.Errorf("group mutation %d accepted", i)
		}
	}

	snapshot := Snapshot{SchemaVersion: SnapshotSchemaVersion, ToolVersion: "0.1.0", ObservedAt: testTime, Platform: Platform{OS: "darwin", Arch: "arm64"}, Availability: []ProbeAvailability{}, Groups: []WorkflowGroup{group}}
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("valid snapshot: %v", err)
	}
	for i, mutate := range []func(*Snapshot){
		func(s *Snapshot) { s.SchemaVersion = "future" }, func(s *Snapshot) { s.ToolVersion = "" },
		func(s *Snapshot) { s.ObservedAt = time.Time{} }, func(s *Snapshot) { s.Platform.OS = "" },
		func(s *Snapshot) { s.Availability = nil }, func(s *Snapshot) { s.Groups[0].ID = "" },
	} {
		copy := snapshot
		copy.Groups = append([]WorkflowGroup(nil), snapshot.Groups...)
		mutate(&copy)
		if err := copy.Validate(); err == nil {
			t.Errorf("snapshot mutation %d accepted", i)
		}
	}

	share := ShareSnapshot{SchemaVersion: ShareSnapshotSchemaVersion, ToolVersion: "0.1.0", Platform: Platform{OS: "darwin", Arch: "arm64"}, Availability: []ProbeAvailability{}, Groups: []ShareWorkflowGroup{{Family: WorkflowFamilyCodex, Classification: ClassificationQuietUnclassified, Attribution: []EvidenceCode{}, Protection: []EvidenceCode{}, ProcessCount: 1, CPUTimeBucket: CPUTimeUnder1s, RSSBucket: SizeUnder100MB}}}
	if err := share.Validate(); err != nil {
		t.Fatalf("valid share snapshot: %v", err)
	}
	for i, mutate := range []func(*ShareSnapshot){
		func(s *ShareSnapshot) { s.SchemaVersion = "future" }, func(s *ShareSnapshot) { s.ToolVersion = "" },
		func(s *ShareSnapshot) { s.Platform.Arch = "" }, func(s *ShareSnapshot) { s.Groups = nil },
		func(s *ShareSnapshot) { s.Groups[0].Family = WorkflowFamily("future") },
		func(s *ShareSnapshot) { s.Groups[0].Attribution = nil }, func(s *ShareSnapshot) { s.Groups[0].RSSBucket = "" },
	} {
		copy := share
		copy.Groups = append([]ShareWorkflowGroup(nil), share.Groups...)
		mutate(&copy)
		if err := copy.Validate(); err == nil {
			t.Errorf("share snapshot mutation %d accepted", i)
		}
	}
}

func TestPreparedAndResultReceiptValidationBranches(t *testing.T) {
	prepared := LocalPreparedReceipt{
		SchemaVersion: PreparedReceiptSchemaVersion, ToolVersion: "0.1.0", ReceiptID: "synthetic-receipt", PreparedAt: testTime,
		DetectorID: CodexV1DetectorID, Target: validCandidate().Target, Protected: []DarwinActionIdentity{},
		Evidence: validCandidate().Evidence, ConfirmationBinding: strings.Repeat("b", 64), ConfirmationOK: false, Outcome: OutcomePrepared,
	}
	if err := prepared.Validate(); err != nil {
		t.Fatalf("valid prepared: %v", err)
	}
	for i, mutate := range []func(*LocalPreparedReceipt){
		func(r *LocalPreparedReceipt) { r.SchemaVersion = "future" }, func(r *LocalPreparedReceipt) { r.PreparedAt = time.Time{} },
		func(r *LocalPreparedReceipt) { r.DetectorID = "other" }, func(r *LocalPreparedReceipt) { r.Target.UniqueID = 0 },
		func(r *LocalPreparedReceipt) { r.Protected = nil }, func(r *LocalPreparedReceipt) { r.Protected = []DarwinActionIdentity{r.Target} },
		func(r *LocalPreparedReceipt) { r.Evidence.Codes = nil }, func(r *LocalPreparedReceipt) { r.ConfirmationBinding = "short" },
	} {
		copy := prepared
		mutate(&copy)
		if err := copy.Validate(); err == nil {
			t.Errorf("prepared mutation %d accepted", i)
		}
	}

	verified := validResultReceipt()
	if err := verified.Validate(); err != nil {
		t.Fatalf("valid result: %v", err)
	}
	for i, mutate := range []func(*LocalResultReceipt){
		func(r *LocalResultReceipt) { r.SchemaVersion = "future" }, func(r *LocalResultReceipt) { r.FinalizedAt = time.Time{} },
		func(r *LocalResultReceipt) { r.PreparedDigest = "short" },
		func(r *LocalResultReceipt) { r.Outcome = OutcomePrepared }, func(r *LocalResultReceipt) { r.Revalidation.Codes = nil },
		func(r *LocalResultReceipt) { r.SignalAttempts = nil }, func(r *LocalResultReceipt) { r.SignalAttempts[0].ErrorCode = ErrorCode("future") },
		func(r *LocalResultReceipt) { r.ErrorCodes = []ErrorCode{ErrorInternal, ErrorEvidenceChanged} },
		func(r *LocalResultReceipt) { r.MemoryPressureAfter = PressureLevel("future") },
		func(r *LocalResultReceipt) { r.TargetExitCount = 0 }, func(r *LocalResultReceipt) { r.ConfirmationOK = false },
	} {
		copy := validResultReceipt()
		copy.SignalAttempts = append([]SignalAttempt(nil), copy.SignalAttempts...)
		mutate(&copy)
		if err := copy.Validate(); err == nil {
			t.Errorf("result mutation %d accepted", i)
		}
	}
}

func TestShareTypesExcludeForbiddenFields(t *testing.T) {
	forbidden := []string{"pid", "time", "path", "argv", "cwd", "repository", "user", "host", "environment", "port", "session", "thread", "descriptor", "stack", "raw", "label"}
	for _, typ := range []reflect.Type{reflect.TypeOf(ShareSnapshot{}), reflect.TypeOf(ShareReceipt{})} {
		walkJSONFields(t, typ, forbidden, map[reflect.Type]bool{})
	}
}

func walkJSONFields(t *testing.T, typ reflect.Type, forbidden []string, seen map[reflect.Type]bool) {
	t.Helper()
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct || seen[typ] || typ.PkgPath() == "time" {
		return
	}
	seen[typ] = true
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		lower := strings.ToLower(name)
		for _, word := range forbidden {
			if lower == word || strings.HasPrefix(lower, word+"_") || strings.HasSuffix(lower, "_"+word) {
				t.Errorf("%s.%s exposes forbidden JSON field %q", typ.Name(), field.Name, name)
			}
		}
		walkJSONFields(t, field.Type, forbidden, seen)
	}
}

func FuzzDecodeStrictShareReceipt(f *testing.F) {
	seed, _ := MarshalDeterministic(validShareReceipt())
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		var value ShareReceipt
		if DecodeStrict(data, &value) == nil {
			encoded, err := MarshalDeterministic(value)
			if err != nil {
				t.Fatalf("accepted value did not re-marshal: %v", err)
			}
			var roundTrip ShareReceipt
			if err := DecodeStrict(encoded, &roundTrip); err != nil {
				t.Fatalf("round-trip rejected: %v", err)
			}
		}
	})
}

func validCandidate() ActionCandidate {
	return ActionCandidate{
		DetectorID: CodexV1DetectorID, Classification: ClassificationSupportedStaleCandidate,
		Target:   DarwinActionIdentity{ProcessIdentity: ProcessIdentity{PID: 42, StartTime: testTime, UID: 9001, Executable: "/synthetic/bin/node"}, PIDVersion: 7, UniqueID: 17},
		Evidence: DetectorEvidence{Availability: []ProbeAvailability{{Probe: ProbeOrigin, Status: AvailabilityAvailable}}, Codes: []EvidenceCode{EvidenceOriginExact}},
	}
}

func validShareReceipt() ShareReceipt {
	return ShareReceipt{
		SchemaVersion: ShareReceiptSchemaVersion, ToolVersion: "0.1.0", Platform: Platform{OS: "darwin", Arch: "arm64"},
		DetectorID: CodexV1DetectorID, SupportState: SupportSupported,
		Availability: []ProbeAvailability{{Probe: ProbeOrigin, Status: AvailabilityAvailable}}, Evidence: []EvidenceCode{EvidenceOriginExact},
		TargetCount: 1, DurationBucket: Duration5To10s, SelectedRSSBytes: 1024, TargetExitCount: 1,
		ProtectedPresent: 2, MemoryPressureBefore: PressureNominal, MemoryPressureAfter: PressureNominal,
		Outcome: OutcomeVerified, ErrorCodes: []ErrorCode{ErrorNone},
	}
}

func validProcessObservation(pid int32) ProcessObservation {
	return ProcessObservation{Identity: ProcessIdentity{PID: pid, StartTime: testTime.Add(time.Duration(pid) * time.Second), UID: 9001, Executable: "/synthetic/bin/tool"}, Argv: []string{}, Availability: []ProbeAvailability{}, Evidence: []EvidenceCode{}}
}

func validWorkflowGroup() WorkflowGroup {
	process := validProcessObservation(42)
	return WorkflowGroup{ID: "wf-0000000000000001", Root: process.Identity, Family: WorkflowFamilyUnclassified, Classification: ClassificationQuietUnclassified, Attribution: []EvidenceCode{}, Protection: []EvidenceCode{}, Processes: []ProcessObservation{process}, Aggregate: ResourceAggregate{ProcessCount: 1}}
}

func validResultReceipt() LocalResultReceipt {
	return LocalResultReceipt{
		SchemaVersion: ResultReceiptSchemaVersion, ToolVersion: "0.1.0", ReceiptID: "synthetic-receipt", FinalizedAt: testTime,
		PreparedDigest: strings.Repeat("a", 64),
		Outcome:        OutcomeVerified, ConfirmationOK: true, Revalidation: validCandidate().Evidence,
		SignalAttempts: []SignalAttempt{{Target: validCandidate().Target, Attempted: true, ErrorCode: ErrorNone}}, TargetExitCount: 1,
		ProtectedPresent: 2, MemoryPressureBefore: PressureNominal, MemoryPressureAfter: PressureNominal, ErrorCodes: []ErrorCode{ErrorNone},
	}
}
