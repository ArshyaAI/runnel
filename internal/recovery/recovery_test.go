package recovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArshyaAI/runnel/internal/codex"
	"github.com/ArshyaAI/runnel/internal/model"
)

var fixedTime = time.Date(2026, 8, 20, 1, 0, 0, 0, time.UTC)

type memoryStore struct {
	mu           sync.Mutex
	prepared     map[string][]byte
	claims       map[string]string
	results      map[string][]byte
	prepareErr   error
	claimErr     error
	finalizeErr  error
	claimStarted chan struct{}
	claimRelease chan struct{}
	claimOnce    sync.Once
}

func (s *memoryStore) Prepare(_ context.Context, id string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prepareErr != nil {
		return s.prepareErr
	}
	if s.prepared == nil {
		s.prepared = map[string][]byte{}
	}
	if _, ok := s.prepared[id]; ok {
		return errors.New("collision")
	}
	s.prepared[id] = append([]byte(nil), data...)
	return nil
}

func (s *memoryStore) ClaimExecution(ctx context.Context, id, digest string) error {
	s.mu.Lock()
	if s.claimErr != nil {
		err := s.claimErr
		s.mu.Unlock()
		return err
	}
	prepared, ok := s.prepared[id]
	if !ok {
		s.mu.Unlock()
		return errors.New("not prepared")
	}
	actual := sha256.Sum256(prepared)
	if hex.EncodeToString(actual[:]) != digest {
		s.mu.Unlock()
		return errors.New("prepared digest mismatch")
	}
	if s.claims == nil {
		s.claims = map[string]string{}
	}
	if _, ok := s.claims[id]; ok {
		s.mu.Unlock()
		return errors.New("already claimed")
	}
	if _, ok := s.results[id]; ok {
		s.mu.Unlock()
		return errors.New("already final")
	}
	s.claims[id] = digest
	s.mu.Unlock()
	if s.claimStarted != nil {
		s.claimOnce.Do(func() { close(s.claimStarted) })
	}
	if s.claimRelease != nil {
		select {
		case <-s.claimRelease:
		case <-ctx.Done():
			// The durable claim remains consumed even when the caller is cancelled.
		}
	}
	return nil
}

func (s *memoryStore) Finalize(_ context.Context, id string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.finalizeErr != nil {
		return s.finalizeErr
	}
	if s.results == nil {
		s.results = map[string][]byte{}
	}
	if _, ok := s.prepared[id]; !ok {
		return errors.New("not prepared")
	}
	if _, ok := s.claims[id]; !ok {
		return errors.New("not claimed")
	}
	if _, ok := s.results[id]; ok {
		return errors.New("collision")
	}
	s.results[id] = append([]byte(nil), data...)
	return nil
}

type fakeRevalidator struct {
	mu    sync.Mutex
	out   Revalidation
	err   error
	calls int
}

func (f *fakeRevalidator) Revalidate(context.Context, Plan) (Revalidation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.out, f.err
}

type fakeSignaler struct {
	mu     sync.Mutex
	err    error
	calls  int
	target model.DarwinActionIdentity
}

func (f *fakeSignaler) SignalTERM(_ context.Context, target model.DarwinActionIdentity) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.target = target
	return f.err
}

type fakeVerifier struct {
	mu    sync.Mutex
	out   Verification
	err   error
	calls int
}

func (f *fakeVerifier) Verify(context.Context, model.DarwinActionIdentity, []model.DarwinActionIdentity) (Verification, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.out, f.err
}

func identity(pid int32, version uint32) model.DarwinActionIdentity {
	return model.DarwinActionIdentity{ProcessIdentity: model.ProcessIdentity{PID: pid, StartTime: fixedTime, UID: 501, Executable: "/safe/node"}, PIDVersion: version, UniqueID: uint64(pid) + 1000}
}

func validCodexSamples(version uint32) []codex.DeepSample {
	leaf := []string{
		"/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node",
		"--experimental-vm-modules",
		"/private/tmp/runnel-recovery/trusted-worker.js",
		"/Users/test/worktree",
	}
	parent := append([]string{"/Applications/ChatGPT.app/Contents/MacOS/codex", "sandbox", "--"}, leaf...)
	target := model.DarwinActionIdentity{
		ProcessIdentity: model.ProcessIdentity{PID: 42, StartTime: fixedTime, UID: 501, Executable: leaf[0]},
		PIDVersion:      version,
		UniqueID:        1042,
	}
	parentIdentity := model.DarwinActionIdentity{
		ProcessIdentity: model.ProcessIdentity{PID: 41, StartTime: fixedTime.Add(-time.Second), UID: 501, Executable: parent[0]},
		PIDVersion:      6,
		UniqueID:        1041,
	}
	origin := codex.OriginEvidence{
		Availability: model.AvailabilityAvailable,
		Codex: codex.SignedArtifact{
			Availability: model.AvailabilityAvailable, ResolvedPath: parent[0],
			Identifier: codex.CodexIdentifier, TeamIdentifier: codex.OpenAITeamIdentifier,
			SHA256: codex.CodexSHA256, SignatureValid: true,
		},
		Node: codex.SignedArtifact{
			Availability: model.AvailabilityAvailable, ResolvedPath: leaf[0],
			Identifier: codex.NodeIdentifier, TeamIdentifier: codex.OpenAITeamIdentifier,
			SHA256: codex.NodeSHA256, SignatureValid: true,
		},
		Worker: codex.HashedArtifact{
			Availability: model.AvailabilityAvailable, ResolvedPath: leaf[2], SHA256: codex.WorkerSHA256,
		},
		LeafUID: 501, ParentUID: 501,
	}
	metadata := codex.MetadataSnapshot{
		Availability: model.AvailabilityAvailable, DataVersion: 7,
		CLIVersion: codex.SupportedCodexVersion, ThreadSource: "subagent", EdgeStatus: "closed",
		ThreadID: "recovery-child", ParentThreadID: "recovery-parent",
		RolloutPath: "/synthetic/recovery-rollout.jsonl",
	}
	file := codex.FileIdentity{Device: 41, Inode: 42, Size: 800, ModifiedNS: 1234}
	tail := codex.TailSnapshot{
		Availability: model.AvailabilityAvailable, EnvelopeType: "event_msg",
		EventType: "task_complete", Successful: true, File: file,
	}
	descriptor := codex.DescriptorEvidence{
		Availability: model.AvailabilityAvailable, Path: metadata.RolloutPath,
		Device: file.Device, Inode: file.Inode, Access: codex.DescriptorReadOnly,
	}
	samples := make([]codex.DeepSample, 4)
	for i := range samples {
		samples[i] = codex.DeepSample{
			Offset:               time.Duration(i) * 2 * time.Second,
			IdentityAvailability: model.AvailabilityAvailable,
			Identity:             target,
			ParentAvailability:   model.AvailabilityAvailable,
			Parent:               parentIdentity,
			CurrentUID:           501,
			LeafArgv:             append([]string(nil), leaf...),
			ParentArgv:           append([]string(nil), parent...),
			TempRoots:            []string{"/private/tmp/runnel-recovery"},
			Origin:               origin,
			Metadata:             metadata,
			Tail:                 tail,
			Descriptor:           descriptor,
			CPUTimeNS:            uint64((i + 1) * 100),
			RSSBytes:             4096,
			TTY:                  codex.PresenceProbe{Availability: model.AvailabilityAvailable},
			Sockets:              codex.SocketProbe{Availability: model.AvailabilityAvailable},
			WritableActivity:     codex.PresenceProbe{Availability: model.AvailabilityAvailable},
			Children:             codex.ChildrenProbe{Availability: model.AvailabilityAvailable, Children: []model.ProcessIdentity{}},
			Stack:                codex.StackEvidence{Availability: model.AvailabilityNotApplicable},
		}
	}
	samples[3].Stack = codex.StackEvidence{Availability: model.AvailabilityAvailable, Predicate: codex.SupportedStackPredicate}
	return samples
}

func authority(t *testing.T, version uint32) *codex.ActionAuthority {
	t.Helper()
	result := codex.Evaluate(validCodexSamples(version))
	authority := result.Authority()
	if authority == nil {
		t.Fatalf("valid detector result did not issue authority: %#v", result)
	}
	return authority
}

func candidate(t *testing.T, version uint32) model.ActionCandidate {
	t.Helper()
	candidate, ok := authority(t, version).Candidate()
	if !ok {
		t.Fatal("valid authority did not expose candidate")
	}
	return candidate
}

func engine(store *memoryStore, revalidator *fakeRevalidator, signaler *fakeSignaler, verifier *fakeVerifier) Engine {
	return Engine{
		Store: store, Revalidator: revalidator, Signaler: signaler, Verifier: verifier,
		NewID:       func() (string, error) { return "r-0123456789abcdef0123456789abcdef", nil },
		Now:         func() time.Time { return fixedTime },
		random:      bytes.NewReader(bytes.Repeat([]byte{0x42}, 1024)),
		ToolVersion: "0.1.0-test",
	}
}

func validSetup(t *testing.T) (Plan, *memoryStore, *fakeRevalidator, *fakeSignaler, *fakeVerifier, Engine) {
	t.Helper()
	protected := []model.DarwinActionIdentity{identity(7, 2)}
	authority := authority(t, 7)
	actionCandidate, ok := authority.Candidate()
	if !ok {
		t.Fatal("valid authority did not expose candidate")
	}
	plan, err := NewPlan(authority, protected, 4096, model.PressureElevated, "0.1.0-test")
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryStore{}
	revalidator := &fakeRevalidator{out: Revalidation{Candidate: actionCandidate, Protected: protected, SelectedRSSBytes: 4096, Pressure: model.PressureElevated}}
	signaler := &fakeSignaler{}
	verifier := &fakeVerifier{out: Verification{TargetAbsent: true, ProtectedPresent: protected, Pressure: model.PressureNominal}}
	return plan, store, revalidator, signaler, verifier, engine(store, revalidator, signaler, verifier)
}

func TestSuccessfulRecovery(t *testing.T) {
	plan, store, revalidator, signaler, verifier, eng := validSetup(t)
	tx, err := eng.Begin(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	result, err := eng.Execute(context.Background(), tx, tx.ConfirmationToken())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Persisted || result.Receipt.Outcome != model.OutcomeVerified || signaler.calls != 1 || verifier.calls != 1 || revalidator.calls != 1 {
		t.Fatalf("unexpected result: %#v calls=%d/%d/%d", result, revalidator.calls, signaler.calls, verifier.calls)
	}
	if len(store.prepared) != 1 || len(store.results) != 1 {
		t.Fatalf("receipt counts: %d/%d", len(store.prepared), len(store.results))
	}
}

func TestConfirmationMismatchNeverSignals(t *testing.T) {
	plan, _, revalidator, signaler, verifier, eng := validSetup(t)
	tx, err := eng.Begin(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	result, err := eng.Execute(context.Background(), tx, "WRONG")
	if !errors.Is(err, ErrConfirmation) || !result.Persisted || result.Receipt.Outcome != model.OutcomeRefused {
		t.Fatalf("unexpected: %#v %v", result, err)
	}
	if revalidator.calls != 0 || signaler.calls != 0 || verifier.calls != 0 {
		t.Fatal("mutation dependencies called on mismatch")
	}
}

func TestChangedEvidenceNeverSignals(t *testing.T) {
	plan, _, revalidator, signaler, verifier, eng := validSetup(t)
	revalidator.out.Candidate.Target.PIDVersion++
	tx, err := eng.Begin(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	result, err := eng.Execute(context.Background(), tx, tx.ConfirmationToken())
	if !errors.Is(err, ErrRevalidation) || result.Receipt.Outcome != model.OutcomeRefused {
		t.Fatalf("unexpected: %#v %v", result, err)
	}
	if signaler.calls != 0 || verifier.calls != 0 {
		t.Fatal("signal or verify called after failed revalidation")
	}
}

func TestConflictingExtraAndNegativeRevalidationEvidenceNeverSignals(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*model.ActionCandidate)
	}{
		{name: "missing canonical code", mutate: func(candidate *model.ActionCandidate) {
			candidate.Evidence.Codes = slices.Clone(candidate.Evidence.Codes[1:])
		}},
		{name: "extra positive code", mutate: func(candidate *model.ActionCandidate) {
			candidate.Evidence.Codes = append(candidate.Evidence.Codes, model.EvidenceCWDWorktree)
			slices.Sort(candidate.Evidence.Codes)
		}},
		{name: "negative code", mutate: func(candidate *model.ActionCandidate) {
			candidate.Evidence.Codes = append(candidate.Evidence.Codes, model.EvidenceTTYPresent)
			slices.Sort(candidate.Evidence.Codes)
		}},
		{name: "contradictory availability", mutate: func(candidate *model.ActionCandidate) {
			candidate.Evidence.Availability[0].Status = model.AvailabilityContradictory
		}},
		{name: "extra availability", mutate: func(candidate *model.ActionCandidate) {
			candidate.Evidence.Availability = append(candidate.Evidence.Availability, model.ProbeAvailability{
				Probe: model.ProbeCWD, Status: model.AvailabilityAvailable,
			})
			slices.SortFunc(candidate.Evidence.Availability, func(a, b model.ProbeAvailability) int {
				if a.Probe < b.Probe {
					return -1
				}
				if a.Probe > b.Probe {
					return 1
				}
				return 0
			})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, _, revalidator, signaler, verifier, eng := validSetup(t)
			test.mutate(&revalidator.out.Candidate)
			tx, err := eng.Begin(context.Background(), plan)
			if err != nil {
				t.Fatal(err)
			}
			result, err := eng.Execute(context.Background(), tx, tx.ConfirmationToken())
			if !errors.Is(err, ErrRevalidation) || result.Receipt.Outcome != model.OutcomeRefused {
				t.Fatalf("unexpected: %#v %v", result, err)
			}
			if signaler.calls != 0 || verifier.calls != 0 {
				t.Fatal("signal or verify called after inexact revalidation evidence")
			}
		})
	}
}

func TestSignalAndVerificationFailuresArePartial(t *testing.T) {
	plan, _, _, signaler, verifier, eng := validSetup(t)
	signaler.err = errors.New("denied")
	verifier.err = errors.New("timeout")
	verifier.out.TargetAbsent = false
	tx, err := eng.Begin(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	result, err := eng.Execute(context.Background(), tx, tx.ConfirmationToken())
	if !errors.Is(err, ErrSignal) || result.Receipt.Outcome != model.OutcomePartial || signaler.calls != 1 || verifier.calls != 1 {
		t.Fatalf("unexpected: %#v %v", result, err)
	}
	if _, replayErr := eng.Execute(context.Background(), tx, tx.ConfirmationToken()); !errors.Is(replayErr, ErrReceiptStore) || signaler.calls != 1 {
		t.Fatalf("partial-result replay was not blocked before signal: calls=%d err=%v", signaler.calls, replayErr)
	}
}

func TestDifferentProtectedIdentityCannotVerify(t *testing.T) {
	plan, _, _, _, verifier, eng := validSetup(t)
	verifier.out.ProtectedPresent = []model.DarwinActionIdentity{identity(8, 2)}
	tx, err := eng.Begin(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	result, err := eng.Execute(context.Background(), tx, tx.ConfirmationToken())
	if !errors.Is(err, ErrVerification) || result.Receipt.Outcome != model.OutcomePartial {
		t.Fatalf("unexpected: %#v %v", result, err)
	}
}

func TestReceiptPrepareFailurePreventsSignal(t *testing.T) {
	plan, store, _, signaler, _, eng := validSetup(t)
	store.prepareErr = errors.New("disk full")
	if _, err := eng.Begin(context.Background(), plan); !errors.Is(err, ErrReceiptStore) {
		t.Fatalf("unexpected error: %v", err)
	}
	if signaler.calls != 0 {
		t.Fatal("signal before durable prepare")
	}
}

func TestReceiptFinalizeFailureLeavesEmergencyResult(t *testing.T) {
	plan, store, _, signaler, _, eng := validSetup(t)
	store.finalizeErr = errors.New("disk full")
	tx, err := eng.Begin(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	result, err := eng.Execute(context.Background(), tx, tx.ConfirmationToken())
	if !errors.Is(err, ErrReceiptStore) || result.Persisted || result.Receipt.Outcome != model.OutcomeVerified || signaler.calls != 1 {
		t.Fatalf("unexpected: %#v %v", result, err)
	}
}

func TestPlanRequiresExactCodexAuthorityAndExcludesProtectedTarget(t *testing.T) {
	if _, err := NewPlan(nil, nil, 1, model.PressureNominal, "v"); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("expected nil authority rejection: %v", err)
	}
	if _, err := NewPlan(&codex.ActionAuthority{}, nil, 1, model.PressureNominal, "v"); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("expected zero authority rejection: %v", err)
	}

	issued := authority(t, 7)
	copied := *issued
	if _, err := NewPlan(&copied, nil, 1, model.PressureNominal, "v"); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("expected copied authority rejection: %v", err)
	}

	forgedCandidate := candidate(t, 7)
	encoded, err := json.Marshal(forgedCandidate)
	if err != nil {
		t.Fatal(err)
	}
	var decoded codex.ActionAuthority
	if err := json.Unmarshal(encoded, &decoded); err == nil {
		t.Fatal("action authority unexpectedly accepted serialized candidate data")
	}
	if _, err := NewPlan(&decoded, nil, 1, model.PressureNominal, "v"); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("expected serialized candidate forgery rejection: %v", err)
	}

	if _, err := NewPlan(issued, []model.DarwinActionIdentity{forgedCandidate.Target}, 1, model.PressureNominal, "v"); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("expected protected target rejection: %v", err)
	}
}

func TestPlanIntegrityBindsAuthorityProvenanceAndCandidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Plan)
	}{
		{name: "authority removed", mutate: func(plan *Plan) { plan.authority = nil }},
		{name: "authority provenance", mutate: func(plan *Plan) { plan.authorityProof[0]++ }},
		{name: "candidate target", mutate: func(plan *Plan) { plan.candidate.Target.PIDVersion++ }},
		{name: "candidate evidence", mutate: func(plan *Plan) { plan.candidate.Evidence.Codes = plan.candidate.Evidence.Codes[1:] }},
		{name: "plan proof", mutate: func(plan *Plan) { plan.proof[0]++ }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, store, _, signaler, _, eng := validSetup(t)
			test.mutate(&plan)
			if _, err := eng.Begin(context.Background(), plan); !errors.Is(err, ErrInvalidPlan) {
				t.Fatalf("expected invalid plan: %v", err)
			}
			if len(store.prepared) != 0 || signaler.calls != 0 {
				t.Fatal("tampered plan reached durable prepare or signal")
			}
		})
	}
}

func TestPlanCandidateAccessorReturnsIsolatedCopy(t *testing.T) {
	plan, _, _, _, _, _ := validSetup(t)
	candidate := plan.Candidate()
	candidate.Evidence.Codes[0] = model.EvidenceTTYPresent
	if slices.Equal(candidate.Evidence.Codes, plan.Candidate().Evidence.Codes) {
		t.Fatal("candidate accessor exposed plan evidence backing storage")
	}
}

func TestTransactionTokenIsBeginTimeRandomAndNeverPersistedPlaintext(t *testing.T) {
	planA, storeA, _, _, _, engA := validSetup(t)
	engA.random = bytes.NewReader(bytes.Repeat([]byte{0x11}, 16))
	txA, err := engA.Begin(context.Background(), planA)
	if err != nil {
		t.Fatal(err)
	}
	planB, storeB, _, _, _, engB := validSetup(t)
	engB.random = bytes.NewReader(bytes.Repeat([]byte{0x22}, 16))
	txB, err := engB.Begin(context.Background(), planB)
	if err != nil {
		t.Fatal(err)
	}
	if txA.ConfirmationToken() == txB.ConfirmationToken() || len(txA.ConfirmationToken()) != 26 || txA.ConfirmationToken() != strings.ToUpper(txA.ConfirmationToken()) {
		t.Fatalf("unexpected begin-time tokens: %q %q", txA.ConfirmationToken(), txB.ConfirmationToken())
	}
	if strings.ContainsAny(txA.ConfirmationToken()+txB.ConfirmationToken(), "ILOU") {
		t.Fatalf("tokens contain visually ambiguous characters: %q %q", txA.ConfirmationToken(), txB.ConfirmationToken())
	}
	if bytes.Contains(storeA.prepared[txA.ID], []byte(txA.ConfirmationToken())) || bytes.Contains(storeB.prepared[txB.ID], []byte(txB.ConfirmationToken())) {
		t.Fatal("plaintext confirmation token persisted")
	}
}

func TestEngineVersionMustMatchPlan(t *testing.T) {
	plan, _, _, signaler, _, eng := validSetup(t)
	eng.ToolVersion = "different"
	if _, err := eng.Begin(context.Background(), plan); !errors.Is(err, ErrInvalidPlan) {
		t.Fatalf("expected version rejection: %v", err)
	}
	if signaler.calls != 0 {
		t.Fatal("signal called for mismatched version")
	}
}

func TestConcurrentExecuteProducesExactlyOneSignalAndResult(t *testing.T) {
	plan, store, revalidator, signaler, verifier, eng := validSetup(t)
	tx, err := eng.Begin(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	type execution struct {
		result Result
		err    error
	}
	const contenders = 32
	start := make(chan struct{})
	completed := make(chan execution, contenders)
	var wait sync.WaitGroup
	for range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			result, err := eng.Execute(context.Background(), tx, tx.ConfirmationToken())
			completed <- execution{result: result, err: err}
		}()
	}
	close(start)
	wait.Wait()
	close(completed)
	persisted := 0
	for item := range completed {
		if item.result.Persisted {
			persisted++
			if item.err != nil {
				t.Fatalf("winning execution failed: %v", item.err)
			}
			continue
		}
		if !errors.Is(item.err, ErrReceiptStore) {
			t.Fatalf("losing execution did not fail at claim: %v", item.err)
		}
	}
	if persisted != 1 || signaler.calls != 1 || revalidator.calls != 1 || verifier.calls != 1 || len(store.results) != 1 || len(store.claims) != 1 {
		t.Fatalf("at-most-once failure: persisted=%d calls=%d/%d/%d results=%d claims=%d", persisted, revalidator.calls, signaler.calls, verifier.calls, len(store.results), len(store.claims))
	}
}

func TestReplayAfterSuccessRefusalAndFailureNeverSignalsAgain(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		plan, _, _, signaler, _, eng := validSetup(t)
		tx, err := eng.Begin(context.Background(), plan)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := eng.Execute(context.Background(), tx, tx.ConfirmationToken()); err != nil {
			t.Fatal(err)
		}
		if _, err := eng.Execute(context.Background(), tx, tx.ConfirmationToken()); !errors.Is(err, ErrReceiptStore) {
			t.Fatalf("replay was not rejected at claim: %v", err)
		}
		if signaler.calls != 1 {
			t.Fatalf("success replay signal count = %d", signaler.calls)
		}
	})

	t.Run("confirmation refusal", func(t *testing.T) {
		plan, _, _, signaler, _, eng := validSetup(t)
		tx, err := eng.Begin(context.Background(), plan)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := eng.Execute(context.Background(), tx, "WRONG"); !errors.Is(err, ErrConfirmation) {
			t.Fatalf("expected confirmation refusal: %v", err)
		}
		if _, err := eng.Execute(context.Background(), tx, tx.ConfirmationToken()); !errors.Is(err, ErrReceiptStore) {
			t.Fatalf("refusal replay was not rejected at claim: %v", err)
		}
		if signaler.calls != 0 {
			t.Fatalf("refusal replay signaled %d times", signaler.calls)
		}
	})

	t.Run("revalidation refusal", func(t *testing.T) {
		plan, _, revalidator, signaler, _, eng := validSetup(t)
		revalidator.err = errors.New("changed")
		tx, err := eng.Begin(context.Background(), plan)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := eng.Execute(context.Background(), tx, tx.ConfirmationToken()); !errors.Is(err, ErrRevalidation) {
			t.Fatalf("expected revalidation refusal: %v", err)
		}
		if _, err := eng.Execute(context.Background(), tx, tx.ConfirmationToken()); !errors.Is(err, ErrReceiptStore) {
			t.Fatalf("revalidation replay was not rejected at claim: %v", err)
		}
		if signaler.calls != 0 {
			t.Fatalf("revalidation replay signaled %d times", signaler.calls)
		}
	})

	t.Run("finalize failure", func(t *testing.T) {
		plan, store, _, signaler, _, eng := validSetup(t)
		store.finalizeErr = errors.New("disk full")
		tx, err := eng.Begin(context.Background(), plan)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := eng.Execute(context.Background(), tx, tx.ConfirmationToken()); !errors.Is(err, ErrReceiptStore) {
			t.Fatalf("expected finalize failure: %v", err)
		}
		if _, err := eng.Execute(context.Background(), tx, tx.ConfirmationToken()); !errors.Is(err, ErrReceiptStore) {
			t.Fatalf("failed-finalize replay was not rejected at claim: %v", err)
		}
		if signaler.calls != 1 || len(store.results) != 0 || len(store.claims) != 1 {
			t.Fatalf("failed-finalize state signals=%d results=%d claims=%d", signaler.calls, len(store.results), len(store.claims))
		}
	})
}

func TestCancellationAfterDurableClaimFinalizesWithoutSignalAndConsumesTransaction(t *testing.T) {
	plan, store, revalidator, signaler, verifier, eng := validSetup(t)
	store.claimStarted = make(chan struct{})
	store.claimRelease = make(chan struct{})
	tx, err := eng.Begin(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	type execution struct {
		result Result
		err    error
	}
	completed := make(chan execution, 1)
	go func() {
		result, err := eng.Execute(ctx, tx, tx.ConfirmationToken())
		completed <- execution{result: result, err: err}
	}()
	<-store.claimStarted
	cancel()
	close(store.claimRelease)
	item := <-completed
	if !errors.Is(item.err, context.Canceled) || !item.result.Persisted || item.result.Receipt.Outcome != model.OutcomeRefused {
		t.Fatalf("unexpected cancelled result: %#v %v", item.result, item.err)
	}
	if revalidator.calls != 0 || signaler.calls != 0 || verifier.calls != 0 {
		t.Fatalf("cancelled execution reached action dependencies: %d/%d/%d", revalidator.calls, signaler.calls, verifier.calls)
	}
	if _, err := eng.Execute(context.Background(), tx, tx.ConfirmationToken()); !errors.Is(err, ErrReceiptStore) {
		t.Fatalf("cancelled transaction replay was not rejected: %v", err)
	}
}

func TestCrashClaimAndTransactionBindingMismatchNeverSignal(t *testing.T) {
	t.Run("crash claim", func(t *testing.T) {
		plan, store, revalidator, signaler, verifier, eng := validSetup(t)
		tx, err := eng.Begin(context.Background(), plan)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.ClaimExecution(context.Background(), tx.ID, hex.EncodeToString(tx.preparedDigest[:])); err != nil {
			t.Fatal(err)
		}
		if _, err := eng.Execute(context.Background(), tx, tx.ConfirmationToken()); !errors.Is(err, ErrReceiptStore) {
			t.Fatalf("crash replay was not rejected: %v", err)
		}
		if revalidator.calls != 0 || signaler.calls != 0 || verifier.calls != 0 || len(store.results) != 0 {
			t.Fatalf("crash replay reached action/final state: %d/%d/%d results=%d", revalidator.calls, signaler.calls, verifier.calls, len(store.results))
		}
	})

	t.Run("directory id swap", func(t *testing.T) {
		plan, store, _, signaler, _, eng := validSetup(t)
		tx, err := eng.Begin(context.Background(), plan)
		if err != nil {
			t.Fatal(err)
		}
		tx.ID = "r-99999999999999999999999999999999"
		if _, err := eng.Execute(context.Background(), tx, tx.ConfirmationToken()); !errors.Is(err, ErrInvalidPlan) {
			t.Fatalf("swapped id not rejected: %v", err)
		}
		if signaler.calls != 0 || len(store.claims) != 0 {
			t.Fatalf("swapped id reached claim/signal: claims=%d signals=%d", len(store.claims), signaler.calls)
		}
	})

	t.Run("malformed directory id", func(t *testing.T) {
		plan, store, _, signaler, _, eng := validSetup(t)
		tx, err := eng.Begin(context.Background(), plan)
		if err != nil {
			t.Fatal(err)
		}
		tx.ID = "../r-99999999999999999999999999999999"
		if _, err := eng.Execute(context.Background(), tx, tx.ConfirmationToken()); !errors.Is(err, ErrInvalidPlan) {
			t.Fatalf("malformed id not rejected: %v", err)
		}
		if signaler.calls != 0 || len(store.claims) != 0 {
			t.Fatalf("malformed id reached claim/signal: claims=%d signals=%d", len(store.claims), signaler.calls)
		}
	})

	t.Run("prepared digest swap", func(t *testing.T) {
		plan, store, _, signaler, _, eng := validSetup(t)
		tx, err := eng.Begin(context.Background(), plan)
		if err != nil {
			t.Fatal(err)
		}
		tx.preparedDigest[0] ^= 0xff
		if _, err := eng.Execute(context.Background(), tx, tx.ConfirmationToken()); !errors.Is(err, ErrReceiptStore) {
			t.Fatalf("swapped digest not rejected by claim: %v", err)
		}
		if signaler.calls != 0 || len(store.claims) != 0 {
			t.Fatalf("swapped digest reached claim/signal: claims=%d signals=%d", len(store.claims), signaler.calls)
		}
	})
}

func TestConfirmationComparisonIsExactAndCaseSensitive(t *testing.T) {
	plan, _, revalidator, signaler, verifier, eng := validSetup(t)
	tx, err := eng.Begin(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(tx.ConfirmationToken())
	if lower == tx.ConfirmationToken() {
		t.Fatalf("test token unexpectedly has no letters: %q", lower)
	}
	result, err := eng.Execute(context.Background(), tx, lower)
	if !errors.Is(err, ErrConfirmation) || !result.Persisted || result.Receipt.ConfirmationOK {
		t.Fatalf("case-changed token was not refused: %#v %v", result, err)
	}
	if revalidator.calls != 0 || signaler.calls != 0 || verifier.calls != 0 {
		t.Fatal("case-changed token reached action dependencies")
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestBeginRandomFailureMutatesNothing(t *testing.T) {
	plan, store, _, signaler, _, eng := validSetup(t)
	eng.random = failingReader{err: errors.New("entropy unavailable")}
	if _, err := eng.Begin(context.Background(), plan); !errors.Is(err, ErrReceiptStore) {
		t.Fatalf("expected random failure: %v", err)
	}
	if len(store.prepared) != 0 || signaler.calls != 0 {
		t.Fatal("entropy failure reached prepare or signal")
	}
}
