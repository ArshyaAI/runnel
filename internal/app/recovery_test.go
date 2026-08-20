package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArshyaAI/runnel/internal/codex"
	"github.com/ArshyaAI/runnel/internal/live"
	"github.com/ArshyaAI/runnel/internal/model"
	"github.com/ArshyaAI/runnel/internal/platform/darwin"
	"github.com/ArshyaAI/runnel/internal/receipt"
	"github.com/ArshyaAI/runnel/internal/recovery"
)

var recoveryTestTime = time.Date(2026, 8, 20, 2, 0, 0, 0, time.UTC)

const (
	recoveryTestReceiptID = "r-0123456789abcdef0123456789abcdef"
	recoveryTestToken     = "0123456789ABCDEFGHJKMNPQRS"
)

type recoveryTestContext struct {
	detector   codex.DetectorResult
	candidate  live.Candidate
	leaf       model.DarwinActionIdentity
	parent     model.DarwinActionIdentity
	protected  []model.DarwinActionIdentity
	tempRoots  []string
	statePath  string
	rollout    string
	rss        uint64
	currentUID uint32
}

func (c recoveryTestContext) DetectorResult() codex.DetectorResult { return c.detector }
func (c recoveryTestContext) Candidate() live.Candidate            { return c.candidate }
func (c recoveryTestContext) Identities() (model.DarwinActionIdentity, model.DarwinActionIdentity) {
	return c.leaf, c.parent
}
func (c recoveryTestContext) CurrentUID() uint32  { return c.currentUID }
func (c recoveryTestContext) TempRoots() []string { return slices.Clone(c.tempRoots) }
func (c recoveryTestContext) StatePath() string   { return c.statePath }
func (c recoveryTestContext) RolloutPath() string { return c.rollout }
func (c recoveryTestContext) Protected() []model.DarwinActionIdentity {
	return slices.Clone(c.protected)
}
func (c recoveryTestContext) RSSBytes() uint64 { return c.rss }

type recoveryTestInspector struct {
	discovery   live.Discovery
	finding     RecoveryFinding
	discoverErr error
	inspectErr  error
	discovers   int
	inspects    int
}

func (f *recoveryTestInspector) Discover(context.Context) (live.Discovery, error) {
	f.discovers++
	return f.discovery, f.discoverErr
}

func (f *recoveryTestInspector) Inspect(_ context.Context, candidate live.Candidate) (RecoveryFinding, error) {
	f.inspects++
	if f.finding.Context != nil {
		leaf, _ := f.finding.Context.Identities()
		if !candidate.Matches(leaf.ProcessIdentity) {
			return RecoveryFinding{}, errors.New("unexpected opaque candidate")
		}
	}
	return f.finding, f.inspectErr
}

type recoveryTestEngineOpener struct {
	session RecoveryEngineSession
	err     error
	opens   int
}

func (o *recoveryTestEngineOpener) Open(context.Context, RecoveryContextView, recovery.Plan) (RecoveryEngineSession, error) {
	o.opens++
	return o.session, o.err
}

type recoveryTestSession struct {
	prepared     PreparedRecovery
	beginErr     error
	executeErr   error
	beginCalls   int
	executeCalls int
	closeCalls   int
	signals      int
	tokens       []string
}

func (s *recoveryTestSession) Begin(context.Context) (PreparedRecovery, error) {
	s.beginCalls++
	return s.prepared, s.beginErr
}

func (s *recoveryTestSession) Execute(_ context.Context, token string) (recovery.Result, error) {
	s.executeCalls++
	s.tokens = append(s.tokens, token)
	receiptID := s.prepared.ReceiptID
	if token != s.prepared.ConfirmationToken {
		return recovery.Result{Persisted: true, Receipt: model.LocalResultReceipt{ReceiptID: receiptID, Outcome: model.OutcomeRefused}}, recovery.ErrConfirmation
	}
	if s.executeErr != nil {
		return recovery.Result{Persisted: true, Receipt: model.LocalResultReceipt{ReceiptID: receiptID, Outcome: model.OutcomeRefused}}, s.executeErr
	}
	s.signals++
	return recovery.Result{Persisted: true, Receipt: model.LocalResultReceipt{ReceiptID: receiptID, Outcome: model.OutcomeVerified}}, nil
}

func (s *recoveryTestSession) Close() error { s.closeCalls++; return nil }

func TestRecoveryCompositionNoCandidateOpensNoReceiptStore(t *testing.T) {
	snapshot, _, _, _ := recoveryCompositionFixture(t)
	inspector := &recoveryTestInspector{discovery: live.Discover(darwin.ProcessSnapshot{
		Availability: model.AvailabilityAvailable, Processes: []darwin.ProcessRecord{}, Failures: []darwin.ProcessFailure{},
	})}
	opener := &recoveryTestEngineOpener{}
	service := &RecoveryService{Radar: fakeSnapshotter{snapshot: snapshot}, Inspector: inspector, Engines: opener, ToolVersion: "test"}
	err := service.Recover(context.Background(), strings.NewReader(""), io.Discard)
	requireRecoveryExit(t, err, recoveryExitLocked)
	if inspector.discovers != 1 || inspector.inspects != 0 || opener.opens != 0 {
		t.Fatalf("calls: discover=%d inspect=%d open=%d", inspector.discovers, inspector.inspects, opener.opens)
	}
}

func TestRecoveryCompositionNonselectableFindingOpensNoReceiptStore(t *testing.T) {
	snapshot, processSnapshot, detector, recoveryContext := recoveryCompositionFixture(t)
	detector.Selectable = false
	inspector := &recoveryTestInspector{
		discovery: live.Discover(processSnapshot),
		finding:   RecoveryFinding{Detector: detector, Context: recoveryContext},
	}
	opener := &recoveryTestEngineOpener{}
	service := &RecoveryService{Radar: fakeSnapshotter{snapshot: snapshot}, Inspector: inspector, Engines: opener, ToolVersion: "test"}
	err := service.Recover(context.Background(), strings.NewReader(""), io.Discard)
	requireRecoveryExit(t, err, recoveryExitLocked)
	if inspector.inspects != 1 || opener.opens != 0 {
		t.Fatalf("inspect=%d open=%d", inspector.inspects, opener.opens)
	}
}

func TestRecoveryEngineExitOutcomeMapping(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		code int
	}{
		{name: "confirmation refused", err: recovery.ErrConfirmation, code: recoveryExitLocked},
		{name: "revalidation refused", err: recovery.ErrRevalidation, code: recoveryExitLocked},
		{name: "capability locked", err: recovery.ErrRecoveryDisabled, code: recoveryExitLocked},
		{name: "signal partial", err: recovery.ErrSignal, code: recoveryExitPartial},
		{name: "verification partial", err: recovery.ErrVerification, code: recoveryExitPartial},
		{name: "failed plan", err: recovery.ErrInvalidPlan, code: recoveryExitFailed},
		{name: "receipt integrity", err: recovery.ErrReceiptStore, code: recoveryExitIntegrity},
	} {
		t.Run(test.name, func(t *testing.T) {
			requireRecoveryExit(t, recoveryEngineFailure(context.Background(), test.err), test.code)
		})
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	requireRecoveryExit(t, recoveryEngineFailure(cancelled, context.Canceled), recoveryExitCancelled)
}

func TestRecoveryCompositionAmbiguousRequiresExactSafeGroupID(t *testing.T) {
	snapshot, processSnapshot, detector, recoveryContext := recoveryCompositionFixture(t)
	secondParent := actionIdentity(51, "/Applications/ChatGPT.app/Contents/Resources/codex", 51)
	secondLeaf := actionIdentity(52, "/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node", 52)
	secondLeaf.StartTime = secondLeaf.StartTime.Add(2 * time.Second)
	secondParent.StartTime = secondParent.StartTime.Add(2 * time.Second)
	secondParentObservation := processObservation(secondParent.ProcessIdentity, 1, 512)
	secondLeafObservation := processObservation(secondLeaf.ProcessIdentity, secondParent.PID, 2048)
	processSnapshot.Processes = append(processSnapshot.Processes,
		darwin.ProcessRecord{Observation: secondParentObservation, ActionIdentity: secondParent, ActionAvailable: model.AvailabilityAvailable},
		darwin.ProcessRecord{Observation: secondLeafObservation, ActionIdentity: secondLeaf, ActionAvailable: model.AvailabilityAvailable},
	)
	slices.SortFunc(processSnapshot.Processes, func(a, b darwin.ProcessRecord) int {
		return int(a.Observation.Identity.PID - b.Observation.Identity.PID)
	})
	secondGroup := workflowGroup("wf-1111111111111111", secondParentObservation, secondLeafObservation)
	snapshot.Groups = append(snapshot.Groups, secondGroup)
	slices.SortFunc(snapshot.Groups, func(a, b model.WorkflowGroup) int { return strings.Compare(a.ID, b.ID) })
	discovery := live.Discover(processSnapshot)
	if discovery.Count != 2 {
		t.Fatalf("discovery count = %d", discovery.Count)
	}
	inspector := &recoveryTestInspector{discovery: discovery, finding: RecoveryFinding{Detector: detector, Context: recoveryContext}}
	session := &recoveryTestSession{prepared: PreparedRecovery{ReceiptID: recoveryTestReceiptID, ConfirmationToken: recoveryTestToken}}
	opener := &recoveryTestEngineOpener{session: session}
	service := &RecoveryService{Radar: fakeSnapshotter{snapshot: snapshot}, Inspector: inspector, Engines: opener, ToolVersion: "test"}

	var output bytes.Buffer
	input := strings.NewReader("wf-0000000000000001\n" + recoveryTestToken + "\n")
	if err := service.Recover(context.Background(), input, &output); err != nil {
		t.Fatal(err)
	}
	for _, safe := range []string{"wf-0000000000000001", "wf-1111111111111111", "codex", "bytes RSS", "exact 6-second"} {
		if !strings.Contains(output.String(), safe) {
			t.Fatalf("missing %q in %q", safe, output.String())
		}
	}
	for _, private := range []string{"/Applications/", "/synthetic/", "state_5.sqlite"} {
		if strings.Contains(output.String(), private) {
			t.Fatalf("output leaked %q: %s", private, output.String())
		}
	}
	if inspector.discovers != 1 || inspector.inspects != 1 || session.beginCalls != 1 || session.executeCalls != 1 || session.signals != 1 {
		t.Fatalf("calls: inspector=%d/%d begin=%d execute=%d signals=%d", inspector.discovers, inspector.inspects, session.beginCalls, session.executeCalls, session.signals)
	}

	wrong := &recoveryTestSession{prepared: PreparedRecovery{ReceiptID: recoveryTestReceiptID, ConfirmationToken: recoveryTestToken}}
	service.Engines = &recoveryTestEngineOpener{session: wrong}
	inspector.inspects = 0
	err := service.Recover(context.Background(), strings.NewReader("WF-0000000000000001\n"), io.Discard)
	requireRecoveryExit(t, err, recoveryExitLocked)
	if inspector.inspects != 0 || wrong.beginCalls != 0 {
		t.Fatalf("wrong selection reached inspect/begin: %d/%d", inspector.inspects, wrong.beginCalls)
	}
}

func TestRecoveryCompositionWrongTokenAndRevalidationDriftNeverSignal(t *testing.T) {
	snapshot, processSnapshot, detector, recoveryContext := recoveryCompositionFixture(t)
	discovery := live.Discover(processSnapshot)
	for _, test := range []struct {
		name       string
		input      string
		executeErr error
	}{
		{name: "wrong token", input: "WRONG\n"},
		{name: "oversized token", input: strings.Repeat("A", maxTokenBytes+1) + "\n"},
		{name: "revalidation drift", input: recoveryTestToken + "\n", executeErr: recovery.ErrRevalidation},
	} {
		t.Run(test.name, func(t *testing.T) {
			inspector := &recoveryTestInspector{discovery: discovery, finding: RecoveryFinding{Detector: detector, Context: recoveryContext}}
			session := &recoveryTestSession{prepared: PreparedRecovery{ReceiptID: recoveryTestReceiptID, ConfirmationToken: recoveryTestToken}, executeErr: test.executeErr}
			service := &RecoveryService{Radar: fakeSnapshotter{snapshot: snapshot}, Inspector: inspector, Engines: &recoveryTestEngineOpener{session: session}, ToolVersion: "test"}
			err := service.Recover(context.Background(), strings.NewReader(test.input), io.Discard)
			requireRecoveryExit(t, err, recoveryExitLocked)
			if session.beginCalls != 1 || session.executeCalls != 1 || session.signals != 0 {
				t.Fatalf("begin=%d execute=%d signals=%d", session.beginCalls, session.executeCalls, session.signals)
			}
		})
	}
}

func TestRecoveryCompositionVerifiedSendsExactlyOneSignal(t *testing.T) {
	snapshot, processSnapshot, detector, recoveryContext := recoveryCompositionFixture(t)
	inspector := &recoveryTestInspector{discovery: live.Discover(processSnapshot), finding: RecoveryFinding{Detector: detector, Context: recoveryContext}}
	session := &recoveryTestSession{prepared: PreparedRecovery{ReceiptID: recoveryTestReceiptID, ConfirmationToken: recoveryTestToken}}
	service := &RecoveryService{Radar: fakeSnapshotter{snapshot: snapshot}, Inspector: inspector, Engines: &recoveryTestEngineOpener{session: session}, ToolVersion: "test"}
	var output bytes.Buffer
	if err := service.Recover(context.Background(), strings.NewReader(recoveryTestToken+"\n"), &output); err != nil {
		t.Fatal(err)
	}
	if session.beginCalls != 1 || session.executeCalls != 1 || session.signals != 1 || session.closeCalls != 1 {
		t.Fatalf("begin=%d execute=%d signals=%d close=%d", session.beginCalls, session.executeCalls, session.signals, session.closeCalls)
	}
	preparedIndex := strings.Index(output.String(), "Prepared receipt")
	tokenIndex := strings.Index(output.String(), "Confirmation token")
	if preparedIndex < 0 || tokenIndex <= preparedIndex {
		t.Fatalf("token rendered before durable begin output: %q", output.String())
	}
}

type recoveryReadyWriter struct {
	mu    sync.Mutex
	data  bytes.Buffer
	ready chan struct{}
	once  sync.Once
}

func (w *recoveryReadyWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.data.Write(data)
	if strings.Contains(w.data.String(), "Confirmation token:") {
		w.once.Do(func() { close(w.ready) })
	}
	return n, err
}

func TestRecoveryCompositionCancellationConsumesPreparedTransactionWithoutSignal(t *testing.T) {
	snapshot, processSnapshot, detector, recoveryContext := recoveryCompositionFixture(t)
	inspector := &recoveryTestInspector{discovery: live.Discover(processSnapshot), finding: RecoveryFinding{Detector: detector, Context: recoveryContext}}
	session := &recoveryTestSession{prepared: PreparedRecovery{ReceiptID: recoveryTestReceiptID, ConfirmationToken: recoveryTestToken}}
	service := &RecoveryService{Radar: fakeSnapshotter{snapshot: snapshot}, Inspector: inspector, Engines: &recoveryTestEngineOpener{session: session}, ToolVersion: "test"}
	input, inputWriter := io.Pipe()
	defer input.Close()
	defer inputWriter.Close()
	output := &recoveryReadyWriter{ready: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- service.Recover(ctx, input, output) }()
	select {
	case <-output.ready:
	case <-time.After(time.Second):
		t.Fatal("confirmation prompt was not reached")
	}
	cancel()
	var err error
	select {
	case err = <-result:
	case <-time.After(time.Second):
		t.Fatal("cancelled recovery did not return")
	}
	requireRecoveryExit(t, err, recoveryExitCancelled)
	if session.beginCalls != 1 || session.executeCalls != 1 || session.signals != 0 || len(session.tokens) != 1 || session.tokens[0] != "" {
		t.Fatalf("begin=%d execute=%d signals=%d tokens=%q", session.beginCalls, session.executeCalls, session.signals, session.tokens)
	}
}

func TestRecoveryTransactionReplayProtectedSurvivalAndArchiveAvailability(t *testing.T) {
	_, _, detector, recoveryContext := recoveryCompositionFixture(t)
	authority := detector.Authority()
	plan, err := recovery.NewPlan(authority, recoveryContext.Protected(), recoveryContext.RSSBytes(), model.PressureUnknown, "test")
	if err != nil {
		t.Fatal(err)
	}
	root := archiveTestRoot(t)
	store, err := receipt.NewModelStore(root)
	if err != nil {
		t.Fatal(err)
	}
	candidate := plan.Candidate()
	signaler := &recoveryRecordingSignaler{}
	engine := recovery.Engine{
		Store:       store,
		Revalidator: recoveryStaticRevalidator{value: recovery.Revalidation{Candidate: candidate, Protected: plan.Protected(), SelectedRSSBytes: plan.SelectedRSSBytes(), Pressure: model.PressureUnknown}},
		Signaler:    signaler,
		Verifier:    recoveryStaticVerifier{value: recovery.Verification{TargetAbsent: true, ProtectedPresent: plan.Protected(), Pressure: model.PressureUnknown}},
		NewID:       func() (string, error) { return "r-0123456789abcdef0123456789abcdef", nil },
		Now:         func() time.Time { return recoveryTestTime },
		ToolVersion: "test",
	}
	session := &productionRecoverySession{engine: engine, store: store, plan: plan}
	prepared, err := session.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	result, err := session.Execute(context.Background(), prepared.ConfirmationToken)
	if err != nil {
		t.Fatal(err)
	}
	if result.Receipt.Outcome != model.OutcomeVerified || result.Receipt.ProtectedPresent != uint32(len(plan.Protected())) || result.Receipt.ProtectedSignaled != 0 {
		t.Fatalf("result receipt = %#v", result.Receipt)
	}
	if signaler.calls != 1 || !signaler.targets[0].Equal(candidate.Target) {
		t.Fatalf("signals = %d targets=%v", signaler.calls, signaler.targets)
	}
	if _, err := session.Execute(context.Background(), prepared.ConfirmationToken); !errors.Is(err, ErrRecoverySession) {
		t.Fatalf("replay error = %v", err)
	}
	if signaler.calls != 1 {
		t.Fatalf("replay signaled: %d", signaler.calls)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}

	archive := Archive{Root: root}
	entries, err := archive.History(context.Background())
	if err != nil || len(entries) != 1 || entries[0].State != receipt.StateResult {
		t.Fatalf("history = %#v, %v", entries, err)
	}
	private, err := archive.Receipt(context.Background(), prepared.ReceiptID, false)
	if err != nil || !bytes.Contains(private, []byte(`"schema_version":"runnel.result-receipt/v1"`)) {
		t.Fatalf("private receipt = %s, %v", private, err)
	}
	share, err := archive.Receipt(context.Background(), prepared.ReceiptID, true)
	if err != nil || !bytes.Contains(share, []byte(`"schema_version":"runnel.share-receipt/v1"`)) {
		t.Fatalf("share receipt = %s, %v", share, err)
	}
}

type recoveryStaticRevalidator struct{ value recovery.Revalidation }

func (r recoveryStaticRevalidator) Revalidate(context.Context, recovery.Plan) (recovery.Revalidation, error) {
	return r.value, nil
}

type recoveryRecordingSignaler struct {
	mu      sync.Mutex
	calls   int
	targets []model.DarwinActionIdentity
}

func (s *recoveryRecordingSignaler) SignalTERM(_ context.Context, target model.DarwinActionIdentity) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.targets = append(s.targets, target)
	return nil
}

type recoveryStaticVerifier struct{ value recovery.Verification }

func (v recoveryStaticVerifier) Verify(context.Context, model.DarwinActionIdentity, []model.DarwinActionIdentity) (recovery.Verification, error) {
	return v.value, nil
}

func requireRecoveryExit(t *testing.T, err error, want int) {
	t.Helper()
	var recoveryErr *RecoveryError
	if !errors.As(err, &recoveryErr) || recoveryErr.ExitCode() != want {
		t.Fatalf("error = %v, exit=%v, want=%d", err, recoveryErr, want)
	}
}

func recoveryCompositionFixture(t *testing.T) (model.Snapshot, darwin.ProcessSnapshot, codex.DetectorResult, recoveryTestContext) {
	t.Helper()
	samples := recoveryValidSamples()
	detector := codex.Evaluate(samples)
	if detector.Authority() == nil {
		t.Fatalf("detector did not issue authority: %#v", detector)
	}
	leaf, parent := samples[0].Identity, samples[0].Parent
	parentObservation := processObservation(parent.ProcessIdentity, 1, 1024)
	leafObservation := processObservation(leaf.ProcessIdentity, parent.PID, samples[0].RSSBytes)
	group := workflowGroup("wf-0000000000000001", parentObservation, leafObservation)
	snapshot := model.Snapshot{
		SchemaVersion: model.SnapshotSchemaVersion, ToolVersion: "test", ObservedAt: recoveryTestTime,
		Platform: model.Platform{OS: "darwin", Arch: "arm64"}, Availability: []model.ProbeAvailability{}, Groups: []model.WorkflowGroup{group},
	}
	processSnapshot := darwin.ProcessSnapshot{
		Availability: model.AvailabilityAvailable,
		Processes: []darwin.ProcessRecord{
			{Observation: parentObservation, ActionIdentity: parent, ActionAvailable: model.AvailabilityAvailable},
			{Observation: leafObservation, ActionIdentity: leaf, ActionAvailable: model.AvailabilityAvailable},
		},
		Failures: []darwin.ProcessFailure{},
	}
	discovery := live.Discover(processSnapshot)
	if discovery.Count != 1 {
		t.Fatalf("discovery count = %d", discovery.Count)
	}
	protected := actionIdentity(77, "/safe/protected", 77)
	context := recoveryTestContext{
		detector: detector, candidate: discovery.Candidates()[0], leaf: leaf, parent: parent,
		protected: []model.DarwinActionIdentity{protected}, tempRoots: []string{"/synthetic/tmp"},
		statePath: "/synthetic/state_5.sqlite", rollout: samples[0].Metadata.RolloutPath,
		rss: samples[0].RSSBytes, currentUID: 501,
	}
	return snapshot, processSnapshot, detector, context
}

func recoveryValidSamples() []codex.DeepSample {
	leafArgv := []string{
		"/Applications/ChatGPT.app/Contents/Resources/cua_node/bin/node",
		"--experimental-vm-modules", "/synthetic/tmp/job/trusted-worker.js", "/synthetic/work",
	}
	parentArgv := append([]string{"/Applications/ChatGPT.app/Contents/Resources/codex", "sandbox", "--"}, leafArgv...)
	leaf := actionIdentity(42, leafArgv[0], 42)
	parent := actionIdentity(41, parentArgv[0], 41)
	parent.StartTime = parent.StartTime.Add(-time.Second)
	origin := codex.OriginEvidence{
		Availability: model.AvailabilityAvailable,
		Codex:        codex.SignedArtifact{Availability: model.AvailabilityAvailable, ResolvedPath: parentArgv[0], Identifier: codex.CodexIdentifier, TeamIdentifier: codex.OpenAITeamIdentifier, SHA256: codex.CodexSHA256, SignatureValid: true},
		Node:         codex.SignedArtifact{Availability: model.AvailabilityAvailable, ResolvedPath: leafArgv[0], Identifier: codex.NodeIdentifier, TeamIdentifier: codex.OpenAITeamIdentifier, SHA256: codex.NodeSHA256, SignatureValid: true},
		Worker:       codex.HashedArtifact{Availability: model.AvailabilityAvailable, ResolvedPath: leafArgv[2], SHA256: codex.WorkerSHA256},
		LeafUID:      501, ParentUID: 501,
	}
	metadata := codex.MetadataSnapshot{
		Availability: model.AvailabilityAvailable, DataVersion: 7, CLIVersion: codex.SupportedCodexVersion,
		ThreadSource: "subagent", EdgeStatus: "closed", ThreadID: "child", ParentThreadID: "parent", RolloutPath: "/synthetic/rollout.jsonl",
	}
	file := codex.FileIdentity{Device: 1, Inode: 2, Size: 800, ModifiedNS: 1234}
	tail := codex.TailSnapshot{Availability: model.AvailabilityAvailable, EnvelopeType: "event_msg", EventType: "task_complete", Successful: true, File: file}
	descriptor := codex.DescriptorEvidence{Availability: model.AvailabilityAvailable, Path: metadata.RolloutPath, Device: 1, Inode: 2, Access: codex.DescriptorReadOnly}
	samples := make([]codex.DeepSample, 4)
	for index := range samples {
		samples[index] = codex.DeepSample{
			Offset:               time.Duration(index) * 2 * time.Second,
			IdentityAvailability: model.AvailabilityAvailable, Identity: leaf,
			ParentAvailability: model.AvailabilityAvailable, Parent: parent, CurrentUID: 501,
			LeafArgv: slices.Clone(leafArgv), ParentArgv: slices.Clone(parentArgv), TempRoots: []string{"/synthetic/tmp"}, Origin: origin,
			Metadata: metadata, Tail: tail, Descriptor: descriptor, CPUTimeNS: uint64(index+1) * 100, RSSBytes: 4096,
			TTY: codex.PresenceProbe{Availability: model.AvailabilityAvailable}, Sockets: codex.SocketProbe{Availability: model.AvailabilityAvailable},
			WritableActivity: codex.PresenceProbe{Availability: model.AvailabilityAvailable},
			Children:         codex.ChildrenProbe{Availability: model.AvailabilityAvailable, Children: []model.ProcessIdentity{}},
			Stack:            codex.StackEvidence{Availability: model.AvailabilityNotApplicable},
		}
	}
	samples[3].Stack = codex.StackEvidence{Availability: model.AvailabilityAvailable, Predicate: codex.SupportedStackPredicate}
	return samples
}

func actionIdentity(pid int32, executable string, version uint32) model.DarwinActionIdentity {
	return model.DarwinActionIdentity{
		ProcessIdentity: model.ProcessIdentity{PID: pid, StartTime: recoveryTestTime, UID: 501, Executable: executable},
		PIDVersion:      version, UniqueID: uint64(pid) + 1000,
	}
}

func processObservation(identity model.ProcessIdentity, parentPID int32, rss uint64) model.ProcessObservation {
	return model.ProcessObservation{
		Identity: identity, ParentPID: parentPID, RSSBytes: rss, Argv: []string{},
		Availability: []model.ProbeAvailability{{Probe: model.ProbeTTY, Status: model.AvailabilityAvailable}}, Evidence: []model.EvidenceCode{},
	}
}

func workflowGroup(id string, parent, leaf model.ProcessObservation) model.WorkflowGroup {
	processes := []model.ProcessObservation{parent, leaf}
	slices.SortFunc(processes, func(a, b model.ProcessObservation) int { return int(a.Identity.PID - b.Identity.PID) })
	return model.WorkflowGroup{
		ID: id, Root: parent.Identity, Family: model.WorkflowFamilyCodex, Classification: model.ClassificationQuietUnclassified,
		Attribution: []model.EvidenceCode{}, Protection: []model.EvidenceCode{}, Processes: processes,
		Aggregate: model.ResourceAggregate{ProcessCount: 2, RSSBytes: parent.RSSBytes + leaf.RSSBytes},
	}
}
