package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/ArshyaAI/runnel/internal/buildinfo"
	"github.com/ArshyaAI/runnel/internal/codex"
	"github.com/ArshyaAI/runnel/internal/live"
	"github.com/ArshyaAI/runnel/internal/model"
	"github.com/ArshyaAI/runnel/internal/platform/darwin"
	"github.com/ArshyaAI/runnel/internal/receipt"
	"github.com/ArshyaAI/runnel/internal/recovery"
)

const (
	defaultVerificationTimeout  = 3 * time.Second
	defaultVerificationInterval = 50 * time.Millisecond
	maxVerificationPolls        = 256
)

var (
	errActionTimeDrift      = errors.New("action-time evidence changed")
	errPostSignalUnverified = errors.New("post-signal state is not exact")
)

// NewProductionRecovery constructs only read-only services. It does not open
// or create the receipt store; that happens lazily after selectable evidence.
func NewProductionRecovery(radar Snapshotter) (*RecoveryService, error) {
	if radar == nil {
		return nil, recovery.ErrRecoveryDisabled
	}
	inspector, err := live.NewProduction(live.Options{
		CurrentUID: uint32(os.Getuid()),
		TempRoots:  defaultTempRoots(),
	})
	if err != nil {
		return nil, err
	}
	version := buildinfo.Current().Version
	return &RecoveryService{
		Radar:       radar,
		Inspector:   recoveryInspector{inspector: inspector},
		Engines:     productionEngineOpener{toolVersion: version},
		ToolVersion: version,
	}, nil
}

type productionEngineOpener struct{ toolVersion string }

func (o productionEngineOpener) Open(ctx context.Context, recoveryContext RecoveryContextView, plan recovery.Plan) (RecoveryEngineSession, error) {
	if err := validateRecoveryContext(ctx, recoveryContext); err != nil {
		return nil, fmt.Errorf("%w: recovery context", recovery.ErrInvalidPlan)
	}
	leaf, _ := recoveryContext.Identities()
	if !plan.Candidate().Target.Equal(leaf) || !sameExactIdentitySet(plan.Protected(), recoveryContext.Protected()) || plan.PressureBefore() != model.PressureUnknown {
		return nil, fmt.Errorf("%w: context and plan differ", recovery.ErrInvalidPlan)
	}
	signaler := darwin.NewAuditTokenSignaler()
	if !signaler.Capability().Supported() {
		return nil, recovery.ErrRecoveryDisabled
	}
	root, err := receipt.DefaultRoot()
	if err != nil {
		return nil, fmt.Errorf("%w: receipt root", recovery.ErrReceiptStore)
	}
	store, err := receipt.NewModelStore(root)
	if err != nil {
		return nil, fmt.Errorf("%w: open receipt store", recovery.ErrReceiptStore)
	}
	collector := darwin.NewCollector(darwin.CollectorConfig{})
	adapter := codex.NewDarwinAdapter(collector, darwin.NewOriginVerifier())
	session := &productionRecoverySession{
		store: store,
		plan:  plan,
		engine: recovery.Engine{
			Store:       store,
			Revalidator: &actionTimeRevalidator{context: recoveryContext, collector: collector, adapter: adapter, state: productionStateOpener{}, tails: codex.NewTailReader(codex.TailReaderOptions{})},
			Signaler:    signaler,
			Verifier:    &postSignalVerifier{collector: collector, timeout: defaultVerificationTimeout, interval: defaultVerificationInterval, sleep: waitRecoveryPoll},
			NewID:       receipt.NewID,
			Now:         time.Now,
			ToolVersion: o.toolVersion,
		},
	}
	return session, nil
}

func validateRecoveryContext(ctx context.Context, value RecoveryContextView) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if value == nil {
		return ErrRecoverySession
	}
	detector := value.DetectorResult()
	authority := detector.Authority()
	if authority == nil {
		return ErrRecoverySession
	}
	leaf, parent := value.Identities()
	if leaf.Validate() != nil || parent.Validate() != nil || leaf.Equal(parent) {
		return ErrRecoverySession
	}
	if !value.Candidate().Matches(leaf.ProcessIdentity) || value.CurrentUID() != leaf.UID || parent.UID != leaf.UID {
		return ErrRecoverySession
	}
	authorized, ok := authority.Candidate()
	if !ok || !authorized.Target.Equal(leaf) {
		return ErrRecoverySession
	}
	for _, path := range []string{value.StatePath(), value.RolloutPath()} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return ErrRecoverySession
		}
	}
	tempRoots := value.TempRoots()
	if len(tempRoots) == 0 {
		return ErrRecoverySession
	}
	for _, root := range tempRoots {
		if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return ErrRecoverySession
		}
	}
	protected := value.Protected()
	for index, identity := range protected {
		if identity.Validate() != nil || identity.Equal(leaf) {
			return ErrRecoverySession
		}
		for previous := 0; previous < index; previous++ {
			if protected[previous].Equal(identity) {
				return ErrRecoverySession
			}
		}
	}
	return nil
}

type productionRecoverySession struct {
	mu       sync.Mutex
	engine   recovery.Engine
	store    *receipt.Store
	plan     recovery.Plan
	tx       recovery.Transaction
	begun    bool
	executed bool
	closed   bool
}

func (s *productionRecoverySession) Begin(ctx context.Context) (PreparedRecovery, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.begun || s.executed {
		return PreparedRecovery{}, ErrRecoverySession
	}
	tx, err := s.engine.Begin(ctx, s.plan)
	if err != nil {
		return PreparedRecovery{}, err
	}
	s.tx = tx
	s.begun = true
	return PreparedRecovery{ReceiptID: tx.ID, ConfirmationToken: tx.ConfirmationToken()}, nil
}

func (s *productionRecoverySession) Execute(ctx context.Context, token string) (recovery.Result, error) {
	s.mu.Lock()
	if s.closed || !s.begun || s.executed {
		s.mu.Unlock()
		return recovery.Result{}, ErrRecoverySession
	}
	s.executed = true
	tx := s.tx
	s.mu.Unlock()
	return s.engine.Execute(ctx, tx, token)
}

func (s *productionRecoverySession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.store == nil {
		return nil
	}
	return s.store.Close()
}

type recoveryCollector interface {
	ActionIdentity(context.Context, int32) (model.DarwinActionIdentity, error)
	Processes(context.Context) (darwin.ProcessSnapshot, error)
	Children(context.Context, model.DarwinActionIdentity, int) (darwin.ChildSnapshot, error)
}

type recoveryRechecker interface {
	RecheckDarwin(context.Context, codex.DetectorResult, codex.DarwinRecheckInput, codex.MetadataReader, codex.CompletionTailReader) codex.RecheckResult
}

type recoveryMetadataStore interface {
	codex.MetadataReader
	Close() error
}

type recoveryStateOpener interface {
	Open(context.Context, string) (recoveryMetadataStore, error)
}

type productionStateOpener struct{}

func (productionStateOpener) Open(ctx context.Context, path string) (recoveryMetadataStore, error) {
	return codex.OpenStore(ctx, path, codex.StoreOptions{})
}

// actionTimeRevalidator repeats all identity/tree/TTY/protected gates and then
// delegates the origin/argv/descriptor/socket/SQLite/tail proof to the pinned
// Codex Darwin adapter. It returns a Revalidation only when Allowed is true.
type actionTimeRevalidator struct {
	context   RecoveryContextView
	collector recoveryCollector
	adapter   recoveryRechecker
	state     recoveryStateOpener
	tails     codex.CompletionTailReader
}

func (r *actionTimeRevalidator) Revalidate(ctx context.Context, plan recovery.Plan) (recovery.Revalidation, error) {
	if r == nil || r.context == nil || r.collector == nil || r.adapter == nil || r.state == nil || r.tails == nil {
		return recovery.Revalidation{}, errActionTimeDrift
	}
	candidate := plan.Candidate()
	leafExpected, parentExpected := r.context.Identities()
	detector := r.context.DetectorResult()
	if !candidate.Target.Equal(leafExpected) || detector.Authority() == nil {
		return recovery.Revalidation{}, errActionTimeDrift
	}
	leaf, err := r.collector.ActionIdentity(ctx, leafExpected.PID)
	if err != nil || !leaf.Equal(leafExpected) {
		return recovery.Revalidation{}, errActionTimeDrift
	}
	parent, err := r.collector.ActionIdentity(ctx, parentExpected.PID)
	if err != nil || !parent.Equal(parentExpected) {
		return recovery.Revalidation{}, errActionTimeDrift
	}
	protected := plan.Protected()
	if !sameExactIdentitySet(protected, r.context.Protected()) {
		return recovery.Revalidation{}, errActionTimeDrift
	}
	for _, expected := range protected {
		current, identityErr := r.collector.ActionIdentity(ctx, expected.PID)
		if identityErr != nil || !current.Equal(expected) {
			return recovery.Revalidation{}, errActionTimeDrift
		}
	}
	children, err := r.collector.Children(ctx, leaf, 0)
	if err != nil || !exactEmptyChildren(children, leaf) {
		return recovery.Revalidation{}, errActionTimeDrift
	}
	snapshot, err := r.collector.Processes(ctx)
	if err != nil {
		return recovery.Revalidation{}, errActionTimeDrift
	}
	target, err := exactTargetRecord(snapshot, leaf, parent)
	if err != nil {
		return recovery.Revalidation{}, errActionTimeDrift
	}

	metadata, err := r.state.Open(ctx, r.context.StatePath())
	if err != nil || metadata == nil {
		return recovery.Revalidation{}, errActionTimeDrift
	}
	defer metadata.Close()
	result := r.adapter.RecheckDarwin(ctx, detector, codex.DarwinRecheckInput{
		CurrentUID:        r.context.CurrentUID(),
		TempRoots:         r.context.TempRoots(),
		TTY:               codex.PresenceProbe{Availability: model.AvailabilityAvailable, Present: false},
		Children:          codex.ChildrenProbe{Availability: model.AvailabilityAvailable, Children: []model.ProcessIdentity{}},
		LeafProtected:     false,
		ProtectedChildren: 0,
	}, metadata, r.tails)
	if !result.Allowed || result.Availability != model.AvailabilityAvailable {
		return recovery.Revalidation{}, errActionTimeDrift
	}
	// RecheckDarwin performs the expensive origin/digest/descriptor/SQLite/tail
	// work. Repeat the cheap identity, protected, childlessness, and TTY gates
	// after it returns so the Engine receives the freshest possible boundary.
	leaf, err = r.collector.ActionIdentity(ctx, leafExpected.PID)
	if err != nil || !leaf.Equal(leafExpected) {
		return recovery.Revalidation{}, errActionTimeDrift
	}
	parent, err = r.collector.ActionIdentity(ctx, parentExpected.PID)
	if err != nil || !parent.Equal(parentExpected) {
		return recovery.Revalidation{}, errActionTimeDrift
	}
	for _, expected := range protected {
		current, identityErr := r.collector.ActionIdentity(ctx, expected.PID)
		if identityErr != nil || !current.Equal(expected) {
			return recovery.Revalidation{}, errActionTimeDrift
		}
	}
	children, err = r.collector.Children(ctx, leaf, 0)
	if err != nil || !exactEmptyChildren(children, leaf) {
		return recovery.Revalidation{}, errActionTimeDrift
	}
	snapshot, err = r.collector.Processes(ctx)
	if err != nil {
		return recovery.Revalidation{}, errActionTimeDrift
	}
	target, err = exactTargetRecord(snapshot, leaf, parent)
	if err != nil {
		return recovery.Revalidation{}, errActionTimeDrift
	}
	return recovery.Revalidation{
		Candidate:        candidate,
		Protected:        protected,
		SelectedRSSBytes: target.Observation.RSSBytes,
		Pressure:         model.PressureUnknown,
	}, nil
}

func sameExactIdentitySet(a, b []model.DarwinActionIdentity) bool {
	if len(a) != len(b) {
		return false
	}
	matched := make([]bool, len(b))
	for _, identity := range a {
		found := false
		for index, candidate := range b {
			if !matched[index] && identity.Equal(candidate) {
				matched[index] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func exactEmptyChildren(snapshot darwin.ChildSnapshot, target model.DarwinActionIdentity) bool {
	return snapshot.Availability == model.AvailabilityAvailable && snapshot.Identity.Equal(target) &&
		!snapshot.Truncated && len(snapshot.Failures) == 0 && len(snapshot.Children) == 0
}

func exactTargetRecord(snapshot darwin.ProcessSnapshot, target, parent model.DarwinActionIdentity) (darwin.ProcessRecord, error) {
	if snapshot.Availability != model.AvailabilityAvailable || snapshot.Truncated {
		return darwin.ProcessRecord{}, errActionTimeDrift
	}
	for _, failure := range snapshot.Failures {
		if failure.PID == target.PID || failure.PID == parent.PID {
			return darwin.ProcessRecord{}, errActionTimeDrift
		}
	}
	var matches []darwin.ProcessRecord
	for _, record := range snapshot.Processes {
		if record.Observation.Identity.PID == target.PID {
			matches = append(matches, record)
		}
	}
	if len(matches) != 1 {
		return darwin.ProcessRecord{}, errActionTimeDrift
	}
	record := matches[0]
	if !record.ActionIdentity.Equal(target) || record.ActionAvailable != model.AvailabilityAvailable ||
		!record.Observation.Identity.Equal(target.ProcessIdentity) || record.Observation.ParentPID != parent.PID ||
		record.Observation.TTY != "" || probeAvailability(record.Observation.Availability, model.ProbeTTY) != model.AvailabilityAvailable {
		return darwin.ProcessRecord{}, errActionTimeDrift
	}
	return record, nil
}

func probeAvailability(values []model.ProbeAvailability, probe model.ProbeKind) model.Availability {
	matched := model.AvailabilityContradictory
	count := 0
	for _, value := range values {
		if value.Probe == probe {
			matched = value.Status
			count++
		}
	}
	if count != 1 {
		return model.AvailabilityContradictory
	}
	return matched
}

type recoveryPollSleeper func(context.Context, time.Duration) error

type postSignalVerifier struct {
	collector recoveryCollector
	timeout   time.Duration
	interval  time.Duration
	sleep     recoveryPollSleeper
}

func (v *postSignalVerifier) Verify(ctx context.Context, target model.DarwinActionIdentity, protected []model.DarwinActionIdentity) (recovery.Verification, error) {
	verification := recovery.Verification{Pressure: model.PressureUnknown, ProtectedPresent: []model.DarwinActionIdentity{}}
	if v == nil || v.collector == nil || target.Validate() != nil {
		return verification, errPostSignalUnverified
	}
	for _, identity := range protected {
		if identity.Validate() != nil || identity.Equal(target) {
			return verification, errPostSignalUnverified
		}
	}
	timeout := v.timeout
	if timeout <= 0 {
		timeout = defaultVerificationTimeout
	}
	interval := v.interval
	if interval <= 0 {
		interval = defaultVerificationInterval
	}
	sleeper := v.sleep
	if sleeper == nil {
		sleeper = waitRecoveryPoll
	}
	verifyCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	present, err := exactProtectedPresent(verifyCtx, v.collector, protected)
	verification.ProtectedPresent = present
	if err != nil {
		return verification, errPostSignalUnverified
	}
	pollRatio := timeout / interval
	polls := maxVerificationPolls
	if pollRatio < maxVerificationPolls {
		polls = max(1, int(pollRatio)+1)
	}
	for poll := 0; poll < polls; poll++ {
		current, identityErr := v.collector.ActionIdentity(verifyCtx, target.PID)
		switch {
		case identityErr == nil && current.Equal(target):
			children, childErr := v.collector.Children(verifyCtx, target, 0)
			if childErr != nil || !exactEmptyChildren(children, target) {
				return verification, errPostSignalUnverified
			}
		case identityErr == nil:
			// The PID was replaced. Replacement is not target absence.
			return verification, errPostSignalUnverified
		case !processAbsent(identityErr):
			return verification, errPostSignalUnverified
		default:
			if err := verifyFinalAbsence(verifyCtx, v.collector, target, protected); err != nil {
				return verification, errPostSignalUnverified
			}
			present, err = exactProtectedPresent(verifyCtx, v.collector, protected)
			verification.ProtectedPresent = present
			if err != nil {
				return verification, errPostSignalUnverified
			}
			verification.TargetAbsent = true
			return verification, nil
		}
		if poll+1 < polls {
			if err := sleeper(verifyCtx, interval); err != nil {
				return verification, errPostSignalUnverified
			}
		}
	}
	return verification, errPostSignalUnverified
}

func exactProtectedPresent(ctx context.Context, collector recoveryCollector, protected []model.DarwinActionIdentity) ([]model.DarwinActionIdentity, error) {
	present := make([]model.DarwinActionIdentity, 0, len(protected))
	for _, expected := range protected {
		current, err := collector.ActionIdentity(ctx, expected.PID)
		if err != nil || !current.Equal(expected) {
			return present, errPostSignalUnverified
		}
		present = append(present, expected)
	}
	return present, nil
}

func verifyFinalAbsence(ctx context.Context, collector recoveryCollector, target model.DarwinActionIdentity, protected []model.DarwinActionIdentity) error {
	snapshot, err := collector.Processes(ctx)
	if err != nil || snapshot.Availability != model.AvailabilityAvailable || snapshot.Truncated {
		return errPostSignalUnverified
	}
	if len(snapshot.Failures) != 0 {
		// A missing process record could be a newly spawned child or a PID
		// replacement, so an incomplete host snapshot cannot prove absence.
		return errPostSignalUnverified
	}
	for _, record := range snapshot.Processes {
		if record.Observation.Identity.PID == target.PID || record.Observation.ParentPID == target.PID {
			return errPostSignalUnverified
		}
	}
	for _, expected := range protected {
		matches := 0
		for _, record := range snapshot.Processes {
			if record.Observation.Identity.PID == expected.PID {
				if !record.ActionIdentity.Equal(expected) || record.ActionAvailable != model.AvailabilityAvailable {
					return errPostSignalUnverified
				}
				matches++
			}
		}
		if matches != 1 {
			return errPostSignalUnverified
		}
	}
	// Seal the host snapshot against an immediate PID replacement.
	if _, err := collector.ActionIdentity(ctx, target.PID); !processAbsent(err) {
		return errPostSignalUnverified
	}
	return nil
}

func processAbsent(err error) bool {
	if err == nil {
		return false
	}
	var operation *darwin.OperationError
	return errors.Is(err, syscall.ESRCH) || errors.Is(err, os.ErrNotExist) ||
		(errors.As(err, &operation) && operation.Availability == model.AvailabilityProcessExited)
}

func waitRecoveryPoll(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
