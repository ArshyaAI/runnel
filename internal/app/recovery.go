package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/ArshyaAI/runnel/internal/codex"
	"github.com/ArshyaAI/runnel/internal/live"
	"github.com/ArshyaAI/runnel/internal/model"
	"github.com/ArshyaAI/runnel/internal/recovery"
)

const (
	recoveryExitLocked    = 4
	recoveryExitPartial   = 5
	recoveryExitFailed    = 6
	recoveryExitIntegrity = 7
	recoveryExitCancelled = 130

	maxRecoveryChoices = 32
	maxGroupIDBytes    = 64
	maxTokenBytes      = 64
)

var (
	ErrRecoveryLocked        = errors.New("recovery is locked because the evidence is not uniquely selectable")
	ErrRecoveryCancelled     = errors.New("recovery cancelled")
	ErrRecoveryInput         = errors.New("recovery input is invalid")
	ErrRecoverySession       = errors.New("recovery session state is invalid")
	recoveryReceiptIDPattern = regexp.MustCompile(`^r-[0-9a-f]{32}$`)
	recoveryTokenPattern     = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
)

// RecoveryError carries the exact shell outcome without exposing private
// process or filesystem details through Error().
type RecoveryError struct {
	code    int
	message string
	cause   error
}

func (e *RecoveryError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.message
}

func (e *RecoveryError) Unwrap() error { return e.cause }
func (e *RecoveryError) ExitCode() int { return e.code }

// RecoveryInspector is the live read-only handoff. Candidate remains opaque:
// callers can select it only by matching it back to a radar group.
type RecoveryInspector interface {
	Discover(context.Context) (live.Discovery, error)
	Inspect(context.Context, live.Candidate) (RecoveryFinding, error)
}

// RecoveryContextView is the minimal immutable private context consumed by the
// action-time revalidator. live.RecoveryContext satisfies this interface.
type RecoveryContextView interface {
	DetectorResult() codex.DetectorResult
	Candidate() live.Candidate
	Identities() (model.DarwinActionIdentity, model.DarwinActionIdentity)
	CurrentUID() uint32
	TempRoots() []string
	StatePath() string
	RolloutPath() string
	Protected() []model.DarwinActionIdentity
	RSSBytes() uint64
}

// RecoveryFinding preserves the explicit three-gate handoff: a selectable
// Finding, its RecoveryContext, and its detector-issued ActionAuthority.
type RecoveryFinding struct {
	Detector codex.DetectorResult
	Context  RecoveryContextView
}

type recoveryInspector struct{ inspector *live.Inspector }

func (b recoveryInspector) Discover(ctx context.Context) (live.Discovery, error) {
	return b.inspector.Discover(ctx)
}

func (b recoveryInspector) Inspect(ctx context.Context, candidate live.Candidate) (RecoveryFinding, error) {
	finding, err := b.inspector.Inspect(ctx, candidate)
	if err != nil {
		return RecoveryFinding{}, err
	}
	detector := finding.DetectorResult()
	recoveryContext, ok := finding.RecoveryContext()
	if !ok {
		return RecoveryFinding{Detector: detector}, nil
	}
	return RecoveryFinding{Detector: detector, Context: recoveryContext}, nil
}

type PreparedRecovery struct {
	ReceiptID         string
	ConfirmationToken string
}

// RecoveryEngineSession owns exactly one transaction and one receipt store.
// Execute may be invoked only once after Begin.
type RecoveryEngineSession interface {
	Begin(context.Context) (PreparedRecovery, error)
	Execute(context.Context, string) (recovery.Result, error)
	Close() error
}

type RecoveryEngineOpener interface {
	Open(context.Context, RecoveryContextView, recovery.Plan) (RecoveryEngineSession, error)
}

// RecoveryService composes the fast radar, live inspector, opaque authority,
// durable recovery engine, and interactive confirmation. It accepts no PID.
type RecoveryService struct {
	Radar       Snapshotter
	Inspector   RecoveryInspector
	Engines     RecoveryEngineOpener
	ToolVersion string
}

type recoveryChoice struct {
	group     model.WorkflowGroup
	candidate live.Candidate
}

// Recover writes prompts to the injected terminal and reads only bounded
// lines from the injected terminal. The CLI owns the dual-TTY gate.
func (s *RecoveryService) Recover(ctx context.Context, input io.Reader, output io.Writer) error {
	if s == nil || s.Radar == nil || s.Inspector == nil || s.Engines == nil || s.ToolVersion == "" || input == nil || output == nil {
		return recoveryFailure(recoveryExitFailed, "recovery is unavailable", recovery.ErrRecoveryDisabled)
	}
	if err := ctx.Err(); err != nil {
		return recoveryFailure(recoveryExitCancelled, "recovery cancelled", err)
	}

	snapshot, _ := s.Radar.Snapshot(ctx)
	if err := ctx.Err(); err != nil {
		return recoveryFailure(recoveryExitCancelled, "recovery cancelled", err)
	}
	if err := snapshot.Validate(); err != nil {
		return recoveryFailure(recoveryExitLocked, "recovery locked: radar evidence is incomplete", ErrRecoveryLocked)
	}
	discovery, err := s.Inspector.Discover(ctx)
	if err != nil || discovery.Availability != model.AvailabilityAvailable || discovery.Code != live.CodeOK {
		return recoveryLockedOrCancelled(ctx, "recovery locked: live discovery is unavailable", err)
	}
	candidates := discovery.Candidates()
	if len(candidates) > maxRecoveryChoices {
		return recoveryFailure(recoveryExitLocked, "recovery locked: too many live candidates", ErrRecoveryLocked)
	}
	choices, err := recoveryChoices(snapshot.Groups, candidates)
	if err != nil || len(choices) == 0 {
		return recoveryFailure(recoveryExitLocked, "recovery locked: no unique live candidate", ErrRecoveryLocked)
	}

	reader := bufio.NewReaderSize(input, 128)
	choice, err := selectRecoveryChoice(ctx, reader, output, choices)
	if err != nil {
		if errors.Is(err, ErrRecoveryCancelled) {
			return recoveryFailure(recoveryExitCancelled, "recovery cancelled", err)
		}
		return recoveryFailure(recoveryExitLocked, "recovery locked: exact group selection required", err)
	}
	if _, err := fmt.Fprintf(output, "Inspecting %s for the exact 6-second evidence window...\n", choice.group.ID); err != nil {
		return recoveryFailure(recoveryExitFailed, "recovery output failed", err)
	}

	finding, err := s.Inspector.Inspect(ctx, choice.candidate)
	if err != nil {
		return recoveryLockedOrCancelled(ctx, "recovery locked: deep evidence did not complete", err)
	}
	if !finding.Detector.Selectable || finding.Context == nil {
		return recoveryFailure(recoveryExitLocked, "recovery locked: deep evidence is not selectable", ErrRecoveryLocked)
	}
	authority := finding.Detector.Authority()
	contextDetector := finding.Context.DetectorResult()
	if authority == nil || contextDetector.Authority() != authority {
		return recoveryFailure(recoveryExitLocked, "recovery locked: detector authority is unavailable", ErrRecoveryLocked)
	}
	leaf, _ := finding.Context.Identities()
	candidate, ok := authority.Candidate()
	if !ok || !candidate.Target.Equal(leaf) || !choice.candidate.Matches(leaf.ProcessIdentity) ||
		!finding.Context.Candidate().Matches(leaf.ProcessIdentity) {
		return recoveryFailure(recoveryExitLocked, "recovery locked: candidate identity changed", ErrRecoveryLocked)
	}

	plan, err := recovery.NewPlan(authority, finding.Context.Protected(), finding.Context.RSSBytes(), model.PressureUnknown, s.ToolVersion)
	if err != nil {
		return recoveryFailure(recoveryExitFailed, "recovery plan integrity failed", err)
	}
	// The receipt store is intentionally opened only after all selectable
	// evidence and authority gates above have passed.
	session, err := s.Engines.Open(ctx, finding.Context, plan)
	if err != nil {
		return recoveryEngineFailure(ctx, err)
	}
	defer session.Close()

	prepared, err := session.Begin(ctx)
	if err != nil {
		return recoveryEngineFailure(ctx, err)
	}
	if !recoveryReceiptIDPattern.MatchString(prepared.ReceiptID) || !recoveryTokenPattern.MatchString(prepared.ConfirmationToken) {
		_, _ = session.Execute(context.WithoutCancel(ctx), "")
		return recoveryFailure(recoveryExitIntegrity, "receipt integrity gate failed", ErrRecoverySession)
	}
	// Never render the confirmation capability until Begin has durably stored
	// the prepared receipt.
	if _, err := fmt.Fprintf(output, "Prepared receipt: %s\nConfirmation token: %s\nType the exact token to send identity-bound SIGTERM, or type cancel: ", prepared.ReceiptID, prepared.ConfirmationToken); err != nil {
		_, executeErr := session.Execute(context.WithoutCancel(ctx), "")
		if executeErr != nil && errors.Is(executeErr, recovery.ErrReceiptStore) {
			return recoveryFailure(recoveryExitIntegrity, "receipt integrity gate failed", executeErr)
		}
		return recoveryFailure(recoveryExitFailed, "recovery output failed", err)
	}
	token, readErr := readBoundedLineContext(ctx, reader, maxTokenBytes)
	cancelled := errors.Is(readErr, ErrRecoveryCancelled) || token == "cancel"
	if readErr != nil || cancelled {
		token = ""
	}
	executeCtx := ctx
	if cancelled {
		executeCtx = context.WithoutCancel(ctx)
	}
	result, executeErr := session.Execute(executeCtx, token)
	if result.Receipt.ReceiptID != "" && (!recoveryReceiptIDPattern.MatchString(result.Receipt.ReceiptID) ||
		result.Receipt.ReceiptID != prepared.ReceiptID || !result.Receipt.Outcome.Valid() || result.Receipt.Outcome == model.OutcomePrepared) {
		return recoveryFailure(recoveryExitIntegrity, "receipt integrity gate failed", ErrRecoverySession)
	}
	if executeErr == nil && result.Receipt.ReceiptID == "" {
		return recoveryFailure(recoveryExitIntegrity, "receipt integrity gate failed", ErrRecoverySession)
	}
	if result.Receipt.ReceiptID != "" {
		_, _ = fmt.Fprintf(output, "\nReceipt %s: %s\n", result.Receipt.ReceiptID, result.Receipt.Outcome)
	}
	if cancelled {
		if errors.Is(executeErr, recovery.ErrReceiptStore) {
			return recoveryFailure(recoveryExitIntegrity, "receipt integrity gate failed", executeErr)
		}
		return recoveryFailure(recoveryExitCancelled, "recovery cancelled", ErrRecoveryCancelled)
	}
	if readErr != nil && executeErr == nil {
		return recoveryFailure(recoveryExitLocked, "recovery locked: exact confirmation token required", readErr)
	}
	if executeErr != nil {
		return recoveryEngineFailure(ctx, executeErr)
	}
	if !result.Persisted || result.Receipt.Outcome != model.OutcomeVerified {
		return recoveryFailure(recoveryExitPartial, "recovery was not verified", recovery.ErrVerification)
	}
	return nil
}

func recoveryChoices(groups []model.WorkflowGroup, candidates []live.Candidate) ([]recoveryChoice, error) {
	if len(groups) == 0 || len(candidates) == 0 {
		return nil, ErrRecoveryLocked
	}
	choices := make([]recoveryChoice, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		matchingGroups := make([]model.WorkflowGroup, 0, 1)
		for _, group := range groups {
			matched := slices.ContainsFunc(group.Processes, func(process model.ProcessObservation) bool {
				return candidate.Matches(process.Identity)
			})
			if matched {
				matchingGroups = append(matchingGroups, group)
			}
		}
		if len(matchingGroups) != 1 {
			return nil, ErrRecoveryLocked
		}
		group := matchingGroups[0]
		if !findingIDPattern.MatchString(group.ID) {
			return nil, ErrRecoveryLocked
		}
		if _, duplicate := seen[group.ID]; duplicate {
			return nil, ErrRecoveryLocked
		}
		seen[group.ID] = struct{}{}
		choices = append(choices, recoveryChoice{group: group, candidate: candidate})
	}
	slices.SortFunc(choices, func(a, b recoveryChoice) int { return strings.Compare(a.group.ID, b.group.ID) })
	return choices, nil
}

func selectRecoveryChoice(ctx context.Context, reader *bufio.Reader, output io.Writer, choices []recoveryChoice) (recoveryChoice, error) {
	if len(choices) == 1 {
		return choices[0], nil
	}
	if _, err := fmt.Fprintln(output, "Multiple safe workflow groups match live candidates:"); err != nil {
		return recoveryChoice{}, err
	}
	for _, choice := range choices {
		if _, err := fmt.Fprintf(output, "%s\t%s\t%d bytes RSS\n", choice.group.ID, choice.group.Family, choice.group.Aggregate.RSSBytes); err != nil {
			return recoveryChoice{}, err
		}
	}
	if _, err := fmt.Fprint(output, "Type the exact workflow group ID, or type cancel: "); err != nil {
		return recoveryChoice{}, err
	}
	selected, err := readBoundedLineContext(ctx, reader, maxGroupIDBytes)
	if err != nil {
		return recoveryChoice{}, err
	}
	if selected == "cancel" {
		return recoveryChoice{}, ErrRecoveryCancelled
	}
	for _, choice := range choices {
		if selected == choice.group.ID {
			return choice, nil
		}
	}
	return recoveryChoice{}, ErrRecoveryInput
}

func readBoundedLine(reader *bufio.Reader, limit int) (string, error) {
	if reader == nil || limit <= 0 {
		return "", ErrRecoveryInput
	}
	line := make([]byte, 0, min(limit, 32))
	for {
		value, err := reader.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) > 0 {
				return string(line), nil
			}
			return "", ErrRecoveryInput
		}
		switch value {
		case '\n':
			return string(line), nil
		case '\r':
			next, peekErr := reader.Peek(1)
			if peekErr == nil && len(next) == 1 && next[0] == '\n' {
				_, _ = reader.ReadByte()
			}
			return string(line), nil
		default:
			if len(line) >= limit {
				return "", ErrRecoveryInput
			}
			line = append(line, value)
		}
	}
}

type boundedLineResult struct {
	value string
	err   error
}

func readBoundedLineContext(ctx context.Context, reader *bufio.Reader, limit int) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", ErrRecoveryCancelled
	}
	result := make(chan boundedLineResult, 1)
	go func() {
		value, err := readBoundedLine(reader, limit)
		result <- boundedLineResult{value: value, err: err}
	}()
	select {
	case <-ctx.Done():
		return "", ErrRecoveryCancelled
	case value := <-result:
		return value.value, value.err
	}
}

func recoveryLockedOrCancelled(ctx context.Context, message string, cause error) error {
	if err := ctx.Err(); err != nil {
		return recoveryFailure(recoveryExitCancelled, "recovery cancelled", err)
	}
	return recoveryFailure(recoveryExitLocked, message, errors.Join(ErrRecoveryLocked, cause))
}

func recoveryEngineFailure(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil && !errors.Is(err, recovery.ErrReceiptStore) {
		return recoveryFailure(recoveryExitCancelled, "recovery cancelled", errors.Join(err, ctxErr))
	}
	switch {
	case errors.Is(err, recovery.ErrReceiptStore):
		return recoveryFailure(recoveryExitIntegrity, "receipt integrity gate failed", err)
	case errors.Is(err, recovery.ErrConfirmation), errors.Is(err, recovery.ErrRevalidation), errors.Is(err, recovery.ErrRecoveryDisabled):
		return recoveryFailure(recoveryExitLocked, "recovery locked before signal", err)
	case errors.Is(err, recovery.ErrSignal), errors.Is(err, recovery.ErrVerification):
		return recoveryFailure(recoveryExitPartial, "recovery signal was not fully verified", err)
	default:
		return recoveryFailure(recoveryExitFailed, "recovery failed", err)
	}
}

func recoveryFailure(code int, message string, cause error) error {
	return &RecoveryError{code: code, message: message, cause: cause}
}
