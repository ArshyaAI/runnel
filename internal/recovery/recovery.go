// Package recovery owns Runnel's only user-process mutation capability.
// It accepts no raw PID and can signal only an opaque, fully gated Plan.
package recovery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"time"

	"github.com/ArshyaAI/runnel/internal/codex"
	"github.com/ArshyaAI/runnel/internal/model"
)

var (
	ErrInvalidPlan       = errors.New("invalid recovery plan")
	ErrConfirmation      = errors.New("confirmation token mismatch")
	ErrRevalidation      = errors.New("action-time revalidation refused")
	ErrSignal            = errors.New("identity-bound SIGTERM failed")
	ErrVerification      = errors.New("post-signal verification failed")
	ErrReceiptStore      = errors.New("receipt store failed")
	ErrRecoveryDisabled  = errors.New("live recovery is unavailable")
	confirmationEncoding = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)
)

type ReceiptStore interface {
	Prepare(context.Context, string, []byte) error
	ClaimExecution(context.Context, string, string) error
	Finalize(context.Context, string, []byte) error
}

// Revalidator repeats every action-grade detector, metadata, rollout, descriptor,
// origin, childlessness, TTY, and socket gate immediately before signaling.
type Revalidator interface {
	Revalidate(context.Context, Plan) (Revalidation, error)
}

// Signaler must implement an identity-bound SIGTERM primitive. A raw-PID
// implementation does not satisfy this interface's contract.
type Signaler interface {
	SignalTERM(context.Context, model.DarwinActionIdentity) error
}

type Verifier interface {
	Verify(context.Context, model.DarwinActionIdentity, []model.DarwinActionIdentity) (Verification, error)
}

type IDGenerator func() (string, error)
type Clock func() time.Time

type Plan struct {
	authority        *codex.ActionAuthority
	authorityProof   [sha256.Size]byte
	candidate        model.ActionCandidate
	protected        []model.DarwinActionIdentity
	selectedRSSBytes uint64
	pressureBefore   model.PressureLevel
	toolVersion      string
	proof            [32]byte
}

type Revalidation struct {
	Candidate        model.ActionCandidate
	Protected        []model.DarwinActionIdentity
	SelectedRSSBytes uint64
	Pressure         model.PressureLevel
}

type Verification struct {
	TargetAbsent     bool
	ProtectedPresent []model.DarwinActionIdentity
	Pressure         model.PressureLevel
}

type Transaction struct {
	ID                  string
	plan                Plan
	confirmationToken   string
	confirmationBinding [sha256.Size]byte
	preparedDigest      [sha256.Size]byte
}

func (t Transaction) ConfirmationToken() string { return t.confirmationToken }

type Result struct {
	Receipt   model.LocalResultReceipt
	Persisted bool
}

type Engine struct {
	Store       ReceiptStore
	Revalidator Revalidator
	Signaler    Signaler
	Verifier    Verifier
	NewID       IDGenerator
	Now         Clock
	ToolVersion string
	random      io.Reader
}

func NewPlan(authority *codex.ActionAuthority, protected []model.DarwinActionIdentity, selectedRSSBytes uint64, pressure model.PressureLevel, toolVersion string) (Plan, error) {
	candidate, candidateOK := authority.Candidate()
	authorityProof, proofOK := authority.Provenance()
	if !candidateOK || !proofOK || authorityProof == ([sha256.Size]byte{}) {
		return Plan{}, fmt.Errorf("%w: codex action authority is absent or invalid", ErrInvalidPlan)
	}
	if toolVersion == "" || !pressure.Valid() {
		return Plan{}, fmt.Errorf("%w: tool version and pressure are required", ErrInvalidPlan)
	}
	protected = slices.Clone(protected)
	sortDarwinIdentities(protected)
	for i, identity := range protected {
		if err := identity.Validate(); err != nil {
			return Plan{}, fmt.Errorf("%w: protected[%d]: %v", ErrInvalidPlan, i, err)
		}
		if candidate.Target.Equal(identity) {
			return Plan{}, fmt.Errorf("%w: target is protected", ErrInvalidPlan)
		}
		if i > 0 && protected[i-1].Equal(identity) {
			return Plan{}, fmt.Errorf("%w: duplicate protected identity", ErrInvalidPlan)
		}
	}
	proof, err := planProof(authorityProof, candidate, protected, selectedRSSBytes, pressure, toolVersion)
	if err != nil {
		return Plan{}, fmt.Errorf("%w: %v", ErrInvalidPlan, err)
	}
	return Plan{
		authority:        authority,
		authorityProof:   authorityProof,
		candidate:        candidate,
		protected:        protected,
		selectedRSSBytes: selectedRSSBytes,
		pressureBefore:   pressure,
		toolVersion:      toolVersion,
		proof:            proof,
	}, nil
}

func (p Plan) Candidate() model.ActionCandidate        { return cloneCandidate(p.candidate) }
func (p Plan) Protected() []model.DarwinActionIdentity { return slices.Clone(p.protected) }
func (p Plan) SelectedRSSBytes() uint64                { return p.selectedRSSBytes }
func (p Plan) PressureBefore() model.PressureLevel     { return p.pressureBefore }

func (e Engine) Begin(ctx context.Context, plan Plan) (Transaction, error) {
	if err := e.validate(); err != nil {
		return Transaction{}, err
	}
	if err := validatePlanIntegrity(plan); err != nil {
		return Transaction{}, err
	}
	if plan.toolVersion != e.ToolVersion {
		return Transaction{}, fmt.Errorf("%w: engine and plan versions differ", ErrInvalidPlan)
	}
	if err := ctx.Err(); err != nil {
		return Transaction{}, err
	}
	id, err := e.NewID()
	if err != nil {
		return Transaction{}, fmt.Errorf("%w: generate id: %v", ErrReceiptStore, err)
	}
	randomSource := e.random
	if randomSource == nil {
		randomSource = rand.Reader
	}
	token, err := newConfirmationToken(randomSource)
	if err != nil {
		return Transaction{}, fmt.Errorf("%w: generate confirmation token: %v", ErrReceiptStore, err)
	}
	binding := confirmationBinding(id, token)
	receipt := model.LocalPreparedReceipt{
		SchemaVersion:       model.PreparedReceiptSchemaVersion,
		ToolVersion:         e.ToolVersion,
		ReceiptID:           id,
		PreparedAt:          e.Now().UTC(),
		DetectorID:          plan.candidate.DetectorID,
		Target:              plan.candidate.Target,
		Protected:           slices.Clone(plan.protected),
		Evidence:            cloneEvidence(plan.candidate.Evidence),
		ConfirmationBinding: hex.EncodeToString(binding[:]),
		ConfirmationOK:      false,
		Outcome:             model.OutcomePrepared,
	}
	data, err := model.MarshalDeterministic(receipt)
	if err != nil {
		return Transaction{}, fmt.Errorf("%w: encode prepared: %v", ErrReceiptStore, err)
	}
	if err := e.Store.Prepare(ctx, id, data); err != nil {
		return Transaction{}, fmt.Errorf("%w: prepare: %v", ErrReceiptStore, err)
	}
	return Transaction{
		ID:                  id,
		plan:                plan,
		confirmationToken:   token,
		confirmationBinding: binding,
		preparedDigest:      sha256.Sum256(data),
	}, nil
}

func (e Engine) Execute(ctx context.Context, tx Transaction, token string) (Result, error) {
	if err := e.validate(); err != nil {
		return Result{}, err
	}
	if tx.ID == "" {
		return Result{}, fmt.Errorf("%w: transaction id is empty", ErrInvalidPlan)
	}
	if err := validatePlanIntegrity(tx.plan); err != nil {
		return Result{}, err
	}
	if err := validateTransactionIntegrity(tx); err != nil {
		return Result{}, err
	}
	preparedDigest := hex.EncodeToString(tx.preparedDigest[:])
	if err := e.Store.ClaimExecution(ctx, tx.ID, preparedDigest); err != nil {
		return Result{}, fmt.Errorf("%w: claim execution: %v", ErrReceiptStore, err)
	}
	providedBinding := confirmationBinding(tx.ID, token)
	if subtle.ConstantTimeCompare(providedBinding[:], tx.confirmationBinding[:]) != 1 {
		return e.finalize(context.WithoutCancel(ctx), tx, refusedReceipt(e, tx, false, model.ErrorConfirmationMismatch), ErrConfirmation)
	}
	if err := ctx.Err(); err != nil {
		return e.finalize(context.WithoutCancel(ctx), tx, refusedReceipt(e, tx, true, model.ErrorCandidateUnavailable), err)
	}

	revalidated, err := e.Revalidator.Revalidate(ctx, tx.plan)
	if err != nil || validateRevalidation(tx.plan, revalidated) != nil {
		return e.finalize(context.WithoutCancel(ctx), tx, refusedReceipt(e, tx, true, model.ErrorEvidenceChanged), fmt.Errorf("%w: %v", ErrRevalidation, err))
	}

	attempt := model.SignalAttempt{Target: revalidated.Candidate.Target, Attempted: true, ErrorCode: model.ErrorNone}
	signalErr := e.Signaler.SignalTERM(ctx, revalidated.Candidate.Target)
	if signalErr != nil {
		attempt.ErrorCode = model.ErrorSignalFailed
	}
	verification, verifyErr := e.Verifier.Verify(context.WithoutCancel(ctx), revalidated.Candidate.Target, revalidated.Protected)
	receipt := resultReceipt(e, tx, revalidated, attempt, verification, signalErr, verifyErr)
	var operationErr error
	if signalErr != nil {
		operationErr = fmt.Errorf("%w: %v", ErrSignal, signalErr)
	} else if verifyErr != nil || !verification.TargetAbsent || !sameDarwinIdentities(verification.ProtectedPresent, revalidated.Protected) {
		operationErr = fmt.Errorf("%w: %v", ErrVerification, verifyErr)
	}
	return e.finalize(context.WithoutCancel(ctx), tx, receipt, operationErr)
}

func (e Engine) validate() error {
	if e.Store == nil || e.Revalidator == nil || e.Signaler == nil || e.Verifier == nil || e.NewID == nil || e.Now == nil || e.ToolVersion == "" {
		return fmt.Errorf("%w: engine dependencies are incomplete", ErrRecoveryDisabled)
	}
	return nil
}

func (e Engine) finalize(ctx context.Context, tx Transaction, receipt model.LocalResultReceipt, operationErr error) (Result, error) {
	data, err := model.MarshalDeterministic(receipt)
	if err != nil {
		return Result{Receipt: receipt}, errors.Join(operationErr, fmt.Errorf("%w: encode result: %v", ErrReceiptStore, err))
	}
	if err := e.Store.Finalize(ctx, tx.ID, data); err != nil {
		return Result{Receipt: receipt}, errors.Join(operationErr, fmt.Errorf("%w: finalize: %v", ErrReceiptStore, err))
	}
	return Result{Receipt: receipt, Persisted: true}, operationErr
}

func refusedReceipt(e Engine, tx Transaction, confirmationOK bool, code model.ErrorCode) model.LocalResultReceipt {
	return model.LocalResultReceipt{
		SchemaVersion:        model.ResultReceiptSchemaVersion,
		ToolVersion:          e.ToolVersion,
		ReceiptID:            tx.ID,
		PreparedDigest:       hex.EncodeToString(tx.preparedDigest[:]),
		FinalizedAt:          e.Now().UTC(),
		Outcome:              model.OutcomeRefused,
		ConfirmationOK:       confirmationOK,
		Revalidation:         cloneEvidence(tx.plan.candidate.Evidence),
		SignalAttempts:       []model.SignalAttempt{},
		TargetExitCount:      0,
		ProtectedSignaled:    0,
		ProtectedPresent:     uint32(len(tx.plan.protected)),
		SelectedRSSBytes:     tx.plan.selectedRSSBytes,
		MemoryPressureBefore: tx.plan.pressureBefore,
		MemoryPressureAfter:  tx.plan.pressureBefore,
		ErrorCodes:           []model.ErrorCode{code},
	}
}

func resultReceipt(e Engine, tx Transaction, revalidation Revalidation, attempt model.SignalAttempt, verification Verification, signalErr, verifyErr error) model.LocalResultReceipt {
	outcome := model.OutcomeVerified
	errorsOut := []model.ErrorCode{}
	targetExit := uint32(0)
	if verification.TargetAbsent {
		targetExit = 1
	}
	if signalErr != nil {
		outcome = model.OutcomePartial
		errorsOut = append(errorsOut, model.ErrorSignalFailed)
	}
	if verifyErr != nil || !verification.TargetAbsent || !sameDarwinIdentities(verification.ProtectedPresent, revalidation.Protected) {
		outcome = model.OutcomePartial
		errorsOut = append(errorsOut, model.ErrorVerificationFailed)
	}
	slices.Sort(errorsOut)
	errorsOut = slices.Compact(errorsOut)
	return model.LocalResultReceipt{
		SchemaVersion:        model.ResultReceiptSchemaVersion,
		ToolVersion:          e.ToolVersion,
		ReceiptID:            tx.ID,
		PreparedDigest:       hex.EncodeToString(tx.preparedDigest[:]),
		FinalizedAt:          e.Now().UTC(),
		Outcome:              outcome,
		ConfirmationOK:       true,
		Revalidation:         cloneEvidence(revalidation.Candidate.Evidence),
		SignalAttempts:       []model.SignalAttempt{attempt},
		TargetExitCount:      targetExit,
		ProtectedSignaled:    0,
		ProtectedPresent:     uint32(len(verification.ProtectedPresent)),
		SelectedRSSBytes:     revalidation.SelectedRSSBytes,
		MemoryPressureBefore: tx.plan.pressureBefore,
		MemoryPressureAfter:  verification.Pressure,
		ErrorCodes:           errorsOut,
	}
}

func validatePlanIntegrity(plan Plan) error {
	rebuilt, err := NewPlan(plan.authority, plan.protected, plan.selectedRSSBytes, plan.pressureBefore, plan.toolVersion)
	if err != nil {
		return err
	}
	if rebuilt.authorityProof != plan.authorityProof ||
		!sameCandidate(rebuilt.candidate, plan.candidate) ||
		rebuilt.proof != plan.proof {
		return fmt.Errorf("%w: plan proof mismatch", ErrInvalidPlan)
	}
	return nil
}

func validateTransactionIntegrity(tx Transaction) error {
	if tx.preparedDigest == ([sha256.Size]byte{}) || tx.confirmationBinding == ([sha256.Size]byte{}) {
		return fmt.Errorf("%w: transaction bindings are absent", ErrInvalidPlan)
	}
	decoded, err := confirmationEncoding.DecodeString(tx.confirmationToken)
	if err != nil || len(decoded) != 16 {
		return fmt.Errorf("%w: transaction confirmation token is malformed", ErrInvalidPlan)
	}
	expected := confirmationBinding(tx.ID, tx.confirmationToken)
	if subtle.ConstantTimeCompare(expected[:], tx.confirmationBinding[:]) != 1 {
		return fmt.Errorf("%w: transaction confirmation binding mismatch", ErrInvalidPlan)
	}
	return nil
}

func validateRevalidation(plan Plan, current Revalidation) error {
	if err := current.Candidate.Validate(); err != nil {
		return err
	}
	if !sameCandidate(current.Candidate, plan.candidate) {
		return ErrRevalidation
	}
	protected := slices.Clone(current.Protected)
	sortDarwinIdentities(protected)
	if len(protected) != len(plan.protected) {
		return ErrRevalidation
	}
	for i := range protected {
		if !protected[i].Equal(plan.protected[i]) {
			return ErrRevalidation
		}
	}
	if !current.Pressure.Valid() {
		return ErrRevalidation
	}
	return nil
}

func planProof(authorityProof [sha256.Size]byte, candidate model.ActionCandidate, protected []model.DarwinActionIdentity, rss uint64, pressure model.PressureLevel, version string) ([32]byte, error) {
	candidateJSON, err := model.MarshalDeterministic(candidate)
	if err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	h.Write([]byte("runnel-recovery-plan/v1\x00"))
	h.Write(authorityProof[:])
	h.Write(candidateJSON)
	for _, identity := range protected {
		fmt.Fprintf(h, "\x00%d\x00%s\x00%d\x00%s\x00%d\x00%d", identity.PID, identity.StartTime.UTC().Format(time.RFC3339Nano), identity.UID, identity.Executable, identity.PIDVersion, identity.UniqueID)
	}
	fmt.Fprintf(h, "\x00%d\x00%s\x00%s", rss, pressure, version)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

func newConfirmationToken(source io.Reader) (string, error) {
	var nonce [16]byte
	if _, err := io.ReadFull(source, nonce[:]); err != nil {
		return "", err
	}
	return confirmationEncoding.EncodeToString(nonce[:]), nil
}

func confirmationBinding(receiptID, token string) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte("runnel-confirmation-binding/v1\x00"))
	h.Write([]byte(receiptID))
	h.Write([]byte{0})
	h.Write([]byte(token))
	var result [sha256.Size]byte
	copy(result[:], h.Sum(nil))
	return result
}

func cloneEvidence(in model.DetectorEvidence) model.DetectorEvidence {
	return model.DetectorEvidence{
		Availability: slices.Clone(in.Availability),
		Codes:        slices.Clone(in.Codes),
	}
}

func cloneCandidate(in model.ActionCandidate) model.ActionCandidate {
	out := in
	out.Evidence = cloneEvidence(in.Evidence)
	return out
}

func sameCandidate(a, b model.ActionCandidate) bool {
	return a.DetectorID == b.DetectorID && a.Classification == b.Classification &&
		a.Target.Equal(b.Target) &&
		slices.Equal(a.Evidence.Availability, b.Evidence.Availability) &&
		slices.Equal(a.Evidence.Codes, b.Evidence.Codes)
}

func sortDarwinIdentities(values []model.DarwinActionIdentity) {
	sort.Slice(values, func(i, j int) bool {
		a, b := values[i], values[j]
		if a.PID != b.PID {
			return a.PID < b.PID
		}
		if !a.StartTime.Equal(b.StartTime) {
			return a.StartTime.Before(b.StartTime)
		}
		if a.UID != b.UID {
			return a.UID < b.UID
		}
		if a.Executable != b.Executable {
			return a.Executable < b.Executable
		}
		if a.PIDVersion != b.PIDVersion {
			return a.PIDVersion < b.PIDVersion
		}
		return a.UniqueID < b.UniqueID
	})
}

func sameDarwinIdentities(a, b []model.DarwinActionIdentity) bool {
	if len(a) != len(b) {
		return false
	}
	a = slices.Clone(a)
	b = slices.Clone(b)
	sortDarwinIdentities(a)
	sortDarwinIdentities(b)
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}
