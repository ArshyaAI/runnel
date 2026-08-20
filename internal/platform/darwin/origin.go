package darwin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"syscall"

	"github.com/ArshyaAI/runnel/internal/model"
)

type OriginPolicy struct {
	DesignatedRequirement string
	TeamIdentifier        string
	Identifier            string
	SHA256Hex             string
	MaxBytes              int64
}

func (p OriginPolicy) validate() ([sha256.Size]byte, OriginPolicy, error) {
	var digest [sha256.Size]byte
	if p.DesignatedRequirement == "" || p.TeamIdentifier == "" || p.Identifier == "" {
		return digest, p, errors.New("origin policy requires designated requirement, team, and identifier")
	}
	if len(p.DesignatedRequirement) > 4096 || len(p.TeamIdentifier) > 128 || len(p.Identifier) > 512 ||
		strings.ContainsRune(p.DesignatedRequirement, '\x00') || strings.ContainsRune(p.TeamIdentifier, '\x00') ||
		strings.ContainsRune(p.Identifier, '\x00') {
		return digest, p, errors.New("origin policy field exceeds native boundary")
	}
	if len(p.SHA256Hex) != sha256.Size*2 {
		return digest, p, errors.New("origin policy requires an exact SHA-256")
	}
	decoded, err := hex.DecodeString(p.SHA256Hex)
	if err != nil || len(decoded) != sha256.Size {
		return digest, p, errors.New("origin policy requires an exact SHA-256")
	}
	copy(digest[:], decoded)
	if p.MaxBytes <= 0 {
		p.MaxBytes = 1 << 30
	}
	p.MaxBytes = min(p.MaxBytes, int64(1<<30))
	return digest, p, nil
}

type OriginResult struct {
	Identity     model.DarwinActionIdentity
	Path         string
	Team         string
	Identifier   string
	SHA256Hex    string
	Availability model.Availability
}

type originProcess struct {
	Identity  model.DarwinActionIdentity
	ParentPID int32
}

type originBackend interface {
	ReadProcess(int32) (originProcess, error)
	Path(model.DarwinActionIdentity) (string, error)
	StaticCode(string, string) (nativeCodeResult, error)
	Digest(context.Context, string, int64) ([sha256.Size]byte, error)
}

type systemOriginBackend struct{}

func (systemOriginBackend) ReadProcess(pid int32) (originProcess, error) {
	value, err := nativeReadIdentity(pid)
	if err != nil {
		return originProcess{}, err
	}
	return originProcess{Identity: actionIdentityFromNative(value), ParentPID: value.PPID}, nil
}
func (systemOriginBackend) Path(identity model.DarwinActionIdentity) (string, error) {
	return nativePIDPath(identity.PID, identity.PIDVersion)
}
func (systemOriginBackend) StaticCode(path, requirement string) (nativeCodeResult, error) {
	return nativeCheckStaticCode(path, requirement)
}
func (systemOriginBackend) Digest(ctx context.Context, path string, maxBytes int64) ([sha256.Size]byte, error) {
	witness, err := readFileDigestNoFollow(ctx, path, maxBytes)
	return witness.SHA256, err
}

type OriginVerifier struct{ backend originBackend }

func NewOriginVerifier() *OriginVerifier { return &OriginVerifier{backend: systemOriginBackend{}} }

func (v *OriginVerifier) Verify(ctx context.Context, identity model.DarwinActionIdentity, policy OriginPolicy) (OriginResult, error) {
	expectedDigest, policy, err := policy.validate()
	if err != nil {
		return OriginResult{}, err
	}
	if err := identity.Validate(); err != nil {
		return OriginResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return OriginResult{}, err
	}
	before, err := v.backend.ReadProcess(identity.PID)
	if err != nil {
		return OriginResult{}, identityReadError("origin_identity_before", err)
	}
	if !before.Identity.Equal(identity) {
		return OriginResult{}, identityMismatch("origin_identity_before")
	}
	path, err := v.backend.Path(identity)
	if err != nil {
		return OriginResult{}, originOperationError("origin_pidpath", err)
	}
	if identity.Executable != path {
		return OriginResult{}, originMismatch("origin_pidpath", errors.New("identity executable and audit-token path differ"))
	}
	code, err := v.backend.StaticCode(path, policy.DesignatedRequirement)
	if err != nil {
		return OriginResult{}, originMismatch("origin_static_code", err)
	}
	if code.Team != policy.TeamIdentifier {
		return OriginResult{}, originMismatch("origin_team", errors.New("team identifier mismatch"))
	}
	if code.Identifier != policy.Identifier {
		return OriginResult{}, originMismatch("origin_identifier", errors.New("code identifier mismatch"))
	}
	digest, err := v.backend.Digest(ctx, path, policy.MaxBytes)
	if err != nil {
		return OriginResult{}, originOperationError("origin_digest", err)
	}
	if digest != expectedDigest {
		return OriginResult{}, originMismatch("origin_digest", errors.New("SHA-256 mismatch"))
	}
	pathAfter, err := v.backend.Path(identity)
	if err != nil {
		return OriginResult{}, originOperationError("origin_pidpath_after", err)
	}
	if pathAfter != path {
		return OriginResult{}, originMismatch("origin_pidpath_after", errors.New("executable path changed"))
	}
	after, err := v.backend.ReadProcess(identity.PID)
	if err != nil {
		return OriginResult{}, identityReadError("origin_identity_after", err)
	}
	if !after.Identity.Equal(identity) || after.ParentPID != before.ParentPID {
		return OriginResult{}, identityMismatch("origin_identity_after")
	}
	if err := ctx.Err(); err != nil {
		return OriginResult{}, err
	}
	return OriginResult{
		Identity:     identity,
		Path:         path,
		Team:         code.Team,
		Identifier:   code.Identifier,
		SHA256Hex:    hex.EncodeToString(digest[:]),
		Availability: model.AvailabilityAvailable,
	}, nil
}

// VerifyParentChain additionally binds a child to its expected exact parent.
// A reparent, mismatched parent PID, or changed parent identity fails closed.
func (v *OriginVerifier) VerifyParentChain(ctx context.Context, child, parent model.DarwinActionIdentity, childPolicy, parentPolicy OriginPolicy) (OriginResult, OriginResult, error) {
	childBefore, err := v.backend.ReadProcess(child.PID)
	if err != nil {
		return OriginResult{}, OriginResult{}, identityReadError("origin_child_parent_before", err)
	}
	if !childBefore.Identity.Equal(child) || childBefore.ParentPID != parent.PID {
		return OriginResult{}, OriginResult{}, originMismatch("origin_parent", errors.New("child parent mismatch"))
	}
	childResult, err := v.Verify(ctx, child, childPolicy)
	if err != nil {
		return OriginResult{}, OriginResult{}, err
	}
	parentResult, err := v.Verify(ctx, parent, parentPolicy)
	if err != nil {
		return OriginResult{}, OriginResult{}, err
	}
	childAfter, err := v.backend.ReadProcess(child.PID)
	if err != nil {
		return OriginResult{}, OriginResult{}, identityReadError("origin_child_parent_after", err)
	}
	if !childAfter.Identity.Equal(child) || childAfter.ParentPID != parent.PID {
		return OriginResult{}, OriginResult{}, originMismatch("origin_parent_after", errors.New("child parent changed"))
	}
	return childResult, parentResult, nil
}

func originMismatch(op string, err error) error {
	return &OperationError{Op: op, Availability: model.AvailabilityContradictory, Err: errors.Join(ErrOriginMismatch, err)}
}

func originOperationError(op string, err error) error {
	if errors.Is(err, syscall.ESRCH) {
		return identityMismatch(op)
	}
	return &OperationError{Op: op, Availability: availabilityForError(err), Err: err}
}
