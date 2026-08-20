package darwin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/ArshyaAI/runnel/internal/model"
)

func TestOriginVerifierExactPolicy(t *testing.T) {
	identity := fakeOriginIdentity(101, "/signed/codex", 3, 11)
	digest := sha256.Sum256([]byte("codex"))
	backend := newFakeOriginBackend(identity, 55, digest, nativeCodeResult{Identifier: "codex", Team: "TEAM123"})
	verifier := &OriginVerifier{backend: backend}
	result, err := verifier.Verify(context.Background(), identity, fakeOriginPolicy("codex", "TEAM123", digest))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Identity != identity || result.SHA256Hex != hex.EncodeToString(digest[:]) || result.Availability != model.AvailabilityAvailable {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestOriginVerifierNegativeContracts(t *testing.T) {
	identity := fakeOriginIdentity(101, "/signed/codex", 3, 11)
	digest := sha256.Sum256([]byte("codex"))
	otherDigest := sha256.Sum256([]byte("altered"))
	tests := []struct {
		name   string
		mutate func(*fakeOriginBackend, *OriginPolicy)
	}{
		{name: "unsigned", mutate: func(backend *fakeOriginBackend, _ *OriginPolicy) {
			backend.staticErr[identity.Executable] = errors.New("unsigned static code")
		}},
		{name: "altered", mutate: func(backend *fakeOriginBackend, _ *OriginPolicy) {
			backend.digests[identity.Executable] = otherDigest
		}},
		{name: "resigned", mutate: func(backend *fakeOriginBackend, _ *OriginPolicy) {
			backend.codes[identity.Executable] = nativeCodeResult{Identifier: "codex", Team: "ATTACKER"}
		}},
		{name: "wrong_team", mutate: func(_ *fakeOriginBackend, policy *OriginPolicy) {
			policy.TeamIdentifier = "OTHERTEAM"
		}},
		{name: "wrong_identifier", mutate: func(_ *fakeOriginBackend, policy *OriginPolicy) {
			policy.Identifier = "lookalike"
		}},
		{name: "wrong_digest", mutate: func(_ *fakeOriginBackend, policy *OriginPolicy) {
			policy.SHA256Hex = hex.EncodeToString(otherDigest[:])
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := newFakeOriginBackend(identity, 55, digest, nativeCodeResult{Identifier: "codex", Team: "TEAM123"})
			policy := fakeOriginPolicy("codex", "TEAM123", digest)
			test.mutate(backend, &policy)
			_, err := (&OriginVerifier{backend: backend}).Verify(context.Background(), identity, policy)
			if !errors.Is(err, ErrOriginMismatch) {
				t.Fatalf("expected origin mismatch, got %v", err)
			}
		})
	}
}

func TestOriginVerifierRejectsMismatchedParent(t *testing.T) {
	child := fakeOriginIdentity(101, "/signed/child", 3, 11)
	parent := fakeOriginIdentity(55, "/signed/parent", 8, 12)
	digest := sha256.Sum256([]byte("same fake bytes"))
	backend := newFakeOriginBackend(child, 999, digest, nativeCodeResult{Identifier: "child", Team: "TEAM123"})
	backend.processes[parent.PID] = originProcess{Identity: parent, ParentPID: 1}
	backend.paths[parent.PID] = parent.Executable
	backend.codes[parent.Executable] = nativeCodeResult{Identifier: "parent", Team: "TEAM123"}
	backend.digests[parent.Executable] = digest
	verifier := &OriginVerifier{backend: backend}
	_, _, err := verifier.VerifyParentChain(
		context.Background(), child, parent,
		fakeOriginPolicy("child", "TEAM123", digest),
		fakeOriginPolicy("parent", "TEAM123", digest),
	)
	if !errors.Is(err, ErrOriginMismatch) {
		t.Fatalf("mismatched parent did not fail closed: %v", err)
	}
}

func TestOriginVerifierRejectsIdentityChangeAfterVerification(t *testing.T) {
	identity := fakeOriginIdentity(101, "/signed/codex", 3, 11)
	digest := sha256.Sum256([]byte("codex"))
	backend := newFakeOriginBackend(identity, 55, digest, nativeCodeResult{Identifier: "codex", Team: "TEAM123"})
	backend.changeAfterRead = true
	_, err := (&OriginVerifier{backend: backend}).Verify(context.Background(), identity, fakeOriginPolicy("codex", "TEAM123", digest))
	if !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("identity change did not fail closed: %v", err)
	}
}

type fakeOriginBackend struct {
	processes       map[int32]originProcess
	paths           map[int32]string
	codes           map[string]nativeCodeResult
	staticErr       map[string]error
	digests         map[string][sha256.Size]byte
	reads           int
	changeAfterRead bool
}

func newFakeOriginBackend(identity model.DarwinActionIdentity, parentPID int32, digest [sha256.Size]byte, code nativeCodeResult) *fakeOriginBackend {
	return &fakeOriginBackend{
		processes: map[int32]originProcess{identity.PID: {Identity: identity, ParentPID: parentPID}},
		paths:     map[int32]string{identity.PID: identity.Executable},
		codes:     map[string]nativeCodeResult{identity.Executable: code},
		staticErr: make(map[string]error),
		digests:   map[string][sha256.Size]byte{identity.Executable: digest},
	}
}

func (f *fakeOriginBackend) ReadProcess(pid int32) (originProcess, error) {
	f.reads++
	process, ok := f.processes[pid]
	if !ok {
		return originProcess{}, errors.New("missing fake process")
	}
	if f.changeAfterRead && f.reads > 1 {
		process.Identity.PIDVersion++
	}
	return process, nil
}
func (f *fakeOriginBackend) Path(identity model.DarwinActionIdentity) (string, error) {
	return f.paths[identity.PID], nil
}
func (f *fakeOriginBackend) StaticCode(path, _ string) (nativeCodeResult, error) {
	if err := f.staticErr[path]; err != nil {
		return nativeCodeResult{}, err
	}
	return f.codes[path], nil
}
func (f *fakeOriginBackend) Digest(_ context.Context, path string, _ int64) ([sha256.Size]byte, error) {
	return f.digests[path], nil
}

func fakeOriginIdentity(pid int32, path string, version uint32, unique uint64) model.DarwinActionIdentity {
	return model.DarwinActionIdentity{
		ProcessIdentity: model.ProcessIdentity{PID: pid, StartTime: time.Unix(100, 0).UTC(), UID: 501, Executable: path},
		PIDVersion:      version,
		UniqueID:        unique,
	}
}

func fakeOriginPolicy(identifier, team string, digest [sha256.Size]byte) OriginPolicy {
	return OriginPolicy{
		DesignatedRequirement: `anchor apple generic and identifier "` + identifier + `"`,
		TeamIdentifier:        team,
		Identifier:            identifier,
		SHA256Hex:             hex.EncodeToString(digest[:]),
		MaxBytes:              1024,
	}
}
