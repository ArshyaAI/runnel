package darwin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ArshyaAI/runnel/internal/model"
)

var ErrFileIdentityChanged = errors.New("file identity changed")

type fileDigestWitness struct {
	SHA256     [sha256.Size]byte
	Device     uint64
	Inode      uint64
	OwnerUID   uint32
	OwnerGID   uint32
	Mode       uint32
	Size       uint64
	ModifiedAt time.Time
}

type FileDigestResult struct {
	Path         string
	SHA256Hex    string
	Device       uint64
	Inode        uint64
	OwnerUID     uint32
	OwnerGID     uint32
	Mode         uint32
	Size         uint64
	ModifiedAt   time.Time
	Availability model.Availability
}

// VerifyFileDigest hashes an absolute, regular, non-symlink file through one
// O_NOFOLLOW descriptor and proves the path, inode, owner, mode, size, and
// timestamps are unchanged across the bounded read. Raw file bytes are never
// returned.
func VerifyFileDigest(ctx context.Context, path, expectedSHA256Hex string, maxBytes int64) (FileDigestResult, error) {
	if !filepath.IsAbs(path) || len(expectedSHA256Hex) != sha256.Size*2 {
		return FileDigestResult{Availability: model.AvailabilityMalformedOutput}, errors.New("file digest requires an absolute path and exact SHA-256")
	}
	expected, err := hex.DecodeString(expectedSHA256Hex)
	if err != nil || len(expected) != sha256.Size {
		return FileDigestResult{Availability: model.AvailabilityMalformedOutput}, errors.New("file digest requires an exact SHA-256")
	}
	if maxBytes <= 0 {
		maxBytes = 256 << 20
	}
	maxBytes = min(maxBytes, int64(1<<30))
	if err := ctx.Err(); err != nil {
		return FileDigestResult{Availability: availabilityForError(err)}, err
	}
	witness, err := readFileDigestNoFollow(ctx, path, maxBytes)
	if err != nil {
		availability := availabilityForError(err)
		if errors.Is(err, ErrFileIdentityChanged) || errors.Is(err, ErrOutputLimit) || errors.Is(err, syscall.ELOOP) {
			availability = model.AvailabilityContradictory
		}
		return FileDigestResult{Availability: availability}, &OperationError{Op: "file_digest", Availability: availability, Err: err}
	}
	if !equalDigestBytes(witness.SHA256, expected) {
		return FileDigestResult{Availability: model.AvailabilityContradictory}, originMismatch("file_digest", errors.New("SHA-256 mismatch"))
	}
	return FileDigestResult{
		Path:         path,
		SHA256Hex:    hex.EncodeToString(witness.SHA256[:]),
		Device:       witness.Device,
		Inode:        witness.Inode,
		OwnerUID:     witness.OwnerUID,
		OwnerGID:     witness.OwnerGID,
		Mode:         witness.Mode,
		Size:         witness.Size,
		ModifiedAt:   witness.ModifiedAt,
		Availability: model.AvailabilityAvailable,
	}, nil
}

func equalDigestBytes(digest [sha256.Size]byte, expected []byte) bool {
	if len(expected) != sha256.Size {
		return false
	}
	var value [sha256.Size]byte
	copy(value[:], expected)
	return digest == value
}
