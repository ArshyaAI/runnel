//go:build darwin

package darwin

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func readFileDigestNoFollow(ctx context.Context, path string, maxBytes int64) (fileDigestWitness, error) {
	var result fileDigestWitness
	var pathBefore unix.Stat_t
	if err := unix.Lstat(path, &pathBefore); err != nil {
		return result, err
	}
	if pathBefore.Mode&unix.S_IFMT != unix.S_IFREG {
		return result, errors.Join(ErrFileIdentityChanged, errors.New("path is not a regular file"))
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return result, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return result, errors.New("failed to wrap file descriptor")
	}
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return result, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG {
		return result, errors.Join(ErrFileIdentityChanged, errors.New("file is not regular"))
	}
	if !sameFileWitness(pathBefore, before) {
		return result, errors.Join(ErrFileIdentityChanged, errors.New("path changed before open"))
	}
	if before.Size < 0 || before.Size > maxBytes {
		return result, ErrOutputLimit
	}
	hash := sha256.New()
	written, err := copyDigestWithContext(ctx, hash, file, maxBytes+1)
	if err != nil {
		return result, err
	}
	if written != before.Size || written > maxBytes {
		return result, errors.Join(ErrFileIdentityChanged, errors.New("file changed while hashing"))
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return result, err
	}
	if !sameFileWitness(before, after) {
		return result, errors.Join(ErrFileIdentityChanged, errors.New("file descriptor changed while hashing"))
	}
	var pathAfter unix.Stat_t
	if err := unix.Lstat(path, &pathAfter); err != nil {
		return result, errors.Join(ErrFileIdentityChanged, err)
	}
	if !sameFileWitness(before, pathAfter) {
		return result, errors.Join(ErrFileIdentityChanged, errors.New("path changed while hashing"))
	}
	copy(result.SHA256[:], hash.Sum(nil))
	result.Device = uint64(uint32(before.Dev))
	result.Inode = before.Ino
	result.OwnerUID = before.Uid
	result.OwnerGID = before.Gid
	result.Mode = uint32(before.Mode)
	result.Size = uint64(before.Size)
	result.ModifiedAt = time.Unix(before.Mtim.Sec, before.Mtim.Nsec).UTC()
	return result, nil
}

func sameFileWitness(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size &&
		a.Uid == b.Uid && a.Gid == b.Gid && a.Mode == b.Mode &&
		a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func copyDigestWithContext(ctx context.Context, dst io.Writer, src io.Reader, maxBytes int64) (int64, error) {
	buffer := make([]byte, 128<<10)
	var total int64
	for total < maxBytes {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		want := int64(len(buffer))
		if remaining := maxBytes - total; remaining < want {
			want = remaining
		}
		n, readErr := src.Read(buffer[:want])
		if n > 0 {
			written, writeErr := dst.Write(buffer[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			return total, nil
		}
		if readErr != nil {
			return total, readErr
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
	return total, nil
}
