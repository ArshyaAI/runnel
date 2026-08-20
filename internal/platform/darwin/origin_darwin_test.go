//go:build darwin && cgo

package darwin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNativeStaticCodeRejectsUnsignedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unsigned-helper")
	if err := os.WriteFile(path, []byte("synthetic unsigned fixture\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := nativeCheckStaticCode(path, `identifier "com.example.runnel.unsigned"`)
	if !errors.Is(err, ErrOriginMismatch) {
		t.Fatalf("Security.framework accepted unsigned file: %v", err)
	}
}

func TestExecutableDigestRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "link")
	if err := os.WriteFile(target, []byte("synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readFileDigestNoFollow(context.Background(), link, 1024); err == nil {
		t.Fatal("symlinked executable digest accepted")
	}
}

func TestVerifyFileDigestReturnsStableIdentityWithoutBody(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted-worker.js")
	body := []byte("synthetic worker fixture\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	result, err := VerifyFileDigest(context.Background(), path, hex.EncodeToString(digest[:]), 1024)
	if err != nil {
		t.Fatalf("VerifyFileDigest: %v", err)
	}
	if result.Availability != Available || result.Device == 0 || result.Inode == 0 ||
		result.OwnerUID != uint32(os.Getuid()) || result.Size != uint64(len(body)) ||
		result.SHA256Hex != hex.EncodeToString(digest[:]) {
		t.Fatalf("incomplete file identity result: %#v", result)
	}
	wrong := sha256.Sum256([]byte("wrong"))
	if _, err := VerifyFileDigest(context.Background(), path, hex.EncodeToString(wrong[:]), 1024); !errors.Is(err, ErrOriginMismatch) {
		t.Fatalf("wrong file digest accepted: %v", err)
	}
}

func TestVerifyFileDigestRejectsSymlinkAsContradictory(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "worker.js")
	body := []byte("synthetic\n")
	if err := os.WriteFile(target, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(body)
	result, err := VerifyFileDigest(context.Background(), link, hex.EncodeToString(digest[:]), 1024)
	if err == nil || result.Availability != Contradictory {
		t.Fatalf("symlink did not fail closed: result=%#v err=%v", result, err)
	}
}

func TestFileWitnessDetectsMetadataAndSizeMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.js")
	if err := os.WriteFile(path, []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var before unix.Stat_t
	if err := unix.Lstat(path, &before); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("after\n"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	var after unix.Stat_t
	if err := unix.Lstat(path, &after); err != nil {
		t.Fatal(err)
	}
	if sameFileWitness(before, after) {
		t.Fatal("file witness missed mode/size/time mutation")
	}
}
