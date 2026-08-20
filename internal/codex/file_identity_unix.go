//go:build darwin || linux || freebsd || openbsd || netbsd

package codex

import (
	"os"
	"syscall"
)

func fileIdentity(info os.FileInfo) (FileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev == 0 || stat.Ino == 0 {
		return FileIdentity{}, safeError(CodeTailUnavailable)
	}
	return FileIdentity{
		Device:     uint64(stat.Dev),
		Inode:      uint64(stat.Ino),
		Size:       info.Size(),
		ModifiedNS: info.ModTime().UnixNano(),
	}, nil
}
