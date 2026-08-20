//go:build !darwin && !linux && !freebsd && !openbsd && !netbsd

package codex

import "os"

func fileIdentity(os.FileInfo) (FileIdentity, error) {
	return FileIdentity{}, safeError(CodeTailUnavailable)
}
