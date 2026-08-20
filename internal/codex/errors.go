package codex

import (
	"errors"
	"fmt"
)

// SafeError deliberately exposes only a closed code. The wrapped technical
// cause is retained for errors.Is/errors.As but is never interpolated into the
// public message.
type SafeError struct {
	Code  Code
	cause error
}

func (e *SafeError) Error() string { return "codex adapter: " + string(e.Code) }
func (e *SafeError) Unwrap() error { return e.cause }

func safeError(code Code) error { return &SafeError{Code: code} }

func safeWrap(code Code, cause error) error {
	if cause == nil {
		cause = fmt.Errorf("unspecified")
	}
	return &SafeError{Code: code, cause: cause}
}

func codeOf(err error, fallback Code) Code {
	var safe *SafeError
	if err != nil && errors.As(err, &safe) {
		return safe.Code
	}
	return fallback
}
