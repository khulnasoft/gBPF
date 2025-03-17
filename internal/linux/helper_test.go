package linux

import (
	"errors"
	"testing"

	"github.com/khulnasoft/gbpf/internal"
)

// skipIfNotSupportedOnOS is a copy of testutils.SkipIfNotSupported to avoid
// a circular dependency.
func skipIfNotSupportedOnOS(tb testing.TB, err error) {
	tb.Helper()

	if err == internal.ErrNotSupportedOnOS {
		tb.Fatal("Unwrapped ErrNotSupportedOnOS")
	}

	if errors.Is(err, internal.ErrNotSupportedOnOS) {
		tb.Skip(err.Error())
	}
}
