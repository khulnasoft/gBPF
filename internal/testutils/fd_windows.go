package testutils

import (
	"testing"

	"github.com/khulnasoft/gbpf/internal/efw"
	"github.com/go-quicktest/qt"
)

func DupFD(tb testing.TB, fd int) int {
	tb.Helper()

	dup, err := efw.GbpfDuplicateFd(fd)
	qt.Assert(tb, qt.IsNil(err))

	return dup
}
