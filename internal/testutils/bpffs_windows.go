package testutils

import (
	"errors"
	"math/rand"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/khulnasoft/gbpf/internal/efw"
	"github.com/go-quicktest/qt"
)

// TempBPFFS creates a random prefix to use when pinning on Windows.
func TempBPFFS(tb testing.TB) string {
	tb.Helper()

	path := filepath.Join("gbpf-go-test", strconv.Itoa(rand.Int()))
	tb.Cleanup(func() {
		tb.Helper()

		cursor := path
		for {
			next, _, err := efw.GbpfGetNextPinnedObjectPath(cursor, efw.GBPF_OBJECT_UNKNOWN)
			if errors.Is(err, efw.GBPF_NO_MORE_KEYS) {
				break
			}
			qt.Assert(tb, qt.IsNil(err))

			if !strings.HasPrefix(next, path) {
				break
			}

			if err := efw.GbpfObjectUnpin(next); err != nil {
				tb.Errorf("Failed to unpin %s: %s", next, err)
			}

			cursor = next
		}
	})

	return path
}
