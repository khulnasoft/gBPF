//go:build !windows

package testutils

import (
	"testing"

	"github.com/khulnasoft/gbpf/internal"
	"github.com/khulnasoft/gbpf/internal/linux"
)

func platformVersion(tb testing.TB) internal.Version {
	tb.Helper()

	v, err := linux.KernelVersion()
	if err != nil {
		tb.Fatal(err)
	}
	return v
}
