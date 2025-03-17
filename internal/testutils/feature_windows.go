package testutils

import (
	"os"
	"testing"

	"github.com/khulnasoft/gbpf/internal"

	"github.com/go-quicktest/qt"
)

func platformVersion(tb testing.TB) internal.Version {
	tb.Helper()
	versionStr, ok := os.LookupEnv("CI_EFW_VERSION")
	qt.Assert(tb, qt.IsTrue(ok), qt.Commentf("Missing CI_EFW_VERSION environment variable"))
	version, err := internal.NewVersion(versionStr)
	qt.Assert(tb, qt.IsNil(err), qt.Commentf("Parse gBPF for Windows version"))
	return version
}
