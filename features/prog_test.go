package features

import (
	"errors"
	"fmt"
	"math"
	"testing"

	gbpf "github.com/khulnasoft/gbpf"
	"github.com/khulnasoft/gbpf/asm"
	"github.com/khulnasoft/gbpf/internal"
	"github.com/khulnasoft/gbpf/internal/testutils"
	"github.com/khulnasoft/gbpf/internal/testutils/fdtrace"
)

func TestMain(m *testing.M) {
	fdtrace.TestMain(m)
}

func TestHaveProgramType(t *testing.T) {
	testutils.CheckFeatureMatrix(t, haveProgramTypeMatrix)
}

func TestHaveProgramTypeInvalid(t *testing.T) {
	if err := HaveProgramType(gbpf.ProgramType(math.MaxUint32)); err == nil {
		t.Fatal("Expected an error")
	} else if errors.Is(err, internal.ErrNotSupported) {
		t.Fatal("Got ErrNotSupported:", err)
	}
}

func TestHaveProgramHelper(t *testing.T) {
	type testCase struct {
		prog     gbpf.ProgramType
		helper   asm.BuiltinFunc
		expected error
		version  string
	}

	// Referencing linux kernel commits to track the kernel version required to pass these test cases.
	// They cases are derived from libbpf's selftests and helper/prog combinations that are
	// probed for in khulnasoft/khulnasoft.
	testCases := []testCase{
		{gbpf.Kprobe, asm.FnMapLookupElem, nil, "3.19"},                     // d0003ec01c66
		{gbpf.SocketFilter, asm.FnKtimeGetCoarseNs, nil, "5.11"},            // d05512618056
		{gbpf.SchedCLS, asm.FnSkbVlanPush, nil, "4.3"},                      // 4e10df9a60d9
		{gbpf.Kprobe, asm.FnSkbVlanPush, gbpf.ErrNotSupported, "4.3"},       // 4e10df9a60d9
		{gbpf.Kprobe, asm.FnSysBpf, gbpf.ErrNotSupported, "5.14"},           // 79a7f8bdb159
		{gbpf.Syscall, asm.FnSysBpf, nil, "5.14"},                           // 79a7f8bdb159
		{gbpf.XDP, asm.FnJiffies64, nil, "5.5"},                             // 5576b991e9c1
		{gbpf.XDP, asm.FnKtimeGetBootNs, nil, "5.7"},                        // 71d19214776e
		{gbpf.SchedCLS, asm.FnSkbChangeHead, nil, "5.8"},                    // 6f3f65d80dac
		{gbpf.SchedCLS, asm.FnRedirectNeigh, nil, "5.10"},                   // b4ab31414970
		{gbpf.SchedCLS, asm.FnSkbEcnSetCe, nil, "5.1"},                      // f7c917ba11a6
		{gbpf.SchedACT, asm.FnSkAssign, nil, "5.6"},                         // cf7fbe660f2d
		{gbpf.SchedACT, asm.FnFibLookup, nil, "4.18"},                       // 87f5fc7e48dd
		{gbpf.Kprobe, asm.FnFibLookup, gbpf.ErrNotSupported, "4.18"},        // 87f5fc7e48dd
		{gbpf.CGroupSockAddr, asm.FnGetsockopt, nil, "5.8"},                 // beecf11bc218
		{gbpf.CGroupSockAddr, asm.FnSkLookupTcp, nil, "4.20"},               // 6acc9b432e67
		{gbpf.CGroupSockAddr, asm.FnGetNetnsCookie, nil, "5.7"},             // f318903c0bf4
		{gbpf.CGroupSock, asm.FnGetNetnsCookie, nil, "5.7"},                 // f318903c0bf4
		{gbpf.Kprobe, asm.FnKtimeGetCoarseNs, gbpf.ErrNotSupported, "5.16"}, // 5e0bc3082e2e
		{gbpf.CGroupSockAddr, asm.FnGetCgroupClassid, nil, "5.7"},           // 5a52ae4e32a6
		{gbpf.Kprobe, asm.FnGetBranchSnapshot, nil, "5.16"},                 // 856c02dbce4f
		{gbpf.SchedCLS, asm.FnSkbSetTstamp, nil, "5.18"},                    // 9bb984f28d5b
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s/%s", tc.prog.String(), tc.helper.String()), func(t *testing.T) {
			feature := fmt.Sprintf("helper %s for program type %s", tc.helper.String(), tc.prog.String())

			testutils.SkipOnOldKernel(t, tc.version, feature)

			err := HaveProgramHelper(tc.prog, tc.helper)
			if !errors.Is(err, tc.expected) {
				t.Fatalf("%s/%s: %v", tc.prog.String(), tc.helper.String(), err)
			}

		})

	}
}

func TestHelperProbeNotImplemented(t *testing.T) {
	// Currently we don't support probing helpers for Tracing, Extension, LSM and StructOps programs.
	// For each of those test the availability of the FnMapLookupElem helper and expect it to fail.
	for _, pt := range []gbpf.ProgramType{gbpf.Tracing, gbpf.Extension, gbpf.LSM, gbpf.StructOps} {
		t.Run(pt.String(), func(t *testing.T) {
			if err := HaveProgramHelper(pt, asm.FnMapLookupElem); err == nil {
				t.Fatal("Expected an error")
			}
		})
	}
}
