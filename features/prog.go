package features

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/khulnasoft/gbpf"
	"github.com/khulnasoft/gbpf/asm"
	"github.com/khulnasoft/gbpf/btf"
	"github.com/khulnasoft/gbpf/internal"
	"github.com/khulnasoft/gbpf/internal/sys"
	"github.com/khulnasoft/gbpf/internal/unix"
)

// HaveProgType probes the running kernel for the availability of the specified program type.
//
// Deprecated: use HaveProgramType() instead.
var HaveProgType = HaveProgramType

// HaveProgramType probes the running kernel for the availability of the specified program type.
//
// See the package documentation for the meaning of the error return value.
func HaveProgramType(pt gbpf.ProgramType) (err error) {
	return haveProgramTypeMatrix.Result(pt)
}

func probeProgram(spec *gbpf.ProgramSpec) error {
	if spec.Instructions == nil {
		spec.Instructions = asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		}
	}
	prog, err := gbpf.NewProgramWithOptions(spec, gbpf.ProgramOptions{
		LogDisabled: true,
	})
	if err == nil {
		prog.Close()
	}

	switch {
	// EINVAL occurs when attempting to create a program with an unknown type.
	// E2BIG occurs when ProgLoadAttr contains non-zero bytes past the end
	// of the struct known by the running kernel, meaning the kernel is too old
	// to support the given prog type.
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.E2BIG):
		err = gbpf.ErrNotSupported
	}

	return err
}

var haveProgramTypeMatrix = internal.FeatureMatrix[gbpf.ProgramType]{
	gbpf.SocketFilter:  {Version: "3.19"},
	gbpf.Kprobe:        {Version: "4.1"},
	gbpf.SchedCLS:      {Version: "4.1"},
	gbpf.SchedACT:      {Version: "4.1"},
	gbpf.TracePoint:    {Version: "4.7"},
	gbpf.XDP:           {Version: "4.8"},
	gbpf.PerfEvent:     {Version: "4.9"},
	gbpf.CGroupSKB:     {Version: "4.10"},
	gbpf.CGroupSock:    {Version: "4.10"},
	gbpf.LWTIn:         {Version: "4.10"},
	gbpf.LWTOut:        {Version: "4.10"},
	gbpf.LWTXmit:       {Version: "4.10"},
	gbpf.SockOps:       {Version: "4.13"},
	gbpf.SkSKB:         {Version: "4.14"},
	gbpf.CGroupDevice:  {Version: "4.15"},
	gbpf.SkMsg:         {Version: "4.17"},
	gbpf.RawTracepoint: {Version: "4.17"},
	gbpf.CGroupSockAddr: {
		Version: "4.17",
		Fn: func() error {
			return probeProgram(&gbpf.ProgramSpec{
				Type:       gbpf.CGroupSockAddr,
				AttachType: gbpf.AttachCGroupInet4Connect,
			})
		},
	},
	gbpf.LWTSeg6Local:          {Version: "4.18"},
	gbpf.LircMode2:             {Version: "4.18"},
	gbpf.SkReuseport:           {Version: "4.19"},
	gbpf.FlowDissector:         {Version: "4.20"},
	gbpf.CGroupSysctl:          {Version: "5.2"},
	gbpf.RawTracepointWritable: {Version: "5.2"},
	gbpf.CGroupSockopt: {
		Version: "5.3",
		Fn: func() error {
			return probeProgram(&gbpf.ProgramSpec{
				Type:       gbpf.CGroupSockopt,
				AttachType: gbpf.AttachCGroupGetsockopt,
			})
		},
	},
	gbpf.Tracing: {
		Version: "5.5",
		Fn: func() error {
			return probeProgram(&gbpf.ProgramSpec{
				Type:       gbpf.Tracing,
				AttachType: gbpf.AttachTraceFEntry,
				AttachTo:   "bpf_init",
			})
		},
	},
	gbpf.StructOps: {
		Version: "5.6",
		Fn: func() error {
			err := probeProgram(&gbpf.ProgramSpec{
				Type:    gbpf.StructOps,
				License: "GPL",
			})
			if errors.Is(err, sys.ENOTSUPP) {
				// ENOTSUPP means the program type is at least known to the kernel.
				return nil
			}
			return err
		},
	},
	gbpf.Extension: {
		Version: "5.6",
		Fn: func() error {
			// create btf.Func to add to first ins of target and extension so both progs are btf powered
			btfFn := btf.Func{
				Name: "a",
				Type: &btf.FuncProto{
					Return: &btf.Int{},
					Params: []btf.FuncParam{
						{Name: "ctx", Type: &btf.Pointer{Target: &btf.Struct{Name: "xdp_md"}}},
					},
				},
				Linkage: btf.GlobalFunc,
			}
			insns := asm.Instructions{
				btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0), &btfFn),
				asm.Return(),
			}

			// create target prog
			prog, err := gbpf.NewProgramWithOptions(
				&gbpf.ProgramSpec{
					Type:         gbpf.XDP,
					Instructions: insns,
				},
				gbpf.ProgramOptions{
					LogDisabled: true,
				},
			)
			if err != nil {
				return err
			}
			defer prog.Close()

			// probe for Extension prog with target
			return probeProgram(&gbpf.ProgramSpec{
				Type:         gbpf.Extension,
				Instructions: insns,
				AttachTarget: prog,
				AttachTo:     btfFn.Name,
			})
		},
	},
	gbpf.LSM: {
		Version: "5.7",
		Fn: func() error {
			return probeProgram(&gbpf.ProgramSpec{
				Type:       gbpf.LSM,
				AttachType: gbpf.AttachLSMMac,
				AttachTo:   "file_mprotect",
				License:    "GPL",
			})
		},
	},
	gbpf.SkLookup: {
		Version: "5.9",
		Fn: func() error {
			return probeProgram(&gbpf.ProgramSpec{
				Type:       gbpf.SkLookup,
				AttachType: gbpf.AttachSkLookup,
			})
		},
	},
	gbpf.Syscall: {
		Version: "5.14",
		Fn: func() error {
			return probeProgram(&gbpf.ProgramSpec{
				Type:  gbpf.Syscall,
				Flags: sys.BPF_F_SLEEPABLE,
			})
		},
	},
}

func init() {
	for key, ft := range haveProgramTypeMatrix {
		ft.Name = key.String()
		if ft.Fn == nil {
			key := key // avoid the dreaded loop variable problem
			ft.Fn = func() error { return probeProgram(&gbpf.ProgramSpec{Type: key}) }
		}
	}
}

type helperKey struct {
	typ    gbpf.ProgramType
	helper asm.BuiltinFunc
}

var helperCache = internal.NewFeatureCache(func(key helperKey) *internal.FeatureTest {
	return &internal.FeatureTest{
		Name: fmt.Sprintf("%s for program type %s", key.helper, key.typ),
		Fn: func() error {
			return haveProgramHelper(key.typ, key.helper)
		},
	}
})

// HaveProgramHelper probes the running kernel for the availability of the specified helper
// function to a specified program type.
// Return values have the following semantics:
//
//	err == nil: The feature is available.
//	errors.Is(err, gbpf.ErrNotSupported): The feature is not available.
//	err != nil: Any errors encountered during probe execution, wrapped.
//
// Note that the latter case may include false negatives, and that program creation may
// succeed despite an error being returned.
// Only `nil` and `gbpf.ErrNotSupported` are conclusive.
//
// Probe results are cached and persist throughout any process capability changes.
func HaveProgramHelper(pt gbpf.ProgramType, helper asm.BuiltinFunc) error {
	return helperCache.Result(helperKey{pt, helper})
}

func haveProgramHelper(pt gbpf.ProgramType, helper asm.BuiltinFunc) error {
	if ok := helperProbeNotImplemented(pt); ok {
		return fmt.Errorf("no feature probe for %v/%v", pt, helper)
	}

	if err := HaveProgramType(pt); err != nil {
		return err
	}

	spec := &gbpf.ProgramSpec{
		Type: pt,
		Instructions: asm.Instructions{
			helper.Call(),
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "GPL",
	}

	switch pt {
	case gbpf.CGroupSockAddr:
		spec.AttachType = gbpf.AttachCGroupInet4Connect
	case gbpf.CGroupSockopt:
		spec.AttachType = gbpf.AttachCGroupGetsockopt
	case gbpf.SkLookup:
		spec.AttachType = gbpf.AttachSkLookup
	case gbpf.Syscall:
		spec.Flags = sys.BPF_F_SLEEPABLE
	}

	prog, err := gbpf.NewProgramWithOptions(spec, gbpf.ProgramOptions{
		LogLevel: 1,
	})
	if err == nil {
		prog.Close()
	}

	var verr *gbpf.VerifierError
	if !errors.As(err, &verr) {
		return err
	}

	helperTag := fmt.Sprintf("#%d", helper)

	switch {
	// EACCES occurs when attempting to create a program probe with a helper
	// while the register args when calling this helper aren't set up properly.
	// We interpret this as the helper being available, because the verifier
	// returns EINVAL if the helper is not supported by the running kernel.
	case errors.Is(err, unix.EACCES):
		err = nil

	// EINVAL occurs when attempting to create a program with an unknown helper.
	case errors.Is(err, unix.EINVAL):
		// https://github.com/torvalds/linux/blob/09a0fa92e5b45e99cf435b2fbf5ebcf889cf8780/kernel/bpf/verifier.c#L10663
		if logContainsAll(verr.Log, "invalid func", helperTag) {
			return gbpf.ErrNotSupported
		}

		// https://github.com/torvalds/linux/blob/09a0fa92e5b45e99cf435b2fbf5ebcf889cf8780/kernel/bpf/verifier.c#L10668
		wrongProgramType := logContainsAll(verr.Log, "program of this type cannot use helper", helperTag)
		// https://github.com/torvalds/linux/blob/59b418c7063d30e0a3e1f592d47df096db83185c/kernel/bpf/verifier.c#L10204
		// 4.9 doesn't include # in verifier output.
		wrongProgramType = wrongProgramType || logContainsAll(verr.Log, "unknown func")
		if wrongProgramType {
			return fmt.Errorf("program of this type cannot use helper: %w", gbpf.ErrNotSupported)
		}
	}

	return err
}

func logContainsAll(log []string, needles ...string) bool {
	first := max(len(log)-5, 0) // Check last 5 lines.
	return slices.ContainsFunc(log[first:], func(line string) bool {
		for _, needle := range needles {
			if !strings.Contains(line, needle) {
				return false
			}
		}
		return true
	})
}

func helperProbeNotImplemented(pt gbpf.ProgramType) bool {
	switch pt {
	case gbpf.Extension, gbpf.LSM, gbpf.StructOps, gbpf.Tracing:
		return true
	}
	return false
}
