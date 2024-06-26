package link

import (
	"errors"

	"github.com/khulnasoft/gbpf"
	"github.com/khulnasoft/gbpf/asm"
	"github.com/khulnasoft/gbpf/internal"
	"github.com/khulnasoft/gbpf/internal/sys"
	"github.com/khulnasoft/gbpf/internal/unix"
)

// Type is the kind of link.
type Type = sys.LinkType

// Valid link types.
const (
	UnspecifiedType   = sys.BPF_LINK_TYPE_UNSPEC
	RawTracepointType = sys.BPF_LINK_TYPE_RAW_TRACEPOINT
	TracingType       = sys.BPF_LINK_TYPE_TRACING
	CgroupType        = sys.BPF_LINK_TYPE_CGROUP
	IterType          = sys.BPF_LINK_TYPE_ITER
	NetNsType         = sys.BPF_LINK_TYPE_NETNS
	XDPType           = sys.BPF_LINK_TYPE_XDP
	PerfEventType     = sys.BPF_LINK_TYPE_PERF_EVENT
	KprobeMultiType   = sys.BPF_LINK_TYPE_KPROBE_MULTI
	TCXType           = sys.BPF_LINK_TYPE_TCX
	UprobeMultiType   = sys.BPF_LINK_TYPE_UPROBE_MULTI
	NetfilterType     = sys.BPF_LINK_TYPE_NETFILTER
	NetkitType        = sys.BPF_LINK_TYPE_NETKIT
)

var haveProgAttach = internal.NewFeatureTest("BPF_PROG_ATTACH", "4.10", func() error {
	prog, err := gbpf.NewProgram(&gbpf.ProgramSpec{
		Type:    gbpf.CGroupSKB,
		License: "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		return internal.ErrNotSupported
	}

	// BPF_PROG_ATTACH was introduced at the same time as CGgroupSKB,
	// so being able to load the program is enough to infer that we
	// have the syscall.
	prog.Close()
	return nil
})

var haveProgAttachReplace = internal.NewFeatureTest("BPF_PROG_ATTACH atomic replacement of MULTI progs", "5.5", func() error {
	if err := haveProgAttach(); err != nil {
		return err
	}

	prog, err := gbpf.NewProgram(&gbpf.ProgramSpec{
		Type:       gbpf.CGroupSKB,
		AttachType: gbpf.AttachCGroupInetIngress,
		License:    "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})

	if err != nil {
		return internal.ErrNotSupported
	}

	defer prog.Close()

	// We know that we have BPF_PROG_ATTACH since we can load CGroupSKB programs.
	// If passing BPF_F_REPLACE gives us EINVAL we know that the feature isn't
	// present.
	attr := sys.ProgAttachAttr{
		// We rely on this being checked after attachFlags.
		TargetFdOrIfindex: ^uint32(0),
		AttachBpfFd:       uint32(prog.FD()),
		AttachType:        uint32(gbpf.AttachCGroupInetIngress),
		AttachFlags:       uint32(flagReplace),
	}

	err = sys.ProgAttach(&attr)
	if errors.Is(err, unix.EINVAL) {
		return internal.ErrNotSupported
	}
	if errors.Is(err, unix.EBADF) {
		return nil
	}
	return err
})

var havgBPFLink = internal.NewFeatureTest("bpf_link", "5.7", func() error {
	attr := sys.LinkCreateAttr{
		// This is a hopefully invalid file descriptor, which triggers EBADF.
		TargetFd:   ^uint32(0),
		ProgFd:     ^uint32(0),
		AttachType: sys.AttachType(gbpf.AttachCGroupInetIngress),
	}
	_, err := sys.LinkCreate(&attr)
	if errors.Is(err, unix.EINVAL) {
		return internal.ErrNotSupported
	}
	if errors.Is(err, unix.EBADF) {
		return nil
	}
	return err
})

var haveProgQuery = internal.NewFeatureTest("BPF_PROG_QUERY", "4.15", func() error {
	attr := sys.ProgQueryAttr{
		// We rely on this being checked during the syscall.
		// With an otherwise correct payload we expect EBADF here
		// as an indication that the feature is present.
		TargetFdOrIfindex: ^uint32(0),
		AttachType:        sys.AttachType(gbpf.AttachCGroupInetIngress),
	}

	err := sys.ProgQuery(&attr)

	if errors.Is(err, unix.EBADF) {
		return nil
	}
	if err != nil {
		return ErrNotSupported
	}
	return errors.New("syscall succeeded unexpectedly")
})

var haveTCX = internal.NewFeatureTest("tcx", "6.6", func() error {
	prog, err := gbpf.NewProgram(&gbpf.ProgramSpec{
		Type:    gbpf.SchedCLS,
		License: "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})

	if err != nil {
		return internal.ErrNotSupported
	}

	defer prog.Close()
	attr := sys.LinkCreateTcxAttr{
		// We rely on this being checked during the syscall.
		// With an otherwise correct payload we expect ENODEV here
		// as an indication that the feature is present.
		TargetIfindex: ^uint32(0),
		ProgFd:        uint32(prog.FD()),
		AttachType:    sys.AttachType(gbpf.AttachTCXIngress),
	}

	_, err = sys.LinkCreateTcx(&attr)

	if errors.Is(err, unix.ENODEV) {
		return nil
	}
	if err != nil {
		return ErrNotSupported
	}
	return errors.New("syscall succeeded unexpectedly")
})

var haveNetkit = internal.NewFeatureTest("netkit", "6.7", func() error {
	prog, err := gbpf.NewProgram(&gbpf.ProgramSpec{
		Type:    gbpf.SchedCLS,
		License: "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})

	if err != nil {
		return internal.ErrNotSupported
	}

	defer prog.Close()
	attr := sys.LinkCreateNetkitAttr{
		// We rely on this being checked during the syscall.
		// With an otherwise correct payload we expect ENODEV here
		// as an indication that the feature is present.
		TargetIfindex: ^uint32(0),
		ProgFd:        uint32(prog.FD()),
		AttachType:    sys.AttachType(gbpf.AttachNetkitPrimary),
	}

	_, err = sys.LinkCreateNetkit(&attr)

	if errors.Is(err, unix.ENODEV) {
		return nil
	}
	if err != nil {
		return ErrNotSupported
	}
	return errors.New("syscall succeeded unexpectedly")
})
