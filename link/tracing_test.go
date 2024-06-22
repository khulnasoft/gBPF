package link

import (
	"testing"

	"github.com/khulnasoft/gbpf"
	"github.com/khulnasoft/gbpf/internal/testutils"
)

func TestFreplace(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.10", "freplace")

	file := testutils.NativeFile(t, "../testdata/freplace-%s.elf")
	spec, err := gbpf.LoadCollectionSpec(file)
	if err != nil {
		t.Fatal("Can't parse ELF:", err)
	}

	target, err := gbpf.NewProgram(spec.Programs["sched_process_exec"])
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't create target program:", err)
	}
	defer target.Close()

	// Test attachment specified at load time
	spec.Programs["replacement"].AttachTarget = target
	replacement, err := gbpf.NewProgram(spec.Programs["replacement"])
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't create replacement program:", err)
	}
	defer replacement.Close()

	freplace, err := AttachFreplace(nil, "", replacement)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't create freplace:", err)
	}

	testLink(t, freplace, replacement)
}

func TestFentryFexit(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.5", "fentry")

	spec, err := gbpf.LoadCollectionSpec(testutils.NativeFile(t, "../testdata/fentry_fexit-%s.elf"))
	if err != nil {
		t.Fatal("Can't parse ELF:", err)
	}

	target, err := gbpf.NewProgram(spec.Programs["target"])
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't create target program:", err)
	}
	defer target.Close()

	for _, name := range []string{"trace_on_entry", "trace_on_exit"} {
		progSpec := spec.Programs[name]
		t.Run(name, func(t *testing.T) {
			progSpec.AttachTarget = target

			prog, err := gbpf.NewProgram(progSpec)
			if err != nil {
				t.Fatal(err)
			}
			defer prog.Close()

			t.Run("link", func(t *testing.T) {
				testutils.SkipOnOldKernel(t, "5.11", "BPF_LINK_TYPE_TRACING")

				tracingLink, err := AttachTracing(TracingOptions{
					Program: prog,
				})
				if err != nil {
					t.Fatal("Can't attach tracing:", err)
				}
				defer tracingLink.Close()

				testLink(t, tracingLink, prog)
			})

		})
	}
}

func TestTracing(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.11", "BPF_LINK_TYPE_TRACING")

	tests := []struct {
		name                             string
		attachTo                         string
		programType                      gbpf.ProgramType
		programAttachType, attachTypeOpt gbpf.AttachType
		cookie                           uint64
	}{
		{
			name:              "AttachTraceFEntry",
			attachTo:          "inet_dgram_connect",
			programType:       gbpf.Tracing,
			programAttachType: gbpf.AttachTraceFEntry,
		},
		{
			name:              "AttachTraceFEntry",
			attachTo:          "inet_dgram_connect",
			programType:       gbpf.Tracing,
			programAttachType: gbpf.AttachTraceFEntry,
			attachTypeOpt:     gbpf.AttachTraceFEntry,
			cookie:            1,
		},
		{
			name:              "AttachTraceFEntry",
			attachTo:          "inet_dgram_connect",
			programType:       gbpf.Tracing,
			programAttachType: gbpf.AttachTraceFEntry,
		},
		{
			name:              "AttachTraceFExit",
			attachTo:          "inet_dgram_connect",
			programType:       gbpf.Tracing,
			programAttachType: gbpf.AttachTraceFExit,
		},
		{
			name:              "AttachModifyReturn",
			attachTo:          "bpf_modify_return_test",
			programType:       gbpf.Tracing,
			programAttachType: gbpf.AttachModifyReturn,
		},
		{
			name:              "AttachTraceRawTp",
			attachTo:          "kfree_skb",
			programType:       gbpf.Tracing,
			programAttachType: gbpf.AttachTraceRawTp,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prog := mustLoadProgram(t, tt.programType, tt.programAttachType, tt.attachTo)

			opts := TracingOptions{Program: prog, AttachType: tt.attachTypeOpt, Cookie: tt.cookie}
			link, err := AttachTracing(opts)
			testutils.SkipIfNotSupported(t, err)
			if err != nil {
				t.Fatal(err)
			}
			testLink(t, link, prog)
			if err = link.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLSM(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.11", "BPF_LINK_TYPE_TRACING")

	prog := mustLoadProgram(t, gbpf.LSM, gbpf.AttachLSMMac, "file_mprotect")

	link, err := AttachLSM(LSMOptions{Program: prog})
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	testLink(t, link, prog)
}
