package link

import (
	"errors"
	"os"
	"testing"

	"github.com/khulnasoft/gbpf"
	"github.com/khulnasoft/gbpf/internal/testutils"
	"github.com/khulnasoft/gbpf/internal/unix"
)

var kprobeMultiSyms = []string{"vprintk", "inet6_release"}

func TestKprobeMulti(t *testing.T) {
	testutils.SkipIfNotSupported(t, havgBPFLinkKprobeMulti())

	prog := mustLoadProgram(t, gbpf.Kprobe, gbpf.AttachTraceKprobeMulti, "")

	km, err := KprobeMulti(prog, KprobeMultiOptions{Symbols: kprobeMultiSyms})
	if err != nil {
		t.Fatal(err)
	}
	defer km.Close()

	testLink(t, km, prog)
}

func TestKprobeMultiInput(t *testing.T) {
	// Program type that loads on all kernels. Not expected to link successfully.
	prog := mustLoadProgram(t, gbpf.SocketFilter, 0, "")

	// One of Symbols or Addresses must be given.
	_, err := KprobeMulti(prog, KprobeMultiOptions{})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput, got: %v", err)
	}

	// Symbols and Addresses are mutually exclusive.
	_, err = KprobeMulti(prog, KprobeMultiOptions{
		Symbols:   []string{"foo"},
		Addresses: []uintptr{1},
	})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput, got: %v", err)
	}

	// One Symbol, two cookies..
	_, err = KprobeMulti(prog, KprobeMultiOptions{
		Symbols: []string{"one"},
		Cookies: []uint64{2, 3},
	})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput, got: %v", err)
	}
}

func TestKprobeMultiErrors(t *testing.T) {
	testutils.SkipIfNotSupported(t, havgBPFLinkKprobeMulti())

	prog := mustLoadProgram(t, gbpf.Kprobe, gbpf.AttachTraceKprobeMulti, "")

	// Nonexistent kernel symbol.
	_, err := KprobeMulti(prog, KprobeMultiOptions{Symbols: []string{"bogus"}})
	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, unix.EINVAL) {
		t.Fatalf("expected ErrNotExist or EINVAL, got: %s", err)
	}

	// Only have a negative test for addresses as it would be hard to maintain a
	// proper one.
	if _, err := KprobeMulti(prog, KprobeMultiOptions{
		Addresses: []uintptr{^uintptr(0)},
	}); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("expected EINVAL, got: %s", err)
	}
}

func TestKprobeMultiCookie(t *testing.T) {
	testutils.SkipIfNotSupported(t, havgBPFLinkKprobeMulti())

	prog := mustLoadProgram(t, gbpf.Kprobe, gbpf.AttachTraceKprobeMulti, "")

	km, err := KprobeMulti(prog, KprobeMultiOptions{
		Symbols: kprobeMultiSyms,
		Cookies: []uint64{0, 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = km.Close()
}

func TestKprobeMultiProgramCall(t *testing.T) {
	testutils.SkipIfNotSupported(t, havgBPFLinkKprobeMulti())

	m, p := newUpdaterMapProg(t, gbpf.Kprobe, gbpf.AttachTraceKprobeMulti)

	// For simplicity, just assert the increment happens with any symbol in the array.
	opts := KprobeMultiOptions{
		Symbols: []string{"__do_sys_getpid", "__do_sys_gettid"},
	}
	km, err := KprobeMulti(p, opts)
	if err != nil {
		t.Fatal(err)
	}

	// Trigger gbpf program call.
	unix.Getpid()
	unix.Gettid()

	// Assert that the value got incremented to at least 2, while allowing
	// for bigger values, because we could race with other getpid/gettid
	// callers.
	assertMapValueGE(t, m, 0, 2)

	// Close the link.
	if err := km.Close(); err != nil {
		t.Fatal(err)
	}

	// Reset map value to 0 at index 0.
	if err := m.Update(uint32(0), uint32(0), gbpf.UpdateExist); err != nil {
		t.Fatal(err)
	}

	// Retrigger the gbpf program call.
	unix.Getpid()
	unix.Gettid()

	// Assert that this time the value has not been updated.
	assertMapValue(t, m, 0, 0)
}

func TestHavgBPFLinkKprobeMulti(t *testing.T) {
	testutils.CheckFeatureTest(t, havgBPFLinkKprobeMulti)
}
