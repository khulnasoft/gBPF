//go:build !windows

package gen

import (
	"testing"

	"github.com/khulnasoft/gbpf"
	"github.com/khulnasoft/gbpf/btf"
	"github.com/khulnasoft/gbpf/internal/testutils"

	"github.com/go-quicktest/qt"
	"github.com/google/go-cmp/cmp"
)

func mustAnyTypeByName(t *testing.T, spec *gbpf.CollectionSpec, name string) btf.Type {
	t.Helper()

	typ, err := spec.Types.AnyTypeByName(name)
	qt.Assert(t, qt.IsNil(err))
	return typ
}

func TestCollectGlobalTypes(t *testing.T) {
	spec, err := gbpf.LoadCollectionSpec(testutils.NativeFile(t, "../testdata/minimal-%s.elf"))
	if err != nil {
		t.Fatal(err)
	}

	bar := mustAnyTypeByName(t, spec, "bar")
	barfoo := mustAnyTypeByName(t, spec, "barfoo")
	baz := mustAnyTypeByName(t, spec, "baz")
	e := mustAnyTypeByName(t, spec, "e")
	ubar := mustAnyTypeByName(t, spec, "ubar")

	got := CollectGlobalTypes(spec)
	qt.Assert(t, qt.IsNil(err))

	want := []btf.Type{bar, barfoo, baz, e, ubar}
	qt.Assert(t, qt.CmpEquals(got, want, cmp.Comparer(func(a, b btf.Type) bool {
		return a.TypeName() == b.TypeName()
	})))
}
