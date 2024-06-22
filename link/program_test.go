package link

import (
	"fmt"
	"net"
	"testing"

	"github.com/khulnasoft/gbpf"
	"github.com/khulnasoft/gbpf/internal/testutils"

	"github.com/go-quicktest/qt"
)

func TestProgramAlter(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.13", "SkSKB type")

	prog := mustLoadProgram(t, gbpf.SkSKB, 0, "")

	var sockMap *gbpf.Map
	sockMap, err := gbpf.NewMap(&gbpf.MapSpec{
		Type:       gbpf.MapType(15), // BPF_MAP_TYPE_SOCKMAP
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sockMap.Close()

	err = RawAttachProgram(RawAttachProgramOptions{
		Target:  sockMap.FD(),
		Program: prog,
		Attach:  gbpf.AttachSkSKBStreamParser,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = RawDetachProgram(RawDetachProgramOptions{
		Target:  sockMap.FD(),
		Program: prog,
		Attach:  gbpf.AttachSkSKBStreamParser,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRawAttachProgramAnchor(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.6", "attach anchor")

	iface, err := net.InterfaceByName("lo")
	qt.Assert(t, qt.IsNil(err))

	a := mustLoadProgram(t, gbpf.SchedCLS, 0, "")
	info, err := a.Info()
	qt.Assert(t, qt.IsNil(err))
	aID, _ := info.ID()

	err = RawAttachProgram(RawAttachProgramOptions{
		Target:  iface.Index,
		Program: a,
		Attach:  gbpf.AttachTCXIngress,
	})
	qt.Assert(t, qt.IsNil(err))
	defer RawDetachProgram(RawDetachProgramOptions{
		Target:  iface.Index,
		Program: a,
		Attach:  gbpf.AttachTCXIngress,
	})

	link, err := AttachTCX(TCXOptions{
		Interface: iface.Index,
		Program:   mustLoadProgram(t, gbpf.SchedCLS, 0, ""),
		Attach:    gbpf.AttachTCXIngress,
	})
	qt.Assert(t, qt.IsNil(err))
	defer link.Close()

	linkInfo, err := link.Info()
	qt.Assert(t, qt.IsNil(err))

	b := mustLoadProgram(t, gbpf.SchedCLS, 0, "")

	for _, anchor := range []Anchor{
		Head(),
		Tail(),
		AfterProgram(a),
		AfterProgramByID(aID),
		AfterLink(link),
		AfterLinkByID(linkInfo.ID),
	} {
		t.Run(fmt.Sprintf("%T", anchor), func(t *testing.T) {
			err := RawAttachProgram(RawAttachProgramOptions{
				Target:  iface.Index,
				Program: b,
				Attach:  gbpf.AttachTCXIngress,
				Anchor:  anchor,
			})
			qt.Assert(t, qt.IsNil(err))

			// Detach doesn't allow first or last anchor.
			if _, ok := anchor.(firstAnchor); ok {
				anchor = nil
			} else if _, ok := anchor.(lastAnchor); ok {
				anchor = nil
			}

			err = RawDetachProgram(RawDetachProgramOptions{
				Target:  iface.Index,
				Program: b,
				Attach:  gbpf.AttachTCXIngress,
				Anchor:  anchor,
			})
			qt.Assert(t, qt.IsNil(err))
		})
	}

	// Check that legacy replacement with a program works.
	err = RawAttachProgram(RawAttachProgramOptions{
		Target:  iface.Index,
		Program: b,
		Attach:  gbpf.AttachTCXIngress,
		Anchor:  ReplaceProgram(a),
	})
	qt.Assert(t, qt.IsNil(err))

	err = RawDetachProgram(RawDetachProgramOptions{
		Target:  iface.Index,
		Program: b,
		Attach:  gbpf.AttachTCXIngress,
	})
	qt.Assert(t, qt.IsNil(err))
}
