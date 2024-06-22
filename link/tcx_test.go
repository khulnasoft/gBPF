package link

import (
	"fmt"
	"math"
	"net"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/khulnasoft/gbpf"
	"github.com/khulnasoft/gbpf/internal/testutils"
	"github.com/khulnasoft/gbpf/internal/unix"
)

func TestAttachTCX(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.6", "TCX link")

	prog := mustLoadProgram(t, gbpf.SchedCLS, gbpf.AttachNone, "")
	link, _ := mustAttachTCX(t, prog, gbpf.AttachTCXIngress)

	testLink(t, link, prog)
}

func TestTCXAnchor(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.6", "TCX link")

	a := mustLoadProgram(t, gbpf.SchedCLS, gbpf.AttachNone, "")
	b := mustLoadProgram(t, gbpf.SchedCLS, gbpf.AttachNone, "")

	linkA, iface := mustAttachTCX(t, a, gbpf.AttachTCXEgress)

	programInfo, err := a.Info()
	qt.Assert(t, qt.IsNil(err))
	programID, _ := programInfo.ID()

	linkInfo, err := linkA.Info()
	qt.Assert(t, qt.IsNil(err))
	linkID := linkInfo.ID

	for _, anchor := range []Anchor{
		Head(),
		Tail(),
		BeforeProgram(a),
		BeforeProgramByID(programID),
		AfterLink(linkA),
		AfterLinkByID(linkID),
	} {
		t.Run(fmt.Sprintf("%T", anchor), func(t *testing.T) {
			linkB, err := AttachTCX(TCXOptions{
				Program:   b,
				Attach:    gbpf.AttachTCXEgress,
				Interface: iface,
				Anchor:    anchor,
			})
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.IsNil(linkB.Close()))
		})
	}
}

func TestTCXExpectedRevision(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.6", "TCX link")

	iface, err := net.InterfaceByName("lo")
	qt.Assert(t, qt.IsNil(err))

	_, err = AttachTCX(TCXOptions{
		Program:          mustLoadProgram(t, gbpf.SchedCLS, gbpf.AttachNone, ""),
		Attach:           gbpf.AttachTCXEgress,
		Interface:        iface.Index,
		ExpectedRevision: math.MaxUint64,
	})
	qt.Assert(t, qt.ErrorIs(err, unix.ESTALE))
}

func mustAttachTCX(tb testing.TB, prog *gbpf.Program, attachType gbpf.AttachType) (Link, int) {
	iface, err := net.InterfaceByName("lo")
	qt.Assert(tb, qt.IsNil(err))

	link, err := AttachTCX(TCXOptions{
		Program:   prog,
		Attach:    attachType,
		Interface: iface.Index,
	})
	qt.Assert(tb, qt.IsNil(err))
	tb.Cleanup(func() { qt.Assert(tb, qt.IsNil(link.Close())) })

	return link, iface.Index
}
