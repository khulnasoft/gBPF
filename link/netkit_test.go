package link

import (
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/jsimonetti/rtnetlink/v2"
	"github.com/jsimonetti/rtnetlink/v2/driver"
	"github.com/khulnasoft/gbpf"
	"github.com/khulnasoft/gbpf/internal/testutils"
	"golang.org/x/sys/unix"
)

func TestAttachNetkit(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.7", "Netkit Device")

	prog := mustLoadProgram(t, gbpf.SchedCLS, gbpf.AttachNetkitPrimary, "")
	link, _ := mustAttachNetkit(t, prog, gbpf.AttachNetkitPrimary)

	testLink(t, link, prog)
}

func TestNetkitAnchor(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.7", "Netkit Device")

	a := mustLoadProgram(t, gbpf.SchedCLS, gbpf.AttachNetkitPrimary, "")
	b := mustLoadProgram(t, gbpf.SchedCLS, gbpf.AttachNetkitPrimary, "")

	linkA, ifIndex := mustAttachNetkit(t, a, gbpf.AttachNetkitPrimary)

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
			linkB, err := AttachNetkit(NetkitOptions{
				Program:   b,
				Attach:    gbpf.AttachNetkitPrimary,
				Interface: ifIndex,
				Anchor:    anchor,
			})
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.IsNil(linkB.Close()))
		})
	}
}

// The last ifindex we created.
var prevIfindex atomic.Uint32

func init() { prevIfindex.Store(1000 - 1) }

func mustAttachNetkit(tb testing.TB, prog *gbpf.Program, attachType gbpf.AttachType) (Link, int) {
	var err error
	conn, err := rtnetlink.Dial(nil)
	qt.Assert(tb, qt.IsNil(err))
	tb.Cleanup(func() {
		qt.Assert(tb, qt.IsNil(conn.Close()))
	})

	ifIndex := prevIfindex.Add(1)

	layer2 := driver.NetkitModeL2
	blackhole := driver.NetkitPolicyDrop
	err = conn.Link.New(&rtnetlink.LinkMessage{
		Family: unix.AF_UNSPEC,
		Index:  ifIndex,
		Flags:  unix.IFF_UP,
		Change: unix.IFF_UP,
		Attributes: &rtnetlink.LinkAttributes{
			Info: &rtnetlink.LinkInfo{
				Kind: "netkit",
				Data: &driver.Netkit{
					Mode:       &layer2,
					PeerPolicy: &blackhole,
				},
			},
		},
	})
	qt.Assert(tb, qt.IsNil(err))
	tb.Cleanup(func() {
		qt.Assert(tb, qt.IsNil(conn.Link.Delete(uint32(ifIndex))))
	})

	link, err := AttachNetkit(NetkitOptions{
		Program:   prog,
		Attach:    attachType,
		Interface: int(ifIndex),
	})
	qt.Assert(tb, qt.IsNil(err))
	tb.Cleanup(func() {
		qt.Assert(tb, qt.IsNil(link.Close()))
	})

	return link, int(ifIndex)
}
