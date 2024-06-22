package link

import (
	"testing"

	"github.com/khulnasoft/gbpf"
	"github.com/khulnasoft/gbpf/internal/testutils"
)

const (
	NFPROTO_IPV4      = 0x2
	NF_INET_LOCAL_OUT = 0x3
)

func TestAttachNetfilter(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.4", "BPF_LINK_TYPE_NETFILTER")

	prog := mustLoadProgram(t, gbpf.Netfilter, gbpf.AttachNetfilter, "")

	l, err := AttachNetfilter(NetfilterOptions{
		Program:        prog,
		ProtocolFamily: NFPROTO_IPV4,
		HookNumber:     NF_INET_LOCAL_OUT,
		Priority:       -128,
	})
	if err != nil {
		t.Fatal(err)
	}

	testLink(t, l, prog)
}
