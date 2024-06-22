package link

import (
	"fmt"

	"github.com/khulnasoft/gbpf"
	"github.com/khulnasoft/gbpf/internal/sys"
)

// NetNsLink is a program attached to a network namespace.
type NetNsLink struct {
	RawLink
}

// AttachNetNs attaches a program to a network namespace.
func AttachNetNs(ns int, prog *gbpf.Program) (*NetNsLink, error) {
	var attach gbpf.AttachType
	switch t := prog.Type(); t {
	case gbpf.FlowDissector:
		attach = gbpf.AttachFlowDissector
	case gbpf.SkLookup:
		attach = gbpf.AttachSkLookup
	default:
		return nil, fmt.Errorf("can't attach %v to network namespace", t)
	}

	link, err := AttachRawLink(RawLinkOptions{
		Target:  ns,
		Program: prog,
		Attach:  attach,
	})
	if err != nil {
		return nil, err
	}

	return &NetNsLink{*link}, nil
}

func (ns *NetNsLink) Info() (*Info, error) {
	var info sys.NetNsLinkInfo
	if err := sys.ObjInfo(ns.fd, &info); err != nil {
		return nil, fmt.Errorf("netns link info: %s", err)
	}
	extra := &NetNsInfo{
		NetnsIno:   info.NetnsIno,
		AttachType: info.AttachType,
	}

	return &Info{
		info.Type,
		info.Id,
		gbpf.ProgramID(info.ProgId),
		extra,
	}, nil
}
