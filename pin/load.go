package pin

import (
	"fmt"
	"io"

	"github.com/khulnasoft/gbpf"
	"github.com/khulnasoft/gbpf/internal/sys"
	"github.com/khulnasoft/gbpf/link"
)

// Pinner is an interface implemented by all gBPF objects that support pinning
// to a bpf virtual filesystem.
type Pinner interface {
	io.Closer
	Pin(string) error
}

// Load retrieves a pinned object from a bpf virtual filesystem. It returns one
// of [gbpf.Map], [gbpf.Program], or [link.Link].
//
// Trying to open anything other than a bpf object is an error.
func Load(path string, opts *gbpf.LoadPinOptions) (Pinner, error) {
	fd, typ, err := sys.ObjGetTyped(&sys.ObjGetAttr{
		Pathname:  sys.NewStringPointer(path),
		FileFlags: opts.Marshal(),
	})
	if err != nil {
		return nil, fmt.Errorf("opening pin %s: %w", path, err)
	}

	switch typ {
	case sys.BPF_TYPE_MAP:
		return gbpf.NewMapFromFD(fd.Disown())
	case sys.BPF_TYPE_PROG:
		return gbpf.NewProgramFromFD(fd.Disown())
	case sys.BPF_TYPE_LINK:
		return link.NewFromFD(fd.Disown())
	}

	return nil, fmt.Errorf("unknown object type %d", typ)
}
