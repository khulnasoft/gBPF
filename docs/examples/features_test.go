//go:build linux

package examples

import (
	"errors"
	"fmt"

	"github.com/khulnasoft/gbpf"
	"github.com/khulnasoft/gbpf/features"
)

func DocDetectXDP() {
	err := features.HaveProgramType(gbpf.XDP)
	if errors.Is(err, gbpf.ErrNotSupported) {
		fmt.Println("XDP program type is not supported")
		return
	}
	if err != nil {
		// Feature detection was inconclusive.
		//
		// Note: always log and investigate these errors! These can be caused
		// by a lack of permissions, verifier errors, etc. Unless stated
		// otherwise, probes are expected to be conclusive. Please file
		// an issue if this is not the case in your environment.
		panic(err)
	}

	fmt.Println("XDP program type is supported")
}
