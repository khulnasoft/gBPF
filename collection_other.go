//go:build !windows

package gbpf

import "github.com/khulnasoft/gbpf/internal"

func loadCollectionFromNativeImage(_ string) (*Collection, error) {
	return nil, internal.ErrNotSupportedOnOS
}
