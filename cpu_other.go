//go:build !windows

package gbpf

import (
	"sync"

	"github.com/khulnasoft/gbpf/internal/linux"
)

var possibleCPU = sync.OnceValues(func() (int, error) {
	return linux.ParseCPUsFromFile("/sys/devices/system/cpu/possible")
})
