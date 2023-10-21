package link

import (
	"testing"

	"github.com/khulnasoft/gbpf/internal/testutils"
)

func TestHaveBPFLinkPerfEvent(t *testing.T) {
	testutils.CheckFeatureTest(t, haveBPFLinkPerfEvent)
}
