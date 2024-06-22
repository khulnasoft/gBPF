package link

import (
	"testing"

	"github.com/khulnasoft/gbpf/internal/testutils"
)

func TestHavgBPFLinkPerfEvent(t *testing.T) {
	testutils.CheckFeatureTest(t, havgBPFLinkPerfEvent)
}
