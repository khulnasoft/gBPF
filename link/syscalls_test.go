package link

import (
	"testing"

	"github.com/khulnasoft/gbpf/internal/testutils"
)

func TestHaveProgAttach(t *testing.T) {
	testutils.CheckFeatureTest(t, haveProgAttach)
}

func TestHaveProgAttachReplace(t *testing.T) {
	testutils.CheckFeatureTest(t, haveProgAttachReplace)
}

func TestHavgBPFLink(t *testing.T) {
	testutils.CheckFeatureTest(t, havgBPFLink)
}

func TestHaveProgQuery(t *testing.T) {
	testutils.CheckFeatureTest(t, haveProgQuery)
}

func TestHaveTCX(t *testing.T) {
	testutils.CheckFeatureTest(t, haveTCX)
}

func TestHaveNetkit(t *testing.T) {
	testutils.CheckFeatureTest(t, haveNetkit)
}
