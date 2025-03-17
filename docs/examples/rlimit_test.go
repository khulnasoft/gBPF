//go:build linux

package examples

// DocRlimit {
import "github.com/khulnasoft/gbpf/rlimit"

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}
}

// }
