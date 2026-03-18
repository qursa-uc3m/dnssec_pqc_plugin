package bench

import (
	"fmt"
	"testing"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func TestListSigs(t *testing.T) {
	for _, s := range oqs.EnabledSigs() {
		fmt.Println(s)
	}
}
