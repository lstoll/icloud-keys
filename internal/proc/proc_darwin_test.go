//go:build darwin

package proc

import (
	"os"
	"strings"
	"testing"
)

func TestDescribe(t *testing.T) {
	// The test binary is named after the package: proc.test.
	if got := Describe(os.Getpid()); !strings.HasPrefix(got, "proc.test") {
		t.Fatalf("Describe(self) = %q, want proc.test…", got)
	}
	if got := Describe(0); got != "" {
		t.Fatalf("Describe(0) = %q, want empty", got)
	}
}
