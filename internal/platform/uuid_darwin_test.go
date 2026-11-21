//go:build darwin

package platform

import (
	"os/exec"
	"strings"
	"testing"
)

func TestUUID(t *testing.T) {
	got, err := UUID()
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		t.Skipf("ioreg: %v", err)
	}
	want := ""
	for _, line := range strings.Split(string(out), "\n") {
		if parts := strings.Split(line, `"`); strings.Contains(line, "IOPlatformUUID") && len(parts) >= 4 {
			want = parts[len(parts)-2]
		}
	}
	if want == "" {
		t.Skip("could not parse ioreg IOPlatformUUID")
	}
	if got != want {
		t.Fatalf("UUID=%q ioreg=%q", got, want)
	}
}
