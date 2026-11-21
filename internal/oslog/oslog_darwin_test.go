//go:build darwin && cgo

package oslog

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestRoundTrip writes an entry and reads it back with log(1). It takes a few
// seconds and depends on the unified log, so it runs only when asked:
// OSLOG_E2E=1 go test ./internal/oslog
func TestRoundTrip(t *testing.T) {
	if os.Getenv("OSLOG_E2E") == "" {
		t.Skip("set OSLOG_E2E=1 to write to and read from the unified log")
	}
	const sub = "li.lds.icloud-keys.oslog-test"
	h, err := Open(sub, "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	marker := fmt.Sprintf("roundtrip-%d", time.Now().UnixNano())
	slog.New(h).Warn("hello", "marker", marker, "text", "ünïcode & spaces")
	want := fmt.Sprintf(`hello marker=%s text="ünïcode & spaces"`, marker)
	var out []byte
	for range 10 {
		time.Sleep(time.Second)
		out, err = exec.Command("/usr/bin/log", "show", "--last", "1m", "--style", "compact",
			"--predicate", fmt.Sprintf("subsystem == %q", sub)).CombinedOutput()
		if err != nil {
			t.Fatalf("log show: %v\n%s", err, out)
		}
		if strings.Contains(string(out), want) {
			return
		}
	}
	t.Fatalf("entry %q not found in:\n%s", want, out)
}
