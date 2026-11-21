package launchsvc

import (
	"runtime"
	"testing"
)

func TestStatusString(t *testing.T) {
	for s, want := range map[Status]string{
		NotRegistered:    "not registered",
		Enabled:          "enabled",
		RequiresApproval: "requires approval",
		NotFound:         "not found",
		Status(42):       "unknown(42)",
	} {
		if got := s.String(); got != want {
			t.Errorf("Status(%d).String() = %q, want %q", int(s), got, want)
		}
	}
}

func TestStatusOfMissing(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin only")
	}
	// Outside an app bundle this may report NotFound or an error; either is
	// fine, it just must not crash.
	st, err := StatusOf("li.lds.does-not-exist.plist")
	t.Logf("status=%v err=%v", st, err)
}
