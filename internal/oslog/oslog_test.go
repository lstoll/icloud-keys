package oslog

import (
	"log/slog"
	"testing"
)

type entry struct {
	t   Type
	msg string
}

func TestHandler(t *testing.T) {
	var got []entry
	h := newHandler(func(t Type, m string) { got = append(got, entry{t, m}) }, &slog.HandlerOptions{Level: slog.LevelDebug})
	l := slog.New(h)

	l.Debug("conn ended", "err", "EOF")
	l.Info("signed without prompt", "key", "work", "requester", "ssh-keygen (from git)")
	l.Warn("denied by policy")
	l.Error("accept", "err", "boom")
	l.With("conn", 3).WithGroup("req").Info("bound", "host", "github.com")

	want := []entry{
		{TypeDebug, "conn ended err=EOF"},
		{TypeDefault, `signed without prompt key=work requester="ssh-keygen (from git)"`},
		{TypeDefault, "denied by policy"},
		{TypeError, "accept err=boom"},
		{TypeDefault, "bound conn=3 req.host=github.com"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries %q, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestHandlerLevel(t *testing.T) {
	n := 0
	l := slog.New(newHandler(func(Type, string) { n++ }, nil))
	l.Debug("dropped")
	l.Info("kept")
	if n != 1 {
		t.Fatalf("got %d entries, want 1 (debug filtered by default)", n)
	}
}
