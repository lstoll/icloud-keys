package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func startWatch(t *testing.T, exe string) (replaced, removed chan struct{}) {
	t.Helper()
	replaced, removed = make(chan struct{}), make(chan struct{})
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	w := appWatch{
		Path: exe, Every: 5 * time.Millisecond, GoneAfter: 100 * time.Millisecond,
		Replaced: func() { close(replaced) }, Removed: func() { close(removed) },
	}
	if err := w.Start(stop); err != nil {
		t.Fatal(err)
	}
	return replaced, removed
}

func writeFile(t *testing.T, p string) {
	t.Helper()
	if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func rename(t *testing.T, from, to string) {
	t.Helper()
	if err := os.Rename(from, to); err != nil {
		t.Fatal(err)
	}
}

func TestAppWatchReplaced(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "agent")
	writeFile(t, exe)
	replaced, removed := startWatch(t, exe)

	none := func(what string) {
		t.Helper()
		select {
		case <-replaced:
			t.Fatalf("reported replaced after %s", what)
		case <-removed:
			t.Fatalf("reported removed after %s", what)
		case <-time.After(40 * time.Millisecond):
		}
	}
	writeFile(t, exe) // same inode
	none("rewriting in place")
	rename(t, exe, exe+".old") // briefly missing, as mid-upgrade
	none("a short gap")
	writeFile(t, exe+".new")
	rename(t, exe+".new", exe)
	select {
	case <-replaced:
	case <-removed:
		t.Fatal("reported removed, want replaced")
	case <-time.After(2 * time.Second):
		t.Fatal("replacement not reported")
	}
}

func TestAppWatchRemoved(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "agent")
	writeFile(t, exe)
	replaced, removed := startWatch(t, exe)
	if err := os.Remove(exe); err != nil {
		t.Fatal(err)
	}
	select {
	case <-removed:
	case <-replaced:
		t.Fatal("reported replaced, want removed")
	case <-time.After(2 * time.Second):
		t.Fatal("removal not reported")
	}
}

func TestAppWatchMissingAtStart(t *testing.T) {
	w := appWatch{Path: filepath.Join(t.TempDir(), "nope"), Every: time.Millisecond}
	if err := w.Start(nil); err == nil {
		t.Fatal("want an error for a missing file")
	}
}
