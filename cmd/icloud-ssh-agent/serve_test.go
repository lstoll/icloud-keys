package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestListenRefusesNonSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "isa") // short: unix socket path limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	file := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(file, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if l, err := listen(file); err == nil {
		l.Close()
		t.Fatal("listened over a regular file")
	}
	if b, err := os.ReadFile(file); err != nil || string(b) != "keep me" {
		t.Fatalf("file damaged: %q, %v", b, err)
	}

	// A stale socket (nothing listening) is replaced.
	sock := filepath.Join(dir, "a.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	l2, err := listen(sock)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	defer l2.Close()

	// A live one is not.
	if l3, err := listen(sock); err == nil {
		l3.Close()
		t.Fatal("took over a live socket")
	}
}
