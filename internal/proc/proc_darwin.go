//go:build darwin

// Package proc names processes for log entries.
package proc

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Describe names a process and, if it's interesting, its parent: e.g.
// "ssh (from git)" or "age (from sops)". Best effort and informational only: a
// process can name itself anything.
func Describe(pid int) string {
	if pid <= 0 {
		return ""
	}
	name, ppid := info(pid)
	if name == "" {
		return fmt.Sprintf("pid %d", pid)
	}
	if parent, _ := info(ppid); parent != "" && !boring(parent) {
		return fmt.Sprintf("%s (from %s)", name, parent)
	}
	return name
}

func info(pid int) (name string, ppid int) {
	if pid <= 1 {
		return "", 0
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return "", 0
	}
	b := kp.Proc.P_comm[:]
	for i, c := range b {
		if c == 0 {
			b = b[:i]
			break
		}
	}
	return string(b), int(kp.Eproc.Ppid)
}

// boring parents add nothing to "requested by ssh".
func boring(name string) bool {
	switch name {
	case "zsh", "bash", "sh", "fish", "login", "launchd", "tmux", "screen":
		return true
	}
	return false
}
