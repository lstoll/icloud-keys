//go:build darwin

package main

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// describePeer names the process on the other end of an agent connection,
// e.g. "ssh (from git)". Best effort, informational only: a process can name
// itself anything.
func describePeer(c net.Conn) string {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return ""
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return ""
	}
	pid := 0
	_ = raw.Control(func(fd uintptr) {
		pid, _ = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	})
	if pid <= 0 {
		return ""
	}
	name, ppid := procInfo(pid)
	if name == "" {
		return fmt.Sprintf("pid %d", pid)
	}
	if parent, _ := procInfo(ppid); parent != "" && !boring(parent) {
		return fmt.Sprintf("%s (from %s)", name, parent)
	}
	return name
}

func procInfo(pid int) (name string, ppid int) {
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
