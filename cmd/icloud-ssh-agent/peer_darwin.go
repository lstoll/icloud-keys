//go:build darwin

package main

import (
	"net"

	"golang.org/x/sys/unix"
	"lds.li/icloud-keys/internal/proc"
)

// describePeer names the process on the other end of an agent connection,
// e.g. "ssh (from git)".
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
	return proc.Describe(pid)
}
