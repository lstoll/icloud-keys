//go:build !darwin

package main

import "net"

func describePeer(net.Conn) string { return "" }
