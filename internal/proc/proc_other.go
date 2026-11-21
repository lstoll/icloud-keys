//go:build !darwin

// Package proc names processes for log entries.
package proc

// Describe returns "" off macOS.
func Describe(pid int) string { return "" }
