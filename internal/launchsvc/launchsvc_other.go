//go:build !darwin

package launchsvc

import "errors"

var errUnsupported = errors.New("launchsvc: only supported on macOS")

// Register is unsupported on this platform.
func Register(plistName string) error { return errUnsupported }

// Unregister is unsupported on this platform.
func Unregister(plistName string) error { return errUnsupported }

// StatusOf is unsupported on this platform.
func StatusOf(plistName string) (Status, error) { return NotFound, errUnsupported }

// OpenLoginItemsSettings is a no-op on this platform.
func OpenLoginItemsSettings() {}
