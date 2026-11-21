// Package kc is the iCloud Keychain storage shared by the tools in this repo:
// one synced data protection keychain store per tool, scoped to that tool's
// own access group, plus app-enforced Touch ID confirmation.
//
// Synced items can't carry SecAccessControl, so user presence is enforced by
// the calling app (see Confirm), not by Keychain.
package kc

import (
	"errors"
	"strings"
)

// Options identifies a tool's store.
type Options struct {
	// Service is kSecAttrService for the tool's items.
	Service string
	// BundleID is the tool's bundle ID; the access group is TEAMID.BundleID.
	BundleID string
	// App names the tool in error messages.
	App string
	// Noun names an item in error messages ("identity", "key").
	Noun string
}

// Item is a stored item's metadata. It never contains the secret.
type Item struct {
	Name  string
	Label string
	Attrs []byte
}

// ErrNotFound matches (via errors.Is) a missing item.
var ErrNotFound = errors.New("not found")

type notFoundError struct{ op, noun string }

func (e *notFoundError) Error() string        { return e.op + ": " + e.noun + " not found" }
func (e *notFoundError) Is(target error) bool { return target == ErrNotFound }

// ErrExists matches (via errors.Is) creating an item whose name is taken.
var ErrExists = errors.New("already exists")

type existsError struct{ op, noun string }

func (e *existsError) Error() string {
	return e.op + ": a" + article(e.noun) + " " + e.noun + " with this name already exists"
}
func (e *existsError) Is(target error) bool { return target == ErrExists }

func article(noun string) string {
	if noun != "" && strings.ContainsRune("aeiou", rune(noun[0])) {
		return "n"
	}
	return ""
}
