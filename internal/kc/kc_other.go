//go:build !darwin

package kc

import "errors"

var errUnavailable = errors.New("iCloud Keychain is only available on macOS")

// Store is unavailable off macOS.
type Store struct{}

func Open(Options) (*Store, error)                         { return nil, errUnavailable }
func (*Store) Create(string, []byte, string, []byte) error { return errUnavailable }
func (*Store) List() ([]Item, error)                       { return nil, errUnavailable }
func (*Store) Item(string) (Item, error)                   { return Item{}, errUnavailable }
func (*Store) SetAttrs(string, string, []byte) error       { return errUnavailable }
func (*Store) Secret(string) ([]byte, error)               { return nil, errUnavailable }
func (*Store) Delete(string) error                         { return errUnavailable }
func Confirm(string, bool) error                           { return errUnavailable }
