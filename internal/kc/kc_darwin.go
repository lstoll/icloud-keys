//go:build darwin

package kc

import (
	"errors"
	"fmt"

	"lds.li/keychain"
)

// Store is one tool's synced keychain items.
type Store struct {
	ps   *keychain.PasswordStore
	opts Options
}

// Open returns the tool's store. The binary must be signed with a Team ID and
// the keychain-access-groups entitlement for TEAMID.BundleID.
func Open(o Options) (*Store, error) {
	team, err := keychain.TeamIdentifier()
	if err != nil {
		return nil, fmt.Errorf("%s must be signed with a stable Apple Team ID (see README): %w", o.App, err)
	}
	ps, err := keychain.NewPasswordStore(keychain.PasswordStoreOptions{
		Service:        o.Service,
		Backend:        keychain.BackendDataProtection,
		Synchronizable: true,
		AccessGroup:    team + "." + o.BundleID,
		AccessControl:  keychain.AccessControl{Protection: keychain.AccessibleAfterFirstUnlock},
	})
	if err != nil {
		return nil, fmt.Errorf("keychain store: %w", err)
	}
	return &Store{ps: ps, opts: o}, nil
}

// Create adds an item, or returns an error matching ErrExists.
func (s *Store) Create(name string, secret []byte, label string, attrs []byte) error {
	err := s.ps.Create(name, secret, &keychain.PasswordAttributes{Label: label, GenericAttributes: attrs})
	return s.wrap("create "+s.opts.Noun+" "+name, err)
}

// List returns all items' metadata without reading secrets.
func (s *Store) List() ([]Item, error) {
	ms, err := s.ps.List()
	if err != nil {
		return nil, s.wrap("list", err)
	}
	items := make([]Item, 0, len(ms))
	for _, m := range ms {
		items = append(items, Item{Name: m.Account, Label: m.Label, Attrs: m.GenericAttributes})
	}
	return items, nil
}

// Item returns one item's metadata without reading its secret.
func (s *Store) Item(name string) (Item, error) {
	m, err := s.ps.Metadata(name)
	if err != nil {
		return Item{}, s.wrap("load "+s.opts.Noun+" "+name, err)
	}
	return Item{Name: m.Account, Label: m.Label, Attrs: m.GenericAttributes}, nil
}

// SetAttrs replaces an item's label and attributes, keeping its secret.
func (s *Store) SetAttrs(name, label string, attrs []byte) error {
	err := s.ps.SetAttributes(name, keychain.PasswordAttributes{Label: label, GenericAttributes: attrs})
	return s.wrap("update "+s.opts.Noun+" "+name, err)
}

// Secret reads an item's secret. Callers enforce their own presence policy
// first.
func (s *Store) Secret(name string) ([]byte, error) {
	b, err := s.ps.Get(name)
	if err != nil {
		return nil, s.wrap("load "+s.opts.Noun+" "+name, err)
	}
	return b, nil
}

// Delete removes an item from iCloud Keychain on every device. A missing item
// is an error matching ErrNotFound.
func (s *Store) Delete(name string) error {
	op := "delete " + s.opts.Noun + " " + name
	if _, err := s.ps.Metadata(name); err != nil {
		return s.wrap(op, err)
	}
	return s.wrap(op, s.ps.Delete(name))
}

func (s *Store) wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	return wrap(op, s.opts.App, s.opts.Noun, err)
}

func wrap(op, app, noun string, err error) error {
	if kcErr, ok := errors.AsType[*keychain.Error](err); ok {
		switch kcErr.Code() {
		case keychain.ErrorCodeMissingEntitlement:
			return fmt.Errorf("%s: iCloud Keychain requires %s to run from its signed .app (see README): %w", op, app, err)
		case keychain.ErrorCodeItemNotFound:
			return &notFoundError{op: op, noun: noun}
		case keychain.ErrorCodeDuplicateItem:
			return &existsError{op: op, noun: noun}
		case keychain.ErrorCodeUserCanceled:
			return fmt.Errorf("%s: Touch ID or passcode cancelled", op)
		case keychain.ErrorCodeAuthFailed:
			return fmt.Errorf("%s: Touch ID or passcode failed", op)
		case keychain.ErrorCodeInteractionNotAllowed:
			return fmt.Errorf("%s: Touch ID needs a logged-in GUI session: %w", op, err)
		}
	}
	return fmt.Errorf("%s: %w", op, err)
}

// Confirm asks for Touch ID (or the device passcode). reason completes
// "<app> is trying to …". Each call evaluates a fresh LAContext, so a
// previous approval is never reused; with allowUnlockReuse, a Touch ID unlock
// of the Mac in the last five minutes counts.
func Confirm(reason string, allowUnlockReuse bool) error {
	ctx, err := keychain.NewAuthContext()
	if err != nil {
		return fmt.Errorf("LAContext: %w", err)
	}
	if allowUnlockReuse {
		if err := ctx.SetMaximumTouchIDReuseDuration(); err != nil {
			return err
		}
	}
	if err := ctx.EvaluatePolicy(keychain.AuthPolicyDeviceOwnerAuthentication, reason); err != nil {
		return wrap("authenticate", "", "", err)
	}
	return nil
}
