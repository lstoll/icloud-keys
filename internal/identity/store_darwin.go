//go:build darwin

package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	"lds.li/age-plugin-icloud/internal/platform"
	"lds.li/keychain"
)

var (
	mu         sync.Mutex
	secrets    = map[string]*age.HybridIdentity{}
	auth       *keychain.AuthContext
	presenceOK bool
	storeOnce  sync.Once
	kc         *keychain.PasswordStore
	storeErr   error
)

// store returns the synced data protection keychain store for identities.
func store() (*keychain.PasswordStore, error) {
	storeOnce.Do(func() {
		team, err := keychain.TeamIdentifier()
		if err != nil {
			storeErr = fmt.Errorf("age-plugin-icloud must be signed with a stable Apple Team ID (see README): %w", err)
			return
		}
		kc, err = keychain.NewPasswordStore(keychain.PasswordStoreOptions{
			Service:        Service,
			Backend:        keychain.BackendDataProtection,
			Synchronizable: true,
			AccessGroup:    team + "." + BundleID,
			AccessControl:  keychain.AccessControl{Protection: keychain.AccessibleAfterFirstUnlock},
		})
		if err != nil {
			storeErr = fmt.Errorf("keychain store: %w", err)
		}
	})
	return kc, storeErr
}

func wrapKeychain(op string, err error) error {
	var kcErr *keychain.Error
	if errors.As(err, &kcErr) {
		switch kcErr.Code() {
		case keychain.ErrorCodeMissingEntitlement:
			return fmt.Errorf("%s: iCloud Keychain requires a signed .app with com.apple.application-identifier (see README): %w", op, err)
		case keychain.ErrorCodeItemNotFound:
			return fmt.Errorf("%s: identity not found", op)
		case keychain.ErrorCodeDuplicateItem:
			return fmt.Errorf("%s: an identity with this name already exists", op)
		case keychain.ErrorCodeUserCanceled:
			return fmt.Errorf("%s: Touch ID or passcode cancelled", op)
		case keychain.ErrorCodeAuthFailed:
			return fmt.Errorf("%s: Touch ID or passcode failed", op)
		case keychain.ErrorCodeInteractionNotAllowed:
			return fmt.Errorf("%s: Touch ID needs a GUI (use --access-control=none over SSH): %w", op, err)
		}
	}
	return fmt.Errorf("%s: %w", op, err)
}

// Generate creates a new MLKEM768-X25519 identity in iCloud Keychain and
// returns the non-secret plugin identity file.
func Generate(name string, mode AccessControlMode) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	if mode == "" {
		mode = AccessControl5m
	}
	s, err := store()
	if err != nil {
		return "", err
	}

	id, err := age.GenerateHybridIdentity()
	if err != nil {
		return "", err
	}
	recipient := id.Recipient().String()
	generic, err := encodePublicAttrs(recipient, mode)
	if err != nil {
		return "", err
	}

	attrs := &keychain.PasswordAttributes{
		Label:             fmt.Sprintf("age-plugin-icloud (%s)", name),
		GenericAttributes: generic,
	}
	if err := s.Create(name, []byte(id.String()), attrs); err != nil {
		return "", wrapKeychain("create identity", err)
	}

	return IdentityFile(name, recipient, time.Now(), mode), nil
}

// List returns names and recipients without reading secrets.
func List() ([]Item, error) {
	s, err := store()
	if err != nil {
		return nil, err
	}
	passwords, err := s.List()
	if err != nil {
		return nil, wrapKeychain("list identities", err)
	}
	items := make([]Item, 0, len(passwords))
	for _, p := range passwords {
		a, err := parsePublicAttrs(p.GenericAttributes)
		if err != nil {
			return nil, fmt.Errorf("identity %q: %w", p.Account, err)
		}
		items = append(items, Item{
			Name:          p.Account,
			Recipient:     a.Recipient,
			AccessControl: a.mode(),
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items, nil
}

// Delete removes a named identity from iCloud Keychain (all devices).
func Delete(name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	s, err := store()
	if err != nil {
		return err
	}
	// Delete of a missing account succeeds; check first to report it.
	if _, err := s.Metadata(name); err != nil {
		return wrapKeychain("delete identity "+name, err)
	}
	if err := s.Delete(name); err != nil {
		return wrapKeychain("delete identity "+name, err)
	}
	mu.Lock()
	delete(secrets, name)
	mu.Unlock()
	return nil
}

// LoadIdentity returns a Keychain-backed HybridIdentity. An empty name loads
// every stored key (for age -j icloud). Secrets are read once per process.
func LoadIdentity(name string) (age.Identity, error) {
	mu.Lock()
	defer mu.Unlock()

	if name == "" {
		items, err := List()
		if err != nil {
			return nil, err
		}
		if len(items) == 0 {
			return nil, errors.New("no identities in iCloud Keychain; run age-plugin-icloud --generate")
		}
		ids := make(multiIdentity, 0, len(items))
		for _, item := range items {
			id, err := loadSecretLocked(item.Name)
			if err != nil {
				return nil, err
			}
			ids = append(ids, id)
		}
		return ids, nil
	}

	return loadSecretLocked(name)
}

// LoadRecipient returns the native age1pq recipient from item attributes.
// An empty name uses "default". This does not read the secret.
func LoadRecipient(name string) (age.Recipient, error) {
	if name == "" {
		name = DefaultName
	}
	s, err := store()
	if err != nil {
		return nil, err
	}
	attrs, err := s.Metadata(name)
	if err != nil {
		if errors.Is(err, keychain.ErrItemNotFound) {
			if name == DefaultName {
				return nil, errors.New("no default identity; run age-plugin-icloud --generate")
			}
			return nil, fmt.Errorf("no identity named %q", name)
		}
		return nil, wrapKeychain("load recipient "+name, err)
	}
	a, err := parsePublicAttrs(attrs.GenericAttributes)
	if err != nil {
		return nil, fmt.Errorf("identity %q: %w", name, err)
	}
	if a.Recipient == "" {
		return nil, fmt.Errorf("identity %q has no stored recipient", name)
	}
	return age.ParseHybridRecipient(a.Recipient)
}

func loadSecretLocked(name string) (*age.HybridIdentity, error) {
	if id, ok := secrets[name]; ok {
		return id, nil
	}
	s, err := store()
	if err != nil {
		return nil, err
	}
	attrs, err := s.Metadata(name)
	if err != nil {
		return nil, wrapKeychain("load identity "+name, err)
	}
	a, err := parsePublicAttrs(attrs.GenericAttributes)
	if err != nil {
		return nil, fmt.Errorf("identity %q: %w", name, err)
	}
	mode := a.mode()
	if mode.prompts() {
		machine := machineID()
		if !(mode == AccessControl5m && a.presenceFresh(machine, time.Now())) {
			if err := requireUserPresenceLocked(presenceReason(name), mode == AccessControl5m); err != nil {
				return nil, err
			}
			if mode == AccessControl5m {
				a.stampPresence(machine, time.Now())
				if raw, err := json.Marshal(a); err == nil {
					// SetAttributes replaces the label too, so carry it over.
					_ = s.SetAttributes(name, keychain.PasswordAttributes{
						Label:             attrs.Label,
						GenericAttributes: raw,
					})
				}
			}
		}
	}
	secret, err := s.Get(name)
	if err != nil {
		return nil, wrapKeychain("load identity "+name, err)
	}
	id, err := age.ParseHybridIdentity(strings.TrimSpace(string(secret)))
	if err != nil {
		return nil, fmt.Errorf("parse identity %q: %w", name, err)
	}
	secrets[name] = id
	return id, nil
}

func requireUserPresenceLocked(reason string, allowUnlockReuse bool) error {
	if presenceOK {
		return nil
	}
	if auth == nil {
		ctx, err := keychain.NewAuthContext()
		if err != nil {
			return fmt.Errorf("LAContext: %w", err)
		}
		if allowUnlockReuse {
			if err := ctx.SetMaximumTouchIDReuseDuration(); err != nil {
				return err
			}
		}
		auth = ctx
	}
	if err := auth.EvaluatePolicy(keychain.AuthPolicyDeviceOwnerAuthentication, reason); err != nil {
		return wrapKeychain("authenticate", err)
	}
	presenceOK = true
	return nil
}

func presenceReason(name string) string {
	if name == "" {
		return "Decrypt using an iCloud Keychain identity"
	}
	return fmt.Sprintf("Decrypt using the “%s” identity", name)
}

func machineID() string {
	id, err := platform.UUID()
	if err != nil || id == "" {
		id, _ = os.Hostname()
	}
	return id
}
