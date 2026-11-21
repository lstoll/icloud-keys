//go:build darwin

package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	"lds.li/icloud-keys/internal/kc"
	"lds.li/icloud-keys/internal/platform"
)

var (
	mu         sync.Mutex
	secrets    = map[string]*age.HybridIdentity{}
	presenceOK bool
	storeOnce  sync.Once
	st         *kc.Store
	storeErr   error
)

func store() (*kc.Store, error) {
	storeOnce.Do(func() {
		st, storeErr = kc.Open(kc.Options{
			Service:  Service,
			BundleID: BundleID,
			App:      "age-plugin-icloud",
			Noun:     "identity",
		})
	})
	return st, storeErr
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
	if err := s.Create(name, []byte(id.String()), label(name), generic); err != nil {
		return "", err
	}
	slog.Info("generated identity", "name", name, "access", mode)
	return IdentityFile(name, recipient, time.Now(), mode), nil
}

func label(name string) string { return fmt.Sprintf("age-plugin-icloud (%s)", name) }

// List returns names and recipients without reading secrets.
func List() ([]Item, error) {
	s, err := store()
	if err != nil {
		return nil, err
	}
	stored, err := s.List()
	if err != nil {
		return nil, err
	}
	items := make([]Item, 0, len(stored))
	for _, it := range stored {
		a, err := parsePublicAttrs(it.Attrs)
		if err != nil {
			return nil, fmt.Errorf("identity %q: %w", it.Name, err)
		}
		items = append(items, Item{
			Name:          it.Name,
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
	if err := s.Delete(name); err != nil {
		return err
	}
	slog.Info("deleted identity", "name", name)
	mu.Lock()
	delete(secrets, name)
	mu.Unlock()
	return nil
}

// SetAccessControl changes a stored identity's access control. It always asks
// for Touch ID first: the setting syncs to every device, and loosening it is
// exactly what an attacker would want. Returns the updated identity file.
func SetAccessControl(name string, mode AccessControlMode) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	s, err := store()
	if err != nil {
		return "", err
	}
	it, err := s.Item(name)
	if err != nil {
		return "", err
	}
	a, err := parsePublicAttrs(it.Attrs)
	if err != nil {
		return "", fmt.Errorf("identity %q: %w", name, err)
	}
	if err := kc.Confirm(fmt.Sprintf("change access control for the “%s” identity to %s", name, mode), false); err != nil {
		slog.Warn("access control change not approved", "name", name, "from", a.mode(), "to", mode, "err", err)
		return "", err
	}
	from := a.mode()
	a.AccessControl = string(mode)
	a.PresenceAt = nil // a new policy starts with no approvals
	raw, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	if err := s.SetAttrs(name, it.Label, raw); err != nil {
		return "", err
	}
	slog.Info("changed access control", "name", name, "from", from, "to", mode)
	return IdentityFile(name, a.Recipient, time.Time{}, mode), nil
}

// Export returns the identity's secret key (AGE-SECRET-KEY-PQ-…). It always
// asks for Touch ID, whatever the identity's access control.
func Export(name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	s, err := store()
	if err != nil {
		return "", err
	}
	if _, err := s.Item(name); err != nil {
		return "", err
	}
	if err := kc.Confirm(fmt.Sprintf("export the secret key of the “%s” identity", name), false); err != nil {
		slog.Warn("export not approved", "name", name, "err", err)
		return "", err
	}
	secret, err := s.Secret(name)
	if err != nil {
		return "", err
	}
	slog.Warn("exported secret key", "name", name)
	return strings.TrimSpace(string(secret)), nil
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
	it, err := s.Item(name)
	if err != nil {
		if errors.Is(err, kc.ErrNotFound) {
			if name == DefaultName {
				return nil, errors.New("no default identity; run age-plugin-icloud --generate")
			}
			return nil, fmt.Errorf("no identity named %q", name)
		}
		return nil, err
	}
	a, err := parsePublicAttrs(it.Attrs)
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
	it, err := s.Item(name)
	if err != nil {
		return nil, err
	}
	a, err := parsePublicAttrs(it.Attrs)
	if err != nil {
		return nil, fmt.Errorf("identity %q: %w", name, err)
	}
	mode := a.mode()
	approval := "not required"
	if mode.prompts() {
		machine := machineID()
		if mode == AccessControl5m && a.presenceFresh(machine, time.Now()) {
			approval = "within 5m"
		} else {
			prompted, err := requireUserPresenceLocked(presenceReason(name), mode == AccessControl5m)
			if err != nil {
				slog.Warn("decrypt not approved", "name", name, "access", mode, "err", err)
				return nil, err
			}
			approval = "touch id"
			if !prompted {
				approval = "earlier in this run"
			}
			if mode == AccessControl5m {
				stampPresence(s, name, machine)
			}
		}
	}
	secret, err := s.Secret(name)
	if err != nil {
		return nil, err
	}
	id, err := age.ParseHybridIdentity(strings.TrimSpace(string(secret)))
	if err != nil {
		return nil, fmt.Errorf("parse identity %q: %w", name, err)
	}
	secrets[name] = id
	slog.Info("unlocked identity", "name", name, "access", mode, "approval", approval)
	return id, nil
}

// stampPresence records a 5m approval for this Mac. It re-reads the item
// rather than writing back what was read before the prompt: a
// --set-access-control while the prompt was open must not be undone. Keychain
// has no compare-and-swap, so a tiny window remains between this read and
// write, but it no longer spans a Touch ID prompt.
func stampPresence(s *kc.Store, name, machine string) {
	it, err := s.Item(name)
	if err != nil {
		return
	}
	a, err := parsePublicAttrs(it.Attrs)
	if err != nil || a.mode() != AccessControl5m {
		return
	}
	a.stampPresence(machine, time.Now())
	if raw, err := json.Marshal(a); err == nil {
		_ = s.SetAttrs(name, it.Label, raw)
	}
}

// requireUserPresenceLocked prompts at most once per process: age -j icloud
// may load several identities for one decrypt. It reports whether it prompted.
func requireUserPresenceLocked(reason string, allowUnlockReuse bool) (bool, error) {
	if presenceOK {
		return false, nil
	}
	if err := kc.Confirm(reason, allowUnlockReuse); err != nil {
		return false, err
	}
	presenceOK = true
	return true, nil
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
