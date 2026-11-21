// Package sshstore keeps SSH keys in iCloud Keychain for icloud-ssh-agent.
//
// Each key is one synced item: the secret is the OpenSSH private key, and the
// public attributes hold the public key and policy, so listing keys never
// reads a secret.
package sshstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"time"

	"golang.org/x/crypto/ssh"
	"lds.li/icloud-keys/internal/kc"
	"lds.li/icloud-keys/internal/sshagent"
)

const (
	Service  = "li.lds.icloud-ssh-agent"
	BundleID = "li.lds.icloud-ssh-agent"
)

// attrs is stored in kSecAttrGeneric. It holds no secrets.
type attrs struct {
	PublicKey string `json:"publicKey"` // authorized_keys format, no comment
	Policy    string `json:"policy"`
	Created   int64  `json:"created,omitempty"`
}

// Backend is the subset of kc.Store this package uses; tests substitute it.
type Backend interface {
	Create(name string, secret []byte, label string, attrs []byte) error
	List() ([]kc.Item, error)
	Item(name string) (kc.Item, error)
	SetAttrs(name, label string, attrs []byte) error
	Secret(name string) ([]byte, error)
	Delete(name string) error
}

// Store is the agent's key store.
type Store struct {
	b Backend
	// Confirm asks for Touch ID. Defaults to kc.Confirm without unlock reuse.
	Confirm func(reason string) error
	Logger  *slog.Logger
}

var _ sshagent.Store = (*Store)(nil)

// Open opens the synced keychain store.
func Open() (*Store, error) {
	b, err := kc.Open(kc.Options{Service: Service, BundleID: BundleID, App: "icloud-ssh-agent", Noun: "key"})
	if err != nil {
		return nil, err
	}
	return New(b), nil
}

// New returns a Store on b.
func New(b Backend) *Store { return &Store{b: b} }

func (s *Store) confirm(reason string) error {
	if s.Confirm != nil {
		return s.Confirm(reason)
	}
	return kc.Confirm(reason, false)
}

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,63}$`)

// ValidateName checks a key name.
func ValidateName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("invalid key name %q (letters, digits, '.', '_', '@' or '-', max 64)", name)
	}
	return nil
}

func label(name string) string { return fmt.Sprintf("icloud-ssh-agent (%s)", name) }

// Generate creates a new Ed25519 key.
func (s *Store) Generate(name string, policy sshagent.Policy) (sshagent.Key, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return sshagent.Key{}, err
	}
	return s.add(name, priv, policy)
}

// Import stores an existing OpenSSH (or PEM) private key. passphrase is
// called only if the key is encrypted. The key file is left alone.
func (s *Store) Import(name string, pemBytes []byte, passphrase func() ([]byte, error), policy sshagent.Policy) (sshagent.Key, error) {
	raw, err := ssh.ParseRawPrivateKey(pemBytes)
	if _, ok := errors.AsType[*ssh.PassphraseMissingError](err); ok {
		if passphrase == nil {
			return sshagent.Key{}, errors.New("key is encrypted and no passphrase is available")
		}
		pw, perr := passphrase()
		if perr != nil {
			return sshagent.Key{}, perr
		}
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, pw)
	}
	if err != nil {
		return sshagent.Key{}, fmt.Errorf("parse private key: %w", err)
	}
	// ParseRawPrivateKey returns *ed25519.PrivateKey for OpenSSH ed25519 keys.
	if p, ok := raw.(*ed25519.PrivateKey); ok {
		raw = *p
	}
	return s.add(name, raw, policy)
}

func (s *Store) add(name string, priv any, policy sshagent.Policy) (sshagent.Key, error) {
	if err := ValidateName(name); err != nil {
		return sshagent.Key{}, err
	}
	if len(policy) == 0 {
		return sshagent.Key{}, errors.New("empty policy")
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return sshagent.Key{}, fmt.Errorf("unsupported key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, name)
	if err != nil {
		return sshagent.Key{}, fmt.Errorf("encode private key: %w", err)
	}
	a, err := json.Marshal(attrs{
		PublicKey: authorizedKey(signer.PublicKey()),
		Policy:    policy.String(),
		Created:   time.Now().Unix(),
	})
	if err != nil {
		return sshagent.Key{}, err
	}
	if err := s.b.Create(name, pemEncode(block), label(name), a); err != nil {
		return sshagent.Key{}, err
	}
	return sshagent.Key{Name: name, Public: signer.PublicKey(), Policy: policy}, nil
}

// Keys lists keys without reading secrets. Items with unreadable attributes
// are skipped (and logged) so one bad item can't take the agent down.
func (s *Store) Keys() ([]sshagent.Key, error) {
	items, err := s.b.List()
	if err != nil {
		return nil, err
	}
	keys := make([]sshagent.Key, 0, len(items))
	for _, it := range items {
		k, err := parseItem(it)
		if err != nil {
			s.logger().Warn("skipping key", "name", it.Name, "err", err)
			continue
		}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Name < keys[j].Name })
	return keys, nil
}

// Key returns one key's public half and policy.
func (s *Store) Key(name string) (sshagent.Key, error) {
	it, err := s.b.Item(name)
	if err != nil {
		return sshagent.Key{}, err
	}
	return parseItem(it)
}

func parseItem(it kc.Item) (sshagent.Key, error) {
	var a attrs
	if err := json.Unmarshal(it.Attrs, &a); err != nil {
		return sshagent.Key{}, fmt.Errorf("attributes: %w", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(a.PublicKey))
	if err != nil {
		return sshagent.Key{}, fmt.Errorf("public key: %w", err)
	}
	pol, err := sshagent.ParsePolicy(a.Policy)
	if err != nil {
		return sshagent.Key{}, err
	}
	return sshagent.Key{Name: it.Name, Public: pub, Policy: pol}, nil
}

// Signer reads the secret. The agent calls it only after policy approval.
func (s *Store) Signer(name string) (ssh.Signer, error) {
	secret, err := s.b.Secret(name)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(secret)
}

// SetPolicy changes a key's policy after Touch ID. The change syncs to every
// device, so it always prompts.
func (s *Store) SetPolicy(name string, policy sshagent.Policy) error {
	if len(policy) == 0 {
		return errors.New("empty policy")
	}
	it, err := s.b.Item(name)
	if err != nil {
		return err
	}
	var a attrs
	if err := json.Unmarshal(it.Attrs, &a); err != nil {
		return fmt.Errorf("key %q attributes: %w", name, err)
	}
	if err := s.confirm(fmt.Sprintf("change the policy of the “%s” SSH key to %s", name, policy)); err != nil {
		return err
	}
	a.Policy = policy.String()
	raw, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return s.b.SetAttrs(name, it.Label, raw)
}

// Export returns the OpenSSH private key after Touch ID, whatever the policy.
func (s *Store) Export(name string) ([]byte, error) {
	if _, err := s.b.Item(name); err != nil {
		return nil, err
	}
	if err := s.confirm(fmt.Sprintf("export the “%s” SSH private key", name)); err != nil {
		return nil, err
	}
	return s.b.Secret(name)
}

// Delete removes a key from iCloud Keychain on every device.
func (s *Store) Delete(name string) error { return s.b.Delete(name) }

func (s *Store) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func authorizedKey(k ssh.PublicKey) string {
	b := ssh.MarshalAuthorizedKey(k)
	return string(b[:len(b)-1]) // drop newline
}
