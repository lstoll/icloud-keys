package sshstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
	"lds.li/icloud-keys/internal/kc"
	"lds.li/icloud-keys/internal/sshagent"
)

type memBackend struct{ items map[string]*memItem }

type memItem struct {
	secret []byte
	kc.Item
}

func newMem() *memBackend { return &memBackend{items: map[string]*memItem{}} }

func (m *memBackend) Create(name string, secret []byte, label string, attrs []byte) error {
	if _, ok := m.items[name]; ok {
		return kc.ErrExists
	}
	m.items[name] = &memItem{secret: secret, Item: kc.Item{Name: name, Label: label, Attrs: attrs}}
	return nil
}
func (m *memBackend) List() ([]kc.Item, error) {
	var out []kc.Item
	for _, it := range m.items {
		out = append(out, it.Item)
	}
	return out, nil
}
func (m *memBackend) Item(name string) (kc.Item, error) {
	it, ok := m.items[name]
	if !ok {
		return kc.Item{}, kc.ErrNotFound
	}
	return it.Item, nil
}
func (m *memBackend) SetAttrs(name, label string, attrs []byte) error {
	it, ok := m.items[name]
	if !ok {
		return kc.ErrNotFound
	}
	it.Label, it.Attrs = label, attrs
	return nil
}
func (m *memBackend) Secret(name string) ([]byte, error) {
	it, ok := m.items[name]
	if !ok {
		return nil, kc.ErrNotFound
	}
	return it.secret, nil
}
func (m *memBackend) Delete(name string) error {
	if _, ok := m.items[name]; !ok {
		return kc.ErrNotFound
	}
	delete(m.items, name)
	return nil
}

type confirmer struct {
	reasons []string
	err     error
}

func (c *confirmer) confirm(r string) error { c.reasons = append(c.reasons, r); return c.err }

func newStore() (*Store, *memBackend, *confirmer) {
	b := newMem()
	c := &confirmer{}
	s := New(b)
	s.Confirm = c.confirm
	return s, b, c
}

func TestGenerateSignAndList(t *testing.T) {
	s, _, c := newStore()
	k, err := s.Generate("work", sshagent.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if k.Public.Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("type = %s", k.Public.Type())
	}
	keys, err := s.Keys()
	if err != nil || len(keys) != 1 || keys[0].Name != "work" || keys[0].Policy.String() != sshagent.DefaultPolicy().String() {
		t.Fatalf("Keys = %+v, %v", keys, err)
	}
	signer, err := s.Signer("work")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(rand.Reader, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Public.Verify([]byte("data"), sig); err != nil {
		t.Fatal(err)
	}
	if len(c.reasons) != 0 {
		t.Fatal("generate/list/sign prompted")
	}
	if _, err := s.Generate("work", sshagent.DefaultPolicy()); !errors.Is(err, kc.ErrExists) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := s.Generate("bad name", sshagent.DefaultPolicy()); err == nil {
		t.Fatal("accepted bad name")
	}
}

func TestImport(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ed, _ := newStoreKey(t)
	for name, tc := range map[string]struct {
		key        any
		passphrase string
	}{
		"ed25519":           {ed, ""},
		"ecdsa":             {ec, ""},
		"rsa":               {rk, ""},
		"ed25519-encrypted": {ed, "hunter2"},
	} {
		t.Run(name, func(t *testing.T) {
			s, _, _ := newStore()
			var block *pem.Block
			var err error
			if tc.passphrase != "" {
				block, err = ssh.MarshalPrivateKeyWithPassphrase(tc.key, "c", []byte(tc.passphrase))
			} else {
				block, err = ssh.MarshalPrivateKey(tc.key, "c")
			}
			if err != nil {
				t.Fatal(err)
			}
			asked := false
			k, err := s.Import("imported", pem.EncodeToMemory(block), func() ([]byte, error) {
				asked = true
				return []byte(tc.passphrase), nil
			}, sshagent.DefaultPolicy())
			if err != nil {
				t.Fatal(err)
			}
			if asked != (tc.passphrase != "") {
				t.Fatalf("asked for passphrase = %v", asked)
			}
			signer, err := s.Signer("imported")
			if err != nil {
				t.Fatal(err)
			}
			if string(signer.PublicKey().Marshal()) != string(k.Public.Marshal()) {
				t.Fatal("stored key differs from imported key")
			}
		})
	}
	t.Run("wrong passphrase", func(t *testing.T) {
		s, _, _ := newStore()
		block, _ := ssh.MarshalPrivateKeyWithPassphrase(ed, "c", []byte("right"))
		if _, err := s.Import("x", pem.EncodeToMemory(block), func() ([]byte, error) { return []byte("wrong"), nil }, sshagent.DefaultPolicy()); err == nil {
			t.Fatal("imported with wrong passphrase")
		}
	})
}

func newStoreKey(t *testing.T) (any, ssh.PublicKey) {
	t.Helper()
	s, b, _ := newStore()
	if _, err := s.Generate("tmp", sshagent.DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	raw, err := ssh.ParseRawPrivateKey(b.items["tmp"].secret)
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(raw)
	return raw, signer.PublicKey()
}

func TestSetPolicyAndExportPrompt(t *testing.T) {
	s, b, c := newStore()
	if _, err := s.Generate("work", sshagent.DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	label := b.items["work"].Label

	c.err = errors.New("cancelled")
	if err := s.SetPolicy("work", sshagent.Policy{sshagent.PurposeSSH: sshagent.ActionAllow}); err == nil {
		t.Fatal("SetPolicy succeeded without approval")
	}
	if _, err := s.Export("work"); err == nil {
		t.Fatal("Export succeeded without approval")
	}
	if k, _ := s.Key("work"); k.Policy.String() != sshagent.DefaultPolicy().String() {
		t.Fatal("policy changed despite refusal")
	}

	c.err = nil
	if err := s.SetPolicy("work", sshagent.Policy{sshagent.PurposeSSH: sshagent.ActionAllow}); err != nil {
		t.Fatal(err)
	}
	if k, _ := s.Key("work"); k.Policy.String() != "ssh=allow" {
		t.Fatalf("policy = %s", k.Policy)
	}
	if b.items["work"].Label != label {
		t.Fatal("SetPolicy dropped the label")
	}
	pemBytes, err := s.Export("work")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ssh.ParsePrivateKey(pemBytes); err != nil {
		t.Fatalf("exported key unparseable: %v", err)
	}
	if len(c.reasons) != 4 {
		t.Fatalf("prompts = %d, want 4", len(c.reasons))
	}
	if _, err := s.Export("missing"); !errors.Is(err, kc.ErrNotFound) {
		t.Fatalf("export missing: %v", err)
	}
	if len(c.reasons) != 4 {
		t.Fatal("prompted for a missing key")
	}
}

func TestBadItemSkipped(t *testing.T) {
	s, b, _ := newStore()
	if _, err := s.Generate("good", sshagent.DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	b.items["bad"] = &memItem{Item: kc.Item{Name: "bad", Attrs: []byte("{nope")}}
	keys, err := s.Keys()
	if err != nil || len(keys) != 1 || keys[0].Name != "good" {
		t.Fatalf("Keys = %+v, %v", keys, err)
	}
}

func TestDuplicateKeyRejected(t *testing.T) {
	s, b, _ := newStore()
	if _, err := s.Generate("work", sshagent.DefaultPolicy()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Import("again", b.items["work"].secret, nil, sshagent.Policy{sshagent.PurposeSSH: sshagent.ActionAllow}); err == nil {
		t.Fatal("same key imported under a second name")
	}
	if len(b.items) != 1 {
		t.Fatalf("items = %d", len(b.items))
	}
}
