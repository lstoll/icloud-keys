package sshagent

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Key is a stored key's public half and policy. Listing keys must not read
// secrets.
type Key struct {
	Name   string
	Public ssh.PublicKey
	Policy Policy
}

// Store provides keys. Signer is only called after the policy allows a
// request, so it may read the secret.
type Store interface {
	Keys() ([]Key, error)
	Signer(name string) (ssh.Signer, error)
}

// Prompter asks the user to approve a request, e.g. with Touch ID. reason
// completes "<app> is trying to …".
type Prompter interface {
	Confirm(reason string) error
}

// Agent serves keys from a Store, applying each key's Policy.
type Agent struct {
	Store    Store
	Prompter Prompter
	// HostName names a host key for prompts. Defaults to its fingerprint.
	HostName func(ssh.PublicKey) string
	// Now defaults to time.Now.
	Now    func() time.Time
	Logger *slog.Logger

	promptMu sync.Mutex // one prompt on screen at a time

	mu       sync.Mutex
	approved map[string]time.Time // key fingerprint + purpose -> last approval
}

// ReuseWindow is how long a prompt-5m approval lasts.
const ReuseWindow = 5 * time.Minute

// maxBindings matches OpenSSH's limit on session-bind hops per connection.
const maxBindings = 16

var (
	ErrDenied      = errors.New("denied by policy")
	errUnsupported = errors.New("not supported: keys live in iCloud Keychain")
)

// ServeConn serves one agent client connection until it closes.
func (a *Agent) ServeConn(c io.ReadWriter) error { return a.ServeConnFrom(c, "") }

// ServeConnFrom is ServeConn with a description of the client process for
// prompts and logs.
func (a *Agent) ServeConnFrom(c io.ReadWriter, requester string) error {
	err := agent.ServeAgent(&conn{a: a, requester: requester}, c)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func (a *Agent) logger() *slog.Logger {
	if a.Logger != nil {
		return a.Logger
	}
	return slog.Default()
}

func (a *Agent) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Agent) hostName(k ssh.PublicKey) string {
	if k == nil {
		return "an SSH server"
	}
	if a.HostName != nil {
		if n := a.HostName(k); n != "" {
			return n
		}
	}
	return ssh.FingerprintSHA256(k)
}

// authorize applies the key's policy to a request, prompting if needed.
func (a *Agent) authorize(k Key, r Request) error {
	action := k.Policy.Decide(r)
	purpose, _ := PurposeOf(r)
	log := a.logger().With("key", k.Name, "purpose", r.Kind.String(), "namespace", r.Namespace, "forwarded", r.Forwarded, "requester", r.Requester)
	if r.Kind == KindUserAuth {
		log = log.With("host", a.hostName(r.HostKey), "user", r.User)
	}

	switch action {
	case ActionAllow:
		log.Info("signed without prompt")
		return nil
	case ActionPrompt, ActionPrompt5m:
	default:
		log.Warn("denied by policy")
		return ErrDenied
	}

	cacheKey := ssh.FingerprintSHA256(k.Public) + "|" + string(purpose)
	if action == ActionPrompt5m && a.fresh(cacheKey) {
		log.Info("signed within approval window")
		return nil
	}

	a.promptMu.Lock()
	defer a.promptMu.Unlock()
	// Another connection may have been approved while we waited.
	if action == ActionPrompt5m && a.fresh(cacheKey) {
		log.Info("signed within approval window")
		return nil
	}
	if a.Prompter == nil {
		log.Warn("denied: no prompter")
		return ErrDenied
	}
	if err := a.Prompter.Confirm(a.reason(k, r)); err != nil {
		log.Warn("prompt refused", "err", err)
		return err
	}
	if action == ActionPrompt5m {
		a.mu.Lock()
		if a.approved == nil {
			a.approved = map[string]time.Time{}
		}
		a.approved[cacheKey] = a.now()
		a.mu.Unlock()
	}
	log.Info("signed after prompt")
	return nil
}

func (a *Agent) fresh(cacheKey string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.approved[cacheKey]
	return ok && a.now().Sub(t) < ReuseWindow && !a.now().Before(t)
}

func (a *Agent) reason(k Key, r Request) string {
	var s string
	switch r.Kind {
	case KindUserAuth:
		s = fmt.Sprintf("log in to %s as %s using “%s”", a.hostName(r.HostKey), r.User, k.Name)
	case KindSSHSig:
		if r.Namespace == "git" {
			s = fmt.Sprintf("sign a git commit or tag using “%s”", k.Name)
		} else {
			s = fmt.Sprintf("create a “%s” signature using “%s”", r.Namespace, k.Name)
		}
	default:
		s = fmt.Sprintf("sign data using “%s”", k.Name)
	}
	if r.Forwarded {
		s += " from a forwarded agent"
	}
	if r.Requester != "" {
		s += " (requested by " + r.Requester + ")"
	}
	return s
}

// conn is per-connection agent state: session-bind is connection-scoped.
type conn struct {
	a         *Agent
	requester string
	bindings  []binding
}

var _ agent.ExtendedAgent = (*conn)(nil)

func (c *conn) List() ([]*agent.Key, error) {
	keys, err := c.a.Store.Keys()
	if err != nil {
		return nil, err
	}
	out := make([]*agent.Key, 0, len(keys))
	for _, k := range keys {
		out = append(out, &agent.Key{Format: k.Public.Type(), Blob: k.Public.Marshal(), Comment: k.Name})
	}
	return out, nil
}

func (c *conn) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return c.SignWithFlags(key, data, 0)
}

func (c *conn) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	k, err := c.find(key)
	if err != nil {
		return nil, err
	}
	r, err := c.request(data)
	if err != nil {
		c.a.logger().Warn("denied", "key", k.Name, "err", err)
		return nil, err
	}
	if err := c.a.authorize(k, r); err != nil {
		return nil, err
	}
	signer, err := c.a.Store.Signer(k.Name)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(signer.PublicKey().Marshal(), k.Public.Marshal()) {
		return nil, fmt.Errorf("key %q: stored secret does not match its public key", k.Name)
	}
	if alg := rsaAlgorithm(flags); alg != "" && signer.PublicKey().Type() == ssh.KeyAlgoRSA {
		if as, ok := signer.(ssh.AlgorithmSigner); ok {
			return as.SignWithAlgorithm(rand.Reader, data, alg)
		}
	}
	return signer.Sign(rand.Reader, data)
}

// request parses sign data and attaches this connection's session binding.
func (c *conn) request(data []byte) (Request, error) {
	r := ParseSignData(data)
	r.Requester = c.requester
	for _, b := range c.bindings {
		if b.forwarding {
			r.Forwarded = true
		}
	}
	if r.Kind != KindUserAuth || len(c.bindings) == 0 {
		return r, nil
	}
	// The client bound this connection to a session; a userauth for any other
	// session is someone replaying a signature request for a different host.
	last := c.bindings[len(c.bindings)-1]
	if !bytes.Equal(last.sessionID, r.SessionID) {
		return r, fmt.Errorf("%w: userauth for a session this connection is not bound to", ErrDenied)
	}
	if r.HostKey != nil && !bytes.Equal(r.HostKey.Marshal(), last.hostKey.Marshal()) {
		return r, fmt.Errorf("%w: userauth host key does not match session binding", ErrDenied)
	}
	r.HostKey = last.hostKey
	return r, nil
}

func (c *conn) find(key ssh.PublicKey) (Key, error) {
	keys, err := c.a.Store.Keys()
	if err != nil {
		return Key{}, err
	}
	want := key.Marshal()
	var found []Key
	for _, k := range keys {
		if bytes.Equal(k.Public.Marshal(), want) {
			found = append(found, k)
		}
	}
	switch len(found) {
	case 0:
		return Key{}, errors.New("key not found")
	case 1:
		return found[0], nil
	}
	// The same key under several names (e.g. imported on two Macs) has
	// several policies; picking one would let the loosest win. Refuse.
	names := make([]string, len(found))
	for i, k := range found {
		names[i] = k.Name
	}
	c.a.logger().Warn("denied: key stored under several names", "names", names)
	return Key{}, fmt.Errorf("%w: key is stored under several names (%s); delete all but one", ErrDenied, strings.Join(names, ", "))
}

func (c *conn) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType != "session-bind@openssh.com" {
		return nil, agent.ErrExtensionUnsupported
	}
	b, err := parseSessionBind(contents)
	if err != nil {
		return nil, err
	}
	// As in OpenSSH: once bound for authentication (not forwarding), the
	// connection is spent; further binds are refused.
	if n := len(c.bindings); n > 0 && !c.bindings[n-1].forwarding {
		return nil, errors.New("session-bind: connection already bound for authentication")
	}
	if len(c.bindings) >= maxBindings {
		return nil, errors.New("session-bind: too many hops")
	}
	c.bindings = append(c.bindings, b)
	return nil, nil
}

func rsaAlgorithm(flags agent.SignatureFlags) string {
	switch {
	case flags&agent.SignatureFlagRsaSha512 != 0:
		return ssh.KeyAlgoRSASHA512
	case flags&agent.SignatureFlagRsaSha256 != 0:
		return ssh.KeyAlgoRSASHA256
	}
	return ""
}

func (c *conn) Add(agent.AddedKey) error       { return errUnsupported }
func (c *conn) Remove(ssh.PublicKey) error     { return errUnsupported }
func (c *conn) RemoveAll() error               { return errUnsupported }
func (c *conn) Lock([]byte) error              { return errUnsupported }
func (c *conn) Unlock([]byte) error            { return errUnsupported }
func (c *conn) Signers() ([]ssh.Signer, error) { return nil, errUnsupported }
