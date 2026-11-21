package sshagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type fakeStore struct {
	keys    []Key
	signers map[string]ssh.Signer
	reads   int
}

func (s *fakeStore) Keys() ([]Key, error) { return s.keys, nil }
func (s *fakeStore) Signer(name string) (ssh.Signer, error) {
	s.reads++
	return s.signers[name], nil
}

type fakePrompter struct {
	mu      sync.Mutex
	reasons []string
	err     error
}

func (p *fakePrompter) Confirm(reason string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reasons = append(p.reasons, reason)
	return p.err
}

func (p *fakePrompter) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.reasons)
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type harness struct {
	agent    *Agent
	store    *fakeStore
	prompter *fakePrompter
	signer   ssh.Signer
	now      time.Time
}

func newHarness(t *testing.T, policy Policy) *harness {
	t.Helper()
	s := newSigner(t)
	h := &harness{
		store: &fakeStore{
			keys:    []Key{{Name: "work", Public: s.PublicKey(), Policy: policy}},
			signers: map[string]ssh.Signer{"work": s},
		},
		prompter: &fakePrompter{},
		signer:   s,
		now:      time.Unix(1_800_000_000, 0),
	}
	h.agent = &Agent{Store: h.store, Prompter: h.prompter, Now: func() time.Time { return h.now }}
	return h
}

// client returns an agent client on a fresh connection.
func (h *harness) client(t *testing.T) agent.ExtendedAgent {
	t.Helper()
	a, b := net.Pipe()
	go func() { _ = h.agent.ServeConn(b) }()
	t.Cleanup(func() { a.Close() })
	return agent.NewClient(a)
}

func sshsigData(namespace string) []byte {
	return append([]byte("SSHSIG"), ssh.Marshal(struct {
		Namespace, Reserved, HashAlg string
		Hash                         []byte
	}{namespace, "", "sha512", make([]byte, 64)})...)
}

func userAuthData(sessionID []byte, user string, key ssh.PublicKey, hostKey ssh.PublicKey) []byte {
	if hostKey == nil {
		return ssh.Marshal(struct {
			SessionID []byte
			Type      byte
			User      string
			Service   string
			Method    string
			HasSig    bool
			Alg       string
			Key       []byte
		}{sessionID, msgUserAuthRequest, user, "ssh-connection", methodPublicKey, true, key.Type(), key.Marshal()})
	}
	return ssh.Marshal(struct {
		SessionID []byte
		Type      byte
		User      string
		Service   string
		Method    string
		HasSig    bool
		Alg       string
		Key       []byte
		HostKey   []byte
	}{sessionID, msgUserAuthRequest, user, "ssh-connection", methodPublicKeyHostV0, true, key.Type(), key.Marshal(), hostKey.Marshal()})
}

func sessionBind(t *testing.T, host ssh.Signer, sessionID []byte, forwarding bool) []byte {
	t.Helper()
	sig, err := host.Sign(rand.Reader, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	return ssh.Marshal(struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}{host.PublicKey().Marshal(), sessionID, ssh.Marshal(sig), forwarding})
}

func TestParseSignData(t *testing.T) {
	k := newSigner(t).PublicKey()
	host := newSigner(t).PublicKey()
	for _, tc := range []struct {
		name string
		data []byte
		want Request
	}{
		{"git", sshsigData("git"), Request{Kind: KindSSHSig, Namespace: "git"}},
		{"file", sshsigData("file"), Request{Kind: KindSSHSig, Namespace: "file"}},
		{"empty namespace", sshsigData(""), Request{Kind: KindUnknown}},
		{"userauth", userAuthData([]byte("sid"), "git", k, nil), Request{Kind: KindUserAuth, SessionID: []byte("sid"), User: "git"}},
		{"hostbound", userAuthData([]byte("sid"), "git", k, host), Request{Kind: KindUserAuth, SessionID: []byte("sid"), User: "git", HostKey: host}},
		{"random", []byte("hello world, please sign me"), Request{Kind: KindUnknown}},
		{"empty", nil, Request{Kind: KindUnknown}},
		{"truncated sshsig", []byte("SSHSIG\x00\x00"), Request{Kind: KindUnknown}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseSignData(tc.data)
			if got.Kind != tc.want.Kind || got.Namespace != tc.want.Namespace || got.User != tc.want.User ||
				string(got.SessionID) != string(tc.want.SessionID) || (got.HostKey == nil) != (tc.want.HostKey == nil) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestPolicyParse(t *testing.T) {
	p, err := ParsePolicy(" ssh=prompt, git=allow ,sign=prompt-5m")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := p.String(), "git=allow,sign=prompt-5m,ssh=prompt"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	for _, bad := range []string{"", "ssh", "ssh=maybe", "web=allow", "ssh=allow,ssh=deny"} {
		if _, err := ParsePolicy(bad); err == nil {
			t.Errorf("ParsePolicy(%q) succeeded", bad)
		}
	}
}

func TestPolicyDecide(t *testing.T) {
	p := Policy{PurposeGit: ActionAllow, PurposeSSH: ActionPrompt5m}
	for _, tc := range []struct {
		name string
		r    Request
		want Action
	}{
		{"git", Request{Kind: KindSSHSig, Namespace: "git"}, ActionAllow},
		{"unlisted purpose", Request{Kind: KindSSHSig, Namespace: "file"}, ActionDeny},
		{"unknown data", Request{Kind: KindUnknown}, ActionDeny},
		{"ssh", Request{Kind: KindUserAuth}, ActionPrompt5m},
		{"forwarded git", Request{Kind: KindSSHSig, Namespace: "git", Forwarded: true}, ActionPrompt},
		{"forwarded ssh", Request{Kind: KindUserAuth, Forwarded: true}, ActionPrompt},
	} {
		if got := p.Decide(tc.r); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestGitSignsWithoutPrompt(t *testing.T) {
	h := newHarness(t, DefaultPolicy())
	c := h.client(t)
	data := sshsigData("git")
	sig, err := c.Sign(h.signer.PublicKey(), data)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.signer.PublicKey().Verify(data, sig); err != nil {
		t.Fatal(err)
	}
	if n := h.prompter.count(); n != 0 {
		t.Fatalf("prompted %d times", n)
	}
}

func TestSSHPromptsEachTime(t *testing.T) {
	h := newHarness(t, DefaultPolicy())
	c := h.client(t)
	data := userAuthData([]byte("sid"), "git", h.signer.PublicKey(), nil)
	for range 2 {
		if _, err := c.Sign(h.signer.PublicKey(), data); err != nil {
			t.Fatal(err)
		}
	}
	if n := h.prompter.count(); n != 2 {
		t.Fatalf("prompted %d times, want 2", n)
	}
	if got := h.prompter.reasons[0]; got != "log in to an SSH server as git using “work”" {
		t.Fatalf("reason = %q", got)
	}
}

func TestPromptRefusedDenies(t *testing.T) {
	h := newHarness(t, DefaultPolicy())
	h.prompter.err = errors.New("cancelled")
	c := h.client(t)
	if _, err := c.Sign(h.signer.PublicKey(), userAuthData([]byte("sid"), "git", h.signer.PublicKey(), nil)); err == nil {
		t.Fatal("signed after refused prompt")
	}
	if h.store.reads != 0 {
		t.Fatal("secret read despite refusal")
	}
}

func TestDenied(t *testing.T) {
	h := newHarness(t, Policy{PurposeGit: ActionAllow})
	c := h.client(t)
	for name, data := range map[string][]byte{
		"unknown": []byte("arbitrary"),
		"ssh":     userAuthData([]byte("sid"), "git", h.signer.PublicKey(), nil),
		"file":    sshsigData("file"),
	} {
		if _, err := c.Sign(h.signer.PublicKey(), data); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
	if h.prompter.count() != 0 || h.store.reads != 0 {
		t.Fatalf("prompts=%d reads=%d, want 0", h.prompter.count(), h.store.reads)
	}
}

func TestPrompt5mWindow(t *testing.T) {
	h := newHarness(t, Policy{PurposeSSH: ActionPrompt5m})
	data := userAuthData([]byte("sid"), "git", h.signer.PublicKey(), nil)
	sign := func() {
		t.Helper()
		// New connection each time: the window is per agent, not per conn.
		if _, err := h.client(t).Sign(h.signer.PublicKey(), data); err != nil {
			t.Fatal(err)
		}
	}
	sign()
	h.now = h.now.Add(4 * time.Minute)
	sign()
	if n := h.prompter.count(); n != 1 {
		t.Fatalf("prompted %d times within window, want 1", n)
	}
	h.now = h.now.Add(2 * time.Minute)
	sign()
	if n := h.prompter.count(); n != 2 {
		t.Fatalf("prompted %d times after window, want 2", n)
	}
}

func TestSessionBind(t *testing.T) {
	h := newHarness(t, DefaultPolicy())
	host := newSigner(t)
	h.agent.HostName = func(k ssh.PublicKey) string {
		if string(k.Marshal()) == string(host.PublicKey().Marshal()) {
			return "github.com"
		}
		return ""
	}
	sid := []byte("session-1")

	t.Run("bound", func(t *testing.T) {
		c := h.client(t)
		if _, err := c.Extension("session-bind@openssh.com", sessionBind(t, host, sid, false)); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Sign(h.signer.PublicKey(), userAuthData(sid, "git", h.signer.PublicKey(), host.PublicKey())); err != nil {
			t.Fatal(err)
		}
		last := h.prompter.reasons[len(h.prompter.reasons)-1]
		if last != "log in to github.com as git using “work”" {
			t.Fatalf("reason = %q", last)
		}
	})

	t.Run("other session", func(t *testing.T) {
		c := h.client(t)
		if _, err := c.Extension("session-bind@openssh.com", sessionBind(t, host, sid, false)); err != nil {
			t.Fatal(err)
		}
		before := h.prompter.count()
		if _, err := c.Sign(h.signer.PublicKey(), userAuthData([]byte("session-2"), "git", h.signer.PublicKey(), nil)); err == nil {
			t.Fatal("signed userauth for unbound session")
		}
		if h.prompter.count() != before {
			t.Fatal("prompted for a mismatched session")
		}
	})

	t.Run("host key mismatch", func(t *testing.T) {
		c := h.client(t)
		if _, err := c.Extension("session-bind@openssh.com", sessionBind(t, host, sid, false)); err != nil {
			t.Fatal(err)
		}
		other := newSigner(t).PublicKey()
		if _, err := c.Sign(h.signer.PublicKey(), userAuthData(sid, "git", h.signer.PublicKey(), other)); err == nil {
			t.Fatal("signed with mismatched host key")
		}
	})

	t.Run("bad signature", func(t *testing.T) {
		c := h.client(t)
		bind := sessionBind(t, host, sid, false)
		bind[len(bind)-10] ^= 0xff
		if _, err := c.Extension("session-bind@openssh.com", bind); err == nil {
			t.Fatal("accepted forged binding")
		}
	})

	t.Run("rebind refused", func(t *testing.T) {
		c := h.client(t)
		if _, err := c.Extension("session-bind@openssh.com", sessionBind(t, host, sid, false)); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Extension("session-bind@openssh.com", sessionBind(t, host, []byte("s2"), false)); err == nil {
			t.Fatal("second auth binding accepted")
		}
	})

	t.Run("forwarded git prompts", func(t *testing.T) {
		c := h.client(t)
		if _, err := c.Extension("session-bind@openssh.com", sessionBind(t, host, sid, true)); err != nil {
			t.Fatal(err)
		}
		before := h.prompter.count()
		if _, err := c.Sign(h.signer.PublicKey(), sshsigData("git")); err != nil {
			t.Fatal(err)
		}
		if h.prompter.count() != before+1 {
			t.Fatal("forwarded git signature did not prompt")
		}
		if last := h.prompter.reasons[len(h.prompter.reasons)-1]; !strings.HasSuffix(last, "from a forwarded agent") {
			t.Fatalf("reason = %q", last)
		}
	})

	t.Run("unknown extension", func(t *testing.T) {
		if _, err := h.client(t).Extension("query", nil); !errors.Is(err, agent.ErrExtensionUnsupported) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestMutationsUnsupported(t *testing.T) {
	h := newHarness(t, DefaultPolicy())
	c := h.client(t)
	if err := c.RemoveAll(); err == nil {
		t.Error("RemoveAll succeeded")
	}
	if err := c.Lock([]byte("x")); err == nil {
		t.Error("Lock succeeded")
	}
	keys, err := c.List()
	if err != nil || len(keys) != 1 || keys[0].Comment != "work" {
		t.Fatalf("List = %v, %v", keys, err)
	}
}

// TestRealUserAuth runs a real SSH handshake through the agent so the
// userauth parser sees what an actual client sends.
func TestRealUserAuth(t *testing.T) {
	h := newHarness(t, Policy{PurposeSSH: ActionPrompt})
	host := newSigner(t)

	srvConf := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if string(k.Marshal()) == string(h.signer.PublicKey().Marshal()) {
				return nil, nil
			}
			return nil, errors.New("unknown key")
		},
	}
	srvConf.AddHostKey(host)
	// Not net.Pipe: both SSH sides write their version line at once, and an
	// unbuffered pipe deadlocks on that.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		ss, err := l.Accept()
		if err != nil {
			return
		}
		conn, chans, reqs, err := ssh.NewServerConn(ss, srvConf)
		if err != nil {
			return
		}
		defer conn.Close()
		go ssh.DiscardRequests(reqs)
		for ch := range chans {
			ch.Reject(ssh.Prohibited, "")
		}
	}()

	cs, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	ag := h.client(t)
	conn, _, _, err := ssh.NewClientConn(cs, "example:22", &ssh.ClientConfig{
		User:            "deploy",
		Auth:            []ssh.AuthMethod{ssh.PublicKeysCallback(ag.Signers)},
		HostKeyCallback: ssh.FixedHostKey(host.PublicKey()),
	})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if n := h.prompter.count(); n != 1 {
		t.Fatalf("prompted %d times, want 1", n)
	}
	if got := h.prompter.reasons[0]; got != "log in to an SSH server as deploy using “work”" {
		t.Fatalf("reason = %q", got)
	}
}

// TestSSHKeygenSign signs with the real ssh-keygen -Y sign over a unix socket
// and verifies the result with ssh-keygen -Y verify.
func TestSSHKeygenSign(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen not found")
	}
	h := newHarness(t, DefaultPolicy())
	dir := t.TempDir()
	sock := filepath.Join(dir, "agent.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _ = h.agent.ServeConn(c) }()
		}
	}()

	pub := filepath.Join(dir, "key.pub")
	msg := filepath.Join(dir, "msg")
	signers := filepath.Join(dir, "allowed")
	authorized := string(ssh.MarshalAuthorizedKey(h.signer.PublicKey()))
	must(t, os.WriteFile(pub, []byte(authorized), 0o600))
	must(t, os.WriteFile(msg, []byte("tree abc\n\ncommit message\n"), 0o600))
	must(t, os.WriteFile(signers, []byte("me@example.com "+authorized), 0o600))

	env := append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	sign := exec.Command(keygen, "-Y", "sign", "-n", "git", "-f", pub, msg)
	sign.Env = env
	if out, err := sign.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -Y sign: %v\n%s", err, out)
	}
	if n := h.prompter.count(); n != 0 {
		t.Fatalf("git signature prompted %d times", n)
	}

	verify := exec.Command(keygen, "-Y", "verify", "-f", signers, "-I", "me@example.com", "-n", "git", "-s", msg+".sig")
	in, err := os.Open(msg)
	must(t, err)
	defer in.Close()
	verify.Stdin = in
	if out, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -Y verify: %v\n%s", err, out)
	}

	// Same key, another namespace: default policy prompts.
	os.Remove(msg + ".sig")
	file := exec.Command(keygen, "-Y", "sign", "-n", "file", "-f", pub, msg)
	file.Env = env
	if out, err := file.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -Y sign -n file: %v\n%s", err, out)
	}
	if n := h.prompter.count(); n != 1 {
		t.Fatalf("file signature prompted %d times, want 1", n)
	}
}

func TestKnownHostsNamer(t *testing.T) {
	host := newSigner(t).PublicKey()
	other := newSigner(t).PublicKey()
	line := func(hosts string, k ssh.PublicKey) string {
		return hosts + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + "\n"
	}
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	must(t, os.WriteFile(kh, []byte(
		"# comment\n"+
			"garbage line\n"+
			line("|1|abc=|def=", host)+
			line("@revoked evil.example", host)+
			line("*.wild.example", host)+
			line("[git.example]:2222,1.2.3.4", host)+
			line("other.example", other),
	), 0o600))
	name := KnownHostsNamer(filepath.Join(dir, "missing"), kh)
	if got := name(host); got != "git.example:2222" {
		t.Errorf("host = %q", got)
	}
	if got := name(other); got != "other.example" {
		t.Errorf("other = %q", got)
	}
	if got := name(newSigner(t).PublicKey()); got != "" {
		t.Errorf("unknown = %q", got)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Duplicates can arrive by sync even though the store refuses them; the agent
// must not let either name's policy decide.
func TestDuplicateKeyDenied(t *testing.T) {
	h := newHarness(t, Policy{PurposeGit: ActionDeny})
	h.store.keys = append(h.store.keys, Key{Name: "loose", Public: h.signer.PublicKey(), Policy: Policy{PurposeGit: ActionAllow}})
	if _, err := h.client(t).Sign(h.signer.PublicKey(), sshsigData("git")); err == nil {
		t.Fatal("signed with a key stored under two names")
	}
	if h.store.reads != 0 || h.prompter.count() != 0 {
		t.Fatal("read secret or prompted for an ambiguous key")
	}
}
