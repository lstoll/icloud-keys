// Package sshagent implements an SSH agent that applies a per-key policy to
// each signature based on what is being signed.
package sshagent

import (
	"bytes"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Kind is what a sign request is for, derived from the bytes being signed.
type Kind int

const (
	// KindUnknown is data that is neither a userauth request nor SSHSIG.
	KindUnknown Kind = iota
	// KindUserAuth is an SSH publickey authentication (logging in to a host).
	KindUserAuth
	// KindSSHSig is an ssh-keygen -Y sign signature (git, files, ...).
	KindSSHSig
)

func (k Kind) String() string {
	switch k {
	case KindUserAuth:
		return "ssh"
	case KindSSHSig:
		return "sshsig"
	default:
		return "unknown"
	}
}

// Request describes a parsed sign request.
type Request struct {
	Kind Kind

	// KindSSHSig
	Namespace string

	// KindUserAuth
	SessionID []byte
	User      string
	// HostKey is the server's host key: from a publickey-hostbound request,
	// or from a session-bind on the same connection. Nil if unknown.
	HostKey ssh.PublicKey
	// Forwarded is set when the request arrived over a forwarded agent
	// connection (session-bind with is_forwarding).
	Forwarded bool
}

const (
	sshsigMagic           = "SSHSIG"
	msgUserAuthRequest    = 50
	methodPublicKey       = "publickey"
	methodPublicKeyHostV0 = "publickey-hostbound-v00@openssh.com"
)

// ParseSignData classifies the data an agent client asks to sign.
//
// SSHSIG (PROTOCOL.sshsig) starts with the 6-byte magic "SSHSIG", which can
// never parse as a userauth request: read as a length it is ~1.4GB. Data that
// matches neither format is KindUnknown.
func ParseSignData(data []byte) Request {
	if r, ok := parseSSHSig(data); ok {
		return r
	}
	if r, ok := parseUserAuth(data); ok {
		return r
	}
	return Request{Kind: KindUnknown}
}

func parseSSHSig(data []byte) (Request, bool) {
	rest, ok := bytes.CutPrefix(data, []byte(sshsigMagic))
	if !ok {
		return Request{}, false
	}
	var blob struct {
		Namespace string
		Reserved  string
		HashAlg   string
		Hash      []byte
	}
	if err := ssh.Unmarshal(rest, &blob); err != nil || blob.Namespace == "" {
		return Request{}, false
	}
	return Request{Kind: KindSSHSig, Namespace: blob.Namespace}, true
}

func parseUserAuth(data []byte) (Request, bool) {
	var hdr struct {
		SessionID []byte
		Type      byte
		User      string
		Service   string
		Method    string
		Rest      []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(data, &hdr); err != nil {
		return Request{}, false
	}
	if hdr.Type != msgUserAuthRequest || hdr.Service != "ssh-connection" || len(hdr.SessionID) == 0 {
		return Request{}, false
	}
	r := Request{Kind: KindUserAuth, SessionID: hdr.SessionID, User: hdr.User}
	switch hdr.Method {
	case methodPublicKey:
		var pk struct {
			HasSig bool
			Alg    string
			Key    []byte
		}
		if err := ssh.Unmarshal(hdr.Rest, &pk); err != nil || !pk.HasSig {
			return Request{}, false
		}
	case methodPublicKeyHostV0:
		var pk struct {
			HasSig  bool
			Alg     string
			Key     []byte
			HostKey []byte
		}
		if err := ssh.Unmarshal(hdr.Rest, &pk); err != nil || !pk.HasSig {
			return Request{}, false
		}
		hk, err := ssh.ParsePublicKey(pk.HostKey)
		if err != nil {
			return Request{}, false
		}
		r.HostKey = hk
	default:
		return Request{}, false
	}
	return r, true
}

// binding is a verified session-bind@openssh.com from the ssh client.
type binding struct {
	hostKey    ssh.PublicKey
	sessionID  []byte
	forwarding bool
}

var errBadBinding = errors.New("session-bind: invalid")

// parseSessionBind parses and verifies a session-bind@openssh.com extension:
// the host key must have signed the session ID, which proves the client
// really is talking to that host in that session.
func parseSessionBind(contents []byte) (binding, error) {
	var msg struct {
		HostKey    []byte
		SessionID  []byte
		Signature  []byte
		Forwarding bool
	}
	if err := ssh.Unmarshal(contents, &msg); err != nil {
		return binding{}, fmt.Errorf("%w: %v", errBadBinding, err)
	}
	hk, err := ssh.ParsePublicKey(msg.HostKey)
	if err != nil {
		return binding{}, fmt.Errorf("%w: host key: %v", errBadBinding, err)
	}
	sig := new(ssh.Signature)
	if err := ssh.Unmarshal(msg.Signature, sig); err != nil {
		return binding{}, fmt.Errorf("%w: signature: %v", errBadBinding, err)
	}
	if err := hk.Verify(msg.SessionID, sig); err != nil {
		return binding{}, fmt.Errorf("%w: host key did not sign session: %v", errBadBinding, err)
	}
	return binding{hostKey: hk, sessionID: msg.SessionID, forwarding: msg.Forwarding}, nil
}
