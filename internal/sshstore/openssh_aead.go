package sshstore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20"
	// Deprecated for general use, but OpenSSH's chacha20-poly1305 isn't the
	// RFC 8439 AEAD (x/crypto/chacha20poly1305), so it needs the primitive.
	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/ssh"
	"lds.li/icloud-keys/internal/bcryptpbkdf"
)

// x/crypto/ssh only decrypts OpenSSH key files encrypted with aes256-ctr or
// aes256-cbc. It implements the AEAD ciphers for connections, but not for key
// files, and those implementations are unexported packet ciphers. ssh-keygen
// -Z can use them for key files, so we decrypt those here and hand x/crypto an
// unencrypted key to parse. Format: PROTOCOL.key and sshkey.c in OpenSSH.

const (
	opensshMagic = "openssh-key-v1\x00"
	aeadTagLen   = 16
	maxKDFRounds = 1 << 11 // same cap as x/crypto: 128x the default
)

type opensshKey struct {
	CipherName   string
	KdfName      string
	KdfOpts      string
	NumKeys      uint32
	PubKey       []byte
	PrivKeyBlock []byte
	Rest         []byte `ssh:"rest"` // the AEAD tag follows the block, unprefixed
}

// aeadCipher returns the cipher name if pemBytes is an OpenSSH key encrypted
// with an AEAD cipher this package decrypts.
func aeadCipher(pemBytes []byte) (string, bool) {
	k, err := parseOpenSSH(pemBytes)
	if err != nil {
		return "", false
	}
	switch k.CipherName {
	case ssh.CipherAES128GCM, ssh.CipherAES256GCM, ssh.CipherChaCha20Poly1305:
		return k.CipherName, true
	}
	return "", false
}

func parseOpenSSH(pemBytes []byte) (*opensshKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" {
		return nil, errors.New("not an OpenSSH private key")
	}
	rest, ok := bytes.CutPrefix(block.Bytes, []byte(opensshMagic))
	if !ok {
		return nil, errors.New("not an openssh-key-v1 key")
	}
	k := new(opensshKey)
	if err := ssh.Unmarshal(rest, k); err != nil {
		return nil, fmt.Errorf("openssh key: %w", err)
	}
	return k, nil
}

var errBadPassphrase = errors.New("incorrect passphrase")

// decryptAEADKey decrypts an aes256-gcm or chacha20-poly1305 OpenSSH key and
// returns it re-encoded unencrypted (in memory only).
func decryptAEADKey(pemBytes, passphrase []byte) ([]byte, error) {
	k, err := parseOpenSSH(pemBytes)
	if err != nil {
		return nil, err
	}
	if k.KdfName != "bcrypt" {
		return nil, fmt.Errorf("openssh key: unsupported KDF %q", k.KdfName)
	}
	var opts struct {
		Salt   string
		Rounds uint32
	}
	if err := ssh.Unmarshal([]byte(k.KdfOpts), &opts); err != nil {
		return nil, fmt.Errorf("openssh key: KDF options: %w", err)
	}
	if opts.Rounds > maxKDFRounds {
		return nil, fmt.Errorf("openssh key: bcrypt KDF rounds %d exceed maximum %d", opts.Rounds, maxKDFRounds)
	}
	if len(k.Rest) < aeadTagLen {
		return nil, errors.New("openssh key: missing authentication tag")
	}
	sealed := append(append([]byte{}, k.PrivKeyBlock...), k.Rest[:aeadTagLen]...)

	var plain []byte
	switch k.CipherName {
	case ssh.CipherAES128GCM, ssh.CipherAES256GCM:
		// 16/32-byte key, 12-byte IV, no AAD; the first (only) message uses
		// the IV as given.
		keyLen := 32
		if k.CipherName == ssh.CipherAES128GCM {
			keyLen = 16
		}
		dk, err := bcryptpbkdf.Key(passphrase, []byte(opts.Salt), int(opts.Rounds), keyLen+12)
		if err != nil {
			return nil, err
		}
		block, err := aes.NewCipher(dk[:keyLen])
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		if plain, err = gcm.Open(nil, dk[keyLen:], sealed, nil); err != nil {
			return nil, errBadPassphrase
		}
	case ssh.CipherChaCha20Poly1305:
		// OpenSSH's chacha20-poly1305: a 64-byte key of which the first 32
		// encrypt the payload (the rest only encrypts packet lengths, unused
		// here). Sequence number 0: the Poly1305 key is block 0 of the
		// keystream, the payload starts at block 1. An all-zero 12-byte IETF
		// nonce equals OpenSSH's zero 8-byte nonce with a zero counter high
		// word.
		dk, err := bcryptpbkdf.Key(passphrase, []byte(opts.Salt), int(opts.Rounds), 64)
		if err != nil {
			return nil, err
		}
		nonce := make([]byte, chacha20.NonceSize)
		c, err := chacha20.NewUnauthenticatedCipher(dk[:32], nonce)
		if err != nil {
			return nil, err
		}
		var polyKey [32]byte
		c.XORKeyStream(polyKey[:], polyKey[:])
		var tag [aeadTagLen]byte
		copy(tag[:], k.Rest[:aeadTagLen])
		if !poly1305.Verify(&tag, k.PrivKeyBlock, &polyKey) {
			return nil, errBadPassphrase
		}
		c.SetCounter(1)
		plain = make([]byte, len(k.PrivKeyBlock))
		c.XORKeyStream(plain, k.PrivKeyBlock)
	default:
		return nil, fmt.Errorf("openssh key: unsupported cipher %q", k.CipherName)
	}

	out := ssh.Marshal(opensshKey{
		CipherName:   "none",
		KdfName:      "none",
		NumKeys:      k.NumKeys,
		PubKey:       k.PubKey,
		PrivKeyBlock: plain,
	})
	return pem.EncodeToMemory(&pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: append([]byte(opensshMagic), out...),
	}), nil
}
