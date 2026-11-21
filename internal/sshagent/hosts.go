package sshagent

import (
	"bytes"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// KnownHostsNamer returns a HostName func that maps a host key back to its
// names in known_hosts files. ssh writes a line per name a host was reached
// by, so one key can have several (an IP from a first connection, a host name
// later). The best comes first: the first name that isn't an IP literal, else
// the first IP; the rest follow in file order, without duplicates. Hashed
// entries can't be reversed and are skipped, as are @revoked and
// @cert-authority lines. Files are re-read on each call so edits take effect
// without restarting the agent.
func KnownHostsNamer(paths ...string) func(ssh.PublicKey) []string {
	return func(key ssh.PublicKey) []string {
		want := key.Marshal()
		var names []string
		for _, p := range paths {
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			names = append(names, knownHostNames(data, want)...)
		}
		return rankHostNames(names)
	}
}

// knownHostNames returns the readable names for the key, in file order, as
// host or host:port.
func knownHostNames(data, want []byte) []string {
	var names []string
	for len(data) > 0 {
		marker, hosts, pub, _, rest, err := ssh.ParseKnownHosts(data)
		if err != nil {
			// Skip the bad line and keep going.
			i := bytes.IndexByte(data, '\n')
			if i < 0 {
				break
			}
			data = data[i+1:]
			continue
		}
		data = rest
		if marker != "" || !bytes.Equal(pub.Marshal(), want) {
			continue
		}
		for _, h := range hosts {
			if strings.HasPrefix(h, "|") || strings.ContainsAny(h, "*?!") {
				continue
			}
			// [host]:port -> host:port, but keep [v6]:port as is: without
			// the brackets the port reads as part of the address.
			if host, port, err := net.SplitHostPort(h); err == nil && !strings.Contains(host, ":") {
				h = host + ":" + port
			}
			names = append(names, h)
		}
	}
	return names
}

// rankHostNames dedupes names and moves the first that isn't an IP address to
// the front.
func rankHostNames(names []string) []string {
	var out []string
	seen := map[string]bool{}
	best := -1
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		if best < 0 && !isIPName(n) {
			best = len(out)
		}
		out = append(out, n)
	}
	if best > 0 {
		out = append([]string{out[best]}, append(out[:best:best], out[best+1:]...)...)
	}
	return out
}

// isIPName reports whether a host or host:port names an IP literal.
func isIPName(n string) bool {
	if h, _, err := net.SplitHostPort(n); err == nil {
		n = h
	}
	return net.ParseIP(n) != nil
}
