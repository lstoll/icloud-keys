package sshagent

import (
	"bytes"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// KnownHostsNamer returns a HostName func that maps a host key back to a name
// from known_hosts files. Hashed entries can't be reversed and are skipped,
// as are @revoked and @cert-authority lines. Files are re-read on each call so
// edits take effect without restarting the agent.
func KnownHostsNamer(paths ...string) func(ssh.PublicKey) string {
	return func(key ssh.PublicKey) string {
		want := key.Marshal()
		for _, p := range paths {
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			if name := lookupKnownHosts(data, want); name != "" {
				return name
			}
		}
		return ""
	}
}

func lookupKnownHosts(data, want []byte) string {
	for len(data) > 0 {
		marker, hosts, pub, _, rest, err := ssh.ParseKnownHosts(data)
		if err != nil {
			// Skip the bad line and keep going.
			i := bytes.IndexByte(data, '\n')
			if i < 0 {
				return ""
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
			// [host]:port -> host:port
			if rest, ok := strings.CutPrefix(h, "["); ok {
				h = strings.Replace(rest, "]", "", 1)
			}
			return h
		}
	}
	return ""
}
