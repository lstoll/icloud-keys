package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"lds.li/icloud-keys/internal/launchsvc"
	"lds.li/icloud-keys/internal/sshstore"
)

const plistName = "li.lds.icloud-ssh-agent.plist"

// requireBundle checks we're running from the .app: SMAppService registers
// the LaunchAgent bundled in the calling app.
func requireBundle() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	if !strings.Contains(exe, ".app/Contents/MacOS/") {
		return fmt.Errorf("run this from icloud-ssh-agent.app (or its symlink), not %s", exe)
	}
	return nil
}

func cmdInstall(args []string) error {
	if _, err := parse(flag.NewFlagSet("install", flag.ContinueOnError), args, 0); err != nil {
		return err
	}
	if err := requireBundle(); err != nil {
		return err
	}
	if err := launchsvc.Register(plistName); err != nil {
		return err
	}
	st, err := launchsvc.StatusOf(plistName)
	if err != nil {
		return err
	}
	switch st {
	case launchsvc.Enabled:
		fmt.Fprintln(os.Stderr, "agent installed and running at login.")
	case launchsvc.RequiresApproval:
		fmt.Fprintln(os.Stderr, "approve icloud-ssh-agent in System Settings → General → Login Items, then it will start.")
		launchsvc.OpenLoginItemsSettings()
	default:
		return fmt.Errorf("agent registration status: %s", st)
	}
	sock := tildePath(defaultSocket())
	fmt.Printf(`
Add to ~/.ssh/config:

  Host *
    IdentityAgent %s

For git commit signing (ssh-keygen reads only SSH_AUTH_SOCK), add to your
shell profile:

  export SSH_AUTH_SOCK=%s

and sign with a key: write out its public key, and point git at the .pub
file (ssh-keygen then asks the agent for the private half):

  icloud-ssh-agent public-key NAME > ~/.ssh/NAME.pub
  git config --global gpg.format ssh
  git config --global user.signingkey ~/.ssh/NAME.pub
  git config --global commit.gpgsign true

The same .pub file in ~/.ssh/config (IdentityFile ~/.ssh/NAME.pub, with
IdentitiesOnly yes) picks which key a host gets.
`, sock, sock)
	return nil
}

func cmdUninstall(args []string) error {
	if _, err := parse(flag.NewFlagSet("uninstall", flag.ContinueOnError), args, 0); err != nil {
		return err
	}
	if err := requireBundle(); err != nil {
		return err
	}
	if err := launchsvc.Unregister(plistName); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "agent removed from login items. Keys stay in iCloud Keychain.")
	return nil
}

func cmdStatus(args []string) error {
	if _, err := parse(flag.NewFlagSet("status", flag.ContinueOnError), args, 0); err != nil {
		return err
	}
	st, err := launchsvc.StatusOf(plistName)
	if err != nil {
		fmt.Printf("login item: unknown (%v)\n", err)
	} else {
		fmt.Printf("login item: %s\n", st)
	}
	sock := defaultSocket()
	if c, err := net.DialTimeout("unix", sock, time.Second); err == nil {
		c.Close()
		fmt.Printf("socket:     %s (listening)\n", tildePath(sock))
	} else {
		fmt.Printf("socket:     %s (not listening)\n", tildePath(sock))
	}
	if env := os.Getenv("SSH_AUTH_SOCK"); env != sock {
		fmt.Printf("SSH_AUTH_SOCK: %q (git signing will not use this agent)\n", env)
	}
	s, err := sshstore.Open()
	if err != nil {
		return err
	}
	keys, err := s.Keys()
	if err != nil {
		return err
	}
	fmt.Printf("keys:       %d\n", len(keys))
	if len(keys) == 0 {
		return errors.New("no keys; run icloud-ssh-agent generate NAME")
	}
	return nil
}
