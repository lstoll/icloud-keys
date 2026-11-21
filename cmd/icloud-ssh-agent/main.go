// Command icloud-ssh-agent is an SSH agent whose keys live in iCloud Keychain.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	"lds.li/icloud-keys/internal/sshagent"
	"lds.li/icloud-keys/internal/sshstore"
)

const usage = `icloud-ssh-agent keeps SSH keys in iCloud Keychain and serves them as an
SSH agent, applying a per-key policy to every signature.

Usage:
  icloud-ssh-agent generate NAME [--policy POLICY]
  icloud-ssh-agent import NAME FILE [--policy POLICY]     (FILE - reads stdin)
  icloud-ssh-agent list
  icloud-ssh-agent public-key NAME
  icloud-ssh-agent set-policy NAME POLICY                 (asks for Touch ID)
  icloud-ssh-agent export NAME                            (asks for Touch ID)
  icloud-ssh-agent delete NAME
  icloud-ssh-agent install | uninstall | status
  icloud-ssh-agent serve [--socket PATH]

POLICY is a comma-separated list of purpose=action:
  purposes: ssh (log in to a host), git (git commit/tag signing),
            sign (other ssh-keygen -Y signatures)
  actions:  allow, prompt (Touch ID each time), prompt-5m, deny
Unlisted purposes are denied. Requests from a forwarded agent always prompt.
Default: ` + "git=allow,sign=prompt,ssh=prompt" + `
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "generate":
		err = cmdGenerate(args)
	case "import":
		err = cmdImport(args)
	case "list", "ls":
		err = cmdList(args)
	case "public-key", "pubkey":
		err = cmdPublicKey(args)
	case "set-policy":
		err = cmdSetPolicy(args)
	case "export":
		err = cmdExport(args)
	case "delete", "rm":
		err = cmdDelete(args)
	case "serve":
		err = cmdServe(args)
	case "install":
		err = cmdInstall(args)
	case "uninstall":
		err = cmdUninstall(args)
	case "status":
		err = cmdStatus(args)
	case "help", "-h", "--help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "icloud-ssh-agent: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if errors.Is(err, errUsage) {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "icloud-ssh-agent: %v\n", err)
		os.Exit(1)
	}
}

var errUsage = errors.New("usage")

// parse parses flags that may appear before, between or after positional
// arguments, and checks the positional count.
func parse(fs *flag.FlagSet, args []string, npos int) ([]string, error) {
	fs.SetOutput(io.Discard)
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, fmt.Errorf("%s: %w", fs.Name(), err)
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(pos) != npos {
		return nil, errUsage
	}
	return pos, nil
}

func policyFlag(fs *flag.FlagSet) *string {
	return fs.String("policy", sshagent.DefaultPolicy().String(), "purpose=action list")
}

func cmdGenerate(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	pol := policyFlag(fs)
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	policy, err := sshagent.ParsePolicy(*pol)
	if err != nil {
		return err
	}
	s, err := sshstore.Open()
	if err != nil {
		return err
	}
	k, err := s.Generate(pos[0], policy)
	if err != nil {
		return err
	}
	printKey(k)
	return nil
}

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	pol := policyFlag(fs)
	pos, err := parse(fs, args, 2)
	if err != nil {
		return err
	}
	policy, err := sshagent.ParsePolicy(*pol)
	if err != nil {
		return err
	}
	var data []byte
	if pos[1] == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(pos[1])
	}
	if err != nil {
		return err
	}
	s, err := sshstore.Open()
	if err != nil {
		return err
	}
	k, err := s.Import(pos[0], data, readPassphrase, policy)
	if err != nil {
		return err
	}
	printKey(k)
	return nil
}

// readPassphrase reads from the terminal, not stdin, so "import NAME -" works.
func readPassphrase() ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("key is encrypted and there is no terminal to ask for its passphrase: %w", err)
	}
	defer tty.Close()
	fmt.Fprint(tty, "Passphrase: ")
	pw, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	return pw, err
}

func printKey(k sshagent.Key) {
	fmt.Printf("%s %s\n", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.Public))), k.Name)
	fmt.Fprintf(os.Stderr, "policy: %s\n", k.Policy)
}

func cmdList(args []string) error {
	if _, err := parse(flag.NewFlagSet("list", flag.ContinueOnError), args, 0); err != nil {
		return err
	}
	s, err := sshstore.Open()
	if err != nil {
		return err
	}
	keys, err := s.Keys()
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		fmt.Fprintln(os.Stderr, "no keys; run icloud-ssh-agent generate NAME")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tTYPE\tPOLICY\tFINGERPRINT")
	for _, k := range keys {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", k.Name, k.Public.Type(), k.Policy, ssh.FingerprintSHA256(k.Public))
	}
	return w.Flush()
}

func cmdPublicKey(args []string) error {
	pos, err := parse(flag.NewFlagSet("public-key", flag.ContinueOnError), args, 1)
	if err != nil {
		return err
	}
	s, err := sshstore.Open()
	if err != nil {
		return err
	}
	k, err := s.Key(pos[0])
	if err != nil {
		return err
	}
	fmt.Printf("%s %s\n", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.Public))), k.Name)
	return nil
}

func cmdSetPolicy(args []string) error {
	pos, err := parse(flag.NewFlagSet("set-policy", flag.ContinueOnError), args, 2)
	if err != nil {
		return err
	}
	policy, err := sshagent.ParsePolicy(pos[1])
	if err != nil {
		return err
	}
	s, err := sshstore.Open()
	if err != nil {
		return err
	}
	if err := s.SetPolicy(pos[0], policy); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s: policy %s\n", pos[0], policy)
	return nil
}

func cmdExport(args []string) error {
	pos, err := parse(flag.NewFlagSet("export", flag.ContinueOnError), args, 1)
	if err != nil {
		return err
	}
	s, err := sshstore.Open()
	if err != nil {
		return err
	}
	pem, err := s.Export(pos[0])
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(pem)
	return err
}

func cmdDelete(args []string) error {
	pos, err := parse(flag.NewFlagSet("delete", flag.ContinueOnError), args, 1)
	if err != nil {
		return err
	}
	s, err := sshstore.Open()
	if err != nil {
		return err
	}
	if err := s.Delete(pos[0]); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "deleted %s from iCloud Keychain on all devices\n", pos[0])
	return nil
}

func defaultSocket() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ssh", "icloud-ssh-agent.sock")
}

// tildePath shortens a path under $HOME for display in config snippets.
func tildePath(p string) string {
	if home, err := os.UserHomeDir(); err == nil {
		if rest, ok := strings.CutPrefix(p, home+"/"); ok {
			return "~/" + rest
		}
	}
	return p
}
