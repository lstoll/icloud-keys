package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"syscall"
	"time"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"lds.li/icloud-keys/internal/identity"
	"lds.li/icloud-keys/internal/oslog"
	"lds.li/icloud-keys/internal/proc"
)

const (
	logSubsystem = identity.BundleID
	logCategory  = "plugin"
)

// setupLog sends identity events (unlocks, exports, policy changes) to the
// unified log, tagged with the program that ran the plugin, e.g. "age (from
// sops)". Never stderr: in plugin mode that's age's, and the user's.
func setupLog() {
	h, err := oslog.Open(logSubsystem, logCategory, nil)
	if err != nil {
		slog.SetDefault(slog.New(slog.DiscardHandler))
		return
	}
	slog.SetDefault(slog.New(h).With("requester", proc.Describe(os.Getppid())))
}

func main() {
	generate := flag.Bool("generate", false, "generate a new identity in iCloud Keychain")
	list := flag.Bool("list", false, "reprint identity files from Keychain attributes")
	delete := flag.Bool("delete", false, "delete a named identity from iCloud Keychain")
	export := flag.Bool("export", false, "print a named identity's secret key (always asks for Touch ID)")
	setAccessControl := flag.Bool("set-access-control", false, "change a named identity's --access-control (always asks for Touch ID)")
	name := flag.String("name", identity.DefaultName, "identity name")
	accessControl := flag.String("access-control", string(identity.AccessControl5m), "`none`, `everyTime` (Touch ID each decrypt), or `5m` (Touch ID, skip 5 minutes on this Mac)")
	logs := flag.Bool("logs", false, "show the plugin's unified log entries (decrypts, exports, changes)")
	follow := flag.Bool("follow", false, "with --logs, stream new entries")
	last := flag.String("last", "1d", "with --logs, how far back to show, e.g. 30m, 2h, 7d")

	p, err := plugin.New(identity.PluginName)
	if err != nil {
		fatal(err)
	}

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `age-plugin-icloud stores age MLKEM768-X25519 keys in iCloud Keychain.

Usage:
  age-plugin-icloud --generate [--name NAME] [--access-control=none|everyTime|5m]
  age-plugin-icloud --list [--name NAME]
  age-plugin-icloud --delete --name NAME
  age-plugin-icloud --set-access-control --name NAME --access-control=none|everyTime|5m
  age-plugin-icloud --export --name NAME
  age-plugin-icloud --logs [--follow] [--last 1d]

age invokes this plugin as age-plugin-icloud --age-plugin=identity-v1.

`)
		flag.PrintDefaults()
	}

	p.RegisterFlags(nil)
	flag.Parse()

	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		return identity.LoadIdentity(string(data))
	})
	p.HandleIdentityAsRecipient(func(data []byte) (age.Recipient, error) {
		return identity.LoadRecipient(string(data))
	})

	n := 0
	for _, set := range []bool{*generate, *list, *delete, *export, *setAccessControl, *logs} {
		if set {
			n++
		}
	}
	if n > 1 {
		fatal(fmt.Errorf("specify only one of --generate, --list, --delete, --export, --set-access-control, --logs"))
	}
	if flag.NArg() > 0 && n > 0 {
		fatal(fmt.Errorf("unexpected arguments: %v", flag.Args()))
	}

	nameSet, accessControlSet := false, false
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "name":
			nameSet = true
		case "access-control":
			accessControlSet = true
		}
	})

	setupLog()

	switch {
	case *logs:
		argv := oslog.ShowArgs(logSubsystem, logCategory, *follow, *last, false)
		if err := syscall.Exec(argv[0], argv, os.Environ()); err != nil {
			fatal(fmt.Errorf("run %s: %w", argv[0], err))
		}
	case *generate:
		mode, err := identity.ParseAccessControl(*accessControl)
		if err != nil {
			fatal(err)
		}
		file, err := identity.Generate(*name, mode)
		if err != nil {
			fatal(err)
		}
		fmt.Print(file)
	case *list:
		items, err := identity.List()
		if err != nil {
			fatal(err)
		}
		if nameSet {
			var found *identity.Item
			for i := range items {
				if items[i].Name == *name {
					found = &items[i]
					break
				}
			}
			if found == nil {
				fatal(fmt.Errorf("no identity named %q", *name))
			}
			items = []identity.Item{*found}
		}
		for _, item := range items {
			fmt.Print(identity.IdentityFile(item.Name, item.Recipient, time.Time{}, item.AccessControl))
		}
	case *delete:
		if !nameSet {
			fatal(fmt.Errorf("--delete requires --name"))
		}
		if err := identity.Delete(*name); err != nil {
			fatal(err)
		}
	case *export:
		if !nameSet {
			fatal(fmt.Errorf("--export requires --name"))
		}
		secret, err := identity.Export(*name)
		if err != nil {
			fatal(err)
		}
		fmt.Println(secret)
	case *setAccessControl:
		if !nameSet || !accessControlSet {
			fatal(fmt.Errorf("--set-access-control requires --name and --access-control"))
		}
		mode, err := identity.ParseAccessControl(*accessControl)
		if err != nil {
			fatal(err)
		}
		file, err := identity.SetAccessControl(*name, mode)
		if err != nil {
			fatal(err)
		}
		fmt.Print(file)
	default:
		sm := flag.Lookup("age-plugin")
		if sm != nil && sm.Value.String() != "" {
			os.Exit(p.Main())
		}
		flag.Usage()
		os.Exit(2)
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "age-plugin-icloud: %v\n", err)
	os.Exit(1)
}
