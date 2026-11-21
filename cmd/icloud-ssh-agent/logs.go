package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"

	"lds.li/icloud-keys/internal/oslog"
)

// cmdLogs shows the agent's unified log entries by running log(1).
func cmdLogs(args []string) error {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	follow := fs.Bool("f", false, "stream new entries")
	last := fs.String("last", "1d", "how far back to show, e.g. 30m, 2h, 7d")
	debug := fs.Bool("debug", false, "include debug entries")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	argv := oslog.ShowArgs(logSubsystem, logCategory, *follow, *last, *debug)
	// Replace this process so Ctrl-C and the exit status go straight to log(1).
	if err := syscall.Exec(argv[0], argv, os.Environ()); err != nil {
		return fmt.Errorf("run %s: %w", argv[0], err)
	}
	return nil
}
