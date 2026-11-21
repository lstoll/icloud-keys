package main

import (
	"flag"
	"fmt"
	"os"
	"syscall"
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
	argv := logArgs(*follow, *last, *debug)
	// Replace this process so Ctrl-C and the exit status go straight to log(1).
	if err := syscall.Exec(argv[0], argv, os.Environ()); err != nil {
		return fmt.Errorf("run %s: %w", argv[0], err)
	}
	return nil
}

func logArgs(follow bool, last string, debug bool) []string {
	argv := []string{"/usr/bin/log"}
	if follow {
		argv = append(argv, "stream")
	} else {
		argv = append(argv, "show", "--last", last)
	}
	argv = append(argv, "--style", "compact",
		"--predicate", fmt.Sprintf("subsystem == %q AND category == %q", logSubsystem, logCategory))
	switch {
	case debug && follow:
		argv = append(argv, "--level", "debug")
	case debug:
		argv = append(argv, "--debug")
	}
	return argv
}
