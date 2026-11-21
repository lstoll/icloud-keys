package oslog

import "fmt"

// ShowArgs returns the log(1) command line that shows (or, with follow,
// streams) one subsystem and category's entries, last being how far back
// to show, e.g. "1d".
func ShowArgs(subsystem, category string, follow bool, last string, debug bool) []string {
	argv := []string{"/usr/bin/log"}
	if follow {
		argv = append(argv, "stream")
	} else {
		argv = append(argv, "show", "--last", last)
	}
	argv = append(argv, "--style", "compact",
		"--predicate", fmt.Sprintf("subsystem == %q AND category == %q", subsystem, category))
	switch {
	case debug && follow:
		argv = append(argv, "--level", "debug")
	case debug:
		argv = append(argv, "--debug")
	}
	return argv
}
