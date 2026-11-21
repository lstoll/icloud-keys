package main

import (
	"slices"
	"testing"
)

func TestLogArgs(t *testing.T) {
	pred := `subsystem == "li.lds.icloud-ssh-agent" AND category == "agent"`
	for _, tc := range []struct {
		follow, debug bool
		want          []string
	}{
		{false, false, []string{"/usr/bin/log", "show", "--last", "1d", "--style", "compact", "--predicate", pred}},
		{false, true, []string{"/usr/bin/log", "show", "--last", "1d", "--style", "compact", "--predicate", pred, "--debug"}},
		{true, false, []string{"/usr/bin/log", "stream", "--style", "compact", "--predicate", pred}},
		{true, true, []string{"/usr/bin/log", "stream", "--style", "compact", "--predicate", pred, "--level", "debug"}},
	} {
		if got := logArgs(tc.follow, "1d", tc.debug); !slices.Equal(got, tc.want) {
			t.Errorf("logArgs(follow=%v, debug=%v) = %q, want %q", tc.follow, tc.debug, got, tc.want)
		}
	}
}
