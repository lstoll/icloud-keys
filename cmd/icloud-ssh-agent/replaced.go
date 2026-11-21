package main

import (
	"os"
	"time"
)

// appWatch reports what happened to the agent's own executable, so the agent
// can follow brew: a different file at the path means the app was upgraded
// (exit, and launchd starts the new version); no file for longer than an
// upgrade takes means it was uninstalled (unload, so launchd stops retrying).
type appWatch struct {
	Path      string
	Every     time.Duration // how often to look
	GoneAfter time.Duration // missing this long means removed, not mid-upgrade
	Replaced  func()
	Removed   func()
}

// Start notes the current file, then watches in the background until stop is
// closed or it has called Replaced or Removed.
func (w appWatch) Start(stop <-chan struct{}) error {
	orig, err := os.Stat(w.Path)
	if err != nil {
		return err
	}
	go w.run(orig, stop)
	return nil
}

func (w appWatch) run(orig os.FileInfo, stop <-chan struct{}) {
	t := time.NewTicker(w.Every)
	defer t.Stop()
	var missingSince time.Time
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			cur, err := os.Stat(w.Path)
			switch {
			case err != nil:
				if missingSince.IsZero() {
					missingSince = now
				} else if now.Sub(missingSince) >= w.GoneAfter {
					w.Removed()
					return
				}
			case !os.SameFile(orig, cur):
				w.Replaced()
				return
			default:
				missingSince = time.Time{}
			}
		}
	}
}
