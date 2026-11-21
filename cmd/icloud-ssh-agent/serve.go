package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/term"
	"lds.li/age-plugin-icloud/internal/kc"
	"lds.li/age-plugin-icloud/internal/sshagent"
	"lds.li/age-plugin-icloud/internal/sshstore"
)

type touchID struct{}

func (touchID) Confirm(reason string) error { return kc.Confirm(reason, false) }

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	sock := fs.String("socket", defaultSocket(), "listen on this unix socket")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}

	logger, closeLog, err := openLog()
	if err != nil {
		return err
	}
	defer closeLog()
	// x/crypto/ssh/agent logs failures with the log package; keep them together.
	slog.SetDefault(logger)

	store, err := sshstore.Open()
	if err != nil {
		return err
	}
	store.Logger = logger
	home, _ := os.UserHomeDir()
	a := &sshagent.Agent{
		Store:    store,
		Prompter: touchID{},
		HostName: sshagent.KnownHostsNamer(filepath.Join(home, ".ssh", "known_hosts"), "/etc/ssh/ssh_known_hosts"),
		Logger:   logger,
	}

	l, err := listen(*sock)
	if err != nil {
		return err
	}
	logger.Info("listening", "socket", *sock)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigs
		logger.Info("shutting down", "signal", s.String())
		l.Close()
	}()

	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				os.Remove(*sock)
				return nil
			}
			logger.Error("accept", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go func() {
			defer c.Close()
			if err := a.ServeConnFrom(c, describePeer(c)); err != nil {
				logger.Debug("connection ended", "err", err)
			}
		}()
	}
}

// listen creates the socket, replacing a stale one but refusing to steal a
// live agent's socket. Only this user can connect.
func listen(path string) (net.Listener, error) {
	if path == "" {
		return nil, errors.New("no socket path")
	}
	// sockaddr_un.sun_path is 104 bytes on macOS, including the NUL.
	if len(path) > 103 {
		return nil, fmt.Errorf("socket path is %d bytes, over the 103-byte limit for unix sockets: %s", len(path), path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); err == nil {
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("an agent is already listening on %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket: %w", err)
		}
	}
	old := syscall.Umask(0o177)
	l, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	l.(*net.UnixListener).SetUnlinkOnClose(true)
	return l, nil
}

// openLog logs to stderr in a terminal, and otherwise (under launchd) to
// ~/Library/Logs/icloud-ssh-agent.log, so silent signatures leave a trace.
func openLog() (*slog.Logger, func(), error) {
	if term.IsTerminal(int(os.Stderr.Fd())) {
		return slog.New(slog.NewTextHandler(os.Stderr, nil)), func() {}, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, err
	}
	dir := filepath.Join(home, "Library", "Logs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "icloud-ssh-agent.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return slog.New(slog.NewTextHandler(f, nil)), func() { f.Close() }, nil
}
