// Package oslog sends slog records to the macOS unified log, where Console.app
// and log(1) read them.
//
// Records are formatted like slog's text handler, minus the time and level
// (the unified log records both), with the message first:
//
//	signed without prompt key=work purpose=git requester="ssh-keygen (from git)"
package oslog

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
)

// Type is an os_log_type_t.
type Type uint8

const (
	TypeDefault Type = 0x00 // stored on disk
	TypeInfo    Type = 0x01 // memory only unless configured otherwise
	TypeDebug   Type = 0x02
	TypeError   Type = 0x10
)

// typeFor maps slog levels to os_log types. Info and Warn both go to Default:
// os_log's Info type isn't kept on disk, and these are the agent's audit trail.
func typeFor(l slog.Level) Type {
	switch {
	case l < slog.LevelInfo:
		return TypeDebug
	case l < slog.LevelError:
		return TypeDefault
	default:
		return TypeError
	}
}

// Handler is a slog.Handler that writes each record as one os_log entry.
type Handler struct {
	inner slog.Handler
	s     *sink
}

// sink receives the text handler's output. A text handler writes each record
// with a single Write, so Handle sets the record's type and message under mu
// and the Write that follows sends the entry.
type sink struct {
	mu   sync.Mutex
	typ  Type
	msg  string
	emit func(Type, string)
}

func (s *sink) Write(p []byte) (int, error) {
	line := strings.TrimSpace(string(bytes.TrimSuffix(p, []byte("\n"))))
	switch {
	case s.msg == "":
	case line == "":
		line = s.msg
	default:
		line = s.msg + " " + line
	}
	s.emit(s.typ, line)
	return len(p), nil
}

func newHandler(emit func(Type, string), opts *slog.HandlerOptions) *Handler {
	var o slog.HandlerOptions
	if opts != nil {
		o = *opts
	}
	next := o.ReplaceAttr
	o.ReplaceAttr = func(groups []string, a slog.Attr) slog.Attr {
		if len(groups) == 0 {
			switch a.Key {
			case slog.TimeKey, slog.LevelKey, slog.MessageKey:
				return slog.Attr{}
			}
		}
		if next != nil {
			return next(groups, a)
		}
		return a
	}
	s := &sink{emit: emit}
	return &Handler{inner: slog.NewTextHandler(s, &o), s: s}
}

func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	h.s.typ, h.s.msg = typeFor(r.Level), r.Message
	return h.inner.Handle(ctx, r)
}

func (h *Handler) WithAttrs(as []slog.Attr) slog.Handler {
	return &Handler{inner: h.inner.WithAttrs(as), s: h.s}
}

func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{inner: h.inner.WithGroup(name), s: h.s}
}
