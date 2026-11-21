//go:build !darwin || !cgo

package oslog

import (
	"errors"
	"log/slog"
)

// Open fails: the unified log needs macOS and cgo.
func Open(subsystem, category string, opts *slog.HandlerOptions) (*Handler, error) {
	return nil, errors.ErrUnsupported
}
