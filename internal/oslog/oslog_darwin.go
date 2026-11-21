//go:build darwin && cgo

package oslog

/*
#include <os/log.h>
#include <stdlib.h>

// os_log_with_type is a macro: the compiler places the format in the binary
// where log(1) can find it and encodes the arguments, so it has to be expanded
// in C rather than called from Go.
static void oslog_write(os_log_t log, uint8_t type, const char *msg) {
	os_log_with_type(log, (os_log_type_t)type, "%{public}s", msg);
}
*/
import "C"

import (
	"errors"
	"log/slog"
	"strings"
	"unsafe"
)

// Open returns a handler that logs to the unified log under subsystem and
// category, e.g. log show --predicate 'subsystem == "li.lds.example"'.
func Open(subsystem, category string, opts *slog.HandlerOptions) (*Handler, error) {
	sub, cat := C.CString(subsystem), C.CString(category)
	defer C.free(unsafe.Pointer(sub))
	defer C.free(unsafe.Pointer(cat))
	log := C.os_log_create(sub, cat) // never released; lives for the process
	if log == nil {
		return nil, errors.New("oslog: os_log_create failed")
	}
	return newHandler(func(t Type, msg string) {
		// A NUL would end the C string early.
		m := C.CString(strings.ReplaceAll(msg, "\x00", " "))
		C.oslog_write(log, C.uint8_t(t), m)
		C.free(unsafe.Pointer(m))
	}, opts), nil
}
