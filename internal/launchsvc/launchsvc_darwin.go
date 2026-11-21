//go:build darwin

// Package launchsvc registers the app's bundled LaunchAgent with SMAppService.
//
// It calls ServiceManagement.framework (macOS 13+) through purego's Objective-C
// bridge, so no cgo is required. The plist must live in the calling app
// bundle's Contents/Library/LaunchAgents/ directory.
package launchsvc

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
)

const frameworkPath = "/System/Library/Frameworks/ServiceManagement.framework/ServiceManagement"

var (
	loadOnce sync.Once
	loadErr  error

	selNew            = objc.RegisterName("new")
	selDrain          = objc.RegisterName("drain")
	selStringWithUTF8 = objc.RegisterName("stringWithUTF8String:")
	selUTF8String     = objc.RegisterName("UTF8String")
	selAgentService   = objc.RegisterName("agentServiceWithPlistName:")
	selRegister       = objc.RegisterName("registerAndReturnError:")
	selUnregister     = objc.RegisterName("unregisterAndReturnError:")
	selStatus         = objc.RegisterName("status")
	selOpenLoginItems = objc.RegisterName("openSystemSettingsLoginItems")
	selLocalizedDesc  = objc.RegisterName("localizedDescription")
	selCode           = objc.RegisterName("code")
	selDomain         = objc.RegisterName("domain")
)

// load dlopens ServiceManagement so that SMAppService is registered with the
// Objective-C runtime; it must happen before objc.GetClass("SMAppService").
func load() error {
	loadOnce.Do(func() {
		if _, err := purego.Dlopen(frameworkPath, purego.RTLD_NOW|purego.RTLD_GLOBAL); err != nil {
			loadErr = fmt.Errorf("launchsvc: load ServiceManagement: %w", err)
		}
	})
	return loadErr
}

// withPool runs fn on a locked OS thread inside an NSAutoreleasePool. The
// thread lock matters: a pool must be drained on the thread that created it,
// and Go may otherwise migrate the goroutine. Anything fn returns must already
// be copied into Go memory, since ObjC objects die when the pool drains.
func withPool(fn func()) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pool := objc.ID(objc.GetClass("NSAutoreleasePool")).Send(selNew)
	defer pool.Send(selDrain)
	fn()
}

func nsString(s string) objc.ID {
	// stringWithUTF8String: takes a NUL-terminated C string. purego converts a
	// Go string argument to a temporary C string for the duration of the call,
	// and NSString copies the bytes. The returned object is autoreleased.
	return objc.ID(objc.GetClass("NSString")).Send(selStringWithUTF8, s)
}

func goString(ns objc.ID) string {
	if ns == 0 {
		return ""
	}
	p := objc.Send[*byte](ns, selUTF8String)
	if p == nil {
		return ""
	}
	// Find the NUL terminator and copy the bytes into Go memory.
	n := 0
	for *(*byte)(unsafe.Add(unsafe.Pointer(p), n)) != 0 {
		n++
	}
	return string(unsafe.Slice(p, n))
}

// nsError converts an NSError object into a Go error.
func nsError(op string, e objc.ID) error {
	desc := goString(e.Send(selLocalizedDesc))
	domain := goString(e.Send(selDomain))
	code := objc.Send[int](e, selCode)
	return fmt.Errorf("launchsvc: %s: %s (%s code %d)", op, desc, domain, code)
}

// service returns the autoreleased SMAppService for plistName. Call within withPool.
func service(plistName string) (objc.ID, error) {
	if err := load(); err != nil {
		return 0, err
	}
	cls := objc.GetClass("SMAppService") // nil on macOS < 13
	if cls == 0 {
		return 0, errors.New("launchsvc: SMAppService unavailable (requires macOS 13+)")
	}
	svc := objc.ID(cls).Send(selAgentService, nsString(plistName))
	if svc == 0 {
		return 0, fmt.Errorf("launchsvc: no service for plist %q", plistName)
	}
	return svc, nil
}

// call invokes a BOOL-returning method of the form -(BOOL)method:(NSError **)error.
func call(op string, plistName string, sel objc.SEL) error {
	var err error
	withPool(func() {
		var svc objc.ID
		if svc, err = service(plistName); err != nil {
			return
		}
		// The NSError** out-param is a pointer to an ID-sized slot we own;
		// the callee writes an autoreleased NSError into it on failure.
		var nserr objc.ID
		ok := objc.Send[bool](svc, sel, unsafe.Pointer(&nserr))
		if !ok {
			if nserr != 0 {
				err = nsError(op, nserr)
			} else {
				err = fmt.Errorf("launchsvc: %s failed", op)
			}
		}
		runtime.KeepAlive(&nserr)
	})
	return err
}

// Register registers the LaunchAgent described by plistName (a file in the
// app bundle's Contents/Library/LaunchAgents). The status may afterwards be
// RequiresApproval; check StatusOf.
func Register(plistName string) error {
	return call("register", plistName, selRegister)
}

// Unregister removes the LaunchAgent registration and stops the service.
func Unregister(plistName string) error {
	return call("unregister", plistName, selUnregister)
}

// StatusOf reports the registration status of the LaunchAgent plistName.
func StatusOf(plistName string) (Status, error) {
	var (
		st  Status
		err error
	)
	withPool(func() {
		var svc objc.ID
		if svc, err = service(plistName); err != nil {
			return
		}
		st = Status(objc.Send[int](svc, selStatus))
	})
	return st, err
}

// OpenLoginItemsSettings opens System Settings at Login Items, where the user
// can approve a service whose status is RequiresApproval. Errors are ignored.
func OpenLoginItemsSettings() {
	if load() != nil {
		return
	}
	withPool(func() {
		if cls := objc.GetClass("SMAppService"); cls != 0 {
			objc.ID(cls).Send(selOpenLoginItems)
		}
	})
}
