//go:build darwin

// Package platform reads Mac hardware identifiers.
package platform

import (
	"fmt"
	"sync"

	"github.com/ebitengine/purego"
)

const cfStringEncodingUTF8 = 0x08000100

var (
	uuidOnce sync.Once
	uuid     string
	uuidErr  error
)

// UUID returns the Mac hardware UUID (IOPlatformUUID). It is stable across
// hostname changes and reboots; it is not an OS-install kern.uuid.
func UUID() (string, error) {
	uuidOnce.Do(func() { uuid, uuidErr = readUUID() })
	return uuid, uuidErr
}

func readUUID() (string, error) {
	cf, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return "", err
	}
	iokit, err := purego.Dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return "", err
	}
	var (
		cfStringCreateWithCString       func(alloc uintptr, s string, encoding uint32) uintptr
		cfStringGetCString              func(s uintptr, buf *byte, size int64, encoding uint32) bool
		cfRelease                       func(ref uintptr)
		ioMainPort                      func(bootstrap uint32, main *uint32) int32
		ioServiceMatching               func(name string) uintptr
		ioServiceGetMatchingService     func(mainPort uint32, matching uintptr) uint32
		ioRegistryEntryCreateCFProperty func(entry uint32, key, alloc uintptr, options uint32) uintptr
		ioObjectRelease                 func(object uint32) int32
	)
	for _, f := range []struct {
		lib  uintptr
		name string
		fn   any
	}{
		{cf, "CFStringCreateWithCString", &cfStringCreateWithCString},
		{cf, "CFStringGetCString", &cfStringGetCString},
		{cf, "CFRelease", &cfRelease},
		{iokit, "IOMainPort", &ioMainPort},
		{iokit, "IOServiceMatching", &ioServiceMatching},
		{iokit, "IOServiceGetMatchingService", &ioServiceGetMatchingService},
		{iokit, "IORegistryEntryCreateCFProperty", &ioRegistryEntryCreateCFProperty},
		{iokit, "IOObjectRelease", &ioObjectRelease},
	} {
		sym, err := purego.Dlsym(f.lib, f.name)
		if err != nil {
			return "", err
		}
		purego.RegisterFunc(f.fn, sym)
	}

	var mainPort uint32
	if kr := ioMainPort(0, &mainPort); kr != 0 {
		return "", fmt.Errorf("IOMainPort: 0x%x", kr)
	}
	// IOServiceGetMatchingService consumes the matching dictionary.
	matching := ioServiceMatching("IOPlatformExpertDevice")
	if matching == 0 {
		return "", fmt.Errorf("IOServiceMatching IOPlatformExpertDevice failed")
	}
	service := ioServiceGetMatchingService(mainPort, matching)
	if service == 0 {
		return "", fmt.Errorf("IOPlatformExpertDevice not found")
	}
	defer ioObjectRelease(service)

	key := cfStringCreateWithCString(0, "IOPlatformUUID", cfStringEncodingUTF8)
	if key == 0 {
		return "", fmt.Errorf("creating IOPlatformUUID key")
	}
	defer cfRelease(key)
	ref := ioRegistryEntryCreateCFProperty(service, key, 0, 0)
	if ref == 0 {
		return "", fmt.Errorf("IOPlatformUUID missing")
	}
	defer cfRelease(ref)
	var buf [128]byte
	if !cfStringGetCString(ref, &buf[0], int64(len(buf)), cfStringEncodingUTF8) {
		return "", fmt.Errorf("reading IOPlatformUUID")
	}
	for i, b := range buf {
		if b == 0 {
			if i == 0 {
				return "", fmt.Errorf("empty IOPlatformUUID")
			}
			return string(buf[:i]), nil
		}
	}
	return "", fmt.Errorf("unterminated IOPlatformUUID")
}
