//go:build windows
// +build windows

package probe

import (
	"syscall"
)

func setsockoptInt(fd uintptr, level, opt, value int) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), level, opt, value)
}
