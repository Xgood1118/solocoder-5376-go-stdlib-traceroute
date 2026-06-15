//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly
// +build linux darwin freebsd netbsd openbsd dragonfly

package privilege

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	capNetRaw = 13
)

type capHeader struct {
	Version uint32
	Pid     int32
}

type capData struct {
	Effective   uint32
	Permitted   uint32
	Inheritable uint32
}

func canUseICMPRaw() bool {
	return os.Getuid() == 0 || hasCapNetRaw()
}

func hasCapNetRaw() bool {
	var hdr capHeader
	var data [2]capData

	hdr.Version = 0x20080522
	hdr.Pid = int32(os.Getpid())

	_, _, errno := syscall.Syscall6(
		syscall.SYS_CAPGET,
		uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&data[0])),
		0, 0, 0, 0,
	)

	if errno != 0 {
		return false
	}

	mask := uint32(1 << capNetRaw)
	return (data[0].Effective&mask) != 0 || (data[0].Permitted&mask) != 0
}
