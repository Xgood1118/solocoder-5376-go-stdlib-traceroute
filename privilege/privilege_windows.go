//go:build windows
// +build windows

package privilege

import (
	"syscall"
	"unsafe"
)

var (
	modAdvapi32                  = syscall.NewLazyDLL("advapi32.dll")
	modKernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcessToken         = modAdvapi32.NewProc("OpenProcessToken")
	procGetTokenInformation      = modAdvapi32.NewProc("GetTokenInformation")
	procCloseHandle              = modKernel32.NewProc("CloseHandle")
	procCheckTokenMembership     = modAdvapi32.NewProc("CheckTokenMembership")
	procAllocateAndInitializeSid = modAdvapi32.NewProc("AllocateAndInitializeSid")
	procFreeSid                  = modAdvapi32.NewProc("FreeSid")
	procGetCurrentProcess        = modKernel32.NewProc("GetCurrentProcess")
)

const (
	TOKEN_QUERY              = 0x0008
	TokenElevation           = 20
	SECURITY_BUILTIN_DOMAIN_RID = 0x00000020
	DOMAIN_ALIAS_RID_ADMINS  = 0x00000220
	SE_GROUP_ENABLED         = 0x00000004
)

type tokenElevation struct {
	TokenIsElevated int32
}

type sidIdentifierAuthority struct {
	Value [6]byte
}

func isWindowsAdmin() bool {
	var token syscall.Handle
	pid, _, _ := procGetCurrentProcess.Call()
	currentProcess := syscall.Handle(pid)
	ok, _, _ := procOpenProcessToken.Call(
		uintptr(currentProcess),
		uintptr(TOKEN_QUERY),
		uintptr(unsafe.Pointer(&token)),
	)
	if ok == 0 {
		return false
	}
	defer procCloseHandle.Call(uintptr(token))

	var elevation tokenElevation
	var returnedLen uint32
	ok, _, _ = procGetTokenInformation.Call(
		uintptr(token),
		uintptr(TokenElevation),
		uintptr(unsafe.Pointer(&elevation)),
		uintptr(unsafe.Sizeof(elevation)),
		uintptr(unsafe.Pointer(&returnedLen)),
	)
	if ok == 0 {
		return false
	}

	if elevation.TokenIsElevated != 0 {
		return true
	}

	return checkAdminGroupMembership(token)
}

func checkAdminGroupMembership(token syscall.Handle) bool {
	auth := sidIdentifierAuthority{}
	auth.Value[5] = 5

	var sid *uintptr
	subAuths := []uint32{SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS}
	ok, _, _ := procAllocateAndInitializeSid.Call(
		uintptr(unsafe.Pointer(&auth)),
		2,
		uintptr(subAuths[0]),
		uintptr(subAuths[1]),
		0, 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&sid)),
	)
	if ok == 0 {
		return false
	}
	defer procFreeSid.Call(uintptr(unsafe.Pointer(sid)))

	var isMember bool
	ok, _, _ = procCheckTokenMembership.Call(
		uintptr(token),
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&isMember)),
	)
	return ok != 0 && isMember
}

func canUseICMPRaw() bool {
	return isWindowsAdmin()
}
