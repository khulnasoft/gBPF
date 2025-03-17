//go:build windows

package efw

import (
	"syscall"
	"unsafe"
)

// gbpf_result_t gbpf_close_fd(fd_t fd)
var gbpfCloseFdProc = newProc("gbpf_close_fd")

func GbpfCloseFd(fd int) error {
	addr, err := gbpfCloseFdProc.Find()
	if err != nil {
		return err
	}

	return errorResult(syscall.SyscallN(addr, uintptr(fd)))
}

// gbpf_result_t gbpf_duplicate_fd(fd_t fd, _Out_ fd_t* dup)
var gbpfDuplicateFdProc = newProc("gbpf_duplicate_fd")

func GbpfDuplicateFd(fd int) (int, error) {
	addr, err := gbpfDuplicateFdProc.Find()
	if err != nil {
		return -1, err
	}

	var dup FD
	err = errorResult(syscall.SyscallN(addr, uintptr(fd), uintptr(unsafe.Pointer(&dup))))
	return int(dup), err
}
