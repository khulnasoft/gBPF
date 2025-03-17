//go:build windows

package efw

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

/*
Converts an attach type enum into a GUID.

	gbpf_result_t gbpf_get_gbpf_attach_type(
		bpf_attach_type_t bpf_attach_type,
		_Out_ gbpf_attach_type_t* gbpf_attach_type_t *gbpf_attach_type)
*/
var gbpfGetGbpfAttachTypeProc = newProc("gbpf_get_gbpf_attach_type")

func GbpfGetGbpfAttachType(attachType uint32) (windows.GUID, error) {
	addr, err := gbpfGetGbpfAttachTypeProc.Find()
	if err != nil {
		return windows.GUID{}, err
	}

	var attachTypeGUID windows.GUID
	err = errorResult(syscall.SyscallN(addr,
		uintptr(attachType),
		uintptr(unsafe.Pointer(&attachTypeGUID)),
	))
	return attachTypeGUID, err
}

/*
Retrieve a program type given a GUID.

	bpf_prog_type_t gbpf_get_bpf_program_type(_In_ const gbpf_program_type_t* program_type)
*/
var gbpfGetBpfProgramTypeProc = newProc("gbpf_get_bpf_program_type")

func GbpfGetBpfProgramType(programType windows.GUID) (uint32, error) {
	addr, err := gbpfGetBpfProgramTypeProc.Find()
	if err != nil {
		return 0, err
	}

	return uint32Result(syscall.SyscallN(addr, uintptr(unsafe.Pointer(&programType)))), nil
}

/*
Retrieve an attach type given a GUID.

	bpf_attach_type_t gbpf_get_bpf_attach_type(_In_ const gbpf_attach_type_t* gbpf_attach_type)
*/
var gbpfGetBpfAttachTypeProc = newProc("gbpf_get_bpf_attach_type")

func GbpfGetBpfAttachType(attachType windows.GUID) (uint32, error) {
	addr, err := gbpfGetBpfAttachTypeProc.Find()
	if err != nil {
		return 0, err
	}

	return uint32Result(syscall.SyscallN(addr, uintptr(unsafe.Pointer(&attachType)))), nil
}
