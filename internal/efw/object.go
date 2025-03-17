//go:build windows

package efw

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// https://github.com/microsoft/gbpf-for-windows/blob/9d9003c39c3fd75be5225ac0fce30077d6bf0604/include/gbpf_core_structs.h#L15
const _GBPF_MAX_PIN_PATH_LENGTH = 256

/*
Retrieve object info and type from a fd.

	gbpf_result_t gbpf_object_get_info_by_fd(
		fd_t bpf_fd,
		_Inout_updates_bytes_to_opt_(*info_size, *info_size) void* info,
		_Inout_opt_ uint32_t* info_size,
		_Out_opt_ gbpf_object_type_t* type)
*/
var gbpfObjectGetInfoByFdProc = newProc("gbpf_object_get_info_by_fd")

func GbpfObjectGetInfoByFd(fd int, info unsafe.Pointer, info_size *uint32) (ObjectType, error) {
	addr, err := gbpfObjectGetInfoByFdProc.Find()
	if err != nil {
		return 0, err
	}

	var objectType ObjectType
	err = errorResult(syscall.SyscallN(addr,
		uintptr(fd),
		uintptr(info),
		uintptr(unsafe.Pointer(info_size)),
		uintptr(unsafe.Pointer(&objectType)),
	))
	return objectType, err
}

// gbpf_result_t gbpf_object_unpin(_In_z_ const char* path)
var gbpfObjectUnpinProc = newProc("gbpf_object_unpin")

func GbpfObjectUnpin(path string) error {
	addr, err := gbpfObjectUnpinProc.Find()
	if err != nil {
		return err
	}

	pathBytes, err := windows.ByteSliceFromString(path)
	if err != nil {
		return err
	}

	return errorResult(syscall.SyscallN(addr, uintptr(unsafe.Pointer(&pathBytes[0]))))
}

/*
Retrieve the next pinned object path.

	gbpf_result_t gbpf_get_next_pinned_object_path(
		_In_opt_z_ const char* start_path,
		_Out_writes_z_(next_path_len) char* next_path,
		size_t next_path_len,
		_Inout_opt_ gbpf_object_type_t* type)
*/
var gbpfGetNextPinnedObjectPath = newProc("gbpf_get_next_pinned_object_path")

func GbpfGetNextPinnedObjectPath(startPath string, objectType ObjectType) (string, ObjectType, error) {
	addr, err := gbpfGetNextPinnedObjectPath.Find()
	if err != nil {
		return "", 0, err
	}

	ptr, err := windows.BytePtrFromString(startPath)
	if err != nil {
		return "", 0, err
	}

	tmp := make([]byte, _GBPF_MAX_PIN_PATH_LENGTH)
	err = errorResult(syscall.SyscallN(addr,
		uintptr(unsafe.Pointer(ptr)),
		uintptr(unsafe.Pointer(&tmp[0])),
		uintptr(len(tmp)),
		uintptr(unsafe.Pointer(&objectType)),
	))
	return windows.ByteSliceToString(tmp), objectType, err
}
