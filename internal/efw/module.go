//go:build windows

// Package efw contains support code for gBPF for Windows.
package efw

import (
	"golang.org/x/sys/windows"
)

// module is the global handle for the gBPF for Windows user-space API.
var module = windows.NewLazyDLL("gbpfapi.dll")

// FD is the equivalent of fd_t.
//
// See https://github.com/microsoft/gbpf-for-windows/blob/54632eb360c560ebef2f173be1a4a4625d540744/include/gbpf_api.h#L24
type FD int32

// Size is the equivalent of size_t.
//
// This is correct on amd64 and arm64 according to tests on godbolt.org.
type Size uint64

// Int is the equivalent of int on MSVC (am64, arm64) and MinGW (gcc, clang).
type Int int32

// ObjectType is the equivalent of gbpf_object_type_t.
//
// See https://github.com/microsoft/gbpf-for-windows/blob/44f5de09ec0f3f7ad176c00a290c1cb7106cdd5e/include/gbpf_core_structs.h#L41
type ObjectType uint32

const (
	GBPF_OBJECT_UNKNOWN ObjectType = iota
	GBPF_OBJECT_MAP
	GBPF_OBJECT_LINK
	GBPF_OBJECT_PROGRAM
)
