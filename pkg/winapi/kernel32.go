package winapi

import (
	"syscall"
	"unsafe"
)

const (
	HEAP_ZERO_MEMORY           = 0x00000008
	HEAP_CREATE_ENABLE_EXECUTE = 0x00040000
	MEM_COMMIT                 = 0x00001000
	MEM_RESERVE                = 0x00002000
	MEM_DECOMMIT               = 0x00004000
	MEM_RELEASE                = 0x00008000
	MEM_RESET                  = 0x00080000
	MEM_TOP_DOWN               = 0x00100000
	MEM_WRITE_WATCH            = 0x00200000
	MEM_PHYSICAL               = 0x00400000
	MEM_RESET_UNDO             = 0x01000000
	MEM_LARGE_PAGES            = 0x20000000

	PAGE_NOACCESS          = 0x00000001
	PAGE_READONLY          = 0x00000002
	PAGE_READWRITE         = 0x00000004
	PAGE_WRITECOPY         = 0x00000008
	PAGE_EXECUTE           = 0x00000010
	PAGE_EXECUTE_READ      = 0x00000020
	PAGE_EXECUTE_READWRITE = 0x00000040
	PAGE_EXECUTE_WRITECOPY = 0x00000080
	PAGE_GUARD             = 0x00000100
	PAGE_NOCACHE           = 0x00000200
	PAGE_WRITECOMBINE      = 0x00000400
	PAGE_TARGETS_INVALID   = 0x40000000
	PAGE_TARGETS_NO_UPDATE = 0x40000000

	QUOTA_LIMITS_HARDWS_MIN_DISABLE = 0x00000002
	QUOTA_LIMITS_HARDWS_MIN_ENABLE  = 0x00000001
	QUOTA_LIMITS_HARDWS_MAX_DISABLE = 0x00000008
	QUOTA_LIMITS_HARDWS_MAX_ENABLE  = 0x00000004
)

var (
	pModKernel32        = syscall.NewLazyDLL("kernel32.dll")
	pGetModuleHandleW   = pModKernel32.NewProc("GetModuleHandleW")
	pGetCurrentProcess  = pModKernel32.NewProc("GetCurrentProcess")
	pOpenProcess        = pModKernel32.NewProc("OpenProcess")
	pGetProcessHeap     = pModKernel32.NewProc("GetProcessHeap")
	pHeapCreate         = pModKernel32.NewProc("HeapCreate")
	pCreateProcess      = pModKernel32.NewProc("CreateProcess")
	pGetExitCodeThread  = pModKernel32.NewProc("GetExitCodeThread")
	pVirtualProtect     = pModKernel32.NewProc("VirtualProtect")
	pVirtualProtectEx   = pModKernel32.NewProc("VirtualProtectEx")
	pReadFile           = pModKernel32.NewProc("ReadFile")
	pHeapAlloc          = pModKernel32.NewProc("HeapAlloc")
	pHeapFree           = pModKernel32.NewProc("HeapFree")
	pVirtualAlloc       = pModKernel32.NewProc("VirtualAlloc")
	pVirtualAllocEx     = pModKernel32.NewProc("VirtualAllocEx")
	pWriteProcessMemory = pModKernel32.NewProc("WriteProcessMemory")
	pReadProcessMemory  = pModKernel32.NewProc("ReadProcessMemory")
	pCreateThread       = pModKernel32.NewProc("CreateThread")
	pCreateRemoteThread = pModKernel32.NewProc("CreateRemoteThread")
	pWriteFile          = pModKernel32.NewProc("WriteFile")
	pWaitNamedPipe      = pModKernel32.NewProc("WaitNamedPipeW")
	pCreateFile         = pModKernel32.NewProc("CreateFileW")
	pFlushFileBuffers   = pModKernel32.NewProc("FlushFileBuffers")
	PGlobalLock         = pModKernel32.NewProc("GlobalLock")
	PGlobalUnlock       = pModKernel32.NewProc("GlobalUnlock")
	pIsBadReadPtr       = pModKernel32.NewProc("IsBadReadPtr")
	pCreatePipe         = pModKernel32.NewProc("CreatePipe")
	pSetStdHandle       = pModKernel32.NewProc("SetStdHandle")
	pLoadLibraryW       = pModKernel32.NewProc("LoadLibraryW")
	pGetProcAddress     = pModKernel32.NewProc("GetProcAddress")
)

func GetProcAddress(hModule uintptr, procName string) uintptr {
	p, err := syscall.UTF16PtrFromString(procName)
	if err != nil {
		return 0
	}
	a, _, _ := pGetProcAddress.Call(hModule, uintptr(unsafe.Pointer(p)))
	return a
}

func LoadLibrary(lib string) uintptr {
	p, err := syscall.UTF16PtrFromString(lib)
	if err != nil {
		return 0
	}
	u, _, _ := pLoadLibraryW.Call(uintptr(unsafe.Pointer(p)))
	return u
}

func GetCurrentProcess() uintptr {
	res, _, _ := pGetCurrentProcess.Call()
	return res
}

func CreateThread(lpThreadAttributes uintptr, dwStackSz uint32, lpStartAddress uintptr, lpParameteter uintptr, dwCreationFlags uint32, lpThreadId *uint32) (syscall.Handle, error) {
	thread, _, err := pCreateThread.Call(
		lpThreadAttributes,
		uintptr(dwStackSz),
		lpStartAddress,
		lpParameteter,
		uintptr(dwCreationFlags),
		uintptr(unsafe.Pointer(lpThreadId)))
	if thread == 0 {
		return 0, err
	}
	return syscall.Handle(thread), nil
}

func WriteProcessMemory(hProcess syscall.Handle, lpAddresss uintptr, lpBuffer uintptr, nSize uint32, lpNumberOfBytesWritten *uint32) (bool, error) {
	writeMem, _, err := pWriteProcessMemory.Call(
		uintptr(hProcess),
		lpAddresss,
		lpBuffer,
		uintptr(nSize),
		uintptr(unsafe.Pointer(lpNumberOfBytesWritten)))
	if writeMem == 0 {
		return false, err
	}
	return true, nil
}

func VirtualAlloc(lpAddress uintptr, dwSize uint32, allocationType uint32, flProtect uint32) (uintptr, error) {
	lpBaseAddress, _, err := pVirtualAlloc.Call(
		lpAddress,
		uintptr(dwSize),
		uintptr(allocationType),
		uintptr(flProtect))
	if lpBaseAddress == 0 {
		return 0, err
	}
	return lpBaseAddress, nil
}

func VirtualProtect(lpAddress uintptr, dwSize uint32, flNewProtect uint32, lpflOldProtect unsafe.Pointer) (uintptr, error) {
	ret, _, err := pVirtualProtect.Call(
		lpAddress,
		uintptr(dwSize),
		uintptr(flNewProtect),
		uintptr(lpflOldProtect))
	if ret == 0 {
		return 0, err
	}
	return ret, nil
}

func ReadProcessMemory(hProcess syscall.Handle, lpBaseAddress uintptr, lpBuffer uintptr, nSize uint32, lpNumberOfBytesRead *uint32) (bool, error) {
	ok, _, err := pReadProcessMemory.Call(
		uintptr(hProcess),
		lpBaseAddress,
		lpBuffer,
		uintptr(nSize),
		uintptr(unsafe.Pointer(lpNumberOfBytesRead)))
	if ok == 0 {
		return false, err
	}
	return true, nil
}
