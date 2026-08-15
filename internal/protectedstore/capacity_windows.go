//go:build windows

package protectedstore

import (
	"fmt"
	"syscall"
	"unsafe"
)

var getDiskFreeSpaceExW = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")

func filesystemCapacity(path string) (uint64, uint64, error) {
	pathPointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, 0, err
	}
	var available, total, free uint64
	result, _, callErr := getDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(pathPointer)),
		uintptr(unsafe.Pointer(&available)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&free)),
	)
	if result == 0 {
		return 0, 0, fmt.Errorf("protected-storage volume capacity unavailable: %w", callErr)
	}
	return total, available, nil
}
