//go:build !windows

package protectedstore

import "syscall"

func filesystemCapacity(path string) (uint64, uint64, error) {
	var statistics syscall.Statfs_t
	if err := syscall.Statfs(path, &statistics); err != nil {
		return 0, 0, err
	}
	return statistics.Blocks * uint64(statistics.Bsize), statistics.Bavail * uint64(statistics.Bsize), nil
}
