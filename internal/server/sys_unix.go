//go:build unix

package server

import (
	"io/fs"
	"syscall"
)

// openFileLimit returns the process's limit on open file descriptors, which
// Go raises to the hard limit at startup. "Unlimited" comes out huge.
func openFileLimit() (uint64, bool) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return 0, false
	}
	return uint64(lim.Cur), true
}

// sameDevice reports whether two entries live on the same file system.
func sameDevice(a, b fs.FileInfo) bool {
	sa, okA := a.Sys().(*syscall.Stat_t)
	sb, okB := b.Sys().(*syscall.Stat_t)
	return !okA || !okB || sa.Dev == sb.Dev
}
