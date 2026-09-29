//go:build unix

package server

import "syscall"

// openFileLimit returns the process's limit on open file descriptors, which
// Go raises to the hard limit at startup. "Unlimited" comes out huge.
func openFileLimit() (uint64, bool) {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return 0, false
	}
	return uint64(lim.Cur), true
}
