//go:build !unix

package server

func openFileLimit() (uint64, bool) { return 0, false }
