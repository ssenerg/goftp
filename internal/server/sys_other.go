//go:build !unix

package server

import "io/fs"

func openFileLimit() (uint64, bool) { return 0, false }

func sameDevice(a, b fs.FileInfo) bool { return true }
