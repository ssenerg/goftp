//go:build !linux

package server

import "os"

// fdPath is unsupported here; callers fall back to resolving the name.
func fdPath(*os.File) (string, bool) { return "", false }
