package server

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"

	"github.com/gofiber/fiber/v3"
)

// While name is uploaded, the lock file .<name>.lock sits next to it. Any
// lock hides the name from listings and downloads, so tools other than
// goftp can use the same convention while writing files in place.
const (
	lockSuffix = ".lock"
	lockMagic  = "goftp-upload "
	tempPrefix = ".goftp-"
	tempSuffix = ".part"
)

var errForeignLock = errors.New("lock not created by goftp")

func lockName(name string) string { return "." + name + lockSuffix }

// lockTarget returns the entry a lock file name refers to.
func lockTarget(lock string) (string, bool) {
	if len(lock) <= len("."+lockSuffix) || lock[0] != '.' || !strings.HasSuffix(lock, lockSuffix) {
		return "", false
	}
	return lock[1 : len(lock)-len(lockSuffix)], true
}

func validTemp(name string) bool {
	return strings.HasPrefix(name, tempPrefix) && strings.HasSuffix(name, tempSuffix) &&
		len(name) <= 64 && !strings.ContainsAny(name, `/\`)
}

// readLock parses a lock file written by goftp: its owner (the process
// instance) and the temp file of the upload. Other locks yield
// errForeignLock.
func readLock(r *os.Root, name string) (owner, tmp string, err error) {
	f, err := r.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	buf := make([]byte, 128)
	n, _ := io.ReadFull(f, buf)
	line, ok := strings.CutPrefix(string(buf[:n]), lockMagic)
	if ok {
		owner, tmp, ok = strings.Cut(strings.TrimSuffix(line, "\n"), " ")
	}
	if !ok || !validTemp(tmp) {
		return "", "", errForeignLock
	}
	return owner, tmp, nil
}

// locked reports whether a lock file hides the entry name in dir (relative
// to the root). Locks left behind by an earlier goftp process are ignored:
// goftp never writes partial data under the final name.
func (s *Server) locked(dir, name string) bool {
	owner, _, err := readLock(s.root, path.Join(dir, lockName(name)))
	switch {
	case err == nil:
		return owner == s.instance
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
		return false
	default:
		return true
	}
}

// acquireLock creates the lock file for uploading name into dir, recording
// the temp file the upload writes to. A stale lock from an earlier goftp
// process is taken over; any other existing lock means the name is busy.
func (s *Server) acquireLock(dir *os.Root, name, tmp string) error {
	s.lockMu.Lock()
	defer s.lockMu.Unlock()
	lock := lockName(name)
	for range 2 {
		f, err := dir.OpenFile(lock, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err == nil {
			_, err = f.WriteString(lockMagic + s.instance + " " + tmp + "\n")
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				_ = dir.Remove(lock)
			}
			return err
		}
		if !errors.Is(err, fs.ErrExist) {
			return err
		}
		owner, staleTmp, err := readLock(dir, lock)
		if err != nil || owner == s.instance {
			return fiber.ErrConflict
		}
		_ = dir.Remove(staleTmp)
		if err := dir.Remove(lock); err != nil {
			return err
		}
	}
	return fiber.ErrConflict
}
