package server

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v3"
)

// While name is uploaded, the lock file .<name>.lock sits next to it. goftp
// writes the data to a hidden temp file and renames it into place, so its
// own locks only keep concurrent uploads out. Locks from other tools hide
// the name from listings and downloads, so such tools can write files in
// place without exposing partial data.
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

// readLock returns the temp file named in a goftp lock file. Other locks
// yield errForeignLock.
func readLock(r *os.Root, name string) (string, error) {
	f, err := r.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]byte, 128)
	n, _ := io.ReadFull(f, buf)
	tmp, ok := strings.CutPrefix(string(buf[:n]), lockMagic)
	tmp, found := strings.CutSuffix(tmp, "\n")
	if !ok || !found || !validTemp(tmp) {
		return "", errForeignLock
	}
	return tmp, nil
}

// locked reports whether a lock file from another tool hides the entry
// name in dir (relative to the root).
func (s *Server) locked(dir, name string) bool {
	_, err := readLock(s.root, path.Join(dir, lockName(name)))
	return err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.ENOTDIR)
}

// acquireLock creates the lock file for uploading name into dir, recording
// the temp file the upload writes to. An abandoned goftp lock (crash,
// restart) is taken over; any other existing lock means the name is busy.
func (s *Server) acquireLock(dir *os.Root, name, tmp string) error {
	s.lockMu.Lock()
	defer s.lockMu.Unlock()
	lock := lockName(name)
	for range 2 {
		f, err := dir.OpenFile(lock, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err == nil {
			_, err = f.WriteString(lockMagic + tmp + "\n")
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
		staleTmp, err := readLock(dir, lock)
		if err != nil || !s.abandoned(dir, lock, staleTmp) {
			return fiber.ErrConflict
		}
		_ = dir.Remove(staleTmp)
		if err := dir.Remove(lock); err != nil {
			return err
		}
	}
	return fiber.ErrConflict
}

// abandoned reports whether an upload has made no progress for a while. A
// live upload writes to its temp file at least every read_timeout, even in
// another goftp process such as the old one during a restart.
func (s *Server) abandoned(dir *os.Root, lock, tmp string) bool {
	cutoff := time.Now().Add(-max(2*s.cfg.Server.ReadTimeout, time.Minute))
	for _, name := range []string{lock, tmp} {
		info, err := dir.Lstat(name)
		if err == nil && info.ModTime().After(cutoff) || err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false
		}
	}
	return true
}
