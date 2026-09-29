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

// A running upload refreshes its lock's mtime every lockRefresh; a lock
// idle for lockExpiry belongs to an upload that died (crash, restart).
var (
	lockRefresh = 15 * time.Second
	lockExpiry  = 4 * lockRefresh
)

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

// readLock returns the temp file named in a goftp lock file; the random
// temp name also identifies the upload that owns the lock. Other locks
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

// lockedPath reports whether a lock file from another tool hides an entry
// on the way to rel, a slash-separated path relative to the root that
// contains no symlinks.
func (s *Server) lockedPath(rel string) bool {
	dir := "."
	for name := range strings.SplitSeq(rel, "/") {
		if s.locked(dir, name) {
			return true
		}
		dir = path.Join(dir, name)
	}
	return false
}

// acquireLock creates the lock file for uploading name into dir, recording
// the temp file the upload writes to, and keeps it fresh until release is
// called. An abandoned goftp lock is taken over; any other existing lock
// means the name is busy.
func (s *Server) acquireLock(dir *os.Root, name, tmp string) (release func(), err error) {
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
				return nil, err
			}
			return s.holdLock(dir, lock, tmp), nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		staleTmp, err := readLock(dir, lock)
		if err != nil {
			return nil, fiber.ErrConflict
		}
		if info, err := dir.Lstat(lock); err != nil || time.Since(info.ModTime()) < lockExpiry {
			return nil, fiber.ErrConflict
		}
		_ = dir.Remove(staleTmp)
		if err := dir.Remove(lock); err != nil {
			return nil, err
		}
	}
	return nil, fiber.ErrConflict
}

// holdLock refreshes the lock until the returned release removes it, and
// only if it still belongs to the upload writing tmp.
func (s *Server) holdLock(dir *os.Root, lock, tmp string) func() {
	ticker := time.NewTicker(lockRefresh)
	done, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-done:
				return
			case now := <-ticker.C:
				_ = dir.Chtimes(lock, now, now)
			}
		}
	}()
	return func() {
		ticker.Stop()
		close(done)
		<-stopped
		s.lockMu.Lock()
		defer s.lockMu.Unlock()
		if owner, err := readLock(dir, lock); err == nil && owner == tmp {
			_ = dir.Remove(lock)
		}
	}
}
