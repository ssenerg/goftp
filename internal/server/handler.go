package server

import (
	"errors"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/gofiber/fiber/v3"

	"goftp/internal/auth"
)

var errBadPath = errors.New("bad path")

func (s *Server) handle(c fiber.Ctx) error {
	urlPath, wantDir, err := cleanPath(c.Path())
	if err != nil {
		return fiber.ErrBadRequest
	}
	// Dotfiles and dot-directories (.git, .env, ...) are never served.
	if hidden(urlPath) {
		return fiber.ErrForbidden
	}
	// Checked before the path is looked up, so that the answer does not
	// reveal what exists. The type is not known yet: either one will do.
	mayRead := func(dir bool) (bool, error) { return s.allowed(c, object(urlPath, dir), auth.ActRead) }
	ok, err := mayRead(wantDir)
	if err == nil && !ok && !wantDir {
		ok, err = mayRead(true)
	}
	if err != nil {
		return err
	}
	if !ok {
		return s.deny(c)
	}
	if dir, name := path.Split(urlPath); name != "" && s.locked(rootName(path.Clean(dir)), name) {
		return fiber.ErrNotFound
	}

	f, err := s.open(urlPath)
	if err != nil {
		return s.openError(err)
	}
	realPath, visible := s.resolve(rootName(urlPath), f)
	if !visible {
		_ = f.Close()
		return fiber.ErrNotFound
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	// Denials look like missing entries from here on: they reveal neither
	// the kind of entry (only the other kind may be read) nor where a
	// symlink leads.
	if ok, err := s.mayAt(c, auth.ActRead, urlPath, realPath, info.IsDir()); err != nil || !ok {
		_ = f.Close()
		if err != nil {
			return err
		}
		return fiber.ErrNotFound
	}

	switch {
	case info.IsDir():
		defer f.Close()
		return s.serveDir(c, f, urlPath, realPath, wantDir)
	case !info.Mode().IsRegular():
		_ = f.Close()
		return fiber.ErrNotFound
	}
	return s.serveFile(c, f, info, path.Base(urlPath))
}

// hidden reports whether any segment of the slash-separated path p starts
// with a dot.
func hidden(p string) bool {
	return strings.Contains("/"+p, "/.")
}

// cleanPath decodes the raw request path into a clean, absolute URL path and
// reports whether the request asked for a directory (trailing slash).
func cleanPath(raw string) (string, bool, error) {
	p, err := url.PathUnescape(raw)
	if err != nil {
		return "", false, err
	}
	if strings.IndexByte(p, 0) >= 0 || (filepath.Separator != '/' && strings.ContainsRune(p, filepath.Separator)) {
		return "", false, errBadPath
	}
	return path.Clean("/" + p), strings.HasSuffix(p, "/"), nil
}

// open resolves urlPath inside the root. os.Root refuses any path or
// symlink that leaves the root; O_NONBLOCK keeps FIFOs from blocking.
func (s *Server) open(urlPath string) (*os.File, error) {
	return s.root.OpenFile(rootName(urlPath), os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

func rootName(urlPath string) string {
	if name := strings.TrimPrefix(urlPath, "/"); name != "" {
		return name
	}
	return "."
}

// resolve returns the URL path where name (relative to the root) really
// lives, following symlinks, and whether it may be shown at all: entries
// in dot-directories may not, nor entries that another tool is writing in
// place, along with everything below them. os.Root already guarantees
// containment. For an opened file f, the file's own path is used where the
// OS exposes it, which cannot race with symlink swaps.
func (s *Server) resolve(name string, f *os.File) (string, bool) {
	real, ok := "", false
	if f != nil {
		real, ok = fdPath(f)
	}
	if !ok {
		var err error
		if real, err = filepath.EvalSymlinks(filepath.Join(s.rootPath, filepath.FromSlash(name))); err != nil {
			return "", false
		}
	}
	rel, err := filepath.Rel(s.rootPath, real)
	if err != nil {
		return "", false
	}
	rel = filepath.ToSlash(rel)
	switch {
	case rel == ".":
		return "/", true
	case hidden(rel), s.lockedPath(rel):
		return "", false
	}
	return "/" + rel, true
}

// visible reports whether name may be shown; see resolve.
func (s *Server) visible(name string, f *os.File) bool {
	_, ok := s.resolve(name, f)
	return ok
}

func (s *Server) openError(err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist),
		errors.Is(err, syscall.ENOTDIR),
		errors.Is(err, syscall.ELOOP),
		errors.Is(err, syscall.ENAMETOOLONG),
		errors.Is(err, syscall.ENXIO),
		s.errEscape != nil && errors.Is(err, s.errEscape):
		return fiber.ErrNotFound
	case errors.Is(err, fs.ErrPermission):
		return fiber.ErrForbidden
	default:
		return err
	}
}
