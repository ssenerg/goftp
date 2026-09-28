package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"
)

const deniedBody = "SIKTIR\n"

var errBadPath = errors.New("bad path")

func (s *Server) handle(c fiber.Ctx) error {
	urlPath, wantDir, err := cleanPath(c.Path())
	if err != nil {
		return fiber.ErrBadRequest
	}
	// Dotfiles and dot-directories (.git, .env, ...) are never served.
	if strings.Contains(urlPath, "/.") {
		return fiber.ErrForbidden
	}

	f, err := s.open(urlPath)
	if err != nil {
		return s.openError(err)
	}
	if !s.visible(rootName(urlPath)) {
		_ = f.Close()
		return fiber.ErrNotFound
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}

	switch {
	case info.IsDir():
		defer f.Close()
		return s.serveDir(c, f, urlPath, wantDir)
	case !info.Mode().IsRegular():
		_ = f.Close()
		return fiber.ErrNotFound
	case !s.authorized(c):
		_ = f.Close()
		c.Set(fiber.HeaderCacheControl, "no-store")
		c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)
		return c.Status(fiber.StatusForbidden).SendString(deniedBody)
	default:
		return s.serveFile(c, f, info, path.Base(urlPath))
	}
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

// visible reports whether name resolves, through any symlinks, to a path
// in the root without dot components. os.Root already guarantees
// containment; this extends the dotfile rule to symlink targets.
func (s *Server) visible(name string) bool {
	real, err := filepath.EvalSymlinks(filepath.Join(s.rootPath, filepath.FromSlash(name)))
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(s.rootPath, real)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	return rel == "." || !strings.Contains("/"+rel, "/.")
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

// authorized compares SHA-256 digests in constant time so neither the key
// nor its length leaks through timing.
func (s *Server) authorized(c fiber.Ctx) bool {
	key := c.Query(s.cfg.Query)
	reason := "missing key"
	if key != "" {
		sum := sha256.Sum256([]byte(key))
		if subtle.ConstantTimeCompare(sum[:], s.keyHash[:]) == 1 {
			return true
		}
		reason = "invalid key"
	}
	s.log.Warn("access denied",
		zap.String("reason", reason),
		zap.String("ip", c.IP()),
		zap.String("path", c.Path()))
	return false
}
