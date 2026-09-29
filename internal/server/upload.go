package server

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"mime"
	"mime/multipart"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"
)

// put stores the request body as the file at the request path, e.g.
// curl -T file.iso -H "Authorization: Bearer $UPLOAD_KEY" https://host/dir/
// The parent directory must exist. "If-None-Match: *" refuses to replace an
// existing file.
func (s *Server) put(c fiber.Ctx) error {
	urlPath, wantDir, err := cleanPath(c.Path())
	if err != nil || wantDir || urlPath == "/" {
		return fiber.ErrBadRequest
	}
	if hidden(urlPath) {
		return fiber.ErrForbidden
	}
	dirPath, name := path.Split(urlPath)
	if !validName(name) {
		return fiber.ErrBadRequest
	}
	if ok, err := s.authorize(c, s.uploadKey(c), &s.uploadKeyHash); !ok {
		return err
	}
	// A chunked body cut off between chunks looks complete; only a declared
	// length lets truncated uploads be detected.
	length := int64(c.Request().Header.ContentLength())
	if length < 0 {
		return fiber.ErrLengthRequired
	}
	if limit := int64(s.cfg.Upload.MaxSize); limit > 0 && length > limit {
		return fiber.ErrRequestEntityTooLarge
	}
	dir, err := s.uploadDir(dirPath)
	if errors.Is(err, fiber.ErrNotFound) {
		return fiber.ErrConflict
	}
	if err != nil {
		return err
	}
	defer dir.Close()

	body := s.requestBody(c)
	created, size, err := s.receive(dir, name, body, c.Get(fiber.HeaderIfNoneMatch) != "*")
	if err != nil {
		return uploadError(body, err)
	}
	s.logUpload(c, urlPath, size, created)
	s.finishBody(c, body)
	if created {
		return c.SendStatus(fiber.StatusCreated)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// postForm stores the files of a multipart/form-data upload (the listing
// page's form) in the directory at the request path. The key field has to
// come before the files.
func (s *Server) postForm(c fiber.Ctx) error {
	urlPath, _, err := cleanPath(c.Path())
	if err != nil {
		return fiber.ErrBadRequest
	}
	if hidden(urlPath) {
		return fiber.ErrForbidden
	}
	mediaType, params, err := mime.ParseMediaType(c.Get(fiber.HeaderContentType))
	if err != nil || mediaType != "multipart/form-data" || params["boundary"] == "" {
		return fiber.ErrUnsupportedMediaType
	}

	body := s.requestBody(c)
	form := multipart.NewReader(body, params["boundary"])
	key := s.uploadKey(c)
	var dir *os.Root
	defer func() {
		if dir != nil {
			_ = dir.Close()
		}
	}()
	stored := 0
	for {
		part, err := form.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return uploadError(body, fiber.ErrBadRequest)
		}
		switch name := part.FileName(); {
		case part.FormName() == s.cfg.Query && name == "":
			v, err := io.ReadAll(io.LimitReader(part, 1024))
			if err != nil {
				return uploadError(body, fiber.ErrBadRequest)
			}
			key = string(v)
		case part.FormName() == "file" && name != "":
			if dir == nil {
				if ok, err := s.authorize(c, key, &s.uploadKeyHash); !ok {
					return err
				}
				if dir, err = s.uploadDir(urlPath); err != nil {
					return err
				}
			}
			if !validName(name) {
				return fiber.ErrBadRequest
			}
			created, size, err := s.receive(dir, name, part, true)
			if err != nil {
				return uploadError(body, err)
			}
			s.logUpload(c, path.Join(urlPath, name), size, created)
			stored++
		}
		_ = part.Close()
	}
	if stored == 0 {
		return fiber.ErrBadRequest
	}
	s.finishBody(c, body)
	return c.Redirect().Status(fiber.StatusSeeOther).To(escapePath(strings.TrimSuffix(urlPath, "/") + "/"))
}

// uploadKey takes the key from an "Authorization: Bearer" header, which
// keeps it out of URLs and logs, or else from the query.
func (s *Server) uploadKey(c fiber.Ctx) string {
	if key, ok := strings.CutPrefix(c.Get(fiber.HeaderAuthorization), "Bearer "); ok {
		return key
	}
	return c.Query(s.cfg.Query)
}

// uploadDir opens the existing directory at urlPath for writing. Its fd pins
// the directory, so later operations cannot be redirected by symlink swaps.
func (s *Server) uploadDir(urlPath string) (*os.Root, error) {
	name := rootName(path.Clean(urlPath))
	// OpenRoot reports non-directories with an unexported error.
	if info, err := s.root.Stat(name); err != nil {
		return nil, s.openError(err)
	} else if !info.IsDir() {
		return nil, fiber.ErrNotFound
	}
	dir, err := s.root.OpenRoot(name)
	if err != nil {
		return nil, s.openError(err)
	}
	f, err := dir.Open(".")
	if err == nil {
		visible := s.visible(name, f)
		_ = f.Close()
		if visible {
			return dir, nil
		}
		err = fiber.ErrNotFound
	}
	_ = dir.Close()
	return nil, err
}

// receive stores body as name in dir. The data goes to a hidden temp file
// that is renamed into place once complete; until then a lock file hides
// the name from listings and downloads and keeps concurrent uploads of the
// same name out.
func (s *Server) receive(dir *os.Root, name string, body io.Reader, replace bool) (created bool, size int64, err error) {
	tmp := tempPrefix + rand.Text() + tempSuffix
	if err := s.acquireLock(dir, name, tmp); err != nil {
		return false, 0, err
	}
	defer func() {
		_ = dir.Remove(tmp)
		_ = dir.Remove(lockName(name))
	}()

	switch info, err := dir.Lstat(name); {
	case err == nil && info.IsDir():
		return false, 0, fiber.ErrConflict
	case err == nil && !replace:
		return false, 0, fiber.ErrPreconditionFailed
	case errors.Is(err, fs.ErrNotExist):
		created = true
	case err != nil:
		return false, 0, err
	}

	f, err := dir.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return false, 0, err
	}
	size, err = s.copyUpload(f, body)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = dir.Rename(tmp, name)
	}
	if err != nil {
		return false, size, err
	}
	syncDir(dir)
	return created, size, nil
}

func (s *Server) copyUpload(dst io.Writer, body io.Reader) (int64, error) {
	limit := int64(s.cfg.Upload.MaxSize)
	if limit <= 0 {
		return io.Copy(dst, body)
	}
	n, err := io.Copy(dst, io.LimitReader(body, limit+1))
	if err == nil && n > limit {
		err = fiber.ErrRequestEntityTooLarge
	}
	return n, err
}

// syncDir makes a rename durable; not every platform can sync directories.
func syncDir(dir *os.Root) {
	if d, err := dir.Open("."); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// validName reports whether name is acceptable for an uploaded file.
func validName(name string) bool {
	if name == "" || hidden(name) || len(lockName(name)) > 255 || !utf8.ValidString(name) {
		return false
	}
	bad := `/\`
	if filepath.Separator == '\\' {
		bad += `:*?"<>|`
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f || strings.ContainsRune(bad, r) {
			return false
		}
	}
	return true
}

func (s *Server) logUpload(c fiber.Ctx, urlPath string, size int64, created bool) {
	s.log.Info("upload",
		zap.String("ip", c.IP()),
		zap.String("path", urlPath),
		zap.Int64("bytes", size),
		zap.Bool("replaced", !created))
}

// uploadError maps a failed upload to a response status.
func uploadError(body *requestBody, err error) error {
	var (
		fe      *fiber.Error
		timeout interface{ Timeout() bool }
	)
	switch {
	case errors.As(err, &fe):
		return err
	case errors.As(body.err, &timeout) && timeout.Timeout():
		return fiber.ErrRequestTimeout
	case body.err != nil:
		return fiber.ErrBadRequest
	case errors.Is(err, syscall.ENOSPC):
		return fiber.ErrInsufficientStorage
	default:
		return err
	}
}

// requestBody reads a streamed request body. fasthttp applies ReadTimeout
// to the whole request, so the read deadline is re-armed before every
// read: an upload only times out when the client stops sending.
type requestBody struct {
	r       io.Reader
	conn    net.Conn
	timeout time.Duration
	length  int64 // declared Content-Length, or -1
	read    int64
	eof     bool
	err     error
}

func (s *Server) requestBody(c fiber.Ctx) *requestBody {
	r := c.Request().BodyStream()
	if r == nil {
		r = bytes.NewReader(c.Request().Body())
	}
	return &requestBody{
		r:       r,
		conn:    c.RequestCtx().Conn(),
		timeout: s.cfg.Server.ReadTimeout,
		length:  max(int64(c.Request().Header.ContentLength()), -1),
	}
}

func (b *requestBody) Read(p []byte) (int, error) {
	if b.conn != nil {
		_ = b.conn.SetReadDeadline(time.Now().Add(b.timeout))
	}
	n, err := b.r.Read(p)
	b.read += int64(n)
	// fasthttp reports a connection closed mid-body as a clean EOF.
	if err == io.EOF && b.length >= 0 && b.read != b.length {
		err = io.ErrUnexpectedEOF
	}
	switch {
	case err == io.EOF:
		b.eof = true
	case err != nil:
		b.err = err
	}
	return n, err
}

// finishBody drains a small remainder of the body (such as a multipart
// epilogue) and marks the body consumed, which keeps the connection open.
func (s *Server) finishBody(c fiber.Ctx, b *requestBody) {
	if !b.eof && b.err == nil {
		_, _ = io.CopyN(io.Discard, b, 64<<10)
	}
	if b.eof {
		c.Locals(bodyDoneKey, true)
	}
}

// closeUnreadBody closes the connection after a request whose streamed body
// was not fully read: fasthttp would parse the rest as the next request.
func closeUnreadBody(c fiber.Ctx) error {
	err := c.Next()
	if c.Request().Header.ContentLength() != 0 && c.Locals(bodyDoneKey) == nil {
		c.Response().SetConnectionClose()
	}
	return err
}
