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
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	"goftp/internal/auth"
)

// uploadRights reports whether the visitor may create new files and replace
// existing ones at obj.
func (s *Server) uploadRights(c fiber.Ctx, obj string) (create, replace bool, err error) {
	if create, err = s.allowed(c, obj, auth.ActWrite); err != nil {
		return false, false, err
	}
	replace, err = s.allowed(c, obj, auth.ActOverwrite)
	return create, replace, err
}

// put stores the request body as the file at the request path, e.g.
// curl -T file.iso -H "Authorization: Bearer $TOKEN" https://host/dir/
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
	create, replace, err := s.uploadRights(c, urlPath)
	if err != nil {
		return err
	}
	if !create && !replace {
		return s.deny(c)
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
	rights := uploadRights{create: create, replace: replace}
	created, size, err := s.receive(dir, name, body, c.Get(fiber.HeaderIfNoneMatch) != "*", rights)
	if errors.Is(err, errExists) {
		return fiber.ErrPreconditionFailed
	}
	if err != nil {
		return s.uploadError(body, err)
	}
	s.logUpload(c, urlPath, size, created)
	s.finishBody(c, body)
	if created {
		return c.SendStatus(fiber.StatusCreated)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// postForm stores the files of a multipart/form-data upload (the listing
// page's form) in the directory at the request path. The replace field has
// to come before the files. Existing files are only replaced when asked to.
// Other forms create a folder there.
func (s *Server) postForm(c fiber.Ctx) error {
	urlPath, _, err := cleanPath(c.Path())
	if err != nil {
		return fiber.ErrBadRequest
	}
	if hidden(urlPath) {
		return fiber.ErrForbidden
	}
	switch mediaType, _, _ := mime.ParseMediaType(c.Get(fiber.HeaderContentType)); mediaType {
	case fiber.MIMEApplicationForm, fiber.MIMEApplicationJSON:
		return s.mkdir(c, urlPath)
	}
	// Each file is checked on its own; this spares reading the body of
	// visitors who may not upload here at all.
	if create, replace, err := s.uploadRights(c, object(urlPath, true)); err != nil {
		return err
	} else if !create && !replace {
		return s.deny(c)
	}
	mediaType, params, err := mime.ParseMediaType(c.Get(fiber.HeaderContentType))
	if err != nil || mediaType != "multipart/form-data" || params["boundary"] == "" {
		return fiber.ErrUnsupportedMediaType
	}

	body := s.requestBody(c)
	form := multipart.NewReader(body, params["boundary"])
	replace := false
	var (
		dir    *os.Root
		stored []string
	)
	defer func() {
		if dir != nil {
			_ = dir.Close()
		}
	}()
	for {
		part, err := form.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return s.formError(c, stored, s.uploadError(body, fiber.ErrBadRequest))
		}
		switch name := part.FileName(); {
		case part.FormName() == "replace" && name == "":
			v, err := io.ReadAll(io.LimitReader(part, 16))
			if err != nil {
				return s.formError(c, stored, s.uploadError(body, fiber.ErrBadRequest))
			}
			replace = slices.Contains([]string{"1", "on", "true"}, string(v))
		case part.FormName() == "file" && name != "":
			if dir == nil {
				if dir, err = s.uploadDir(urlPath); err != nil {
					return err
				}
			}
			if !validName(name) {
				return s.formError(c, stored, fiber.ErrBadRequest)
			}
			create, mayReplace, err := s.uploadRights(c, path.Join(urlPath, name))
			if err != nil {
				return s.formError(c, stored, err)
			}
			created, size, err := s.receive(dir, name, part, replace, uploadRights{create: create, replace: mayReplace})
			if errors.Is(err, errExists) {
				err = fiber.ErrConflict
			}
			if err != nil {
				return s.formError(c, stored, s.uploadError(body, err))
			}
			s.logUpload(c, path.Join(urlPath, name), size, created)
			stored = append(stored, name)
		}
		_ = part.Close()
	}
	if len(stored) == 0 {
		return fiber.ErrBadRequest
	}
	s.finishBody(c, body)
	// Scripts upload with Accept: */* and need no page.
	if !strings.Contains(c.Get(fiber.HeaderAccept), fiber.MIMETextHTML) {
		return c.SendStatus(fiber.StatusCreated)
	}
	return c.Redirect().Status(fiber.StatusSeeOther).To(escapePath(object(urlPath, true)) + "?uploaded=" + strconv.Itoa(len(stored)))
}

// formError reports a failed form upload, naming the files that were
// already stored before the failure.
func (s *Server) formError(c fiber.Ctx, stored []string, err error) error {
	if len(stored) == 0 {
		return err
	}
	return s.sendError(c, err, "Stored before the error: "+strings.Join(stored, ", "))
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

var errExists = errors.New("file exists")

// uploadRights are the visitor's permissions for one upload target.
type uploadRights struct{ create, replace bool }

// receive stores body as name in dir. The data goes to a hidden temp file
// that is renamed into place once complete, so partial data never appears
// under the real name; the lock file keeps concurrent uploads out. Without
// replace, an existing name yields errExists.
func (s *Server) receive(dir *os.Root, name string, body io.Reader, replace bool, rights uploadRights) (created bool, size int64, err error) {
	tmp := tempPrefix + rand.Text() + tempSuffix
	release, err := s.acquireLock(dir, name, tmp)
	if err != nil {
		return false, 0, err
	}
	defer func() {
		_ = dir.Remove(tmp)
		release()
	}()

	created = true
	switch info, err := dir.Lstat(name); {
	case err == nil && info.IsDir():
		return false, 0, fiber.ErrConflict
	case err == nil && !replace:
		return false, 0, errExists
	case err == nil && !rights.replace:
		return false, 0, fiber.ErrForbidden
	case err == nil:
		created = false
	case !errors.Is(err, fs.ErrNotExist):
		return false, 0, err
	case !rights.create:
		return false, 0, fiber.ErrForbidden
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
		err = commit(dir, tmp, name, replace && rights.replace)
	}
	if err != nil {
		return false, size, err
	}
	syncDir(dir)
	return created, size, nil
}

// commit moves a finished temp file into place. Without replace, a hard
// link makes "only if absent" atomic even against writers that ignore lock
// files; without hard link support it falls back to check-then-rename.
func commit(dir *os.Root, tmp, name string, replace bool) error {
	if !replace {
		err := dir.Link(tmp, name)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, fs.ErrExist):
			return errExists
		}
		if _, err := dir.Lstat(name); err == nil {
			return errExists
		}
	}
	return dir.Rename(tmp, name)
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
	user := auth.Anonymous
	if u := userOf(c); u != nil {
		user = u.Username
	}
	s.log.Info("upload",
		zap.String("ip", c.IP()),
		zap.String("user", user),
		zap.String("path", urlPath),
		zap.Int64("bytes", size),
		zap.Bool("replaced", !created))
}

// uploadError maps a failed upload to a response status; other errors
// are server-side faults (500, logged).
func (s *Server) uploadError(body *requestBody, err error) error {
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
	case errors.Is(err, syscall.ENAMETOOLONG):
		return fiber.ErrBadRequest
	default:
		return err
	}
}

// requestBody reads a streamed request body. fasthttp applies ReadTimeout
// to the whole request, so the read deadline is re-armed before every
// read: an upload only times out when the client stops sending.
type requestBody struct {
	r        io.Reader
	conn     net.Conn
	timeout  time.Duration
	deadline time.Time // if set, for the whole body instead
	length   int64     // declared Content-Length, or -1
	read     int64
	eof      bool
	err      error
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
		deadline := b.deadline
		if deadline.IsZero() {
			deadline = time.Now().Add(b.timeout)
		}
		_ = b.conn.SetReadDeadline(deadline)
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
		c.RequestCtx().SetUserValue(bodyDoneKey, true)
	}
}

// wrapHandler wraps the fasthttp handler, so it also covers responses Fiber
// sends outside the middleware chain. fasthttp does not drain a streamed
// request body the handler left unread and would parse the rest as the next
// request, so such connections are closed.
func (s *Server) wrapHandler(next fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		next(ctx)
		// ContentLength is -1 for chunked bodies, -2 when there is none.
		if n := ctx.Request.Header.ContentLength(); (n > 0 || n == -1) && ctx.UserValue(bodyDoneKey) == nil {
			ctx.SetConnectionClose()
		}
		// Fiber answers unknown methods without running any middleware; the
		// client address is logged without proxy header processing.
		if ctx.UserValue(logStateKey) == nil {
			s.writeAccess(access{
				ip:     ctx.RemoteIP().String(),
				method: string(ctx.Method()),
				path:   string(ctx.URI().PathOriginal()),
				status: ctx.Response.StatusCode(),
				start:  ctx.Time(),
			}, int64(len(ctx.Response.Body())), nil)
		}
	}
}
