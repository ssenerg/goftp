package server

import (
	"crypto/rand"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"
)

// serveFile streams f (taking ownership of it) with Range and conditional
// request support.
func (s *Server) serveFile(c fiber.Ctx, f *os.File, info fs.FileInfo, name string) error {
	size := info.Size()
	modTime := info.ModTime()
	etag := `"` + strconv.FormatInt(modTime.UnixNano(), 16) + "-" + strconv.FormatInt(size, 16) + `"`

	c.Set(fiber.HeaderETag, etag)
	c.Set(fiber.HeaderLastModified, modTime.UTC().Format(http.TimeFormat))
	c.Set(fiber.HeaderAcceptRanges, "bytes")
	c.Set(fiber.HeaderCacheControl, "no-store")

	if notModified(c.Get(fiber.HeaderIfNoneMatch), c.Get(fiber.HeaderIfModifiedSince), etag, modTime) {
		_ = f.Close()
		return c.SendStatus(fiber.StatusNotModified)
	}

	var ranges []byteRange
	if h := c.Get(fiber.HeaderRange); h != "" && size > 0 && ifRangeMatch(c.Get(fiber.HeaderIfRange), etag, modTime) {
		var err error
		if ranges, err = parseRange(h, size); err != nil {
			_ = f.Close()
			c.Set(fiber.HeaderContentRange, "bytes */"+strconv.FormatInt(size, 10))
			return fiber.ErrRequestedRangeNotSatisfiable
		}
	}

	ctype := sniffType(f)
	c.Set(fiber.HeaderContentDisposition, mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	body := s.newBodyStream(c, f)

	switch len(ranges) {
	case 0:
		c.Set(fiber.HeaderContentType, ctype)
		body.r = io.NewSectionReader(f, 0, size)
		return sendStream(c, fiber.StatusOK, body, size)
	case 1:
		r := ranges[0]
		c.Set(fiber.HeaderContentType, ctype)
		c.Set(fiber.HeaderContentRange, r.contentRange(size))
		body.r = io.NewSectionReader(f, r.start, r.length)
		return sendStream(c, fiber.StatusPartialContent, body, r.length)
	default:
		boundary := rand.Text()
		var length int64
		body.r, length = multipartBody(f, ranges, boundary, ctype, size)
		c.Set(fiber.HeaderContentType, "multipart/byteranges; boundary="+boundary)
		return sendStream(c, fiber.StatusPartialContent, body, length)
	}
}

func sendStream(c fiber.Ctx, status int, body io.Reader, length int64) error {
	n := int(length)
	if int64(n) != length {
		n = -1 // too large for int on 32-bit platforms: use chunked encoding
	}
	return c.Status(status).SendStream(body, n)
}

func multipartBody(f *os.File, ranges []byteRange, boundary, ctype string, size int64) (io.Reader, int64) {
	parts := make([]io.Reader, 0, 2*len(ranges)+1)
	var length int64
	for i, r := range ranges {
		head := "--" + boundary + "\r\nContent-Type: " + ctype +
			"\r\nContent-Range: " + r.contentRange(size) + "\r\n\r\n"
		if i > 0 {
			head = "\r\n" + head
		}
		parts = append(parts, strings.NewReader(head), io.NewSectionReader(f, r.start, r.length))
		length += int64(len(head)) + r.length
	}
	tail := "\r\n--" + boundary + "--\r\n"
	parts = append(parts, strings.NewReader(tail))
	return io.MultiReader(parts...), length + int64(len(tail))
}

func sniffType(f *os.File) string {
	var buf [512]byte
	n, _ := f.ReadAt(buf[:], 0)
	if n == 0 {
		return "application/octet-stream"
	}
	return http.DetectContentType(buf[:n])
}

// bodyStream feeds a response body from an open file. fasthttp applies
// WriteTimeout once per response, so the stream re-arms the write deadline
// on every read: a transfer only times out when the client stops reading,
// not when a large download simply takes long.
type bodyStream struct {
	r       io.Reader
	file    *os.File
	conn    net.Conn
	timeout time.Duration
	log     *zap.Logger
	path    string
	ip      string
	read    int64
}

func (s *Server) newBodyStream(c fiber.Ctx, f *os.File) *bodyStream {
	return &bodyStream{
		file:    f,
		conn:    c.RequestCtx().Conn(),
		timeout: s.cfg.Server.WriteTimeout,
		log:     s.log,
		path:    strings.Clone(c.Path()),
		ip:      strings.Clone(c.IP()),
	}
}

func (b *bodyStream) Read(p []byte) (int, error) {
	if b.conn != nil {
		_ = b.conn.SetWriteDeadline(time.Now().Add(b.timeout))
	}
	n, err := b.r.Read(p)
	b.read += int64(n)
	return n, err
}

// CloseWithError is called by fasthttp once the response is written.
func (b *bodyStream) CloseWithError(err error) error {
	if err != nil {
		b.log.Debug("transfer aborted",
			zap.String("ip", b.ip),
			zap.String("path", b.path),
			zap.Int64("read", b.read),
			zap.Error(err))
	}
	return b.file.Close()
}
