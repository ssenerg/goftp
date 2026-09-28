package server

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type ctxKey int

const logStateKey ctxKey = iota

type logState struct {
	start    time.Time
	deferred bool
}

// logRequests writes one access log line per request. The query string is
// never logged because it carries the access key.
func (s *Server) logRequests(c fiber.Ctx) error {
	st := &logState{start: time.Now()}
	c.Locals(logStateKey, st)

	err := c.Next()
	if err == nil && !c.Matched() {
		// Fiber's request-level error pass (malformed request, timeout,
		// 405...): the final status is set later, in handleError.
		st.deferred = true
		return nil
	}
	if err != nil {
		if herr := c.App().ErrorHandler(c, err); herr != nil {
			_ = c.SendStatus(fiber.StatusInternalServerError)
		}
	}

	// Downloads are logged once the body has been sent (or aborted).
	a := newAccess(c, st.start)
	if body, ok := c.Response().BodyStream().(*bodyStream); ok {
		body.onClose = func(sent int64, err error) { s.writeAccess(a, sent, err) }
		return nil
	}
	s.writeAccess(a, bodySize(c), nil)
	return nil
}

// access holds copies of the request data: Fiber reuses its buffers once
// the handler returns, before a streamed body is finished.
type access struct {
	ip, method, path string
	status           int
	start            time.Time
}

func newAccess(c fiber.Ctx, start time.Time) access {
	return access{
		ip:     strings.Clone(c.IP()),
		method: string(c.Request().Header.Method()),
		path:   strings.Clone(c.Path()),
		status: c.Response().StatusCode(),
		start:  start,
	}
}

func bodySize(c fiber.Ctx) int64 {
	if c.Request().Header.IsHead() {
		return 0
	}
	return int64(len(c.Response().Body()))
}

func (s *Server) writeAccess(a access, bytes int64, err error) {
	level := zapcore.InfoLevel
	switch {
	case a.status >= fiber.StatusInternalServerError:
		level = zapcore.ErrorLevel
	case a.status == fiber.StatusRequestTimeout:
		// Usually an idle (pre)connection that never sent a request.
		level = zapcore.DebugLevel
	}
	ce := s.log.Check(level, "request")
	if ce == nil {
		return
	}
	fields := []zap.Field{
		zap.String("ip", a.ip),
		zap.String("method", a.method),
		zap.String("path", a.path),
		zap.Int("status", a.status),
		zap.Int64("bytes", bytes),
		zap.Duration("latency", time.Since(a.start)),
	}
	if err != nil {
		fields = append(fields, zap.Error(err))
	}
	ce.Write(fields...)
}

// handleError replies with a generic status text so internal details never
// reach the client.
func (s *Server) handleError(c fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	var fe *fiber.Error
	if errors.As(err, &fe) {
		code = fe.Code
	} else {
		s.log.Error("request failed", zap.String("path", c.Path()), zap.Error(err))
	}
	if code == fiber.StatusMethodNotAllowed {
		c.Set(fiber.HeaderAllow, "GET, HEAD")
	}
	c.Set(fiber.HeaderXContentTypeOptions, "nosniff")
	c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)
	err = c.Status(code).SendString(http.StatusText(code))

	// Fiber calls the error handler outside the middleware chain for
	// request-level failures; log those here.
	switch st, _ := c.Locals(logStateKey).(*logState); {
	case st == nil:
		s.writeAccess(newAccess(c, time.Now()), bodySize(c), nil)
	case st.deferred:
		s.writeAccess(newAccess(c, st.start), bodySize(c), nil)
	}
	return err
}

func (s *Server) logPanic(c fiber.Ctx, e any) {
	s.log.Error("panic", zap.Any("panic", e), zap.String("path", c.Path()), zap.Stack("stack"))
}

// clientKey groups IPv6 clients by /64, since a single host usually owns
// the whole prefix.
func clientKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return strings.Clone(ip)
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return strings.Clone(ip)
	}
	return prefix.String()
}
