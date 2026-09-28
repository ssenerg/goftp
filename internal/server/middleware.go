package server

import (
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type ctxKey int

const logStartKey ctxKey = iota

// logRequests writes one access log line per request. The query string is
// never logged because it carries the access key.
func (s *Server) logRequests(c fiber.Ctx) error {
	start := time.Now()
	err := c.Next()
	if err == nil && !c.Matched() {
		// Fiber's server-error pass (malformed request, timeout, 405...):
		// the final status is only known in handleError, which logs it.
		c.Locals(logStartKey, start)
		return nil
	}
	if err != nil {
		if herr := c.App().ErrorHandler(c, err); herr != nil {
			_ = c.SendStatus(fiber.StatusInternalServerError)
		}
	}
	s.logRequest(c, start)
	return nil
}

func (s *Server) logRequest(c fiber.Ctx, start time.Time) {
	status := c.Response().StatusCode()
	level := zapcore.InfoLevel
	if status >= fiber.StatusInternalServerError {
		level = zapcore.ErrorLevel
	}
	if ce := s.log.Check(level, "request"); ce != nil {
		ce.Write(
			zap.String("ip", c.IP()),
			zap.String("method", c.Method()),
			zap.String("path", c.Path()),
			zap.Int("status", status),
			zap.Int("bytes", responseSize(c.Response())),
			zap.Duration("latency", time.Since(start)),
		)
	}
}

// responseSize must not call Body() on streamed responses: that would
// buffer the whole file in memory.
func responseSize(r *fasthttp.Response) int {
	if r.IsBodyStream() {
		return r.Header.ContentLength()
	}
	return len(r.Body())
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
	c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)
	err = c.Status(code).SendString(http.StatusText(code))
	if start, ok := c.Locals(logStartKey).(time.Time); ok {
		s.logRequest(c, start)
	}
	return err
}

func (s *Server) logPanic(c fiber.Ctx, e any) {
	s.log.Error("panic", zap.Any("panic", e), zap.String("path", c.Path()), zap.Stack("stack"))
}

func (s *Server) limitReached(c fiber.Ctx) error {
	c.Set(fiber.HeaderRetryAfter, strconv.Itoa(int(s.cfg.Limiter.Window.Seconds())))
	return fiber.ErrTooManyRequests
}

// clientKey groups IPv6 clients by /64, since a single host usually owns
// the whole prefix.
func clientKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return ip
	}
	return prefix.String()
}
