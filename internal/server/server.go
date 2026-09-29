package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/helmet"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"go.uber.org/zap"

	"goftp/internal/auth"
	"goftp/internal/config"
)

// readBufferSize bounds the request line plus headers; percent-encoded
// non-ASCII paths are long. Idle connections release it (ReduceMemoryUsage).
const readBufferSize = 16 << 10

const contentSecurityPolicy = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; " +
	"base-uri 'none'; frame-ancestors 'none'; form-action 'self'"

const allowedMethods = "GET, HEAD, PUT, POST"

type Server struct {
	cfg       *config.Config
	log       *zap.Logger
	auth      *auth.Service
	app       *fiber.App
	root      *os.Root
	rootPath  string
	limiter   *failureLimiter
	errEscape error
	lockMu    sync.Mutex
}

func New(cfg *config.Config, log *zap.Logger, authSvc *auth.Service) (*Server, error) {
	rootPath, err := filepath.EvalSymlinks(cfg.Dir)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:       cfg,
		log:       log,
		auth:      authSvc,
		root:      root,
		rootPath:  rootPath,
		errEscape: escapeError(root),
	}

	s.app = fiber.New(fiber.Config{
		ErrorHandler:      s.handleError,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		ReadBufferSize:    readBufferSize,
		ReduceMemoryUsage: true,
		// Uploads are streamed to disk instead of buffered in memory.
		StreamRequestBody:            true,
		DisablePreParseMultipartForm: true,
		CaseSensitive:                true,
		StrictRouting:                true,
		ProxyHeader:                  cfg.Server.ProxyHeader,
		TrustProxy:                   cfg.Server.ProxyHeader != "",
		TrustProxyConfig:             fiber.TrustProxyConfig{Proxies: cfg.Server.TrustedProxies},
		EnableIPValidation:           true,
	})

	hsts := 0
	if cfg.TLS.CertFile != "" {
		hsts = 365 * 24 * 60 * 60
	}
	panics := recover.Config{EnableStackTrace: true, StackTraceHandler: s.logPanic}
	// The outer recover guards the logger; the inner one turns handler
	// panics into logged 500s.
	s.app.Use(recover.New(panics))
	s.app.Use(s.logRequests)
	s.app.Use(recover.New(panics))
	s.app.Use(helmet.New(helmet.Config{
		XFrameOptions:         "DENY",
		ContentSecurityPolicy: contentSecurityPolicy,
		HSTSMaxAge:            hsts,
		HSTSExcludeSubdomains: true,
	}))
	if cfg.Limiter.MaxFailures > 0 {
		s.limiter = newFailureLimiter(cfg.Limiter.MaxFailures, cfg.Limiter.Window)
	}
	s.app.Use(s.checkOrigin, s.identify, s.requirePasswordChange)
	s.app.Get(loginPath, s.loginPage)
	s.app.Post(loginPath, s.login)
	s.app.Post(logoutPath, s.logout)
	s.app.Get(passwordPath, s.passwordPage)
	s.app.Post(passwordPath, s.changePassword)
	s.app.Get("/*", s.handle)
	s.app.Put("/*", s.put)
	s.app.Post("/*", s.postForm)
	srv := s.app.Server()
	srv.Handler = s.wrapHandler(srv.Handler)
	return s, nil
}

// App exposes the Fiber application, mainly for tests.
func (s *Server) App() *fiber.App { return s.app }

// Listen serves until ctx is cancelled, then waits up to shutdown_timeout
// for in-flight requests before returning.
func (s *Server) Listen(ctx context.Context) error {
	ln, err := s.listen()
	if err != nil {
		return err
	}
	s.log.Info("listening",
		zap.String("addr", ln.Addr().String()),
		zap.String("dir", s.cfg.Dir),
		zap.Bool("tls", s.cfg.TLS.CertFile != ""))

	served := make(chan error, 1)
	go func() {
		served <- s.app.Listener(ln, fiber.ListenConfig{DisableStartupMessage: true})
	}()
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}

	s.log.Info("shutting down", zap.Duration("timeout", s.cfg.Server.ShutdownTimeout))
	err = s.app.ShutdownWithTimeout(s.cfg.Server.ShutdownTimeout)
	// Serve may not have registered the listener yet; closing it here
	// guarantees that it returns.
	_ = ln.Close()
	<-served
	if errors.Is(err, context.DeadlineExceeded) {
		s.log.Warn("shutdown timed out, in-flight requests will be cut off")
		return nil
	}
	return err
}

func (s *Server) listen() (net.Listener, error) {
	ln, err := net.Listen(fiber.NetworkTCP, s.cfg.Addr)
	if err != nil {
		return nil, err
	}
	if s.cfg.TLS.CertFile == "" {
		return ln, nil
	}
	cert, err := tls.LoadX509KeyPair(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
	if err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("load TLS key pair: %w", err)
	}
	return tls.NewListener(ln, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}), nil
}

func (s *Server) Close() error {
	return s.root.Close()
}

// escapeError captures os.Root's unexported "path escapes" error.
func escapeError(root *os.Root) error {
	f, err := root.Open("..")
	if err == nil {
		_ = f.Close()
		return nil
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return nil
}
