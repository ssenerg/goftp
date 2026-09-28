package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"io/fs"
	"net"
	"os"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/helmet"
	"github.com/gofiber/fiber/v3/middleware/limiter"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"go.uber.org/zap"

	"goftp/internal/config"
)

const contentSecurityPolicy = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; " +
	"base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

type Server struct {
	cfg       *config.Config
	log       *zap.Logger
	app       *fiber.App
	root      *os.Root
	keyHash   [sha256.Size]byte
	errEscape error
}

func New(cfg *config.Config, log *zap.Logger) (*Server, error) {
	root, err := os.OpenRoot(cfg.Dir)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:       cfg,
		log:       log,
		root:      root,
		keyHash:   sha256.Sum256([]byte(cfg.SecureKey)),
		errEscape: escapeError(root),
	}

	s.app = fiber.New(fiber.Config{
		ErrorHandler:       s.handleError,
		ReadTimeout:        cfg.Server.ReadTimeout,
		WriteTimeout:       cfg.Server.WriteTimeout,
		IdleTimeout:        cfg.Server.IdleTimeout,
		GETOnly:            true,
		CaseSensitive:      true,
		StrictRouting:      true,
		ProxyHeader:        cfg.Server.ProxyHeader,
		TrustProxy:         cfg.Server.ProxyHeader != "",
		TrustProxyConfig:   fiber.TrustProxyConfig{Proxies: cfg.Server.TrustedProxies},
		EnableIPValidation: true,
	})

	hsts := 0
	if cfg.TLS.CertFile != "" {
		hsts = 365 * 24 * 60 * 60
	}
	s.app.Use(recover.New(recover.Config{EnableStackTrace: true, StackTraceHandler: s.logPanic}))
	s.app.Use(s.logRequests)
	s.app.Use(helmet.New(helmet.Config{
		XFrameOptions:         "DENY",
		ContentSecurityPolicy: contentSecurityPolicy,
		HSTSMaxAge:            hsts,
		HSTSExcludeSubdomains: true,
	}))
	if cfg.Limiter.MaxFailures > 0 {
		s.app.Use(limiter.New(limiter.Config{
			Max:                    cfg.Limiter.MaxFailures,
			Expiration:             cfg.Limiter.Window,
			SkipSuccessfulRequests: true,
			DisableHeaders:         true,
			KeyGenerator:           func(c fiber.Ctx) string { return clientKey(c.IP()) },
			LimitReached:           s.limitReached,
		}))
	}
	s.app.Get("/*", s.handle)
	return s, nil
}

// App exposes the Fiber application, mainly for tests.
func (s *Server) App() *fiber.App { return s.app }

// Listen serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Listen(ctx context.Context) error {
	return s.app.Listen(s.cfg.Addr, fiber.ListenConfig{
		ListenerNetwork:       fiber.NetworkTCP,
		DisableStartupMessage: true,
		GracefulContext:       ctx,
		ShutdownTimeout:       s.cfg.Server.ShutdownTimeout,
		CertFile:              s.cfg.TLS.CertFile,
		CertKeyFile:           s.cfg.TLS.KeyFile,
		ListenerAddrFunc: func(addr net.Addr) {
			s.log.Info("listening",
				zap.String("addr", addr.String()),
				zap.String("dir", s.cfg.Dir),
				zap.Bool("tls", s.cfg.TLS.CertFile != ""))
		},
	})
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
