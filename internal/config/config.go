package config

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// MinKeyLength is the shortest accepted access key.
const MinKeyLength = 16

var queryNameRe = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)

type Config struct {
	Dir       string        `mapstructure:"dir"`
	Addr      string        `mapstructure:"addr"`
	Query     string        `mapstructure:"query"`
	SecureKey string        `mapstructure:"secure_key"`
	Log       LogConfig     `mapstructure:"log"`
	Server    ServerConfig  `mapstructure:"server"`
	TLS       TLSConfig     `mapstructure:"tls"`
	Limiter   LimiterConfig `mapstructure:"limiter"`
}

type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

type ServerConfig struct {
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	IdleTimeout     time.Duration `mapstructure:"idle_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	ProxyHeader     string        `mapstructure:"proxy_header"`
	TrustedProxies  []string      `mapstructure:"trusted_proxies"`
}

type TLSConfig struct {
	CertFile string `mapstructure:"cert_file"`
	KeyFile  string `mapstructure:"key_file"`
}

type LimiterConfig struct {
	MaxFailures int           `mapstructure:"max_failures"`
	Window      time.Duration `mapstructure:"window"`
}

// Load builds the configuration from defaults, an optional config file,
// GOFTP_* environment variables and command-line flags (in rising priority).
func Load(args []string) (*Config, error) {
	fs := pflag.NewFlagSet("goftp", pflag.ContinueOnError)
	configFile := fs.String("config", "", "path to a config file (yaml, json or toml)")
	fs.String("dir", ".", "directory to serve")
	fs.String("addr", ":8080", "listen address")
	fs.String("query", "key", "query parameter that carries the access key")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}

	v := viper.New()
	setDefaults(v)
	for _, name := range []string{"dir", "addr", "query"} {
		if err := v.BindPFlag(name, fs.Lookup(name)); err != nil {
			return nil, err
		}
	}

	v.SetEnvPrefix("GOFTP")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	// SECURE_KEY is kept for compatibility with older deployments.
	if err := v.BindEnv("secure_key", "GOFTP_SECURE_KEY", "SECURE_KEY"); err != nil {
		return nil, err
	}

	if *configFile != "" {
		v.SetConfigFile(*configFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}

	var cfg Config
	if err := v.UnmarshalExact(&cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("secure_key", "")
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("server.read_timeout", 10*time.Second)
	v.SetDefault("server.write_timeout", time.Minute)
	v.SetDefault("server.idle_timeout", 2*time.Minute)
	v.SetDefault("server.shutdown_timeout", 10*time.Second)
	v.SetDefault("server.proxy_header", "")
	v.SetDefault("server.trusted_proxies", []string{})
	v.SetDefault("tls.cert_file", "")
	v.SetDefault("tls.key_file", "")
	v.SetDefault("limiter.max_failures", 20)
	v.SetDefault("limiter.window", time.Minute)
}

func (c *Config) normalize() error {
	var errs []error

	if c.Dir == "" {
		errs = append(errs, errors.New("dir must not be empty"))
	} else if abs, err := filepath.Abs(c.Dir); err != nil {
		errs = append(errs, fmt.Errorf("dir: %w", err))
	} else {
		c.Dir = abs
	}
	if c.Addr == "" {
		errs = append(errs, errors.New("addr must not be empty"))
	}
	if !queryNameRe.MatchString(c.Query) {
		errs = append(errs, fmt.Errorf("query %q must only contain letters, digits, '.', '_', '~' or '-'", c.Query))
	}
	switch {
	case c.SecureKey == "":
		errs = append(errs, errors.New("secure key is required (set SECURE_KEY or GOFTP_SECURE_KEY)"))
	case len(c.SecureKey) < MinKeyLength:
		errs = append(errs, fmt.Errorf("secure key must be at least %d characters", MinKeyLength))
	}

	s := &c.Server
	if s.ReadTimeout <= 0 || s.WriteTimeout <= 0 || s.IdleTimeout <= 0 || s.ShutdownTimeout <= 0 {
		errs = append(errs, errors.New("server timeouts must be positive"))
	}
	s.ProxyHeader = strings.TrimSpace(s.ProxyHeader)
	proxies := s.TrustedProxies[:0]
	for _, p := range s.TrustedProxies {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if net.ParseIP(p) == nil {
			if _, _, err := net.ParseCIDR(p); err != nil {
				errs = append(errs, fmt.Errorf("server.trusted_proxies: invalid IP or CIDR %q", p))
			}
		}
		proxies = append(proxies, p)
	}
	s.TrustedProxies = proxies
	if s.ProxyHeader != "" && len(s.TrustedProxies) == 0 {
		errs = append(errs, errors.New("server.proxy_header requires server.trusted_proxies"))
	}

	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		errs = append(errs, errors.New("tls.cert_file and tls.key_file must be set together"))
	}
	if c.Limiter.MaxFailures < 0 {
		errs = append(errs, errors.New("limiter.max_failures must not be negative"))
	}
	if c.Limiter.MaxFailures > 0 && c.Limiter.Window < time.Second {
		errs = append(errs, errors.New("limiter.window must be at least 1s"))
	}
	return errors.Join(errs...)
}
