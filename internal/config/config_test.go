package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
)

const validKey = "0123456789abcdef"

// clearEnv isolates a test from GOFTP_* and SECURE_KEY in the environment.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "GOFTP_") || name == "SECURE_KEY" {
			t.Setenv(name, "")
			_ = os.Unsetenv(name)
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	clearEnv(t)
	t.Setenv("SECURE_KEY", validKey)

	cfg, err := Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(cfg.Dir) {
		t.Errorf("dir %q is not absolute", cfg.Dir)
	}
	if cfg.Addr != ":8080" || cfg.Query != "key" || cfg.SecureKey != validKey {
		t.Errorf("unexpected basics: %+v", cfg)
	}
	if cfg.Log.Level != "info" || cfg.Log.Format != "json" {
		t.Errorf("unexpected log config: %+v", cfg.Log)
	}
	want := ServerConfig{ReadTimeout: 10 * time.Second, WriteTimeout: time.Minute, IdleTimeout: 2 * time.Minute, ShutdownTimeout: 10 * time.Second}
	if cfg.Server.ReadTimeout != want.ReadTimeout || cfg.Server.WriteTimeout != want.WriteTimeout ||
		cfg.Server.IdleTimeout != want.IdleTimeout || cfg.Server.ShutdownTimeout != want.ShutdownTimeout {
		t.Errorf("unexpected server config: %+v", cfg.Server)
	}
	if cfg.Limiter.MaxFailures != 20 || cfg.Limiter.Window != time.Minute {
		t.Errorf("unexpected limiter config: %+v", cfg.Limiter)
	}
}

func TestLoadPrecedence(t *testing.T) {
	clearEnv(t)
	t.Setenv("SECURE_KEY", "legacy-key-0123456789")
	t.Setenv("GOFTP_SECURE_KEY", "prefixed-key-0123456789")
	t.Setenv("GOFTP_ADDR", ":9000")
	t.Setenv("GOFTP_QUERY", "token")
	t.Setenv("GOFTP_LOG_LEVEL", "debug")
	t.Setenv("GOFTP_SERVER_WRITE_TIMEOUT", "5s")
	t.Setenv("GOFTP_LIMITER_MAX_FAILURES", "7")
	t.Setenv("GOFTP_SERVER_PROXY_HEADER", "X-Real-IP")
	t.Setenv("GOFTP_SERVER_TRUSTED_PROXIES", "10.0.0.1, 10.1.0.0/16")

	cfg, err := Load([]string{"--addr", ":7000"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SecureKey != "prefixed-key-0123456789" {
		t.Errorf("GOFTP_SECURE_KEY should win over SECURE_KEY, got %q", cfg.SecureKey)
	}
	if cfg.Addr != ":7000" {
		t.Errorf("flag should win over env, got %q", cfg.Addr)
	}
	if cfg.Query != "token" || cfg.Log.Level != "debug" || cfg.Server.WriteTimeout != 5*time.Second || cfg.Limiter.MaxFailures != 7 {
		t.Errorf("env overrides not applied: %+v", cfg)
	}
	if got := strings.Join(cfg.Server.TrustedProxies, "|"); got != "10.0.0.1|10.1.0.0/16" {
		t.Errorf("trusted proxies = %q", got)
	}
}

func TestLoadConfigFile(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "goftp.yaml")
	content := "dir: " + dir + "\nsecure_key: " + validKey + "\nlog:\n  format: console\nserver:\n  idle_timeout: 30s\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOFTP_LOG_FORMAT", "json")

	cfg, err := Load([]string{"--config", file})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Dir != dir || cfg.SecureKey != validKey || cfg.Server.IdleTimeout != 30*time.Second {
		t.Errorf("config file not applied: %+v", cfg)
	}
	if cfg.Log.Format != "json" {
		t.Errorf("env should win over config file, got %q", cfg.Log.Format)
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	typo := filepath.Join(dir, "typo.yaml")
	if err := os.WriteFile(typo, []byte("limitter:\n  max_failures: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		env  map[string]string
		args []string
		want string
	}{
		{"missing key", nil, nil, "secure key is required"},
		{"short key", map[string]string{"SECURE_KEY": "short"}, nil, "at least 16"},
		{"bad query", map[string]string{"SECURE_KEY": validKey}, []string{"--query", "a&b"}, "query"},
		{"empty dir", map[string]string{"SECURE_KEY": validKey}, []string{"--dir", ""}, "dir must not be empty"},
		{"proxy without trust", map[string]string{"SECURE_KEY": validKey, "GOFTP_SERVER_PROXY_HEADER": "X-Real-IP"}, nil, "requires server.trusted_proxies"},
		{"bad proxy", map[string]string{"SECURE_KEY": validKey, "GOFTP_SERVER_TRUSTED_PROXIES": "nope"}, nil, "invalid IP or CIDR"},
		{"half tls", map[string]string{"SECURE_KEY": validKey, "GOFTP_TLS_CERT_FILE": "cert.pem"}, nil, "must be set together"},
		{"zero timeout", map[string]string{"SECURE_KEY": validKey, "GOFTP_SERVER_READ_TIMEOUT": "0s"}, nil, "timeouts must be positive"},
		{"negative limiter", map[string]string{"SECURE_KEY": validKey, "GOFTP_LIMITER_MAX_FAILURES": "-1"}, nil, "must not be negative"},
		{"short window", map[string]string{"SECURE_KEY": validKey, "GOFTP_LIMITER_WINDOW": "500ms"}, nil, "at least 1s"},
		{"positional arg", map[string]string{"SECURE_KEY": validKey}, []string{"extra"}, "unexpected arguments"},
		{"unknown key", map[string]string{"SECURE_KEY": validKey}, []string{"--config", typo}, "limitter"},
		{"missing file", map[string]string{"SECURE_KEY": validKey}, []string{"--config", filepath.Join(dir, "nope.yaml")}, "read config"},
		{"legacy flag", map[string]string{"SECURE_KEY": validKey}, []string{"-dir", "."}, "unknown shorthand"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			_, err := Load(tt.args)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got error %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestLoadHelp(t *testing.T) {
	clearEnv(t)
	if _, err := Load([]string{"--help"}); !errors.Is(err, pflag.ErrHelp) {
		t.Fatalf("got %v, want pflag.ErrHelp", err)
	}
}
