package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
)

const dbURL = "postgres://goftp@localhost/goftp"

// clearEnv isolates a test from GOFTP_* in the environment and sets the
// required database URL.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "GOFTP_") {
			t.Setenv(name, "")
			_ = os.Unsetenv(name)
		}
	}
	t.Setenv("GOFTP_DATABASE_URL", dbURL)
}

// load parses args with flags like the serve command's.
func load(args ...string) (*Config, error) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.String("config", "", "")
	fs.String("dir", ".", "")
	fs.String("addr", ":8080", "")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return Load(fs)
}

func TestLoadDefaults(t *testing.T) {
	clearEnv(t)

	cfg, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(cfg.Dir) {
		t.Errorf("dir %q is not absolute", cfg.Dir)
	}
	if cfg.Addr != ":8080" || cfg.Database.URL != dbURL || cfg.Auth.SessionTTL != 12*time.Hour || cfg.Upload.MaxSize != 0 {
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
	t.Setenv("GOFTP_ADDR", ":9000")
	t.Setenv("GOFTP_AUTH_SESSION_TTL", "30m")
	t.Setenv("GOFTP_LOG_LEVEL", "debug")
	t.Setenv("GOFTP_SERVER_WRITE_TIMEOUT", "5s")
	t.Setenv("GOFTP_LIMITER_MAX_FAILURES", "7")
	t.Setenv("GOFTP_SERVER_PROXY_HEADER", "X-Real-IP")
	t.Setenv("GOFTP_SERVER_TRUSTED_PROXIES", "10.0.0.1, 10.1.0.0/16")

	cfg, err := load("--addr", ":7000")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != ":7000" {
		t.Errorf("flag should win over env, got %q", cfg.Addr)
	}
	if cfg.Auth.SessionTTL != 30*time.Minute || cfg.Log.Level != "debug" || cfg.Server.WriteTimeout != 5*time.Second || cfg.Limiter.MaxFailures != 7 {
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
	content := "dir: " + dir + "\ndatabase:\n  url: postgres://file/db\nlog:\n  format: console\nserver:\n  idle_timeout: 30s\n  read_timeout: 500ms\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOFTP_LOG_FORMAT", "json")
	_ = os.Unsetenv("GOFTP_DATABASE_URL")

	cfg, err := load("--config", file)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Dir != dir || cfg.Database.URL != "postgres://file/db" || cfg.Server.IdleTimeout != 30*time.Second || cfg.Server.ReadTimeout != 500*time.Millisecond {
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
	legacy := filepath.Join(dir, "legacy.yaml")
	if err := os.WriteFile(legacy, []byte("secure_key: 0123456789abcdef\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unitless := filepath.Join(dir, "unitless.yaml")
	if err := os.WriteFile(unitless, []byte("server:\n  write_timeout: 60\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		env  map[string]string
		args []string
		want string
	}{
		{"missing database", map[string]string{"GOFTP_DATABASE_URL": ""}, nil, "database.url is required"},
		{"short session", map[string]string{"GOFTP_AUTH_SESSION_TTL": "30s"}, nil, "at least 1m"},
		{"empty dir", nil, []string{"--dir", ""}, "dir must not be empty"},
		{"proxy without trust", map[string]string{"GOFTP_SERVER_PROXY_HEADER": "X-Real-IP"}, nil, "requires server.trusted_proxies"},
		{"bad proxy", map[string]string{"GOFTP_SERVER_TRUSTED_PROXIES": "nope"}, nil, "invalid IP or CIDR"},
		{"half tls", map[string]string{"GOFTP_TLS_CERT_FILE": "cert.pem"}, nil, "must be set together"},
		{"zero timeout", map[string]string{"GOFTP_SERVER_READ_TIMEOUT": "0s"}, nil, "must be positive"},
		{"unitless timeout", nil, []string{"--config", unitless}, "needs a unit"},
		{"unitless env timeout", map[string]string{"GOFTP_SERVER_IDLE_TIMEOUT": "30"}, nil, "missing unit"},
		{"negative limiter", map[string]string{"GOFTP_LIMITER_MAX_FAILURES": "-1"}, nil, "must not be negative"},
		{"short window", map[string]string{"GOFTP_LIMITER_WINDOW": "500ms"}, nil, "at least 1s"},
		{"unknown key", nil, []string{"--config", typo}, "limitter"},
		{"removed key", nil, []string{"--config", legacy}, "secure_key"},
		{"missing file", nil, []string{"--config", filepath.Join(dir, "nope.yaml")}, "read config"},
		{"bad max size", map[string]string{"GOFTP_UPLOAD_MAX_SIZE": "10XB"}, nil, "invalid size"},
		{"negative max size", map[string]string{"GOFTP_UPLOAD_MAX_SIZE": "-1"}, nil, "invalid size"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			_, err := load(tt.args...)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got error %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

// Commands without --dir and --addr flags still load.
func TestLoadWithoutServeFlags(t *testing.T) {
	clearEnv(t)
	t.Setenv("GOFTP_UPLOAD_MAX_SIZE", "1.5GiB")
	fs := pflag.NewFlagSet("user", pflag.ContinueOnError)
	fs.String("config", "", "")
	cfg, err := Load(fs)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != ":8080" || !filepath.IsAbs(cfg.Dir) || cfg.Upload.MaxSize != 3<<29 {
		t.Errorf("config %+v", cfg)
	}
}

func TestParseByteSize(t *testing.T) {
	tests := map[string]ByteSize{
		"0": 0, "1024": 1024, "10B": 10, "1kb": 1000, "2 MiB": 2 << 20,
		"10GB": 10e9, "1.5GiB": 3 << 29, "1TiB": 1 << 40,
	}
	for in, want := range tests {
		if got, err := parseByteSize(in); err != nil || got != want {
			t.Errorf("parseByteSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "GB", "1.2.3MB", "-5", "5PB", "1e3", "9999999999TiB", "NaN"} {
		if _, err := parseByteSize(in); err == nil {
			t.Errorf("parseByteSize(%q) should fail", in)
		}
	}
}
