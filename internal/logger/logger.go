package logger

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// New builds a zap logger writing to stderr in "json" or "console" format.
func New(level, format string) (*zap.Logger, error) {
	lvl, err := zapcore.ParseLevel(level)
	if err != nil {
		return nil, fmt.Errorf("log level: %w", err)
	}

	var cfg zap.Config
	switch format {
	case "json":
		cfg = zap.NewProductionConfig()
	case "console":
		cfg = zap.NewDevelopmentConfig()
		cfg.Development = false
	default:
		return nil, fmt.Errorf("log format %q: want json or console", format)
	}
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	// Access and auth logs must never be dropped.
	cfg.Sampling = nil
	cfg.DisableStacktrace = true
	cfg.EncoderConfig.TimeKey = "ts"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.OutputPaths = []string{"stderr"}
	cfg.ErrorOutputPaths = []string{"stderr"}
	return cfg.Build()
}
