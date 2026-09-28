package logger

import (
	"testing"

	"go.uber.org/zap/zapcore"
)

func TestNew(t *testing.T) {
	for _, format := range []string{"json", "console"} {
		log, err := New("warn", format)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if log.Core().Enabled(zapcore.InfoLevel) || !log.Core().Enabled(zapcore.WarnLevel) {
			t.Errorf("%s: level not applied", format)
		}
	}
	if _, err := New("loud", "json"); err == nil {
		t.Error("expected error for unknown level")
	}
	if _, err := New("info", "xml"); err == nil {
		t.Error("expected error for unknown format")
	}
}
