package cli

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"

	"goftp/internal/db/dbtest"
)

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := Execute(context.Background(), args, &out, &out)
	return out.String(), err
}

func mustRun(t *testing.T, args ...string) string {
	t.Helper()
	out, err := run(t, args...)
	if err != nil {
		t.Fatalf("goftp %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

var tempPassword = regexp.MustCompile(`(?m)^temporary password: (\S{26})$`)

func TestUserCommands(t *testing.T) {
	_, url := dbtest.Open(t)
	t.Setenv("GOFTP_DATABASE_URL", url)

	out := mustRun(t, "user", "add", "Alice", "--role", "operator")
	if !strings.Contains(out, "created user alice with role operator") || !tempPassword.MatchString(out) {
		t.Errorf("user add: %q", out)
	}
	mustRun(t, "user", "add", "bob")
	for _, args := range [][]string{
		{"user", "add", "alice"},
		{"user", "add", "carol", "--role", "king"},
		{"user", "add", "X Y"},
		{"user", "role", "nobody", "admin"},
		{"user", "passwd", "nobody"},
		{"user", "delete", "nobody"},
		{"user", "add"},
	} {
		if out, err := run(t, args...); err == nil {
			t.Errorf("goftp %s succeeded: %q", strings.Join(args, " "), out)
		}
	}

	mustRun(t, "user", "role", "bob", "admin")
	out = mustRun(t, "user", "passwd", "bob")
	if !tempPassword.MatchString(out) {
		t.Errorf("user passwd: %q", out)
	}
	out = mustRun(t, "user", "list")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !regexp.MustCompile(`^alice\s+operator\s+temporary\s`).MatchString(lines[1]) ||
		!regexp.MustCompile(`^bob\s+admin\s+temporary\s`).MatchString(lines[2]) {
		t.Errorf("user list:\n%s", out)
	}
	mustRun(t, "user", "delete", "bob")
	if out := mustRun(t, "user", "list"); strings.Contains(out, "bob") {
		t.Errorf("deleted user listed:\n%s", out)
	}
}

func TestPolicyCommands(t *testing.T) {
	_, url := dbtest.Open(t)
	t.Setenv("GOFTP_DATABASE_URL", url)

	mustRun(t, "policy", "add", "anonymous", "/public/*", "read")
	if _, err := run(t, "policy", "add", "anonymous", "/public/*", "read"); err == nil {
		t.Error("duplicate rule added")
	}
	if _, err := run(t, "policy", "add", "anonymous", "public", "read"); err == nil {
		t.Error("invalid rule added")
	}
	out := mustRun(t, "policy", "list")
	for _, want := range []string{`anonymous\s+/public/\*\s+read`, `superadmin\s+/\*\s+\*`, `operator\s+user`} {
		if !regexp.MustCompile(want).MatchString(out) {
			t.Errorf("policy list lacks %s:\n%s", want, out)
		}
	}
	mustRun(t, "policy", "remove", "anonymous", "/public/*", "read")
	if _, err := run(t, "policy", "remove", "anonymous", "/public/*", "read"); err == nil {
		t.Error("removed a missing rule")
	}
	if out := mustRun(t, "migrate"); !strings.Contains(out, "up to date") {
		t.Errorf("migrate: %q", out)
	}
}

func TestUsageErrors(t *testing.T) {
	t.Setenv("GOFTP_DATABASE_URL", "")
	for _, args := range [][]string{{"usr"}, {"serve", "extra"}, {"--nope"}} {
		if _, err := run(t, args...); err == nil {
			t.Errorf("goftp %s succeeded", strings.Join(args, " "))
		}
	}
	if _, err := run(t, "user", "list"); err == nil || !strings.Contains(err.Error(), "database.url is required") {
		t.Errorf("missing database URL: %v", err)
	}
	if out := mustRun(t, "--help"); !strings.Contains(out, "user") || !strings.Contains(out, "policy") {
		t.Errorf("help: %q", out)
	}
}
