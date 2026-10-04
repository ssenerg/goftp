package server

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"goftp/internal/auth"
)

// zipEntries returns the names in a zip archive and the contents of its
// files.
func zipEntries(t *testing.T, body string) ([]string, map[string]string) {
	t.Helper()
	zr, err := zip.NewReader(strings.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("not a zip archive: %v", err)
	}
	var names []string
	contents := make(map[string]string)
	for _, f := range zr.File {
		names = append(names, f.Name)
		if f.FileInfo().IsDir() {
			continue
		}
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		contents[f.Name] = string(b)
	}
	return names, contents
}

func TestZip(t *testing.T) {
	ta := newTestAuth(t)
	f := newFixtureWith(t, ta)
	f.write(t, "a.txt", "alpha")
	f.write(t, "sub/b.txt", "beta")
	f.write(t, "sub/.hidden", "secret")
	f.write(t, "sub/deep/c.txt", "gamma")
	f.write(t, "busy.txt", "half written")
	f.write(t, lockName("busy.txt"), "another tool's lock")
	if err := os.Mkdir(filepath.Join(f.dir, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}

	resp, body := f.as("user").do(t, "GET", "/?zip")
	expectStatus(t, resp, http.StatusOK)
	for k, v := range map[string]string{
		"Content-Type":        "application/zip",
		"Content-Disposition": "attachment; filename=files.zip",
		"Cache-Control":       "no-store",
	} {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	names, contents := zipEntries(t, body)
	if want := []string{"a.txt", "empty/", "sub/", "sub/b.txt", "sub/deep/", "sub/deep/c.txt"}; !slices.Equal(names, want) {
		t.Errorf("zip holds %q, want %q", names, want)
	}
	if contents["a.txt"] != "alpha" || contents["sub/deep/c.txt"] != "gamma" {
		t.Errorf("contents %q", contents)
	}
	if e := f.logs.entries("request"); e[len(e)-1]["bytes"] != float64(len(body)) {
		t.Errorf("logged %v bytes of %d", e[len(e)-1]["bytes"], len(body))
	}

	_, body = f.as("user").do(t, "GET", "/sub/?zip")
	if names, _ := zipEntries(t, body); !slices.Equal(names, []string{"b.txt", "deep/", "deep/c.txt"}) {
		t.Errorf("sub.zip holds %q", names)
	}
	resp, body = f.as("user").do(t, "HEAD", "/sub/?zip")
	expectStatus(t, resp, http.StatusOK)
	if body != "" || resp.Header.Get("Content-Disposition") != "attachment; filename=sub.zip" {
		t.Errorf("HEAD: %q %v", body, resp.Header)
	}

	// Only what the visitor may read.
	erin := ta.addUser(t, "erin", "user")
	if _, err := ta.svc.Enforcer().DeleteRolesForUser(auth.Subject("erin")); err != nil {
		t.Fatal(err)
	}
	for _, obj := range []string{"/", "/sub/*"} {
		if _, err := ta.svc.AddPolicy(auth.Subject("erin"), obj, auth.ActRead); err != nil {
			t.Fatal(err)
		}
	}
	e := &fixture{srv: f.srv, dir: f.dir, logs: f.logs, auth: ta, token: erin}
	_, body = e.do(t, "GET", "/?zip")
	if names, _ := zipEntries(t, body); !slices.Equal(names, []string{"sub/", "sub/b.txt", "sub/deep/", "sub/deep/c.txt"}) {
		t.Errorf("erin's zip holds %q", names)
	}
	if resp, _ := f.as("").do(t, "GET", "/?zip"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous zip: %d", resp.StatusCode)
	}
}

// Large files are streamed, not held in memory.
func TestZipLargeFile(t *testing.T) {
	f := newFixture(t)
	big := bytes.Repeat([]byte("0123456789abcdef"), 1<<16)
	if err := os.WriteFile(filepath.Join(f.dir, "big.bin"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	_, body := f.do(t, "GET", "/?zip")
	if _, contents := zipEntries(t, body); contents["big.bin"] != string(big) {
		t.Error("big.bin damaged")
	}
}

// A client that goes away stops the zip: nothing stays open.
func TestZipClientGone(t *testing.T) {
	if _, err := os.Stat("/proc/self/fd"); err != nil {
		t.Skip("needs /proc")
	}
	f := newFixture(t)
	big := bytes.Repeat([]byte("x"), 32<<20)
	if err := os.WriteFile(filepath.Join(f.dir, "big.bin"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	addr, _ := startServer(t, f)
	fds := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	before := fds()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "GET /?zip HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer %s\r\n\r\n", f.token)
	if _, err := io.ReadFull(conn, make([]byte, 64<<10)); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	waitFor(t, "the zip to stop", func() bool { return fds() <= before })
}
