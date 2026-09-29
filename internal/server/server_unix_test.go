//go:build unix

package server

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSymlinks(t *testing.T) {
	f := newFixture(t)
	f.write(t, "real/file.txt", "inside")
	f.write(t, ".git/config", "secret")
	f.write(t, ".env", "secret")
	f.write(t, "real/.hidden/x", "secret")
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		"to-real":     "real",
		"to-file.txt": "real/file.txt",
		"to-outside":  outside,
		"to-secret":   filepath.Join(outside, "secret.txt"),
		"to-parent":   "..",
		"abs-inside":  filepath.Join(f.dir, "real"),
		"dangling":    "missing",
		"pub":         ".git",
		"env":         ".env",
		"deep":        "real/.hidden",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(f.dir, name)); err != nil {
			t.Fatal(err)
		}
	}

	tests := map[string]int{
		"/to-real/file.txt":       200,
		"/to-file.txt":            200,
		"/to-outside/secret.txt":  404,
		"/to-secret":              404,
		"/to-parent/":             404,
		"/abs-inside/file.txt":    404, // os.Root rejects absolute link targets
		"/dangling":               404,
		"/to-real/../to-file.txt": 200,
		"/pub/config":             404, // links into hidden paths count as hidden
		"/pub/":                   404,
		"/env":                    404,
		"/deep/x":                 404,
	}
	for p, want := range tests {
		resp, body := f.do(t, "GET", keyed(p))
		if resp.StatusCode != want || strings.Contains(body, "secret") {
			t.Errorf("%s: status %d, want %d (body %q)", p, resp.StatusCode, want, body)
		}
	}

	_, body := f.do(t, "GET", "/")
	for _, want := range []string{`href="/to-real/"`, `href="/to-file.txt"`} {
		if !strings.Contains(body, want) {
			t.Errorf("listing lacks %s", want)
		}
	}
	for _, hidden := range []string{"to-outside", "to-secret", "to-parent", "abs-inside", "dangling", "pub", "env", "deep"} {
		if strings.Contains(body, hidden) {
			t.Errorf("listing shows unusable link %s", hidden)
		}
	}
}

func TestSpecialFilesDoNotBlock(t *testing.T) {
	f := newFixture(t)
	if err := syscall.Mkfifo(filepath.Join(f.dir, "fifo"), 0o644); err != nil {
		t.Skip("mkfifo:", err)
	}
	start := time.Now()
	resp, _ := f.do(t, "GET", keyed("/fifo"))
	expectStatus(t, resp, 404)
	if time.Since(start) > 2*time.Second {
		t.Error("FIFO request blocked")
	}
	if _, body := f.do(t, "GET", "/"); strings.Contains(body, "fifo") {
		t.Error("listing shows FIFO")
	}
}

func TestNoFileDescriptorLeaks(t *testing.T) {
	if _, err := os.Stat("/proc/self/fd"); err != nil {
		t.Skip("needs /proc")
	}
	f := newFixture(t)
	f.write(t, "f.txt", "0123456789")
	f.write(t, "d/x", "x")
	resp, _ := f.do(t, "GET", keyed("/f.txt"))
	etag := resp.Header.Get("ETag")

	countFDs := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	before := countFDs()
	for i := 0; i < 20; i++ {
		f.do(t, "GET", keyed("/f.txt"))
		f.do(t, "HEAD", keyed("/f.txt"))
		f.do(t, "GET", "/f.txt")
		f.do(t, "GET", keyed("/f.txt"), "If-None-Match", etag)
		f.do(t, "GET", keyed("/f.txt"), "Range", "bytes=99-")
		f.do(t, "GET", keyed("/f.txt"), "Range", "bytes=0-1,3-4")
		f.do(t, "GET", "/d/")
		f.do(t, "GET", "/d")
	}
	deadline := time.Now().Add(2 * time.Second)
	for countFDs() > before && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if after := countFDs(); after > before {
		t.Errorf("file descriptors leaked: %d before, %d after", before, after)
	}
}

func TestUploadIntoHiddenDirViaSymlink(t *testing.T) {
	f := newFixture(t, withUploads)
	f.write(t, ".git/config", "secret")
	if err := os.Symlink(".git", filepath.Join(f.dir, "pub")); err != nil {
		t.Fatal(err)
	}
	if resp, _ := f.send(t, "PUT", upKeyed("/pub/x.txt"), strings.NewReader("x")); resp.StatusCode != 409 {
		t.Errorf("PUT through link: %d", resp.StatusCode)
	}
	form, ctype := multipartForm(t, formPart{field: "key", content: uploadKey}, formPart{field: "file", filename: "y.txt", content: "y"})
	if resp, _ := f.send(t, "POST", "/pub/", form, "Content-Type", ctype); resp.StatusCode != 404 {
		t.Errorf("form upload through link: %d", resp.StatusCode)
	}
	entries, _ := os.ReadDir(filepath.Join(f.dir, ".git"))
	if len(entries) != 1 {
		t.Errorf("files written into .git: %v", entries)
	}
}
