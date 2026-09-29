package server

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goftp/internal/config"
)

const uploadKey = "upload-key-0123456789"

func withUploads(c *config.Config) {
	c.Upload = config.UploadConfig{Enabled: true, Key: uploadKey}
}

func upKeyed(p string) string { return p + "?key=" + url.QueryEscape(uploadKey) }

func readFile(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// leftovers lists lock and temp files under dir.
func leftovers(dir string) []string {
	var out []string
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && (strings.HasSuffix(d.Name(), lockSuffix) || strings.HasPrefix(d.Name(), tempPrefix)) {
			out = append(out, p)
		}
		return nil
	})
	return out
}

type formPart struct{ field, filename, content string }

func multipartForm(t *testing.T, parts ...formPart) (io.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, p := range parts {
		var (
			pw  io.Writer
			err error
		)
		if p.filename != "" {
			pw, err = w.CreateFormFile(p.field, p.filename)
		} else {
			pw, err = w.CreateFormField(p.field)
		}
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(pw, p.content)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, w.FormDataContentType()
}

func TestUploadsDisabledByDefault(t *testing.T) {
	f := newFixture(t)
	for _, method := range []string{"PUT", "POST"} {
		resp, _ := f.send(t, method, upKeyed("/a.txt"), strings.NewReader("data"))
		expectStatus(t, resp, 405)
		if got := resp.Header.Get("Allow"); got != "GET, HEAD" {
			t.Errorf("Allow %q", got)
		}
	}
	if _, body := f.do(t, "GET", "/"); strings.Contains(body, "<form") {
		t.Error("upload form shown although uploads are disabled")
	}
	if _, err := os.Stat(filepath.Join(f.dir, "a.txt")); err == nil {
		t.Error("file created although uploads are disabled")
	}
}

func TestPutUpload(t *testing.T) {
	f := newFixture(t, withUploads)
	f.write(t, "sub/keep.txt", "k")

	resp, _ := f.send(t, "PUT", upKeyed("/sub/new.txt"), strings.NewReader("first"))
	expectStatus(t, resp, http.StatusCreated)
	resp, _ = f.send(t, "PUT", "/sub/new.txt", strings.NewReader("second"), "Authorization", "Bearer "+uploadKey)
	expectStatus(t, resp, http.StatusNoContent)
	resp, _ = f.send(t, "PUT", upKeyed("/sub/new.txt"), strings.NewReader("third"), "If-None-Match", "*")
	expectStatus(t, resp, http.StatusPreconditionFailed)
	if got := readFile(t, f.dir, "sub/new.txt"); got != "second" {
		t.Errorf("content %q", got)
	}
	if _, body := f.do(t, "GET", "/sub/"); !strings.Contains(body, `href="/sub/new.txt"`) {
		t.Error("uploaded file not listed")
	}
	if resp, body := f.do(t, "GET", keyed("/sub/new.txt")); resp.StatusCode != 200 || body != "second" {
		t.Errorf("download: %d %q", resp.StatusCode, body)
	}

	tests := map[string]int{
		keyed("/sub/x.txt"):            403, // the download key cannot upload
		"/sub/x.txt":                   403,
		upKeyed("/nope/x.txt"):         409,
		upKeyed("/sub/keep.txt/x"):     409,
		upKeyed("/sub"):                409,
		upKeyed("/sub/"):               400,
		upKeyed("/"):                   400,
		upKeyed("/.env"):               403,
		upKeyed("/sub/.hidden"):        403,
		upKeyed("/sub/..%2f.x"):        403,
		upKeyed("/sub/a%0Ab.txt"):      400,
		upKeyed("/sub/%FF.txt"):        400,
		upKeyed("/sub/%2e%2e%2fx.txt"): 201, // cleans to /x.txt
	}
	for target, want := range tests {
		if resp, _ := f.send(t, "PUT", target, strings.NewReader("x")); resp.StatusCode != want {
			t.Errorf("PUT %s: status %d, want %d", target, resp.StatusCode, want)
		}
	}
	if _, err := os.Stat(filepath.Join(f.dir, "sub", "x.txt")); err == nil {
		t.Error("rejected upload created a file")
	}
	if l := leftovers(f.dir); len(l) > 0 {
		t.Errorf("leftover files: %v", l)
	}

	resp, _ = f.do(t, "DELETE", "/sub/new.txt")
	expectStatus(t, resp, 405)
	if got := resp.Header.Get("Allow"); got != "GET, HEAD, PUT, POST" {
		t.Errorf("Allow %q", got)
	}
}

func TestUploadMaxSize(t *testing.T) {
	f := newFixture(t, withUploads, func(c *config.Config) { c.Upload.MaxSize = 10 })
	resp, _ := f.send(t, "PUT", upKeyed("/big.txt"), strings.NewReader(strings.Repeat("x", 11)))
	expectStatus(t, resp, http.StatusRequestEntityTooLarge)
	if !resp.Close {
		t.Error("connection kept open with an unread body")
	}
	resp, _ = f.send(t, "PUT", upKeyed("/ok.txt"), strings.NewReader(strings.Repeat("x", 10)))
	expectStatus(t, resp, http.StatusCreated)
	if _, err := os.Stat(filepath.Join(f.dir, "big.txt")); err == nil {
		t.Error("oversized upload stored")
	}
}

func TestFormUpload(t *testing.T) {
	f := newFixture(t, withUploads)
	f.write(t, "sub/keep.txt", "k")

	resp, body := f.do(t, "GET", "/sub/")
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.HasSuffix(csp, "form-action 'self'") {
		t.Errorf("CSP %q", csp)
	}
	for _, want := range []string{`<form class="upload" method="post" enctype="multipart/form-data" action="/sub/">`, `name="key"`, `name="replace"`, `name="file"`} {
		if !strings.Contains(body, want) {
			t.Errorf("listing lacks %s", want)
		}
	}

	form, ctype := multipartForm(t,
		formPart{field: "key", content: uploadKey},
		formPart{field: "file", filename: "a.txt", content: "alpha"},
		formPart{field: "file", filename: "../../b.txt", content: "beta"},
	)
	resp, _ = f.send(t, "POST", "/sub", form, "Content-Type", ctype)
	expectStatus(t, resp, http.StatusSeeOther)
	if got := resp.Header.Get("Location"); got != "/sub/" {
		t.Errorf("Location %q", got)
	}
	if readFile(t, f.dir, "sub/a.txt") != "alpha" || readFile(t, f.dir, "sub/b.txt") != "beta" {
		t.Error("uploaded files have the wrong content")
	}

	file := formPart{field: "file", filename: "c.txt", content: "gamma"}
	cases := []struct {
		name   string
		target string
		parts  []formPart
		want   int
	}{
		{"key after file", "/sub/", []formPart{file, {field: "key", content: uploadKey}}, 403},
		{"wrong key", "/sub/", []formPart{{field: "key", content: "wrong"}, file}, 403},
		{"download key", "/sub/", []formPart{{field: "key", content: testKey}, file}, 403},
		{"no files", "/sub/", []formPart{{field: "key", content: uploadKey}}, 400},
		{"hidden name", "/sub/", []formPart{{field: "key", content: uploadKey}, {field: "file", filename: ".c.txt", content: "x"}}, 400},
		{"not a directory", "/sub/keep.txt", []formPart{{field: "key", content: uploadKey}, file}, 404},
	}
	for _, tc := range cases {
		form, ctype := multipartForm(t, tc.parts...)
		if resp, _ := f.send(t, "POST", tc.target, form, "Content-Type", ctype); resp.StatusCode != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, resp.StatusCode, tc.want)
		}
	}
	if _, err := os.Stat(filepath.Join(f.dir, "sub", "c.txt")); err == nil {
		t.Error("rejected form upload stored a file")
	}
	resp, _ = f.send(t, "POST", "/sub/", strings.NewReader("x=1"), "Content-Type", "application/x-www-form-urlencoded")
	expectStatus(t, resp, http.StatusUnsupportedMediaType)

	// Existing files are kept unless replace is checked; the reply names
	// the files stored before the failure.
	form, ctype = multipartForm(t,
		formPart{field: "key", content: uploadKey},
		formPart{field: "file", filename: "d.txt", content: "delta"},
		formPart{field: "file", filename: "a.txt", content: "changed"},
	)
	resp, body = f.send(t, "POST", "/sub/", form, "Content-Type", ctype)
	expectStatus(t, resp, http.StatusConflict)
	if body != "Conflict\nStored before the error: d.txt\n" || readFile(t, f.dir, "sub/a.txt") != "alpha" {
		t.Errorf("no-replace upload: %q, a.txt=%q", body, readFile(t, f.dir, "sub/a.txt"))
	}
	form, ctype = multipartForm(t,
		formPart{field: "key", content: uploadKey},
		formPart{field: "replace", content: "0"},
		formPart{field: "file", filename: "a.txt", content: "changed"},
	)
	resp, _ = f.send(t, "POST", "/sub/", form, "Content-Type", ctype)
	expectStatus(t, resp, http.StatusConflict)
	form, ctype = multipartForm(t,
		formPart{field: "key", content: uploadKey},
		formPart{field: "replace", content: "1"},
		formPart{field: "file", filename: "a.txt", content: "changed"},
	)
	resp, _ = f.send(t, "POST", "/sub/", form, "Content-Type", ctype)
	expectStatus(t, resp, http.StatusSeeOther)
	if readFile(t, f.dir, "sub/a.txt") != "changed" {
		t.Error("replace did not replace")
	}
	if l := leftovers(f.dir); len(l) > 0 {
		t.Errorf("leftover files: %v", l)
	}
}

func TestLockFiles(t *testing.T) {
	f := newFixture(t, withUploads)
	past := time.Now().Add(-2 * time.Hour)
	// Abandoned by a crashed goftp: taken over by the next upload.
	f.write(t, "stale.txt", "old")
	f.write(t, ".stale.txt.lock", lockMagic+".goftp-STALE.part\n")
	f.write(t, ".goftp-STALE.part", "partial")
	for _, name := range []string{".stale.txt.lock", ".goftp-STALE.part"} {
		if err := os.Chtimes(filepath.Join(f.dir, name), past, past); err != nil {
			t.Fatal(err)
		}
	}
	// Still running in another goftp process, e.g. during a restart.
	f.write(t, "live.txt", "old")
	f.write(t, ".live.txt.lock", lockMagic+".goftp-LIVE.part\n")
	f.write(t, ".goftp-LIVE.part", "partial")
	// Written by another tool: hides the file.
	f.write(t, "busy.txt", "partial")
	f.write(t, ".busy.txt.lock", "rsync\n")
	f.write(t, "busydir/x", "x")
	f.write(t, ".busydir.lock", "")
	// A crafted lock must not make goftp delete other files.
	f.write(t, "victim.txt", "keep")
	f.write(t, "evil.txt", "old")
	f.write(t, ".evil.txt.lock", lockMagic+"../victim.txt\n")

	_, body := f.do(t, "GET", "/")
	for _, name := range []string{"stale.txt", "live.txt"} {
		if !strings.Contains(body, `href="/`+name+`"`) {
			t.Errorf("goftp lock hides %s", name)
		}
	}
	for _, name := range []string{"busy.txt", "busydir", "evil.txt"} {
		if strings.Contains(body, name) {
			t.Errorf("locked %s is listed", name)
		}
	}
	for target, want := range map[string]int{keyed("/busy.txt"): 404, "/busydir/": 404, keyed("/live.txt"): 200} {
		if resp, _ := f.do(t, "GET", target); resp.StatusCode != want {
			t.Errorf("GET %s: status %d, want %d", target, resp.StatusCode, want)
		}
	}

	for target, want := range map[string]int{"/busy.txt": 409, "/evil.txt": 409, "/live.txt": 409, "/stale.txt": 204} {
		if resp, _ := f.send(t, "PUT", upKeyed(target), strings.NewReader("new")); resp.StatusCode != want {
			t.Errorf("PUT %s: status %d, want %d", target, resp.StatusCode, want)
		}
	}
	for name, want := range map[string]string{"stale.txt": "new", "live.txt": "old", "victim.txt": "keep", "busy.txt": "partial", ".goftp-LIVE.part": "partial"} {
		if got := readFile(t, f.dir, name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	for _, gone := range []string{".stale.txt.lock", ".goftp-STALE.part"} {
		if exists(filepath.Join(f.dir, gone)) {
			t.Errorf("stale %s not cleaned up", gone)
		}
	}
}

// "Only if absent" must hold even against writers that ignore lock files.
func TestCommitWithoutReplaceIsAtomic(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for name, content := range map[string]string{".goftp-T.part": "new", "f.txt": "written meanwhile"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := commit(root, ".goftp-T.part", "f.txt", false); !errors.Is(err, errExists) {
		t.Fatalf("commit = %v, want errExists", err)
	}
	if got := readFile(t, dir, "f.txt"); got != "written meanwhile" {
		t.Errorf("existing file replaced: %q", got)
	}
	if err := commit(root, ".goftp-T.part", "g.txt", false); err != nil || readFile(t, dir, "g.txt") != "new" {
		t.Errorf("commit to a free name: %v", err)
	}
}

// With uploads on, bodyless requests must keep their connection alive.
func TestKeepAliveWithUploads(t *testing.T) {
	f := newFixture(t, withUploads)
	f.write(t, "a.txt", "a")
	for _, target := range []string{"/", keyed("/a.txt")} {
		for _, method := range []string{"GET", "HEAD"} {
			if resp, _ := f.do(t, method, target); resp.Close {
				t.Errorf("%s %s closes the connection", method, target)
			}
		}
	}
	if resp, _ := f.send(t, "PUT", upKeyed("/b.txt"), strings.NewReader("b")); resp.StatusCode != 201 || resp.Close {
		t.Errorf("completed upload: status %d, close %v", resp.StatusCode, resp.Close)
	}
}

func TestUploadKeyLimiter(t *testing.T) {
	f := newFixture(t, withUploads, func(c *config.Config) {
		c.Limiter = config.LimiterConfig{MaxFailures: 2, Window: time.Minute}
	})
	for i := 0; i < 2; i++ {
		resp, _ := f.send(t, "PUT", "/a.txt?key=guess", strings.NewReader("x"))
		expectStatus(t, resp, 403)
	}
	resp, _ := f.send(t, "PUT", upKeyed("/a.txt"), strings.NewReader("x"))
	expectStatus(t, resp, http.StatusTooManyRequests)
}
