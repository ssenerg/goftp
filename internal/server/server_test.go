package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"goftp/internal/config"
)

const testKey = "test-key-0123456789"

type fixture struct {
	srv  *Server
	dir  string
	logs *logSink
}

// logSink captures JSON log lines exactly as production would encode them.
type logSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logSink) Sync() error { return nil }

// entries returns the decoded log lines with the given message.
func (l *logSink) entries(msg string) []map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []map[string]any
	for _, line := range bytes.Split(l.buf.Bytes(), []byte("\n")) {
		var m map[string]any
		if json.Unmarshal(line, &m) == nil && m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

func (l *logSink) raw() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func newFixture(t *testing.T, mutate ...func(*config.Config)) *fixture {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		Dir:       dir,
		Addr:      "127.0.0.1:0",
		Query:     "key",
		SecureKey: testKey,
		Server: config.ServerConfig{
			ReadTimeout:     5 * time.Second,
			WriteTimeout:    5 * time.Second,
			IdleTimeout:     5 * time.Second,
			ShutdownTimeout: 5 * time.Second,
		},
	}
	for _, m := range mutate {
		m(cfg)
	}
	logs := &logSink{}
	enc := zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig())
	srv, err := New(cfg, zap.New(zapcore.NewCore(enc, logs, zapcore.DebugLevel)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return &fixture{srv: srv, dir: dir, logs: logs}
}

func (f *fixture) write(t *testing.T, name, content string) {
	t.Helper()
	p := filepath.Join(f.dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// do sends rawURI verbatim, so malformed paths reach the server unchanged.
func (f *fixture) do(t *testing.T, method, rawURI string, headers ...string) (*http.Response, string) {
	t.Helper()
	req := httptest.NewRequest(method, "/", nil)
	req.URL = &url.URL{Opaque: rawURI}
	if strings.HasPrefix(rawURI, "//") {
		// Opaque would gain a scheme prefix; use a raw path instead.
		p, q, _ := strings.Cut(rawURI, "?")
		decoded, err := url.PathUnescape(p)
		if err != nil {
			t.Fatal(err)
		}
		req.URL = &url.URL{Path: decoded, RawPath: p, RawQuery: q}
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := f.srv.App().Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("%s %s: %v", method, rawURI, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

func keyed(p string) string { return p + "?key=" + url.QueryEscape(testKey) }

func expectStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("%s: status %d, want %d", resp.Request.URL, resp.StatusCode, want)
	}
}

func TestListing(t *testing.T) {
	f := newFixture(t)
	f.write(t, "a.txt", "hello")
	f.write(t, "B.txt", "x")
	f.write(t, "sub/c.txt", "c")
	f.write(t, ".env", "secret")
	f.write(t, ".git/config", "cfg")
	f.write(t, "weird #?%name.txt", "w")
	f.write(t, "<script>.txt", "x")

	resp, body := f.do(t, "GET", "/")
	expectStatus(t, resp, 200)
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type %q", ct)
	}
	for _, want := range []string{`href="/sub/"`, `href="/a.txt"`, `href="/B.txt"`, `href="/weird%20%23%3F%25name.txt"`, "&lt;script&gt;.txt"} {
		if !strings.Contains(body, want) {
			t.Errorf("listing lacks %s", want)
		}
	}
	for _, hidden := range []string{".env", ".git", "<script>"} {
		if strings.Contains(body, hidden) {
			t.Errorf("listing exposes %q", hidden)
		}
	}
	if strings.Index(body, `href="/sub/"`) > strings.Index(body, `href="/a.txt"`) ||
		strings.Index(body, `href="/a.txt"`) > strings.Index(body, `href="/B.txt"`) {
		t.Error("expected directories first, then case-insensitive name order")
	}
	if strings.Contains(body, "Parent directory") {
		t.Error("root listing should not link to a parent")
	}

	resp, body = f.do(t, "GET", "/sub/")
	expectStatus(t, resp, 200)
	if !strings.Contains(body, `href="/"`) || !strings.Contains(body, `href="/sub/c.txt"`) {
		t.Error("sub listing lacks parent or file link")
	}

	resp, body = f.do(t, "HEAD", "/")
	expectStatus(t, resp, 200)
	if body != "" || resp.ContentLength <= 0 {
		t.Errorf("HEAD listing: body %q, length %d", body, resp.ContentLength)
	}
}

func TestSecurityHeaders(t *testing.T) {
	f := newFixture(t)
	resp, _ := f.do(t, "GET", "/")
	want := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"Content-Security-Policy": contentSecurityPolicy,
	}
	for k, v := range want {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if resp.Header.Get("Server") != "" || resp.Header.Get("Strict-Transport-Security") != "" {
		t.Error("unexpected Server or HSTS header")
	}
}

func TestDirectoryRedirect(t *testing.T) {
	f := newFixture(t)
	f.write(t, "sub dir/x", "x")
	for raw, loc := range map[string]string{
		"/sub%20dir":                "/sub%20dir/",
		"//sub%20dir":               "/sub%20dir/",
		"/sub%20dir/.":              "/sub%20dir/",
		"/sub%20dir/x/..":           "/sub%20dir/",
		keyed("/sub%20dir"):         "/sub%20dir/",
		"/./sub%20dir/../sub%20dir": "/sub%20dir/",
	} {
		resp, _ := f.do(t, "GET", raw)
		expectStatus(t, resp, http.StatusMovedPermanently)
		if got := resp.Header.Get("Location"); got != loc {
			t.Errorf("%s: Location %q, want %q", raw, got, loc)
		}
	}
}

func TestDownloadAuth(t *testing.T) {
	f := newFixture(t)
	f.write(t, "docs/report.txt", "hello world")

	for _, target := range []string{"/docs/report.txt", "/docs/report.txt?key=wrong", "/docs/report.txt?key=", "/docs/report.txt?KEY=" + testKey} {
		resp, body := f.do(t, "GET", target)
		expectStatus(t, resp, 403)
		if body != deniedBody || resp.Header.Get("Content-Disposition") != "" || resp.Header.Get("ETag") != "" {
			t.Errorf("%s: leaked content or metadata: %q %v", target, body, resp.Header)
		}
	}

	resp, body := f.do(t, "GET", keyed("/docs/report.txt"))
	expectStatus(t, resp, 200)
	if body != "hello world" {
		t.Errorf("body %q", body)
	}
	checks := map[string]string{
		"Content-Type":        "text/plain; charset=utf-8",
		"Content-Length":      "11",
		"Content-Disposition": "attachment; filename=report.txt",
		"Accept-Ranges":       "bytes",
		"Cache-Control":       "no-store",
	}
	for k, v := range checks {
		if got := resp.Header.Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if resp.Header.Get("ETag") == "" || resp.Header.Get("Last-Modified") == "" {
		t.Error("missing validators")
	}

	resp, body = f.do(t, "HEAD", keyed("/docs/report.txt"))
	expectStatus(t, resp, 200)
	if body != "" || resp.Header.Get("Content-Length") != "11" {
		t.Errorf("HEAD: body %q, length %q", body, resp.Header.Get("Content-Length"))
	}

	resp, body = f.do(t, "HEAD", "/docs/report.txt")
	expectStatus(t, resp, 403)
	if body != "" {
		t.Errorf("HEAD denied body %q", body)
	}
}

func TestContentDispositionEncoding(t *testing.T) {
	f := newFixture(t)
	f.write(t, "rapport été.txt", "x")
	f.write(t, `q"uote.txt`, "x")
	for name, raw := range map[string]string{"rapport été.txt": "/rapport%20%C3%A9t%C3%A9.txt", `q"uote.txt`: "/q%22uote.txt"} {
		resp, _ := f.do(t, "GET", keyed(raw))
		expectStatus(t, resp, 200)
		_, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition"))
		if err != nil || params["filename"] != name {
			t.Errorf("Content-Disposition %q: %v %v", resp.Header.Get("Content-Disposition"), params, err)
		}
	}
}

func TestPathSafety(t *testing.T) {
	f := newFixture(t)
	f.write(t, "a.txt", "a")
	f.write(t, ".env", "secret")
	f.write(t, ".git/config", "cfg")
	f.write(t, "sub/.hidden", "h")
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("top secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(f.dir, filepath.Join(outside, "secret.txt"))
	if err != nil {
		t.Fatal(err)
	}
	relURL := filepath.ToSlash(rel)

	tests := map[string]int{
		"/.env":                        403,
		"/.git/config":                 403,
		"/%2egit/config":               403,
		"/sub/.hidden":                 403,
		"/sub/..%2f.env":               403,
		"/a.txt/":                      200,
		"/nope.txt":                    404,
		"/a.txt/child":                 404,
		"/" + relURL:                   404,
		"/%2e%2e/%2e%2e/etc/passwd":    404,
		"/../../../../etc/passwd":      404,
		"/..%2f..%2f..%2fetc%2fpasswd": 404,
		"/%00":                         400,
		"/a.txt%00.png":                400,
		"/%zz":                         400,
		"/%2e%2e":                      200,
	}
	for raw, want := range tests {
		target := raw
		if want != 403 && want != 400 {
			target = keyed(raw)
		}
		resp, body := f.do(t, "GET", target)
		if resp.StatusCode != want {
			t.Errorf("%s: status %d, want %d", raw, resp.StatusCode, want)
		}
		if strings.Contains(body, "secret") {
			t.Errorf("%s: leaked secret content", raw)
		}
	}
}

func TestRanges(t *testing.T) {
	f := newFixture(t)
	const content = "0123456789abcdefghij"
	f.write(t, "f.bin", content)
	f.write(t, "empty", "")
	target := keyed("/f.bin")

	tests := []struct {
		rng, body, contentRange string
		status                  int
	}{
		{"bytes=0-4", "01234", "bytes 0-4/20", 206},
		{"bytes=15-", "fghij", "bytes 15-19/20", 206},
		{"bytes=-3", "hij", "bytes 17-19/20", 206},
		{"bytes=18-100", "ij", "bytes 18-19/20", 206},
		{"bytes=20-", "Requested Range Not Satisfiable", "bytes */20", 416},
		{"bytes=9-2", content, "", 200},
		{"lines=1-2", content, "", 200},
		{"bytes=0-,0-", content, "", 200},
	}
	for _, tt := range tests {
		resp, body := f.do(t, "GET", target, "Range", tt.rng)
		if resp.StatusCode != tt.status || body != tt.body || resp.Header.Get("Content-Range") != tt.contentRange {
			t.Errorf("Range %q: %d %q %q", tt.rng, resp.StatusCode, body, resp.Header.Get("Content-Range"))
		}
	}

	resp, body := f.do(t, "GET", keyed("/empty"), "Range", "bytes=0-")
	expectStatus(t, resp, 200)
	if body != "" || resp.Header.Get("Content-Type") != "application/octet-stream" {
		t.Errorf("empty file: %q %q", body, resp.Header.Get("Content-Type"))
	}

	resp, body = f.do(t, "HEAD", target, "Range", "bytes=0-4")
	expectStatus(t, resp, 206)
	if body != "" || resp.Header.Get("Content-Length") != "5" {
		t.Errorf("HEAD range: %q %q", body, resp.Header.Get("Content-Length"))
	}
}

func TestMultipartRanges(t *testing.T) {
	f := newFixture(t)
	f.write(t, "f.bin", "0123456789abcdefghij")

	resp, body := f.do(t, "GET", keyed("/f.bin"), "Range", "bytes=0-1, 5-6, -2")
	expectStatus(t, resp, 206)
	if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(body)) {
		t.Fatalf("Content-Length %s, body %d bytes", got, len(body))
	}
	mediaType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/byteranges" {
		t.Fatalf("content-type %q: %v", resp.Header.Get("Content-Type"), err)
	}
	mr := multipart.NewReader(strings.NewReader(body), params["boundary"])
	want := []struct{ data, rng string }{{"01", "bytes 0-1/20"}, {"56", "bytes 5-6/20"}, {"ij", "bytes 18-19/20"}}
	for i, w := range want {
		part, err := mr.NextPart()
		if err != nil {
			t.Fatalf("part %d: %v", i, err)
		}
		data, _ := io.ReadAll(part)
		if string(data) != w.data || part.Header.Get("Content-Range") != w.rng {
			t.Errorf("part %d: %q %q", i, data, part.Header.Get("Content-Range"))
		}
	}
	if _, err := mr.NextPart(); err != io.EOF {
		t.Errorf("expected end of multipart body, got %v", err)
	}
}

func TestConditionalRequests(t *testing.T) {
	f := newFixture(t)
	f.write(t, "f.txt", "0123456789")
	target := keyed("/f.txt")

	resp, _ := f.do(t, "GET", target)
	etag, lastMod := resp.Header.Get("ETag"), resp.Header.Get("Last-Modified")

	resp, body := f.do(t, "GET", target, "If-None-Match", `"x", W/`+etag)
	expectStatus(t, resp, 304)
	if body != "" || resp.Header.Get("ETag") != etag {
		t.Errorf("304: body %q etag %q", body, resp.Header.Get("ETag"))
	}
	resp, _ = f.do(t, "GET", target, "If-Modified-Since", lastMod)
	expectStatus(t, resp, 304)
	resp, _ = f.do(t, "GET", target, "If-None-Match", `"stale"`, "If-Modified-Since", lastMod)
	expectStatus(t, resp, 200)

	resp, body = f.do(t, "GET", target, "Range", "bytes=0-1", "If-Range", etag)
	if resp.StatusCode != 206 || body != "01" {
		t.Errorf("If-Range etag match: %d %q", resp.StatusCode, body)
	}
	resp, body = f.do(t, "GET", target, "Range", "bytes=0-1", "If-Range", lastMod)
	if resp.StatusCode != 206 || body != "01" {
		t.Errorf("If-Range date match: %d %q", resp.StatusCode, body)
	}
	resp, body = f.do(t, "GET", target, "Range", "bytes=0-1", "If-Range", `"stale"`)
	if resp.StatusCode != 200 || body != "0123456789" {
		t.Errorf("If-Range mismatch: %d %q", resp.StatusCode, body)
	}
	// A failed If-Range means the Range header is ignored, even an unsatisfiable one.
	resp, _ = f.do(t, "GET", target, "Range", "bytes=50-", "If-Range", `"stale"`)
	expectStatus(t, resp, 200)
}

func TestMethodNotAllowed(t *testing.T) {
	f := newFixture(t)
	for _, method := range []string{"POST", "PUT", "DELETE", "OPTIONS"} {
		resp, _ := f.do(t, method, "/")
		expectStatus(t, resp, 405)
		if got := resp.Header.Get("Allow"); got != "GET, HEAD" {
			t.Errorf("%s: Allow %q", method, got)
		}
	}
}

func TestAccessLog(t *testing.T) {
	f := newFixture(t)
	f.write(t, "a.txt", "hello")

	f.do(t, "GET", keyed("/a.txt"))
	f.do(t, "HEAD", keyed("/a.txt"))
	f.do(t, "GET", "/a.txt?key=wrong")
	f.do(t, "POST", "/a.txt")
	f.do(t, "PROPFIND", "/a.txt")
	f.do(t, "GET", "/missing")
	f.do(t, "GET", "/")

	var got []string
	for _, e := range f.logs.entries("request") {
		got = append(got, fmt.Sprintf("%s %s %v %v", e["method"], e["path"], e["status"], e["bytes"]))
	}
	want := []string{
		"GET /a.txt 200 5",
		"HEAD /a.txt 200 0",
		"GET /a.txt 403 7",
		"POST /a.txt 405 18",
		"PROPFIND /a.txt 405 18",
		"GET /missing 404 9",
	}
	if len(got) != len(want)+1 || strings.Join(got[:len(want)], "|") != strings.Join(want, "|") {
		t.Errorf("access log:\n got %q\nwant %q (+ listing)", got, want)
	}

	denied := f.logs.entries("access denied")
	if len(denied) != 1 || denied[0]["reason"] != "invalid key" {
		t.Errorf("access denied entries: %v", denied)
	}
	if strings.Contains(f.logs.raw(), testKey) || strings.Contains(f.logs.raw(), "key=") {
		t.Error("access key or query string leaked into logs")
	}
}

func TestLimiter(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		c.Limiter = config.LimiterConfig{MaxFailures: 3, Window: time.Minute}
	})
	f.write(t, "a.txt", "a")

	// Only wrong keys count: successes, missing keys and other errors don't.
	for i := 0; i < 5; i++ {
		for target, want := range map[string]int{keyed("/a.txt"): 200, "/a.txt": 403, "/nope": 404} {
			resp, _ := f.do(t, "GET", target)
			expectStatus(t, resp, want)
		}
		resp, _ := f.do(t, "POST", "/a.txt")
		expectStatus(t, resp, 405)
	}
	for i := 0; i < 3; i++ {
		resp, _ := f.do(t, "GET", "/a.txt?key=guess"+strconv.Itoa(i))
		expectStatus(t, resp, 403)
	}
	// The budget is spent: even the right key is refused without being checked.
	resp, body := f.do(t, "GET", keyed("/a.txt"))
	expectStatus(t, resp, http.StatusTooManyRequests)
	if ra, err := strconv.Atoi(resp.Header.Get("Retry-After")); err != nil || ra < 59 || ra > 60 || body != "Too Many Requests" {
		t.Errorf("429 response: Retry-After %q, body %q", resp.Header.Get("Retry-After"), body)
	}
	// Listings stay public.
	resp, _ = f.do(t, "GET", "/")
	expectStatus(t, resp, 200)
}

// Concurrent guesses must not slip past the budget.
func TestLimiterConcurrentGuesses(t *testing.T) {
	f := newFixture(t, func(c *config.Config) {
		c.Limiter = config.LimiterConfig{MaxFailures: 3, Window: time.Minute}
	})
	f.write(t, "a.txt", "a")

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		counts = map[int]int{}
	)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest("GET", "/a.txt?key=guess"+strconv.Itoa(i), nil)
			resp, err := f.srv.App().Test(req, fiber.TestConfig{Timeout: 5 * time.Second})
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			counts[resp.StatusCode]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if counts[403] != 3 || counts[429] != 97 {
		t.Errorf("status counts %v, want 3×403 and 97×429", counts)
	}
}

func TestFailureLimiterWindow(t *testing.T) {
	l := newFailureLimiter(2, time.Minute)
	now := time.Unix(1000, 0)
	if l.attempt("a", true, now) != 0 || l.attempt("a", false, now) != 0 {
		t.Fatal("blocked below the limit")
	}
	if l.attempt("a", true, now.Add(time.Second)) != 0 {
		t.Fatal("the last allowed failure was blocked")
	}
	if got := l.attempt("a", false, now.Add(2*time.Second)); got != 58*time.Second {
		t.Fatalf("blocked for %v, want 58s", got)
	}
	if l.attempt("b", false, now) != 0 {
		t.Fatal("unrelated client blocked")
	}
	if l.attempt("a", false, now.Add(time.Minute)) != 0 {
		t.Fatal("block outlived the window")
	}
	l.attempt("c", true, now.Add(2*time.Minute))
	if _, ok := l.hits["a"]; ok {
		t.Error("expired entries are not swept")
	}
}

func TestFailureLimiterBounded(t *testing.T) {
	l := newFailureLimiter(1, time.Minute)
	now := time.Unix(1000, 0)
	for i := 0; i < maxTrackedClients+10; i++ {
		l.attempt(strconv.Itoa(i), true, now)
	}
	if len(l.hits) > maxTrackedClients {
		t.Fatalf("tracking %d clients", len(l.hits))
	}
	if l.attempt(strconv.Itoa(maxTrackedClients+9), false, now) == 0 {
		t.Error("newest client is not tracked")
	}
}

func TestErrorResponsesAreGeneric(t *testing.T) {
	f := newFixture(t)
	resp, body := f.do(t, "GET", "/nope")
	expectStatus(t, resp, 404)
	if body != "Not Found" || resp.Header.Get("Content-Type") != fiber.MIMETextPlainCharsetUTF8 {
		t.Errorf("404 response %q %q", body, resp.Header.Get("Content-Type"))
	}
}

func TestLongNonASCIIPath(t *testing.T) {
	f := newFixture(t)
	segment := strings.Repeat("é", 100) // 200 bytes on disk, 600 percent-encoded
	var parts []string
	for i := 0; i < 15; i++ {
		parts = append(parts, segment)
	}
	name := strings.Join(parts, "/") + "/f.txt"
	f.write(t, name, "deep")

	raw := escapePath("/" + name)
	if len(raw) < 9000 {
		t.Fatalf("path only %d bytes", len(raw))
	}
	resp, body := f.do(t, "GET", keyed(raw), "Cookie", "session="+strings.Repeat("c", 1024))
	if resp.StatusCode != 200 || body != "deep" {
		t.Fatalf("status %d, body %q", resp.StatusCode, body)
	}
}
