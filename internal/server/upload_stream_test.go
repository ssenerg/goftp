package server

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goftp/internal/config"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// startUpload sends the headers and the first half of a PUT and waits until
// the server has started writing it.
func startUpload(t *testing.T, f *fixture, addr, name string, data []byte) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	fmt.Fprintf(conn, "PUT /%s HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer %s\r\nContent-Length: %d\r\n\r\n", name, f.token, len(data))
	if _, err := conn.Write(data[:len(data)/2]); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "partial upload on disk", func() bool {
		temps, _ := filepath.Glob(filepath.Join(f.dir, tempPrefix+"*"))
		if len(temps) != 1 || !exists(filepath.Join(f.dir, lockName(name))) {
			return false
		}
		info, err := os.Stat(temps[0])
		return err == nil && info.Size() > 0
	})
	return conn
}

func TestPartialUploadIsHidden(t *testing.T) {
	f := newFixture(t)
	addr, _ := startServer(t, f)
	data := bytes.Repeat([]byte("0123456789"), 100_000)
	conn := startUpload(t, f, addr, "video.bin", data)

	if _, body := f.do(t, "GET", "/"); strings.Contains(body, "video.bin") {
		t.Error("partial upload is listed")
	}
	if resp, _ := f.do(t, "GET", "/video.bin"); resp.StatusCode != 404 {
		t.Errorf("partial upload downloadable: %d", resp.StatusCode)
	}
	if resp, _ := f.send(t, "PUT", "/video.bin", strings.NewReader("x")); resp.StatusCode != 409 {
		t.Errorf("concurrent upload: %d", resp.StatusCode)
	}

	if _, err := conn.Write(data[len(data)/2:]); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	expectStatus(t, resp, http.StatusCreated)
	if _, body := f.do(t, "GET", "/"); !strings.Contains(body, `href="/video.bin"`) {
		t.Error("completed upload is not listed")
	}
	if readFile(t, f.dir, "video.bin") != string(data) {
		t.Error("stored content differs")
	}
	if l := leftovers(f.dir); len(l) > 0 {
		t.Errorf("leftover files: %v", l)
	}
}

func TestAbortedUploadCleansUp(t *testing.T) {
	f := newFixture(t)
	f.write(t, "doc.txt", "old version")
	addr, _ := startServer(t, f)
	conn := startUpload(t, f, addr, "doc.txt", bytes.Repeat([]byte("x"), 1<<20))
	_ = conn.Close()

	waitFor(t, "cleanup", func() bool { return len(leftovers(f.dir)) == 0 })
	if readFile(t, f.dir, "doc.txt") != "old version" {
		t.Error("aborted upload replaced the existing file")
	}
}

func TestStalledUploadTimesOut(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.Server.ReadTimeout = 300 * time.Millisecond })
	addr, _ := startServer(t, f)
	startUpload(t, f, addr, "stalled.bin", bytes.Repeat([]byte("x"), 1<<20))

	waitFor(t, "cleanup", func() bool { return len(leftovers(f.dir)) == 0 })
	if exists(filepath.Join(f.dir, "stalled.bin")) {
		t.Error("stalled upload stored")
	}
	if e := requestEntry(t, f, "/stalled.bin"); e["status"] != float64(http.StatusRequestTimeout) {
		t.Errorf("logged status %v", e["status"])
	}
}

// Like downloads, uploads may take longer than read_timeout as long as the
// client keeps sending.
func TestSlowUploadOutlivesReadTimeout(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.Server.ReadTimeout = 300 * time.Millisecond })
	addr, _ := startServer(t, f)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	chunk := bytes.Repeat([]byte("y"), 64<<10)
	const chunks = 10
	fmt.Fprintf(conn, "PUT /slow.bin HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer %s\r\nContent-Length: %d\r\n\r\n", f.token, chunks*len(chunk))
	for range chunks {
		if _, err := conn.Write(chunk); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	expectStatus(t, resp, http.StatusCreated)
	if info, err := os.Stat(filepath.Join(f.dir, "slow.bin")); err != nil || info.Size() != chunks*int64(len(chunk)) {
		t.Errorf("stored file: %v %v", info, err)
	}
}

// A chunked body cut off between chunks is indistinguishable from a complete
// one, so PUT needs a Content-Length.
func TestChunkedPutRejected(t *testing.T) {
	f := newFixture(t)
	addr, _ := startServer(t, f)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "PUT /c.bin HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer %s\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n", f.token, 500, strings.Repeat("z", 500))

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	expectStatus(t, resp, http.StatusLengthRequired)
	if !resp.Close {
		t.Error("connection kept open with an unread body")
	}
	if exists(filepath.Join(f.dir, "c.bin")) || len(leftovers(f.dir)) > 0 {
		t.Error("rejected upload left files behind")
	}
}

// Form uploads may be chunked: the multipart boundaries reveal truncation.
func TestFormUploadLimitAndTruncation(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.Upload.MaxSize = 1000 })
	addr, _ := startServer(t, f)
	post := func(parts ...formPart) (net.Conn, []byte, string) {
		form, ctype := multipartForm(t, parts...)
		data, _ := io.ReadAll(form)
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		fmt.Fprintf(conn, "POST / HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer %s\r\nContent-Type: %s\r\nTransfer-Encoding: chunked\r\n\r\n", f.token, ctype)
		return conn, data, ctype
	}

	conn, data, _ := post(formPart{field: "file", filename: "big.bin", content: strings.Repeat("z", 2000)})
	fmt.Fprintf(conn, "%x\r\n%s\r\n0\r\n\r\n", len(data), data)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	expectStatus(t, resp, http.StatusRequestEntityTooLarge)

	// Cut off at a chunk boundary inside the file part.
	conn, data, _ = post(formPart{field: "file", filename: "cut.bin", content: strings.Repeat("c", 900)})
	fmt.Fprintf(conn, "%x\r\n%s\r\n", len(data)/2, data[:len(data)/2])
	waitFor(t, "partial upload on disk", func() bool { return exists(filepath.Join(f.dir, lockName("cut.bin"))) })
	_ = conn.Close()
	waitFor(t, "cleanup", func() bool { return len(leftovers(f.dir)) == 0 })

	for _, name := range []string{"big.bin", "cut.bin"} {
		if exists(filepath.Join(f.dir, name)) {
			t.Errorf("%s stored", name)
		}
	}
}

// fasthttp does not drain unread streamed bodies; the rest of a rejected
// body must never be parsed as another request.
func TestUnreadBodyClosesConnection(t *testing.T) {
	f := newFixture(t)
	addr, _ := startServer(t, f)
	smuggled := "GET /smuggled HTTP/1.1\r\nHost: t\r\n\r\n"
	// fasthttp buffers the first 8 KiB of a body before calling the handler.
	body := strings.Repeat("A", 8<<10) + smuggled

	// PROPFIND is answered by Fiber before any middleware runs.
	for _, method := range []string{"PUT", "POST", "GET", "DELETE", "PROPFIND"} {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(conn, "%s /x.txt HTTP/1.1\r\nHost: t\r\nContent-Length: %d\r\n\r\n%s", method, len(body), body)
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if extra, _ := io.ReadAll(br); len(extra) > 0 || !resp.Close {
			t.Errorf("%s: connection reused after an unread body (extra %q)", method, extra)
		}
		_ = conn.Close()
	}
	for _, e := range f.logs.entries("request") {
		if e["path"] == "/smuggled" {
			t.Error("smuggled request was served")
		}
	}
}

// A live upload keeps its lock fresh even while no data arrives (slow
// client, long fsync), and never removes a lock that is not its own.
func TestLockHeartbeatAndOwnership(t *testing.T) {
	refresh, expiry := lockRefresh, lockExpiry
	lockRefresh, lockExpiry = 50*time.Millisecond, 200*time.Millisecond
	t.Cleanup(func() { lockRefresh, lockExpiry = refresh, expiry })

	f := newFixture(t)
	addr, _ := startServer(t, f)
	conn := startUpload(t, f, addr, "held.bin", bytes.Repeat([]byte("h"), 1<<20))
	lock := filepath.Join(f.dir, lockName("held.bin"))

	time.Sleep(3 * lockExpiry)
	if info, err := os.Stat(lock); err != nil || time.Since(info.ModTime()) > lockExpiry {
		t.Fatalf("lock not refreshed: %v", err)
	}
	if resp, _ := f.send(t, "PUT", "/held.bin", strings.NewReader("x")); resp.StatusCode != 409 {
		t.Errorf("live upload taken over: %d", resp.StatusCode)
	}

	other := lockMagic + ".goftp-OTHER.part\n"
	if err := os.WriteFile(lock, []byte(other), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	waitFor(t, "aborted upload to finish", func() bool {
		for _, e := range f.logs.entries("request") {
			if e["path"] == "/held.bin" && e["status"] == float64(http.StatusBadRequest) {
				return true
			}
		}
		return false
	})
	if got := readFile(t, f.dir, lockName("held.bin")); got != other {
		t.Errorf("upload removed a lock it does not own: %q", got)
	}
}
