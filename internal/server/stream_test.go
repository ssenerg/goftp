package server

import (
	"bufio"
	"context"
	"errors"
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

// startServer runs f's server on a real listener and returns its address.
func startServer(t *testing.T, f *fixture) (string, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.srv.Listen(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("server did not shut down")
		}
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if entries := f.logs.FilterMessage("listening").All(); len(entries) > 0 {
			return entries[0].ContextMap()["addr"].(string), cancel
		}
		select {
		case err := <-done:
			t.Fatalf("listen: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatal("server did not start")
	return "", cancel
}

func sparseFile(t *testing.T, dir, name string, size int64) {
	t.Helper()
	fh, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	if err := fh.Truncate(size); err != nil {
		t.Fatal(err)
	}
}

func dialGet(t *testing.T, addr, target string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetReadBuffer(64 << 10)
	}
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: test\r\n\r\n", target)
	br := bufio.NewReaderSize(conn, 64<<10)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	return conn, br, resp
}

// A download that takes longer than write_timeout must still complete as
// long as the client keeps reading.
func TestSlowDownloadOutlivesWriteTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	const size = 16 << 20
	f := newFixture(t, func(c *config.Config) { c.Server.WriteTimeout = 300 * time.Millisecond })
	sparseFile(t, f.dir, "big.bin", size)
	addr, _ := startServer(t, f)

	start := time.Now()
	_, _, resp := dialGet(t, addr, keyed("/big.bin"))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	buf := make([]byte, 256<<10)
	var n int64
	for {
		m, err := io.ReadFull(resp.Body, buf)
		n += int64(m)
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			t.Fatalf("after %d bytes: %v", n, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n != size {
		t.Fatalf("received %d of %d bytes", n, size)
	}
	if elapsed := time.Since(start); elapsed < 600*time.Millisecond {
		t.Skipf("download finished in %v; too fast to exercise the timeout", elapsed)
	}
	if aborted := f.logs.FilterMessage("transfer aborted").Len(); aborted != 0 {
		t.Errorf("%d transfers aborted", aborted)
	}
}

// A client that stops reading must not hold the connection forever.
func TestStalledClientIsDisconnected(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	const size = 256 << 20
	f := newFixture(t, func(c *config.Config) { c.Server.WriteTimeout = 200 * time.Millisecond })
	sparseFile(t, f.dir, "huge.bin", size)
	addr, _ := startServer(t, f)

	conn, br, resp := dialGet(t, addr, keyed("/huge.bin"))
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}

	deadline := time.Now().Add(5 * time.Second)
	for f.logs.FilterMessage("transfer aborted").Len() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("server kept writing to a stalled client")
		}
		time.Sleep(50 * time.Millisecond)
	}
	entry := f.logs.FilterMessage("transfer aborted").All()[0].ContextMap()
	if !strings.Contains(fmt.Sprint(entry["error"]), "timeout") {
		t.Errorf("unexpected abort reason: %v", entry["error"])
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := io.Copy(io.Discard, br)
	if n >= size {
		t.Errorf("stalled client still received the whole file")
	}
}

func TestGracefulShutdown(t *testing.T) {
	f := newFixture(t)
	f.write(t, "a.txt", "a")
	addr, cancel := startServer(t, f)

	resp, err := http.Get("http://" + addr + keyed("/a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}

	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("server still accepting connections after shutdown")
}

type deadlineConn struct {
	net.Conn
	deadlines []time.Time
}

func (d *deadlineConn) SetWriteDeadline(t time.Time) error {
	d.deadlines = append(d.deadlines, t)
	return nil
}

func TestBodyStreamRearmsDeadline(t *testing.T) {
	conn := &deadlineConn{}
	b := &bodyStream{r: strings.NewReader(strings.Repeat("x", 10)), conn: conn, timeout: time.Minute}
	buf := make([]byte, 4)
	for {
		if _, err := b.Read(buf); err != nil {
			break
		}
	}
	if len(conn.deadlines) < 3 || b.read != 10 {
		t.Fatalf("deadline re-armed %d times, read %d bytes", len(conn.deadlines), b.read)
	}
	if d := time.Until(conn.deadlines[0]); d < 50*time.Second {
		t.Errorf("deadline too short: %v", d)
	}
}
