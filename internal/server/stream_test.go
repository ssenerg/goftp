package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
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
		if entries := f.logs.entries("listening"); len(entries) > 0 {
			return entries[0]["addr"].(string), cancel
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
	entry := requestEntry(t, f, "/big.bin")
	if entry["error"] != nil || entry["bytes"] != float64(size) {
		t.Errorf("access log: %v", entry)
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

	entry := requestEntry(t, f, "/huge.bin")
	if !strings.Contains(fmt.Sprint(entry["error"]), "timeout") {
		t.Errorf("unexpected abort reason: %v", entry["error"])
	}
	if sent, _ := entry["bytes"].(float64); sent <= 0 || sent >= size {
		t.Errorf("logged bytes %v", entry["bytes"])
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := io.Copy(io.Discard, br)
	if n >= size {
		t.Errorf("stalled client still received the whole file")
	}
}

// requestEntry waits for the access log line of a download to appear.
func requestEntry(t *testing.T, f *fixture, path string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, e := range f.logs.entries("request") {
			if e["path"] == path {
				return e
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no access log entry for %s", path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Shutdown must wait for in-flight downloads instead of cutting them off.
func TestShutdownWaitsForDownloads(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	const size = 32 << 20
	f := newFixture(t)
	sparseFile(t, f.dir, "big.bin", size)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- f.srv.Listen(ctx) }()
	var addr string
	for addr == "" {
		if e := f.logs.entries("listening"); len(e) > 0 {
			addr = e[0]["addr"].(string)
		}
		time.Sleep(10 * time.Millisecond)
	}

	_, _, resp := dialGet(t, addr, keyed("/big.bin"))
	received := make(chan int64, 1)
	go func() {
		buf := make([]byte, 1<<20)
		var n int64
		for {
			m, err := resp.Body.Read(buf)
			n += int64(m)
			if err != nil {
				received <- n
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Listen did not return")
	}
	// Listen returned, so the download must already be complete on our side.
	entries := f.logs.entries("request")
	if len(entries) != 1 || entries[0]["bytes"] != float64(size) || entries[0]["error"] != nil {
		t.Fatalf("download not finished when Listen returned: %v", entries)
	}
	if n := <-received; n != size {
		t.Errorf("client received %d of %d bytes", n, size)
	}
	if _, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
		t.Error("server still accepting connections after shutdown")
	}
}

// Idle connections time out without a misleading access log line.
func TestIdleConnectionNotLoggedAsRequest(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.Server.ReadTimeout = 200 * time.Millisecond })
	addr, _ := startServer(t, f)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.Copy(io.Discard, conn)
	for _, e := range f.logs.entries("request") {
		if e["level"] != "debug" {
			t.Errorf("idle connection logged at %v: %v", e["level"], e)
		}
	}
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
	for _, useWriteTo := range []bool{true, false} {
		conn := &deadlineConn{}
		data := strings.Repeat("x", 200<<10)
		b := &bodyStream{r: strings.NewReader(data), conn: conn, timeout: time.Minute}
		var out bytes.Buffer
		if useWriteTo {
			if _, err := b.WriteTo(&out); err != nil {
				t.Fatal(err)
			}
		} else if _, err := io.CopyBuffer(struct{ io.Writer }{&out}, struct{ io.Reader }{b}, make([]byte, 4096)); err != nil {
			t.Fatal(err)
		}
		if out.String() != data || b.sent != int64(len(data)) {
			t.Fatalf("writeTo=%v: copied %d bytes, sent %d", useWriteTo, out.Len(), b.sent)
		}
		if len(conn.deadlines) < 3 {
			t.Errorf("writeTo=%v: deadline re-armed %d times", useWriteTo, len(conn.deadlines))
		}
		if d := time.Until(conn.deadlines[0]); d < 50*time.Second {
			t.Errorf("deadline too short: %v", d)
		}
	}
}

func TestTLS(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	pool := writeSelfSignedCert(t, certFile, keyFile)
	f := newFixture(t, func(c *config.Config) {
		c.TLS = config.TLSConfig{CertFile: certFile, KeyFile: keyFile}
	})
	f.write(t, "a.txt", "secure")
	addr, _ := startServer(t, f)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resp, err := client.Get("https://" + addr + keyed("/a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "secure" {
		t.Fatalf("status %d, body %q", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Errorf("HSTS header %q", got)
	}
}

func writeSelfSignedCert(t *testing.T, certFile, keyFile string) *x509.CertPool {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return pool
}
