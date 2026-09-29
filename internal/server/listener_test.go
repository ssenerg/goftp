package server

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"

	"go.uber.org/zap"

	"goftp/internal/config"
)

type stubListener struct {
	errs []error
	conn net.Conn
}

func (l *stubListener) Accept() (net.Conn, error) {
	if len(l.errs) > 0 {
		err := l.errs[0]
		l.errs = l.errs[1:]
		return nil, err
	}
	return l.conn, nil
}

func (l *stubListener) Close() error   { return nil }
func (l *stubListener) Addr() net.Addr { return nil }

// Running out of file descriptors must not stop the server: fasthttp gives
// up on every accept error but a timeout.
func TestAcceptSurvivesExhaustion(t *testing.T) {
	conn, other := net.Pipe()
	defer conn.Close()
	defer other.Close()
	emfile := &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept4", syscall.EMFILE)}
	ln := &retryListener{Listener: &stubListener{errs: []error{emfile, syscall.ENFILE}, conn: conn}, log: zap.NewNop()}
	if c, err := ln.Accept(); err != nil || c != conn {
		t.Fatalf("Accept: %v, %v", c, err)
	}
	ln = &retryListener{Listener: &stubListener{errs: []error{net.ErrClosed}}, log: zap.NewNop()}
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("closed listener: %v", err)
	}
}

func TestMaxConnsFitsFileLimit(t *testing.T) {
	limit, ok := openFileLimit()
	if !ok {
		t.Skip("no file limit")
	}
	if n := maxConns(); n <= 0 || uint64(n)*fdsPerConn+reservedFDs > limit {
		t.Errorf("maxConns() = %d with a limit of %d files", n, limit)
	}
}

func TestMaxConnsPerIP(t *testing.T) {
	f := newFixture(t, func(c *config.Config) { c.Server.MaxConnsPerIP = 2 })
	addr, _ := startServer(t, f)
	dial := func() net.Conn {
		t.Helper()
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	first, _ := dial(), dial()

	// The third is closed right away.
	third := dial()
	_ = third.SetReadDeadline(time.Now().Add(2 * time.Second))
	var ne net.Error
	if _, err := third.Read(make([]byte, 1)); err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		t.Errorf("third connection: %v", err)
	}

	// Closing one makes room again.
	_ = first.Close()
	waitFor(t, "a free slot", func() bool {
		c := dial()
		fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		_, err := http.ReadResponse(bufio.NewReader(c), nil)
		return err == nil
	})
}

func TestListenerSurvivesExhaustion(t *testing.T) {
	f := newFixture(t)
	ln, err := f.srv.listen()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if _, ok := ln.(*retryListener); !ok {
		t.Errorf("listener %T does not retry when out of file descriptors", ln)
	}
}
