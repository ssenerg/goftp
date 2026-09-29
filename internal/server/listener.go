package server

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// retryListener keeps accepting connections when the process runs out of
// file descriptors or memory for them. fasthttp stops serving on any such
// error, so a client opening enough connections would take the server down.
type retryListener struct {
	net.Listener
	log    *zap.Logger
	logged time.Time // Accept is only called from fasthttp's accept loop
}

func (l *retryListener) Accept() (net.Conn, error) {
	var delay time.Duration
	for {
		c, err := l.Listener.Accept()
		if err == nil || !outOfResources(err) {
			return c, err
		}
		if time.Since(l.logged) > time.Minute {
			l.log.Warn("cannot accept connections, retrying", zap.Error(err))
			l.logged = time.Now()
		}
		delay = min(max(2*delay, 5*time.Millisecond), time.Second)
		time.Sleep(delay)
	}
}

func outOfResources(err error) bool {
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.ENOMEM)
}

// perClientListener caps the connections each client holds at once, with
// clients grouped like the sign-in limiter's (IPv6 by /64). fasthttp's
// MaxConnsPerIP only counts IPv4 clients. Excess connections are closed
// right away.
type perClientListener struct {
	net.Listener
	max   int
	mu    sync.Mutex
	conns map[string]int
}

func newPerClientListener(ln net.Listener, max int) *perClientListener {
	return &perClientListener{Listener: ln, max: max, conns: make(map[string]int)}
}

func (l *perClientListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		key := ""
		if addr, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			key = clientKey(addr.IP.String())
		}
		l.mu.Lock()
		if l.conns[key] >= l.max {
			l.mu.Unlock()
			_ = c.Close()
			continue
		}
		l.conns[key]++
		l.mu.Unlock()
		return &clientConn{Conn: c, release: func() { l.release(key) }}, nil
	}
}

func (l *perClientListener) release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conns[key]--; l.conns[key] <= 0 {
		delete(l.conns, key)
	}
}

type clientConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *clientConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

// Each connection may hold a few more file descriptors: the file it
// downloads, or the folder, temp file and lock of an upload.
const (
	fdsPerConn  = 4
	reservedFDs = 64 // listener, database pool, logs
)

// maxConns bounds concurrent connections so that they cannot use up the
// open file limit; 0 means fasthttp's default.
func maxConns() int {
	limit, ok := openFileLimit()
	if !ok || limit <= reservedFDs+fdsPerConn {
		return 0
	}
	return int(min((limit-reservedFDs)/fdsPerConn, 256*1024))
}
