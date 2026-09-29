package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"go.uber.org/zap"

	"goftp/internal/auth"
	"goftp/internal/db/dbtest"
)

func tokenHash() []byte {
	sum := sha256.Sum256([]byte(rand.Text()))
	return sum[:]
}

func TestPgSessions(t *testing.T) {
	pool, _ := dbtest.Open(t)
	st := auth.NewPgStore(pool)
	ctx := context.Background()
	id, err := st.CreateUser(ctx, "dave", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, "dave", "hash"); !errors.Is(err, auth.ErrExists) {
		t.Errorf("duplicate: %v", err)
	}
	if _, err := st.UserByName(ctx, "nobody"); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("missing user: %v", err)
	}
	if err := st.SetPassword(ctx, id+1, "x", false); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("SetPassword of a missing user: %v", err)
	}

	expired := tokenHash()
	if err := st.CreateSession(ctx, expired, id, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SessionUser(ctx, expired); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("expired session: %v", err)
	}
	// A user's sessions are capped; the newest survive.
	var hashes [][]byte
	for range 105 {
		h := tokenHash()
		hashes = append(hashes, h)
		if err := st.CreateSession(ctx, h, id, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM sessions").Scan(&n); err != nil || n != 100 {
		t.Errorf("%d sessions kept: %v", n, err)
	}
	if u, err := st.SessionUser(ctx, hashes[104]); err != nil || u.Username != "dave" {
		t.Errorf("newest session: %v %v", u, err)
	}
	if _, err := st.SessionUser(ctx, hashes[0]); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("oldest session kept: %v", err)
	}

	if err := st.CreateSession(ctx, expired, id, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteExpiredSessions(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM sessions WHERE expires_at <= now()").Scan(&n); err != nil || n != 0 {
		t.Errorf("%d expired sessions left: %v", n, err)
	}
}

// Policy changes made elsewhere, e.g. by the CLI, reach running servers.
func TestWatchPolicies(t *testing.T) {
	pool, _ := dbtest.Open(t)
	server, err := auth.NewPgEnforcer(pool)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		auth.WatchPolicies(ctx, pool, server, zap.NewNop())
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	cli, err := auth.NewPgEnforcer(pool)
	if err != nil {
		t.Fatal(err)
	}
	waitFor := func(want bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			ok, err := server.Enforce(auth.Anonymous, "/pub/x", auth.ActRead)
			if err != nil {
				t.Fatal(err)
			}
			if ok == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("policy not reloaded, still %v", ok)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if _, err := cli.AddPolicy(auth.Anonymous, "/pub/*", auth.ActRead); err != nil {
		t.Fatal(err)
	}
	waitFor(true)
	if _, err := cli.RemovePolicy(auth.Anonymous, "/pub/*", auth.ActRead); err != nil {
		t.Fatal(err)
	}
	waitFor(false)
	if _, err := cli.AddRoleForUser(auth.Subject("erin"), "user"); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.DeleteUser(auth.Subject("erin")); err != nil {
		t.Fatal(err)
	}
	if err := cli.SavePolicy(); err != nil {
		t.Fatal(err)
	}
	fresh, err := auth.NewPgEnforcer(pool)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := fresh.GetPolicy(); len(got) != 4 {
		t.Errorf("policies after SavePolicy: %v", got)
	}
}
