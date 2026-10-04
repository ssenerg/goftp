package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/casbin/casbin/v3"
	"github.com/jackc/pgx/v5/pgxpool"
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
	dave, err := st.UserByName(ctx, "dave")
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
	if err := st.CreateSession(ctx, expired, dave, time.Now().Add(-time.Minute)); err != nil {
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
		if err := st.CreateSession(ctx, h, dave, time.Now().Add(time.Hour)); err != nil {
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

	if err := st.CreateSession(ctx, expired, dave, time.Now().Add(-time.Minute)); err != nil {
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
	watch(t, pool, server)

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
	perms := 0
	for _, rule := range auth.DefaultPolicies {
		if rule[0] == "p" {
			perms++
		}
	}
	if got, _ := fresh.GetPolicy(); len(got) != perms {
		t.Errorf("policies after SavePolicy: %v", got)
	}
}

// watch runs WatchPolicies for e until the test ends.
func watch(t *testing.T, pool *pgxpool.Pool, e *casbin.SyncedEnforcer) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		auth.WatchPolicies(ctx, pool, e, zap.NewNop())
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// Running servers never see a user without a role while it changes.
func TestSetRoleKeepsARole(t *testing.T) {
	pool, _ := dbtest.Open(t)
	server, err := auth.NewPgEnforcer(pool)
	if err != nil {
		t.Fatal(err)
	}
	watch(t, pool, server)
	e, err := auth.NewPgEnforcer(pool)
	if err != nil {
		t.Fatal(err)
	}
	svc := auth.NewService(auth.NewPgStore(pool), e, time.Hour)
	if _, err := svc.CreateUser(context.Background(), "bob", "user"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for ok := false; !ok; ok, _ = server.Enforce(auth.Subject("bob"), "/x", auth.ActRead) {
		if time.Now().After(deadline) {
			t.Fatal("new user never allowed")
		}
		time.Sleep(10 * time.Millisecond)
	}

	var denied atomic.Int64
	stop := make(chan struct{})
	polled := make(chan struct{})
	go func() {
		defer close(polled)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if ok, _ := server.Enforce(auth.Subject("bob"), "/x", auth.ActRead); !ok {
				denied.Add(1)
			}
		}
	}()
	for i := range 20 {
		if err := svc.SetRole(context.Background(), "bob", []string{"operator", "user"}[i%2]); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	close(stop)
	<-polled
	if n := denied.Load(); n > 0 {
		t.Errorf("bob was denied %d times while changing roles", n)
	}
	if svc.Role("bob") != "user" {
		t.Errorf("roles %q", svc.Role("bob"))
	}
}

// The listener's connection never returns to the pool, and does not
// starve a pool of one.
func TestWatchPoliciesLeavesPoolUsable(t *testing.T) {
	_, raw := dbtest.Open(t)
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("pool_max_conns", "1")
	u.RawQuery = q.Encode()
	pool, err := pgxpool.New(context.Background(), u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	e, err := auth.NewPgEnforcer(pool)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		auth.WatchPolicies(ctx, pool, e, zap.NewNop())
		close(done)
	}()
	query := func(when string) {
		qctx, qcancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer qcancel()
		if _, err := pool.Exec(qctx, "SELECT 1"); err != nil {
			t.Errorf("query %s: %v", when, err)
		}
	}
	time.Sleep(200 * time.Millisecond)
	query("while listening")
	cancel()
	<-done
	for range 3 {
		query("after listening")
	}
}

// Casbin calls the batch and update methods of adapters without checking
// that they exist.
func TestAdapterBatchAndUpdate(t *testing.T) {
	pool, _ := dbtest.Open(t)
	e, err := auth.NewPgEnforcer(pool)
	if err != nil {
		t.Fatal(err)
	}
	steps := []func() (bool, error){
		func() (bool, error) { return e.AddRolesForUser("user:a", []string{"user", "operator"}) },
		func() (bool, error) {
			return e.AddPolicies([][]string{{"user:a", "/a/*", "read"}, {"user:a", "/b/*", "read"}})
		},
		func() (bool, error) {
			return e.UpdatePolicy([]string{"user:a", "/a/*", "read"}, []string{"user:a", "/a/*", "write"})
		},
		func() (bool, error) {
			return e.UpdatePolicies([][]string{{"user:a", "/b/*", "read"}}, [][]string{{"user:a", "/c/*", "read"}})
		},
		func() (bool, error) {
			return e.UpdateFilteredPolicies([][]string{{"user:a", "/d/*", "read"}}, 1, "/c/*")
		},
		func() (bool, error) { return e.RemovePolicies([][]string{{"user:a", "/a/*", "write"}}) },
	}
	for i, step := range steps {
		if ok, err := step(); !ok || err != nil {
			t.Fatalf("step %d: %v, %v", i, ok, err)
		}
	}
	stored, err := auth.NewPgEnforcer(pool)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []*casbin.SyncedEnforcer{e, stored} {
		perms, _ := e.GetFilteredPolicy(0, "user:a")
		roles, _ := e.GetRolesForUser("user:a")
		slices.Sort(roles)
		if len(perms) != 1 || strings.Join(perms[0], " ") != "user:a /d/* read" || strings.Join(roles, " ") != "operator user" {
			t.Errorf("policies %v, roles %v", perms, roles)
		}
	}
}

// The limit on a user's links counts unexpired ones only.
func TestPgShareLimit(t *testing.T) {
	pool, _ := dbtest.Open(t)
	st := auth.NewPgStore(pool)
	ctx := context.Background()
	id, err := st.CreateUser(ctx, "ann", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO shares (token_hash, path, is_dir, created_by, expires_at)
		SELECT sha256(i::text::bytea), '/f', false, $1, now() + CASE WHEN i < $2 THEN interval '1 hour' ELSE interval '-1 hour' END
		FROM generate_series(1, $2 + 5) AS i`, id, auth.MaxShares); err != nil {
		t.Fatal(err)
	}
	sh := &auth.Share{Path: "/f", CreatedBy: id, ExpiresAt: time.Now().Add(time.Hour)}
	if err := st.CreateShare(ctx, tokenHash(), sh); err != nil || sh.ID == 0 || sh.CreatedAt.IsZero() {
		t.Fatalf("last link: %+v %v", sh, err)
	}
	if err := st.CreateShare(ctx, tokenHash(), &auth.Share{Path: "/f", CreatedBy: id, ExpiresAt: time.Now().Add(time.Hour)}); !errors.Is(err, auth.ErrTooMany) {
		t.Errorf("one link too many: %v", err)
	}
	if err := st.DeleteExpiredShares(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM shares").Scan(&n); err != nil || n != auth.MaxShares {
		t.Errorf("%d links after purging, want %d: %v", n, auth.MaxShares, err)
	}
}
