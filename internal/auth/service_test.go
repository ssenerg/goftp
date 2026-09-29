package auth_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"goftp/internal/auth"
	"goftp/internal/auth/authtest"
	"goftp/internal/db/dbtest"
)

// services runs fn against the in-memory store and, when a test database
// is configured, against Postgres.
func services(t *testing.T, fn func(t *testing.T, svc *auth.Service)) {
	t.Run("memory", func(t *testing.T) {
		svc, _ := authtest.NewService(time.Hour)
		fn(t, svc)
	})
	t.Run("postgres", func(t *testing.T) {
		pool, _ := dbtest.Open(t)
		e, err := auth.NewPgEnforcer(pool)
		if err != nil {
			t.Fatal(err)
		}
		fn(t, auth.NewService(auth.NewPgStore(pool), e, time.Hour))
	})
}

func TestSignUpAndFirstLogin(t *testing.T) {
	services(t, func(t *testing.T, svc *auth.Service) {
		ctx := context.Background()
		temp, err := svc.CreateUser(ctx, " Alice ", "operator")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.CreateUser(ctx, "alice", "user"); !errors.Is(err, auth.ErrExists) {
			t.Errorf("duplicate user: %v", err)
		}
		for _, tc := range []struct{ name, role string }{{"x", "user"}, {"bob", "root"}, {"user:bob", "user"}} {
			if _, err := svc.CreateUser(ctx, tc.name, tc.role); err == nil {
				t.Errorf("CreateUser(%q, %q) succeeded", tc.name, tc.role)
			}
		}

		for _, pw := range []string{"", "wrong", strings.Repeat("x", 300)} {
			if _, err := svc.Login(ctx, "alice", pw); !errors.Is(err, auth.ErrInvalidCredentials) {
				t.Errorf("Login with %q: %v", pw, err)
			}
		}
		if _, err := svc.Login(ctx, "nobody", temp); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("unknown user: %v", err)
		}
		sess, err := svc.Login(ctx, "ALICE", temp)
		if err != nil {
			t.Fatal(err)
		}
		if !sess.User.MustChangePassword || sess.User.Username != "alice" || len(sess.Token) != 43 {
			t.Errorf("session %+v", sess)
		}
		other, err := svc.Login(ctx, "alice", temp)
		if err != nil {
			t.Fatal(err)
		}
		if u, err := svc.Authenticate(ctx, sess.Token); err != nil || u.Username != "alice" {
			t.Fatalf("Authenticate: %v %v", u, err)
		}
		for _, bad := range []string{"", "short", sess.Token[:42] + "x"} {
			if _, err := svc.Authenticate(ctx, bad); !errors.Is(err, auth.ErrNotFound) {
				t.Errorf("Authenticate(%q): %v", bad, err)
			}
		}

		if _, err := svc.ChangePassword(ctx, sess.User, "wrong", "a fine new password"); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("wrong current password: %v", err)
		}
		for _, next := range []string{"short", temp} {
			if _, err := svc.ChangePassword(ctx, sess.User, temp, next); !errors.Is(err, auth.ErrWeakPassword) {
				t.Errorf("new password %q: %v", next, err)
			}
		}
		changed, err := svc.ChangePassword(ctx, sess.User, temp, "a fine new password")
		if err != nil {
			t.Fatal(err)
		}
		if changed.User.MustChangePassword {
			t.Error("password still temporary")
		}
		// Every earlier session ends.
		for _, token := range []string{sess.Token, other.Token} {
			if _, err := svc.Authenticate(ctx, token); !errors.Is(err, auth.ErrNotFound) {
				t.Errorf("old session survived: %v", err)
			}
		}
		u, err := svc.Authenticate(ctx, changed.Token)
		if err != nil || u.MustChangePassword {
			t.Fatalf("new session: %+v %v", u, err)
		}
		if _, err := svc.Login(ctx, "alice", temp); err == nil {
			t.Error("temporary password still works")
		}
		if _, err := svc.Login(ctx, "alice", "a fine new password"); err != nil {
			t.Error(err)
		}

		if err := svc.Logout(ctx, changed.Token); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Authenticate(ctx, changed.Token); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("session survived logout: %v", err)
		}
	})
}

func TestUserAdministration(t *testing.T) {
	services(t, func(t *testing.T, svc *auth.Service) {
		ctx := context.Background()
		if _, err := svc.CreateUser(ctx, "carol", "user"); err != nil {
			t.Fatal(err)
		}
		temp, err := svc.CreateUser(ctx, "bob", "admin")
		if err != nil {
			t.Fatal(err)
		}
		sess, err := svc.Login(ctx, "bob", temp)
		if err != nil {
			t.Fatal(err)
		}
		if ok, _ := svc.Allowed(sess.User, "/x", auth.ActOverwrite); !ok {
			t.Error("admin may not overwrite")
		}

		if err := svc.SetRole(ctx, "bob", "operator"); err != nil {
			t.Fatal(err)
		}
		if ok, _ := svc.Allowed(sess.User, "/x", auth.ActOverwrite); ok {
			t.Error("old role kept")
		}
		for _, tc := range []struct{ name, role string }{{"bob", "king"}, {"nobody", "user"}} {
			if err := svc.SetRole(ctx, tc.name, tc.role); err == nil {
				t.Errorf("SetRole(%q, %q) succeeded", tc.name, tc.role)
			}
		}

		reset, err := svc.ResetPassword(ctx, "bob")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Authenticate(ctx, sess.Token); !errors.Is(err, auth.ErrNotFound) {
			t.Error("reset kept the session")
		}
		if sess, err = svc.Login(ctx, "bob", reset); err != nil || !sess.User.MustChangePassword {
			t.Fatalf("login after reset: %v", err)
		}

		users, err := svc.Users(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, u := range users {
			got = append(got, u.Username+"="+u.Role)
		}
		if strings.Join(got, " ") != "bob=operator carol=user" {
			t.Errorf("users %v", got)
		}

		if err := svc.DeleteUser(ctx, "bob"); err != nil {
			t.Fatal(err)
		}
		if err := svc.DeleteUser(ctx, "bob"); !errors.Is(err, auth.ErrNotFound) {
			t.Errorf("second delete: %v", err)
		}
		if _, err := svc.Authenticate(ctx, sess.Token); !errors.Is(err, auth.ErrNotFound) {
			t.Error("deleted user's session survived")
		}
		// A new user of the same name starts without the old rules.
		if _, err := svc.CreateUser(ctx, "bob", "user"); err != nil {
			t.Fatal(err)
		}
		if svc.Role("bob") != "user" {
			t.Errorf("recreated bob has roles %q", svc.Role("bob"))
		}
	})
}

func TestPolicyAdministration(t *testing.T) {
	services(t, func(t *testing.T, svc *auth.Service) {
		perms, roles, err := svc.Policies()
		if err != nil {
			t.Fatal(err)
		}
		var rules [][]string
		for _, p := range perms {
			rules = append(rules, append([]string{"p"}, p...))
		}
		for _, g := range roles {
			rules = append(rules, append([]string{"g"}, g...))
		}
		// The first migration seeds the same rules as the in-memory default.
		if !slices.EqualFunc(rules, auth.DefaultPolicies, slices.Equal) {
			t.Errorf("policies %v, want %v", rules, auth.DefaultPolicies)
		}

		for _, rule := range [][3]string{
			{"root", "/*", "read"}, {"user:X", "/*", "read"}, {"user", "docs/*", "read"}, {"user", "/a/../b", "read"},
			{"user", "/a//b", "read"}, {"user", "/*/x", "read"}, {"user", "/a\\b", "read"}, {"user", "/a\nb", "read"},
			{"user", "/a", "delete"}, {"user", "", "read"}, {"anonymous", "/pub*", "read"}, {"user", "*", "read"},
		} {
			if _, err := svc.AddPolicy(rule[0], rule[1], rule[2]); err == nil {
				t.Errorf("AddPolicy(%q) accepted", rule)
			}
		}
		for _, rule := range [][3]string{{"anonymous", "/pub/*", "read"}, {"user:bob", "/bob/", "*"}, {"operator", "/", "write"}, {"admin", "/a.txt", "overwrite"}} {
			if ok, err := svc.AddPolicy(rule[0], rule[1], rule[2]); !ok || err != nil {
				t.Errorf("AddPolicy(%q) = %v, %v", rule, ok, err)
			}
		}
		if ok, _ := svc.AddPolicy("anonymous", "/pub/*", "read"); ok {
			t.Error("duplicate rule added")
		}
		if ok, _ := svc.Allowed(nil, "/pub/f", auth.ActRead); !ok {
			t.Error("anonymous rule not applied")
		}
		if ok, err := svc.RemovePolicy("anonymous", "/pub/*", "read"); !ok || err != nil {
			t.Errorf("RemovePolicy = %v, %v", ok, err)
		}
		if ok, _ := svc.Allowed(nil, "/pub/f", auth.ActRead); ok {
			t.Error("removed rule still applies")
		}
		if ok, _ := svc.RemovePolicy("anonymous", "/pub/*", "read"); ok {
			t.Error("removed a missing rule")
		}
	})
}

// A password change must end the sessions of logins that were checking the
// old password while it happened.
func TestPasswordChangeEndsConcurrentLogins(t *testing.T) {
	services(t, func(t *testing.T, svc *auth.Service) {
		ctx := context.Background()
		temp, err := svc.CreateUser(ctx, "victim", "user")
		if err != nil {
			t.Fatal(err)
		}
		sess, err := svc.Login(ctx, "victim", temp)
		if err != nil {
			t.Fatal(err)
		}
		const leaked = "leaked old password"
		if sess, err = svc.ChangePassword(ctx, sess.User, temp, leaked); err != nil {
			t.Fatal(err)
		}

		var (
			stop   atomic.Bool
			mu     sync.Mutex
			tokens []string
			wg     sync.WaitGroup
		)
		for range 4 {
			wg.Go(func() {
				for !stop.Load() {
					if s, err := svc.Login(ctx, "victim", leaked); err == nil {
						mu.Lock()
						tokens = append(tokens, s.Token)
						mu.Unlock()
					}
				}
			})
		}
		time.Sleep(200 * time.Millisecond)
		if _, err := svc.ChangePassword(ctx, sess.User, leaked, "a brand new password"); err != nil {
			t.Fatal(err)
		}
		time.Sleep(200 * time.Millisecond)
		stop.Store(true)
		wg.Wait()

		for _, token := range tokens {
			if _, err := svc.Authenticate(ctx, token); err == nil {
				t.Fatalf("a session from the old password survived (%d logins)", len(tokens))
			}
		}
	})
}

// Temporary passwords forgive spaces from copying and lower case from
// typing; passwords that users chose are taken as they are.
func TestTemporaryPasswordSlips(t *testing.T) {
	svc, _ := authtest.NewService(time.Hour)
	ctx := context.Background()
	temp, err := svc.CreateUser(ctx, "carl", "user")
	if err != nil {
		t.Fatal(err)
	}
	sloppy := " " + strings.ToLower(temp) + "\t"
	sess, err := svc.Login(ctx, "carl", sloppy)
	if err != nil {
		t.Fatalf("sloppy temporary password: %v", err)
	}
	if _, err := svc.ChangePassword(ctx, sess.User, sloppy, "Chosen Password 1"); err != nil {
		t.Fatalf("change with a sloppy temporary password: %v", err)
	}
	for _, pw := range []string{"chosen password 1", " Chosen Password 1", temp} {
		if _, err := svc.Login(ctx, "carl", pw); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("Login(%q): %v", pw, err)
		}
	}
	if _, err := svc.Login(ctx, "carl", "Chosen Password 1"); err != nil {
		t.Error(err)
	}
}
