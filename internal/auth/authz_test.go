package auth_test

import (
	"testing"

	"goftp/internal/auth"
)

func TestDefaultPolicy(t *testing.T) {
	e, err := auth.NewEnforcer(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		role string
		acts map[string]bool
	}{
		{"user", map[string]bool{auth.ActRead: true, auth.ActWrite: false, auth.ActOverwrite: false, auth.ActDelete: false}},
		{"operator", map[string]bool{auth.ActRead: true, auth.ActWrite: true, auth.ActOverwrite: false, auth.ActDelete: false}},
		{"admin", map[string]bool{auth.ActRead: true, auth.ActWrite: true, auth.ActOverwrite: true, auth.ActDelete: true}},
		{"superadmin", map[string]bool{auth.ActRead: true, auth.ActWrite: true, auth.ActOverwrite: true, auth.ActDelete: true, "anything": true}},
		{auth.Anonymous, map[string]bool{auth.ActRead: false}},
	} {
		if _, err := e.AddRoleForUser(auth.Subject("u-"+tc.role), tc.role); err != nil {
			t.Fatal(err)
		}
		for act, want := range tc.acts {
			for _, obj := range []string{"/", "/a.txt", "/deep/dir/"} {
				if got, err := e.Enforce(auth.Subject("u-"+tc.role), obj, act); got != want || err != nil {
					t.Errorf("%s %s %s = %v, %v", tc.role, act, obj, got, err)
				}
			}
		}
	}
	// A user named like a role does not hold it.
	if ok, _ := e.Enforce(auth.Subject("admin"), "/", auth.ActRead); ok {
		t.Error("user admin holds the admin role")
	}
}

func TestPathPatterns(t *testing.T) {
	e, err := auth.NewEnforcer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddPolicy("user:bob", "/docs/*", auth.ActRead); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddPolicy("user:bob", "/list/", auth.ActRead); err != nil {
		t.Fatal(err)
	}
	for obj, want := range map[string]bool{
		"/docs/": true, "/docs/a.txt": true, "/docs/sub/b": true, "/docs": false, "/docsx": false, "/": false,
		"/list/": true, "/list/a.txt": false,
	} {
		if got, _ := e.Enforce("user:bob", obj, auth.ActRead); got != want {
			t.Errorf("%s: %v, want %v", obj, got, want)
		}
	}
}
