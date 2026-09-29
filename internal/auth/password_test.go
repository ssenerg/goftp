package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestHashAndVerify(t *testing.T) {
	h := hashPassword("correct horse")
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("hash %q", h)
	}
	if h == hashPassword("correct horse") {
		t.Error("hashes are not salted")
	}
	if !verifyPassword(h, "correct horse") || verifyPassword(h, "correct horsE") || verifyPassword(h, "") {
		t.Error("verification is wrong")
	}

	parts := strings.Split(h, "$")
	for _, bad := range []string{
		"", "plain", strings.Replace(h, "argon2id", "argon2i", 1),
		strings.Replace(h, "v=19", "v=16", 1),
		// Parameters from the database must not make verification a DoS.
		strings.Replace(h, "m=19456", "m=4194304", 1),
		strings.Replace(h, "t=2", "t=100", 1),
		strings.Replace(h, "p=1", "p=0", 1),
		strings.Join(append(parts[:5:5], "AAAA"), "$"),
		strings.Join(append(parts[:4:4], "!!", parts[5]), "$"),
	} {
		if verifyPassword(bad, "correct horse") {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestCheckPassword(t *testing.T) {
	for pw, ok := range map[string]bool{
		"twelve chars":           true,
		"eleven char":            false,
		"ééééééééééé":            false, // 11 runes, 22 bytes
		"éééééééééééé":           true,
		strings.Repeat("x", 256): true,
		strings.Repeat("x", 257): false,
		"Alice.Smith1":           false, // the username
	} {
		err := CheckPassword("alice.smith1", pw)
		if (err == nil) != ok || (err != nil && !errors.Is(err, ErrWeakPassword)) {
			t.Errorf("CheckPassword(%q) = %v", pw, err)
		}
	}
}

func TestValidUsername(t *testing.T) {
	for name, ok := range map[string]bool{
		"al": true, "alice": true, "a.b_c-d": true, "0day": true, strings.Repeat("a", 32): true,
		"a": false, "Alice": false, ".alice": false, "-a": false, "al ice": false, "user:x": false,
		strings.Repeat("a", 33): false, "": false, "élan": false,
	} {
		if ValidUsername(name) != ok {
			t.Errorf("ValidUsername(%q) = %v", name, !ok)
		}
	}
}

func TestTemporaryPassword(t *testing.T) {
	a, b := TemporaryPassword(), TemporaryPassword()
	if a == b || len(a) < MinPasswordLength || CheckPassword("someone", a) != nil {
		t.Errorf("temporary passwords %q %q", a, b)
	}
}

// Password checks give up when all hashing slots stay busy.
func TestHashingSlots(t *testing.T) {
	defer func(d time.Duration) { hashWait = d }(hashWait)
	hashWait = 20 * time.Millisecond
	s := &Service{hashing: make(chan struct{}, 1)}
	release, err := s.acquireHashing(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.acquireHashing(context.Background()); !errors.Is(err, ErrBusy) {
		t.Errorf("second check: %v", err)
	}
	release()
	if release, err = s.acquireHashing(context.Background()); err != nil {
		t.Errorf("after release: %v", err)
	} else {
		release()
	}
}
