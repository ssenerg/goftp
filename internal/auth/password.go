package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters: the OWASP recommended minimum.
const (
	argonTime    = 2
	argonMemory  = 19 * 1024 // KiB
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16
)

const (
	MinPasswordLength = 12
	MaxPasswordLength = 256
)

// Superadmin is the role that administers users and rules.
const Superadmin = "superadmin"

// Roles, from most to least privileged.
var Roles = []string{Superadmin, "admin", "operator", "user"}

var (
	ErrWeakPassword    = errors.New("password does not meet the policy")
	ErrInvalidUsername = errors.New("username must be 2-32 characters of a-z, 0-9, '.', '_' or '-', starting with a letter or digit")
	ErrInvalidRole     = fmt.Errorf("role must be one of %s", strings.Join(Roles, ", "))
)

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,31}$`)

func checkUsername(name string) error {
	if !ValidUsername(name) {
		return ErrInvalidUsername
	}
	return nil
}

func ValidUsername(name string) bool { return usernameRe.MatchString(name) }

func checkRole(role string) error {
	if !slices.Contains(Roles, role) {
		return ErrInvalidRole
	}
	return nil
}

// CheckPassword enforces the password policy for username.
func CheckPassword(username, password string) error {
	switch n := utf8.RuneCountInString(password); {
	case n < MinPasswordLength:
		return fmt.Errorf("%w: use at least %d characters", ErrWeakPassword, MinPasswordLength)
	case len(password) > MaxPasswordLength:
		return fmt.Errorf("%w: use at most %d bytes", ErrWeakPassword, MaxPasswordLength)
	case strings.EqualFold(password, username):
		return fmt.Errorf("%w: it must differ from the username", ErrWeakPassword)
	}
	return nil
}

// TemporaryPassword returns a random password for a new or reset account:
// 26 upper-case letters and digits.
func TemporaryPassword() string {
	return rand.Text()
}

// forgiveTemporary undoes slips in entering a temporary password: spaces
// picked up when copying it, lower-case letters when typing it.
func forgiveTemporary(password string) string {
	return strings.ToUpper(strings.TrimSpace(password))
}

// hashPassword returns an Argon2id hash in PHC string format.
func hashPassword(password string) string {
	salt := make([]byte, argonSaltLen)
	_, _ = rand.Read(salt)
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

// verifyPassword reports whether password matches an encoded hash.
func verifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return false
	}
	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil ||
		memory > 1<<21 || time > 16 || threads == 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(key) < 16 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(key)))
	return subtle.ConstantTimeCompare(got, key) == 1
}
