package auth

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
)

type User struct {
	ID                 int64
	Username           string
	PasswordHash       string
	MustChangePassword bool
	CreatedAt          time.Time
}

// Store persists users and sessions. Sessions are keyed by the SHA-256
// hash of their token.
type Store interface {
	CreateUser(ctx context.Context, username, passwordHash string) (int64, error)
	UserByName(ctx context.Context, username string) (*User, error)
	ListUsers(ctx context.Context) ([]User, error)
	// SetPassword also ends all of the user's sessions.
	SetPassword(ctx context.Context, userID int64, passwordHash string, mustChange bool) error
	DeleteUser(ctx context.Context, userID int64) error

	// CreateSession may drop the user's oldest sessions to bound their number.
	CreateSession(ctx context.Context, tokenHash []byte, userID int64, expires time.Time) error
	// SessionUser returns the user of an unexpired session.
	SessionUser(ctx context.Context, tokenHash []byte) (*User, error)
	DeleteSession(ctx context.Context, tokenHash []byte) error
	DeleteExpiredSessions(ctx context.Context) error
}
