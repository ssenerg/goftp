package auth

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
	ErrTooMany  = errors.New("too many")
)

type User struct {
	ID                 int64
	Username           string
	PasswordHash       string
	MustChangePassword bool
	CreatedAt          time.Time
}

// Share is a link that lets people without an account read a file or
// folder until it expires.
type Share struct {
	ID           int64
	Path         string // URL path of the shared file or folder
	IsDir        bool
	PasswordHash string // empty when the link needs no password
	CreatedBy    int64
	Creator      string // the username of CreatedBy
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

// Store persists users, sessions and share links. Sessions and links are
// keyed by the SHA-256 hash of their token.
type Store interface {
	CreateUser(ctx context.Context, username, passwordHash string) (int64, error)
	UserByName(ctx context.Context, username string) (*User, error)
	ListUsers(ctx context.Context) ([]User, error)
	// SetPassword also ends all of the user's sessions and, for a
	// temporary password (mustChange), their share links.
	SetPassword(ctx context.Context, userID int64, passwordHash string, mustChange bool) error
	// DeleteUser also deletes the user's sessions and share links.
	DeleteUser(ctx context.Context, userID int64) error

	// CreateSession starts a session for u, unless u was deleted or changed
	// password since it was read (ErrNotFound). It may drop the user's
	// oldest sessions to bound their number.
	CreateSession(ctx context.Context, tokenHash []byte, u *User, expires time.Time) error
	// SessionUser returns the user of an unexpired session.
	SessionUser(ctx context.Context, tokenHash []byte) (*User, error)
	DeleteSession(ctx context.Context, tokenHash []byte) error
	DeleteExpiredSessions(ctx context.Context) error

	// CreateShare stores sh and sets its ID and CreatedAt, unless its
	// creator was deleted (ErrNotFound) or has MaxShares unexpired links
	// already (ErrTooMany).
	CreateShare(ctx context.Context, tokenHash []byte, sh *Share) error
	// ShareByToken returns an unexpired share link.
	ShareByToken(ctx context.Context, tokenHash []byte) (*Share, error)
	// Shares lists the unexpired links created by userID, or by anyone if
	// userID is 0, newest first.
	Shares(ctx context.Context, userID int64) ([]Share, error)
	// DeleteShare deletes the link id if userID created it, or whoever did
	// if userID is 0.
	DeleteShare(ctx context.Context, id, userID int64) error
	DeleteExpiredShares(ctx context.Context) error
}
