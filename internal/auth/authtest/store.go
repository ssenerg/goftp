// Package authtest provides an in-memory auth.Store for tests.
package authtest

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"

	"goftp/internal/auth"
)

type Store struct {
	mu       sync.Mutex
	nextID   int64
	users    map[int64]*auth.User
	sessions map[string]session
}

type session struct {
	userID  int64
	expires time.Time
}

var _ auth.Store = (*Store)(nil)

func NewStore() *Store {
	return &Store{users: make(map[int64]*auth.User), sessions: make(map[string]session)}
}

// NewService returns a service with an empty store and the default policy.
func NewService(ttl time.Duration) (*auth.Service, *Store) {
	e, err := auth.NewEnforcer(nil)
	if err != nil {
		panic(err)
	}
	st := NewStore()
	return auth.NewService(st, e, ttl), st
}

// Sessions returns the number of stored sessions.
func (s *Store) Sessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

func (s *Store) CreateUser(_ context.Context, username, passwordHash string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.Username == username {
			return 0, auth.ErrExists
		}
	}
	s.nextID++
	s.users[s.nextID] = &auth.User{ID: s.nextID, Username: username, PasswordHash: passwordHash,
		MustChangePassword: true, CreatedAt: time.Now()}
	return s.nextID, nil
}

func (s *Store) UserByName(_ context.Context, username string) (*auth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.users {
		if u.Username == username {
			c := *u
			return &c, nil
		}
	}
	return nil, auth.ErrNotFound
}

func (s *Store) ListUsers(context.Context) ([]auth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []auth.User
	for _, u := range s.users {
		out = append(out, *u)
	}
	slices.SortFunc(out, func(a, b auth.User) int { return strings.Compare(a.Username, b.Username) })
	return out, nil
}

func (s *Store) SetPassword(_ context.Context, userID int64, passwordHash string, mustChange bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return auth.ErrNotFound
	}
	u.PasswordHash, u.MustChangePassword = passwordHash, mustChange
	s.deleteSessions(userID)
	return nil
}

func (s *Store) DeleteUser(_ context.Context, userID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[userID]; !ok {
		return auth.ErrNotFound
	}
	delete(s.users, userID)
	s.deleteSessions(userID)
	return nil
}

func (s *Store) CreateSession(_ context.Context, tokenHash []byte, u *auth.User, expires time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.users[u.ID]; !ok || cur.PasswordHash != u.PasswordHash {
		return auth.ErrNotFound
	}
	s.sessions[string(tokenHash)] = session{userID: u.ID, expires: expires}
	return nil
}

func (s *Store) SessionUser(_ context.Context, tokenHash []byte) (*auth.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.sessions[string(tokenHash)]
	if !ok || !time.Now().Before(v.expires) {
		return nil, auth.ErrNotFound
	}
	c := *s.users[v.userID]
	return &c, nil
}

func (s *Store) DeleteSession(_ context.Context, tokenHash []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, string(tokenHash))
	return nil
}

func (s *Store) deleteSessions(userID int64) {
	for k, v := range s.sessions {
		if v.userID == userID {
			delete(s.sessions, k)
		}
	}
}

func (s *Store) DeleteExpiredSessions(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.sessions {
		if !time.Now().Before(v.expires) {
			delete(s.sessions, k)
		}
	}
	return nil
}
