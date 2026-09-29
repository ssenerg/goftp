package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/casbin/casbin/v3"
	"go.uber.org/zap"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrSamePassword       = fmt.Errorf("%w: the new password must differ from the current one", ErrWeakPassword)
)

// Service authenticates users with sessions and authorizes their requests
// with Casbin.
type Service struct {
	store    Store
	enforcer *casbin.SyncedEnforcer
	ttl      time.Duration

	// hashing bounds concurrent Argon2 runs, which take 19 MiB each.
	hashing   chan struct{}
	dummyOnce sync.Once
	dummy     string
}

func NewService(store Store, enforcer *casbin.SyncedEnforcer, sessionTTL time.Duration) *Service {
	return &Service{
		store:    store,
		enforcer: enforcer,
		ttl:      sessionTTL,
		hashing:  make(chan struct{}, runtime.GOMAXPROCS(0)),
	}
}

// Enforcer exposes the policy enforcer.
func (s *Service) Enforcer() *casbin.SyncedEnforcer { return s.enforcer }

func (s *Service) acquireHashing(ctx context.Context) (func(), error) {
	select {
	case s.hashing <- struct{}{}:
		return func() { <-s.hashing }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// verify checks password against u's hash. For unknown users (u == nil) it
// verifies against a dummy hash, so response times do not reveal which
// usernames exist.
func (s *Service) verify(ctx context.Context, u *User, password string) (bool, error) {
	release, err := s.acquireHashing(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	if u == nil {
		s.dummyOnce.Do(func() { s.dummy = hashPassword(rand.Text()) })
		verifyPassword(s.dummy, password)
		return false, nil
	}
	return verifyPassword(u.PasswordHash, password), nil
}

func (s *Service) hash(ctx context.Context, password string) (string, error) {
	release, err := s.acquireHashing(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	return hashPassword(password), nil
}

// NormalizeUsername lowercases and trims a username as typed by a person.
func NormalizeUsername(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// Session is a signed-in user with their session token.
type Session struct {
	Token   string
	Expires time.Time
	User    *User
}

// Login checks the credentials and starts a session.
func (s *Service) Login(ctx context.Context, username, password string) (*Session, error) {
	username = NormalizeUsername(username)
	if password == "" || len(password) > MaxPasswordLength || checkUsername(username) != nil {
		return nil, ErrInvalidCredentials
	}
	u, err := s.store.UserByName(ctx, username)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	ok, err := s.verify(ctx, u, password)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrInvalidCredentials
	}
	return s.newSession(ctx, u)
}

func (s *Service) newSession(ctx context.Context, u *User) (*Session, error) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	sess := &Session{Token: base64.RawURLEncoding.EncodeToString(b), Expires: time.Now().Add(s.ttl), User: u}
	if err := s.store.CreateSession(ctx, tokenHash(sess.Token), u.ID, sess.Expires); err != nil {
		return nil, err
	}
	return sess, nil
}

func tokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// Authenticate returns the user of a live session, or ErrNotFound.
func (s *Service) Authenticate(ctx context.Context, token string) (*User, error) {
	if len(token) != 43 {
		return nil, ErrNotFound
	}
	return s.store.SessionUser(ctx, tokenHash(token))
}

func (s *Service) Logout(ctx context.Context, token string) error {
	return s.store.DeleteSession(ctx, tokenHash(token))
}

// ChangePassword replaces u's password after checking the current one. All
// of u's sessions end and a new one starts.
func (s *Service) ChangePassword(ctx context.Context, u *User, current, next string) (*Session, error) {
	if len(current) > MaxPasswordLength {
		return nil, ErrInvalidCredentials
	}
	ok, err := s.verify(ctx, u, current)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrInvalidCredentials
	}
	if err := CheckPassword(u.Username, next); err != nil {
		return nil, err
	}
	if next == current {
		return nil, ErrSamePassword
	}
	hash, err := s.hash(ctx, next)
	if err != nil {
		return nil, err
	}
	if err := s.store.SetPassword(ctx, u.ID, hash, false); err != nil {
		return nil, err
	}
	changed := *u
	changed.PasswordHash, changed.MustChangePassword = hash, false
	return s.newSession(ctx, &changed)
}

// Allowed reports whether u (nil for anonymous) may perform act on obj.
// Signing in never takes away what anonymous visitors may do.
func (s *Service) Allowed(u *User, obj, act string) (bool, error) {
	if u != nil {
		if ok, err := s.enforcer.Enforce(Subject(u.Username), obj, act); ok || err != nil {
			return ok, err
		}
	}
	return s.enforcer.Enforce(Anonymous, obj, act)
}

// Role returns the roles assigned to username, comma separated.
func (s *Service) Role(username string) string {
	roles, _ := s.enforcer.GetRolesForUser(Subject(username))
	return strings.Join(roles, ",")
}

// PurgeSessions deletes expired sessions periodically until ctx ends.
func (s *Service) PurgeSessions(ctx context.Context, every time.Duration, log *zap.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := s.store.DeleteExpiredSessions(ctx); err != nil && ctx.Err() == nil {
			log.Warn("purge sessions", zap.Error(err))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
