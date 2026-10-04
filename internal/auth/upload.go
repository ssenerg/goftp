package auth

import (
	"context"
	"time"
)

// CreateUpload records an unfinished upload, which expires after keep, and
// returns its token.
func (s *Service) CreateUpload(ctx context.Context, up *Upload, keep time.Duration) (string, error) {
	token := newToken()
	if err := s.store.CreateUpload(ctx, tokenHash(token), up, keep); err != nil {
		return "", err
	}
	return token, nil
}

// UploadByToken returns the unfinished upload with token, unless it expired
// or ended (ErrNotFound).
func (s *Service) UploadByToken(ctx context.Context, token string) (*Upload, error) {
	if !ValidToken(token) {
		return nil, ErrNotFound
	}
	return s.store.UploadByToken(ctx, tokenHash(token))
}

// ClaimUpload makes writer the one writer of upload id for lease, unless
// another writer's claim still holds (false).
func (s *Service) ClaimUpload(ctx context.Context, id int64, writer string, lease time.Duration) (bool, error) {
	return s.store.ClaimUpload(ctx, id, writer, lease)
}

// ExtendUpload renews writer's claim for lease and keeps the upload for keep
// from now; false if writer lost the claim.
func (s *Service) ExtendUpload(ctx context.Context, id int64, writer string, lease, keep time.Duration) (bool, error) {
	return s.store.ExtendUpload(ctx, id, writer, lease, keep)
}

// ReleaseUpload ends writer's claim and keeps the upload for keep from now.
func (s *Service) ReleaseUpload(ctx context.Context, id int64, writer string, keep time.Duration) error {
	return s.store.ReleaseUpload(ctx, id, writer, keep)
}

// DeleteUpload forgets an upload, finished or abandoned.
func (s *Service) DeleteUpload(ctx context.Context, id int64) error {
	return s.store.DeleteUpload(ctx, id)
}

// TakeExpiredUploads forgets up to limit expired uploads that no writer
// claims, and returns them, so their data can be removed.
func (s *Service) TakeExpiredUploads(ctx context.Context, limit int) ([]Upload, error) {
	return s.store.TakeExpiredUploads(ctx, limit)
}
