package storage

import (
	"context"
	"errors"
	"sync"
	"time"
)

// RefreshRecord represents a persisted refresh token and the user it belongs to.
type RefreshRecord struct {
	Token     string
	UserID    string
	Email     string
	Provider  string
	ExpiresAt time.Time
}

// ErrNotFound indicates that a refresh token does not exist (or has already been used).
var ErrNotFound = errors.New("refresh token not found")

// RefreshStore persists refresh tokens so they can be validated and rotated.
type RefreshStore interface {
	Save(ctx context.Context, record RefreshRecord) error
	Get(ctx context.Context, token string) (RefreshRecord, error)
	Delete(ctx context.Context, token string) error
	Replace(ctx context.Context, previousToken string, next RefreshRecord) error
}

// MemoryRefreshStore keeps refresh tokens in-memory. Useful for demos and tests, but not production-ready.
type MemoryRefreshStore struct {
	mu     sync.RWMutex
	tokens map[string]RefreshRecord
}

// NewMemoryRefreshStore returns a new in-memory store.
func NewMemoryRefreshStore() *MemoryRefreshStore {
	return &MemoryRefreshStore{
		tokens: map[string]RefreshRecord{},
	}
}

// Save stores (or overwrites) a refresh token.
func (s *MemoryRefreshStore) Save(_ context.Context, record RefreshRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[record.Token] = record
	return nil
}

// Get returns a refresh token if present.
func (s *MemoryRefreshStore) Get(_ context.Context, token string) (RefreshRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, ok := s.tokens[token]
	if !ok {
		return RefreshRecord{}, ErrNotFound
	}
	return record, nil
}

// Delete removes a refresh token.
func (s *MemoryRefreshStore) Delete(_ context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
	return nil
}

// Replace atomically swaps an existing refresh token with a new one.
func (s *MemoryRefreshStore) Replace(ctx context.Context, previousToken string, next RefreshRecord) error {
	if err := s.Delete(ctx, previousToken); err != nil {
		return err
	}
	return s.Save(ctx, next)
}

// CleanupExpired removes expired tokens and returns the number of deleted items.
func (s *MemoryRefreshStore) CleanupExpired(_ context.Context, now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for token, record := range s.tokens {
		if record.ExpiresAt.Before(now) {
			delete(s.tokens, token)
			count++
		}
	}
	return count
}
