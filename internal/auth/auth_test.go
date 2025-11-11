package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"ledger/internal/oauth"
	"ledger/internal/storage"
)

const testJWTSecret = "test-secret"

func TestTokenManagerGenerateAndParseAccessToken(t *testing.T) {
	tokens := NewTokenManager(testJWTSecret, time.Minute, time.Hour)
	user := &oauth.UserProfile{
		ID:       "user-123",
		Email:    "user@example.com",
		Provider: oauth.ProviderGoogle,
	}

	accessToken, expiresAt, err := tokens.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("GenerateAccessToken returned error: %v", err)
	}
	if accessToken == "" {
		t.Fatalf("expected signed token, got empty string")
	}
	if expiresAt.Before(time.Now().Add(30*time.Second)) || expiresAt.After(time.Now().Add(90*time.Second)) {
		t.Fatalf("unexpected expiry %s", expiresAt)
	}

	claims, err := tokens.Parse(accessToken)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if claims.UserID != user.ID || claims.Email != user.Email || claims.Provider != user.Provider {
		t.Fatalf("claims mismatch: %#v", claims)
	}
	if claims.Subject != user.ID {
		t.Fatalf("expected subject %s, got %s", user.ID, claims.Subject)
	}
}

func TestTokenManagerGenerateRefreshToken(t *testing.T) {
	tokens := NewTokenManager(testJWTSecret, time.Minute, time.Hour)

	tokenA, expiresA, err := tokens.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken returned error: %v", err)
	}
	tokenB, expiresB, err := tokens.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken returned error: %v", err)
	}

	if tokenA == "" || tokenB == "" {
		t.Fatalf("expected non-empty refresh tokens")
	}
	if tokenA == tokenB {
		t.Fatalf("expected refresh tokens to be random")
	}
	if time.Until(expiresA) < 59*time.Minute || time.Until(expiresB) < 59*time.Minute {
		t.Fatalf("expected refresh tokens to expire in the future")
	}
}

func TestTokenManagerParseRejectsUnexpectedSigningMethod(t *testing.T) {
	tokens := NewTokenManager(testJWTSecret, time.Minute, time.Hour)

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, Claims{
		UserID: "user-123",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-123",
		},
	})

	signed, err := token.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("SignedString returned error: %v", err)
	}

	if _, err := tokens.Parse(signed); err == nil || !strings.Contains(err.Error(), "unexpected signing method") {
		t.Fatalf("expected signing method error, got %v", err)
	}
}

func TestTokenManagerFromRequest(t *testing.T) {
	tokens := NewTokenManager(testJWTSecret, time.Minute, time.Hour)
	user := &oauth.UserProfile{ID: "user-1"}
	signed, _, err := tokens.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("GenerateAccessToken returned error: %v", err)
	}

	t.Run("success", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		req.Header.Set("Authorization", "Bearer "+signed)
		claims, err := tokens.FromRequest(req)
		if err != nil {
			t.Fatalf("FromRequest returned error: %v", err)
		}
		if claims.UserID != user.ID {
			t.Fatalf("expected user id %s, got %s", user.ID, claims.UserID)
		}
	})

	t.Run("missing header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		if _, err := tokens.FromRequest(req); err == nil || !strings.Contains(err.Error(), "missing authorization header") {
			t.Fatalf("expected missing header error, got %v", err)
		}
	})

	t.Run("invalid scheme", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/me", nil)
		req.Header.Set("Authorization", "Basic "+signed)
		if _, err := tokens.FromRequest(req); err == nil || !strings.Contains(err.Error(), "invalid authorization header") {
			t.Fatalf("expected invalid scheme error, got %v", err)
		}
	})
}

func TestContextHelpers(t *testing.T) {
	claims := &Claims{UserID: "abc"}
	ctx := ContextWithClaims(context.Background(), claims)
	got, ok := ClaimsFromContext(ctx)
	if !ok || got != claims {
		t.Fatalf("expected to retrieve claims from context")
	}
}

func TestMiddlewareRequireAuth(t *testing.T) {
	tokens := NewTokenManager(testJWTSecret, time.Minute, time.Hour)
	user := &oauth.UserProfile{ID: "user-1"}
	signed, _, err := tokens.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("GenerateAccessToken returned error: %v", err)
	}

	middleware := NewMiddleware(tokens)
	var called bool
	protected := middleware.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		claims, ok := ClaimsFromContext(r.Context())
		if !ok || claims.UserID != user.ID {
			t.Fatalf("expected claims in context")
		}
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rr := httptest.NewRecorder()
	protected(rr, req)

	if !called {
		t.Fatalf("expected handler to be called")
	}
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected status %d, got %d", http.StatusNoContent, rr.Code)
	}
}

func TestMiddlewareRequireAuthUnauthorized(t *testing.T) {
	middleware := NewMiddleware(NewTokenManager(testJWTSecret, time.Minute, time.Hour))
	protected := middleware.RequireAuth(func(w http.ResponseWriter, r *http.Request) {})

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	rr := httptest.NewRecorder()
	protected(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestHandleOAuthLoginSuccess(t *testing.T) {
	store := storage.NewMemoryRefreshStore()
	tokens := NewTokenManager(testJWTSecret, time.Minute, time.Hour)
	profile := &oauth.UserProfile{
		ID:       "user-123",
		Email:    "user@example.com",
		Provider: oauth.ProviderGoogle,
	}
	provider := &stubProvider{profile: profile}

	handler := NewHandler(tokens, store, map[string]oauth.Provider{
		oauth.ProviderGoogle: provider,
	})

	req := newJSONRequest(t, http.MethodPost, "/auth/google", oauthRequest{AuthCode: "code-123"})
	rr := httptest.NewRecorder()

	handler.HandleOAuthLogin(oauth.ProviderGoogle)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	var response tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if response.AccessToken == "" || response.RefreshToken == "" {
		t.Fatalf("expected tokens in response")
	}

	record, err := store.Get(context.Background(), response.RefreshToken)
	if err != nil {
		t.Fatalf("expected refresh token to be stored: %v", err)
	}
	if record.UserID != profile.ID || record.Email != profile.Email || record.Provider != profile.Provider {
		t.Fatalf("stored record mismatch: %#v", record)
	}

	if provider.lastPayload.AuthCode != "code-123" {
		t.Fatalf("expected provider to receive auth code")
	}
}

func TestHandleOAuthLoginErrors(t *testing.T) {
	cases := []struct {
		name       string
		payload    any
		provider   *stubProvider
		providers  map[string]oauth.Provider
		expectCode int
	}{
		{
			name:       "unsupported provider",
			payload:    oauthRequest{AuthCode: "a"},
			providers:  map[string]oauth.Provider{},
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "invalid payload",
			payload:    "{",
			providers:  map[string]oauth.Provider{oauth.ProviderGoogle: &stubProvider{}},
			expectCode: http.StatusBadRequest,
		},
		{
			name:       "missing credential",
			payload:    oauthRequest{},
			providers:  map[string]oauth.Provider{oauth.ProviderGoogle: &stubProvider{}},
			expectCode: http.StatusBadRequest,
		},
		{
			name:    "provider unavailable",
			payload: oauthRequest{AuthCode: "a"},
			provider: &stubProvider{
				err: oauth.ErrProviderUnavailable,
			},
			providers:  map[string]oauth.Provider{},
			expectCode: http.StatusBadGateway,
		},
		{
			name:    "provider invalid credential",
			payload: oauthRequest{AuthCode: "a"},
			provider: &stubProvider{
				err: oauth.ErrInvalidCredential,
			},
			providers:  map[string]oauth.Provider{},
			expectCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			providers := tc.providers
			if tc.provider != nil {
				providers = map[string]oauth.Provider{oauth.ProviderGoogle: tc.provider}
			}

			handler := NewHandler(NewTokenManager(testJWTSecret, time.Minute, time.Hour), storage.NewMemoryRefreshStore(), providers)

			var req *http.Request
			switch payload := tc.payload.(type) {
			case string:
				req = httptest.NewRequest(http.MethodPost, "/auth/google", strings.NewReader(payload))
			default:
				req = newJSONRequest(t, http.MethodPost, "/auth/google", payload)
			}

			rr := httptest.NewRecorder()
			handler.HandleOAuthLogin(oauth.ProviderGoogle)(rr, req)

			if rr.Code != tc.expectCode {
				t.Fatalf("expected status %d, got %d (%s)", tc.expectCode, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestHandleOAuthLoginStoreError(t *testing.T) {
	storeErr := errors.New("boom")
	store := &stubRefreshStore{
		saveFn: func(ctx context.Context, record storage.RefreshRecord) error {
			return storeErr
		},
	}

	provider := &stubProvider{profile: &oauth.UserProfile{
		ID:       "user",
		Email:    "user@example.com",
		Provider: oauth.ProviderGoogle,
	}}

	handler := NewHandler(NewTokenManager(testJWTSecret, time.Minute, time.Hour), store, map[string]oauth.Provider{
		oauth.ProviderGoogle: provider,
	})

	req := newJSONRequest(t, http.MethodPost, "/auth/google", oauthRequest{AuthCode: "code"})
	rr := httptest.NewRecorder()
	handler.HandleOAuthLogin(oauth.ProviderGoogle)(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "persist refresh token") {
		t.Fatalf("unexpected error message: %s", rr.Body.String())
	}
}

func TestHandleRefreshSuccess(t *testing.T) {
	store := storage.NewMemoryRefreshStore()
	record := storage.RefreshRecord{
		Token:     "refresh-1",
		UserID:    "user-1",
		Email:     "user@example.com",
		Provider:  oauth.ProviderGoogle,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := store.Save(context.Background(), record); err != nil {
		t.Fatalf("failed to seed store: %v", err)
	}

	handler := NewHandler(NewTokenManager(testJWTSecret, time.Minute, time.Hour), store, nil)
	req := newJSONRequest(t, http.MethodPost, "/auth/refresh", refreshRequest{RefreshToken: record.Token})
	rr := httptest.NewRecorder()
	handler.HandleRefresh()(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rr.Code, rr.Body.String())
	}

	var response tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("invalid json: %v", err)
	}

	if response.RefreshToken == record.Token {
		t.Fatalf("expected refresh token rotation")
	}

	if _, err := store.Get(context.Background(), response.RefreshToken); err != nil {
		t.Fatalf("expected new token to be stored: %v", err)
	}

	if _, err := store.Get(context.Background(), record.Token); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected previous token to be deleted")
	}
}

func TestHandleRefreshErrors(t *testing.T) {
	handler := NewHandler(NewTokenManager(testJWTSecret, time.Minute, time.Hour), storage.NewMemoryRefreshStore(), nil)

	t.Run("invalid payload", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/refresh", strings.NewReader("{"))
		rr := httptest.NewRecorder()
		handler.HandleRefresh()(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("missing refresh token", func(t *testing.T) {
		req := newJSONRequest(t, http.MethodPost, "/auth/refresh", refreshRequest{})
		rr := httptest.NewRecorder()
		handler.HandleRefresh()(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rr.Code)
		}
	})

	t.Run("not found", func(t *testing.T) {
		req := newJSONRequest(t, http.MethodPost, "/auth/refresh", refreshRequest{RefreshToken: "missing"})
		rr := httptest.NewRecorder()
		handler.HandleRefresh()(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rr.Code)
		}
	})
}

func TestHandleRefreshExpiredToken(t *testing.T) {
	store := storage.NewMemoryRefreshStore()
	record := storage.RefreshRecord{
		Token:     "expired",
		UserID:    "user",
		Email:     "user@example.com",
		Provider:  oauth.ProviderGoogle,
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	_ = store.Save(context.Background(), record)

	handler := NewHandler(NewTokenManager(testJWTSecret, time.Minute, time.Hour), store, nil)
	req := newJSONRequest(t, http.MethodPost, "/auth/refresh", refreshRequest{RefreshToken: record.Token})
	rr := httptest.NewRecorder()
	handler.HandleRefresh()(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}

	if _, err := store.Get(context.Background(), record.Token); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("expected expired token to be deleted")
	}
}

func TestHandleRefreshStoreReplaceError(t *testing.T) {
	storeErr := errors.New("boom")
	store := &stubRefreshStore{
		getFn: func(ctx context.Context, token string) (storage.RefreshRecord, error) {
			return storage.RefreshRecord{
				Token:     token,
				UserID:    "user",
				Email:     "user@example.com",
				Provider:  oauth.ProviderGoogle,
				ExpiresAt: time.Now().Add(time.Hour),
			}, nil
		},
		replaceFn: func(ctx context.Context, previousToken string, next storage.RefreshRecord) error {
			return storeErr
		},
	}

	handler := NewHandler(NewTokenManager(testJWTSecret, time.Minute, time.Hour), store, nil)
	req := newJSONRequest(t, http.MethodPost, "/auth/refresh", refreshRequest{RefreshToken: "token"})
	rr := httptest.NewRecorder()
	handler.HandleRefresh()(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "rotate refresh token") {
		t.Fatalf("unexpected error message: %s", rr.Body.String())
	}
}

func TestHandleProfile(t *testing.T) {
	handler := NewHandler(NewTokenManager(testJWTSecret, time.Minute, time.Hour), storage.NewMemoryRefreshStore(), nil)

	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	claims := &Claims{UserID: "user", Email: "user@example.com", Provider: oauth.ProviderGoogle, RegisteredClaims: jwt.RegisteredClaims{
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}}
	req = req.WithContext(ContextWithClaims(req.Context(), claims))
	rr := httptest.NewRecorder()
	handler.HandleProfile()(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if payload["userId"] != claims.UserID || payload["email"] != claims.Email || payload["provider"] != claims.Provider {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestHandleProfileUnauthorized(t *testing.T) {
	handler := NewHandler(NewTokenManager(testJWTSecret, time.Minute, time.Hour), storage.NewMemoryRefreshStore(), nil)
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	rr := httptest.NewRecorder()
	handler.HandleProfile()(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

type stubProvider struct {
	profile     *oauth.UserProfile
	err         error
	lastPayload oauth.CredentialPayload
}

func (p *stubProvider) Name() string {
	if p.profile != nil {
		return p.profile.Provider
	}
	return ""
}

func (p *stubProvider) Authenticate(ctx context.Context, payload oauth.CredentialPayload) (*oauth.UserProfile, error) {
	p.lastPayload = payload
	if p.err != nil {
		return nil, p.err
	}
	if p.profile == nil {
		return nil, errors.New("no profile configured")
	}
	return p.profile, nil
}

type stubRefreshStore struct {
	saveFn    func(context.Context, storage.RefreshRecord) error
	getFn     func(context.Context, string) (storage.RefreshRecord, error)
	deleteFn  func(context.Context, string) error
	replaceFn func(context.Context, string, storage.RefreshRecord) error
}

func (s *stubRefreshStore) Save(ctx context.Context, record storage.RefreshRecord) error {
	if s.saveFn != nil {
		return s.saveFn(ctx, record)
	}
	return nil
}

func (s *stubRefreshStore) Get(ctx context.Context, token string) (storage.RefreshRecord, error) {
	if s.getFn != nil {
		return s.getFn(ctx, token)
	}
	return storage.RefreshRecord{}, storage.ErrNotFound
}

func (s *stubRefreshStore) Delete(ctx context.Context, token string) error {
	if s.deleteFn != nil {
		return s.deleteFn(ctx, token)
	}
	return nil
}

func (s *stubRefreshStore) Replace(ctx context.Context, previousToken string, next storage.RefreshRecord) error {
	if s.replaceFn != nil {
		return s.replaceFn(ctx, previousToken, next)
	}
	_ = s.Delete(ctx, previousToken)
	return s.Save(ctx, next)
}

func newJSONRequest(t *testing.T, method, target string, payload any) *http.Request {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}
