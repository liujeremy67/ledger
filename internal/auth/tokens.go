package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"ledger/internal/oauth"
)

// Claims defines the JWT payload shared with the mobile client.
type Claims struct {
	UserID   string `json:"uid"`
	Email    string `json:"email"`
	Provider string `json:"prv"`
	jwt.RegisteredClaims
}

// TokenManager issues and validates access/refresh tokens for the API.
type TokenManager struct {
	secret        []byte
	accessTTL     time.Duration
	refreshTTL    time.Duration
	signingMethod jwt.SigningMethod
}

// NewTokenManager builds a TokenManager with the provided secret and lifetimes.
func NewTokenManager(secret string, accessTTL, refreshTTL time.Duration) *TokenManager {
	return &TokenManager{
		secret:        []byte(secret),
		accessTTL:     accessTTL,
		refreshTTL:    refreshTTL,
		signingMethod: jwt.SigningMethodHS256,
	}
}

// GenerateAccessToken creates a signed JWT for the given user profile.
func (m *TokenManager) GenerateAccessToken(user *oauth.UserProfile) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(m.accessTTL)

	claims := Claims{
		UserID:   user.ID,
		Email:    user.Email,
		Provider: user.Provider,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(m.signingMethod, claims)
	signed, err := token.SignedString(m.secret)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expiresAt, nil
}

// GenerateRefreshToken returns a random refresh token string suitable for storage.
func (m *TokenManager) GenerateRefreshToken() (string, time.Time, error) {
	buf := make([]byte, 48)
	if _, err := rand.Read(buf); err != nil {
		return "", time.Time{}, err
	}
	expiresAt := time.Now().Add(m.refreshTTL)
	return base64.RawURLEncoding.EncodeToString(buf), expiresAt, nil
}

// Parse verifies a JWT string and returns its claims.
func (m *TokenManager) Parse(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != m.signingMethod {
			return nil, errors.New("unexpected signing method")
		}
		return m.secret, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}

// FromRequest extracts and validates the Authorization header from an HTTP request.
func (m *TokenManager) FromRequest(r *http.Request) (*Claims, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, errors.New("missing authorization header")
	}

	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, errors.New("invalid authorization header")
	}

	return m.Parse(parts[1])
}

type contextKey string

const claimsContextKey contextKey = "authClaims"

// ContextWithClaims stores the JWT claims in context for downstream handlers.
func ContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsContextKey, claims)
}

// ClaimsFromContext retrieves claims from the request context.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(*Claims)
	return claims, ok
}

// Middleware validates JWTs before protected handlers run.
type Middleware struct {
	tokens *TokenManager
}

// NewMiddleware creates a middleware wrapper.
func NewMiddleware(tokens *TokenManager) *Middleware {
	return &Middleware{tokens: tokens}
}

// RequireAuth ensures a valid JWT is present, otherwise it responds with 401.
func (m *Middleware) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := m.tokens.FromRequest(r)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		ctx := ContextWithClaims(r.Context(), claims)
		next(w, r.WithContext(ctx))
	}
}
