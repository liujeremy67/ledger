package oauth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const appleJWKSURL = "https://appleid.apple.com/auth/keys"

// AppleProvider verifies Sign in with Apple identity tokens.
type AppleProvider struct {
	clientID   string
	httpClient *http.Client

	cacheTTL time.Duration

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	expiresAt time.Time
}

// NewAppleProvider builds a provider that validates Apple identity tokens (JWTs).
func NewAppleProvider(clientID string) *AppleProvider {
	return &AppleProvider{
		clientID:   clientID,
		httpClient: http.DefaultClient,
		cacheTTL:   6 * time.Hour,
		keys:       map[string]*rsa.PublicKey{},
	}
}

// Name implements Provider.
func (p *AppleProvider) Name() string {
	return ProviderApple
}

// Authenticate validates the identity token from Apple and returns the normalized profile.
func (p *AppleProvider) Authenticate(ctx context.Context, payload CredentialPayload) (*UserProfile, error) {
	if payload.IdentityToken == "" {
		return nil, errors.New("apple: identity token required")
	}

	claims := &appleIDTokenClaims{}
	token, err := jwt.ParseWithClaims(payload.IdentityToken, claims, p.keyFunc(ctx), jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || token == nil {
		return nil, fmt.Errorf("apple: token parse failed: %w", ErrInvalidCredential)
	}

	if claims.Subject == "" {
		return nil, fmt.Errorf("apple: missing subject: %w", ErrInvalidCredential)
	}

	if p.clientID != "" && (len(claims.Audience) == 0 || !audienceContains(claims.Audience, p.clientID)) {
		return nil, fmt.Errorf("apple: invalid audience: %w", ErrInvalidCredential)
	}

	if claims.Issuer != "https://appleid.apple.com" {
		return nil, fmt.Errorf("apple: invalid issuer: %w", ErrInvalidCredential)
	}

	return &UserProfile{
		ID:       claims.Subject,
		Email:    claims.Email,
		Name:     claims.Name(),
		Provider: ProviderApple,
	}, nil
}

func (p *AppleProvider) keyFunc(ctx context.Context) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("apple: missing kid header")
		}

		return p.lookupKey(ctx, kid)
	}
}

func (p *AppleProvider) lookupKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	now := time.Now()
	p.mu.RLock()
	if now.Before(p.expiresAt) {
		if key, ok := p.keys[kid]; ok {
			p.mu.RUnlock()
			return key, nil
		}
	}
	p.mu.RUnlock()

	p.mu.Lock()
	defer p.mu.Unlock()

	if now.Before(p.expiresAt) {
		if key, ok := p.keys[kid]; ok {
			return key, nil
		}
	}

	keys, err := p.fetchKeys(ctx)
	if err != nil {
		return nil, err
	}

	p.keys = keys
	p.expiresAt = time.Now().Add(p.cacheTTL)

	key, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("apple: key %s not found", kid)
	}

	return key, nil
}

func (p *AppleProvider) fetchKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, appleJWKSURL, nil)
	if err != nil {
		return nil, err
	}

	res, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("apple: jwks fetch failed: %w", ErrProviderUnavailable)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("apple: jwks status %d: %w", res.StatusCode, ErrProviderUnavailable)
	}

	var payload struct {
		Keys []appleJWK `json:"keys"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return nil, err
	}

	if len(payload.Keys) == 0 {
		return nil, errors.New("apple: jwks empty")
	}

	keys := make(map[string]*rsa.PublicKey, len(payload.Keys))
	for _, jwk := range payload.Keys {
		key, err := jwk.toPublicKey()
		if err != nil {
			return nil, err
		}
		keys[jwk.Kid] = key
	}

	return keys, nil
}

type appleJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (k appleJWK) toPublicKey() (*rsa.PublicKey, error) {
	if k.Kty != "RSA" {
		return nil, errors.New("apple: unsupported key type")
	}

	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("apple: decode modulus: %w", err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("apple: decode exponent: %w", err)
	}

	e := 0
	for _, b := range eb {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: e,
	}, nil
}

type appleIDTokenClaims struct {
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	AuthTime      int64  `json:"auth_time"`
	jwt.RegisteredClaims
}

func (c *appleIDTokenClaims) Name() string {
	switch {
	case c.GivenName != "" && c.FamilyName != "":
		return c.GivenName + " " + c.FamilyName
	case c.GivenName != "":
		return c.GivenName
	default:
		return c.FamilyName
	}
}

func audienceContains(aud jwt.ClaimStrings, target string) bool {
	for _, value := range aud {
		if value == target {
			return true
		}
	}
	return false
}
