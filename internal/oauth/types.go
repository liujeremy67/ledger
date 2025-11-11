package oauth

import (
	"context"
	"errors"
)

const (
	ProviderGoogle = "google"
	ProviderApple  = "apple"
)

var (
	// ErrInvalidCredential indicates the upstream credential is invalid or expired.
	ErrInvalidCredential = errors.New("invalid credential")
	// ErrProviderUnavailable indicates the upstream provider cannot be reached.
	ErrProviderUnavailable = errors.New("identity provider unavailable")
)

// CredentialPayload represents the data sent by the mobile client after a successful sign-in with an identity provider.
type CredentialPayload struct {
	AuthCode      string
	IdentityToken string
}

// UserProfile is the normalized identity data shared by all providers.
type UserProfile struct {
	ID       string
	Email    string
	Name     string
	Picture  string
	Provider string
}

// Provider verifies upstream credentials (Google, Apple, etc.) and returns a normalized profile.
type Provider interface {
	Name() string
	Authenticate(ctx context.Context, payload CredentialPayload) (*UserProfile, error)
}
