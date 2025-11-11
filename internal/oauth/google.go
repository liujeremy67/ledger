package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	googleUserInfoEndpoint  = "https://www.googleapis.com/oauth2/v3/userinfo"
	googleTokenInfoEndpoint = "https://oauth2.googleapis.com/tokeninfo"
)

// GoogleProvider verifies Google Sign-In (OAuth) responses and builds a normalized profile.
type GoogleProvider struct {
	config     *oauth2.Config
	httpClient *http.Client
}

// NewGoogleProvider builds a Google provider backed by the provided OAuth client credentials.
func NewGoogleProvider(clientID, clientSecret, redirectURL string, scopes []string) *GoogleProvider {
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	return &GoogleProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     google.Endpoint,
			RedirectURL:  redirectURL,
			Scopes:       scopes,
		},
		httpClient: http.DefaultClient,
	}
}

// Name implements Provider.
func (p *GoogleProvider) Name() string {
	return ProviderGoogle
}

// Authenticate validates the credential payload with Google and returns the associated user profile.
func (p *GoogleProvider) Authenticate(ctx context.Context, payload CredentialPayload) (*UserProfile, error) {
	switch {
	case payload.AuthCode != "":
		return p.authenticateWithCode(ctx, payload.AuthCode)
	case payload.IdentityToken != "":
		return p.authenticateWithIDToken(ctx, payload.IdentityToken)
	default:
		return nil, errors.New("google: missing auth code or id token")
	}
}

func (p *GoogleProvider) authenticateWithCode(ctx context.Context, code string) (*UserProfile, error) {
	token, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("google: exchange failed: %w", ErrInvalidCredential)
	}

	if !token.Valid() || token.AccessToken == "" {
		return nil, fmt.Errorf("google: empty access token: %w", ErrInvalidCredential)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleUserInfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	res, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("google: userinfo request failed: %w", ErrProviderUnavailable)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google: userinfo status %d: %w", res.StatusCode, ErrInvalidCredential)
	}

	var payload googleUserInfoResponse
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return nil, err
	}

	if payload.Sub == "" {
		return nil, fmt.Errorf("google: missing subject: %w", ErrInvalidCredential)
	}

	return payload.toUserProfile(), nil
}

func (p *GoogleProvider) authenticateWithIDToken(ctx context.Context, idToken string) (*UserProfile, error) {
	endpoint, _ := url.Parse(googleTokenInfoEndpoint)
	query := endpoint.Query()
	query.Set("id_token", idToken)
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}

	res, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("google: tokeninfo request failed: %w", ErrProviderUnavailable)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google: invalid id token: %w", ErrInvalidCredential)
	}

	var payload googleTokenInfoResponse
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return nil, err
	}

	if payload.Sub == "" {
		return nil, fmt.Errorf("google: missing subject: %w", ErrInvalidCredential)
	}

	return payload.toUserProfile(), nil
}

type googleUserInfoResponse struct {
	Sub     string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
}

type googleTokenInfoResponse struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func (p googleUserInfoResponse) toUserProfile() *UserProfile {
	return &UserProfile{
		ID:       p.Sub,
		Email:    p.Email,
		Name:     p.Name,
		Picture:  p.Picture,
		Provider: ProviderGoogle,
	}
}

func (p googleTokenInfoResponse) toUserProfile() *UserProfile {
	return &UserProfile{
		ID:       p.Sub,
		Email:    p.Email,
		Name:     p.Name,
		Provider: ProviderGoogle,
	}
}
