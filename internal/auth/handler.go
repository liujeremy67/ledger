package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"ledger/internal/oauth"
	"ledger/internal/storage"
)

// Handler wires HTTP requests to the OAuth providers and token manager.
type Handler struct {
	tokens    *TokenManager
	store     storage.RefreshStore
	providers map[string]oauth.Provider
}

// NewHandler builds a new auth HTTP handler bundle.
func NewHandler(tokens *TokenManager, store storage.RefreshStore, providers map[string]oauth.Provider) *Handler {
	return &Handler{
		tokens:    tokens,
		store:     store,
		providers: providers,
	}
}

// HandleOAuthLogin processes /auth/google or /auth/apple requests.
func (h *Handler) HandleOAuthLogin(providerName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provider, ok := h.providers[providerName]
		if !ok {
			http.Error(w, "unsupported provider", http.StatusBadRequest)
			return
		}

		var body oauthRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}

		if body.AuthCode == "" && body.IdentityToken == "" {
			http.Error(w, "credential required", http.StatusBadRequest)
			return
		}

		profile, err := provider.Authenticate(r.Context(), oauth.CredentialPayload{
			AuthCode:      body.AuthCode,
			IdentityToken: body.IdentityToken,
		})
		if err != nil {
			status := http.StatusUnauthorized
			if errors.Is(err, oauth.ErrProviderUnavailable) {
				status = http.StatusBadGateway
			}
			http.Error(w, err.Error(), status)
			return
		}

		h.issueTokens(w, r, profile, "")
	}
}

// HandleRefresh rotates refresh tokens and returns a new access token.
func (h *Handler) HandleRefresh() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body refreshRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RefreshToken == "" {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}

		record, err := h.store.Get(r.Context(), body.RefreshToken)
		if err != nil {
			http.Error(w, "invalid refresh token", http.StatusUnauthorized)
			return
		}

		if time.Now().After(record.ExpiresAt) {
			_ = h.store.Delete(r.Context(), body.RefreshToken)
			http.Error(w, "refresh token expired", http.StatusUnauthorized)
			return
		}

		profile := &oauth.UserProfile{
			ID:       record.UserID,
			Email:    record.Email,
			Provider: record.Provider,
		}

		h.issueTokens(w, r, profile, body.RefreshToken)
	}
}

// HandleProfile returns the authenticated user's claims.
func (h *Handler) HandleProfile() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var issuedAt time.Time
		if claims.IssuedAt != nil {
			issuedAt = claims.IssuedAt.Time
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"userId":   claims.UserID,
			"email":    claims.Email,
			"provider": claims.Provider,
			"issuedAt": issuedAt,
		})
	}
}

func (h *Handler) issueTokens(w http.ResponseWriter, r *http.Request, profile *oauth.UserProfile, previousRefresh string) {
	accessToken, accessExpiresAt, err := h.tokens.GenerateAccessToken(profile)
	if err != nil {
		http.Error(w, "unable to issue access token", http.StatusInternalServerError)
		return
	}

	refreshToken, refreshExpiresAt, err := h.tokens.GenerateRefreshToken()
	if err != nil {
		http.Error(w, "unable to issue refresh token", http.StatusInternalServerError)
		return
	}

	record := storage.RefreshRecord{
		Token:     refreshToken,
		UserID:    profile.ID,
		Email:     profile.Email,
		Provider:  profile.Provider,
		ExpiresAt: refreshExpiresAt,
	}

	if previousRefresh == "" {
		if err := h.store.Save(r.Context(), record); err != nil {
			http.Error(w, "unable to persist refresh token", http.StatusInternalServerError)
			return
		}
	} else {
		if err := h.store.Replace(r.Context(), previousRefresh, record); err != nil {
			http.Error(w, "unable to rotate refresh token", http.StatusInternalServerError)
			return
		}
	}

	response := tokenResponse{
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  accessExpiresAt,
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: refreshExpiresAt,
	}

	writeJSON(w, http.StatusOK, response)
}

type oauthRequest struct {
	AuthCode      string `json:"authCode"`
	IdentityToken string `json:"identityToken"`
}

type refreshRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type tokenResponse struct {
	AccessToken           string    `json:"accessToken"`
	AccessTokenExpiresAt  time.Time `json:"accessTokenExpiresAt"`
	RefreshToken          string    `json:"refreshToken"`
	RefreshTokenExpiresAt time.Time `json:"refreshTokenExpiresAt"`
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
