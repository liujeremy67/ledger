package config

import (
	"log"
	"os"
	"strconv"
	"time"
)

// Config contains runtime configuration for the auth server.
type Config struct {
	HTTPAddr        string
	JWTSecret       string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration

	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string

	AppleClientID string
	AppleTeamID   string
	AppleKeyID    string
	AppleKey      string
}

// Load reads configuration from environment variables, falling back to sensible defaults for local development.
func Load() Config {
	cfg := Config{
		HTTPAddr:        getEnv("HTTP_ADDR", ":8080"),
		JWTSecret:       getEnv("JWT_SECRET", "dev-secret-change-me"),
		AccessTokenTTL:  getEnvDuration("ACCESS_TOKEN_TTL", 15*time.Minute),
		RefreshTokenTTL: getEnvDuration("REFRESH_TOKEN_TTL", 30*24*time.Hour),

		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURL:  getEnv("GOOGLE_REDIRECT_URL", "http://localhost:3000/auth/google/callback"),

		AppleClientID: os.Getenv("APPLE_CLIENT_ID"),
		AppleTeamID:   os.Getenv("APPLE_TEAM_ID"),
		AppleKeyID:    os.Getenv("APPLE_KEY_ID"),
		AppleKey:      os.Getenv("APPLE_PRIVATE_KEY"),
	}

	if cfg.JWTSecret == "" {
		log.Fatal("JWT_SECRET must not be empty")
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if dur, err := time.ParseDuration(value); err == nil {
			return dur
		}

		if minutes, err := strconv.Atoi(value); err == nil {
			return time.Duration(minutes) * time.Minute
		}
	}
	return fallback
}
