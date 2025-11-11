package server

import (
	"log"
	"net/http"
	"time"

	"ledger/internal/auth"
	"ledger/internal/oauth"
)

// NewRouter wires HTTP routes to handlers and middleware.
func NewRouter(handler *auth.Handler, middleware *auth.Middleware) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.Handle("POST /auth/google", handler.HandleOAuthLogin(oauth.ProviderGoogle))
	mux.Handle("POST /auth/apple", handler.HandleOAuthLogin(oauth.ProviderApple))
	mux.Handle("POST /auth/refresh", handler.HandleRefresh())
	mux.Handle("GET /me", middleware.RequireAuth(handler.HandleProfile()))

	return logRequests(mux)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}
