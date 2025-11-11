# OAuth + JWT Auth Server

This Go service exchanges Google or Apple sign-in credentials for first-party JWT access tokens and opaque refresh tokens that mobile apps can store securely. Access tokens expire quickly (default 15 min) and protect every API route via middleware, while refresh tokens (default 30 days) are rotated on each `/auth/refresh` call.

## Configuration

Environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `HTTP_ADDR` | `:8080` | Listen address |
| `JWT_SECRET` | _required_ | HMAC secret for first-party JWTs |
| `ACCESS_TOKEN_TTL` | `15m` | Access token lifetime (duration string or minutes) |
| `REFRESH_TOKEN_TTL` | `720h` | Refresh token lifetime (30 days) |
| `GOOGLE_CLIENT_ID` | – | Google OAuth client ID (required for auth-code flow) |
| `GOOGLE_CLIENT_SECRET` | – | Google OAuth client secret |
| `GOOGLE_REDIRECT_URL` | `http://localhost:3000/auth/google/callback` | OAuth redirect used for auth-code exchanges |
| `APPLE_CLIENT_ID` | – | Service ID used when verifying Apple identity tokens |

## Running locally

```bash
export JWT_SECRET="dev-secret"
go run ./cmd/server
```

### OAuth endpoints

- `POST /auth/google` — body `{ "authCode": "..."} ` or `{ "identityToken": "..." }`
- `POST /auth/apple` — body `{ "identityToken": "..." }`
- `POST /auth/refresh` — body `{ "refreshToken": "..." }`

Example login flow:

```bash
curl -X POST http://localhost:8080/auth/google \
  -H "Content-Type: application/json" \
  -d '{"identityToken":"<google-id-token>"}'
```

On success:

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIs...",
  "accessTokenExpiresAt": "2024-05-20T12:34:56Z",
  "refreshToken": "4fJk...",
  "refreshTokenExpiresAt": "2024-06-19T12:34:56Z"
}
```

Use the access token for protected routes:

```bash
curl http://localhost:8080/me \
  -H "Authorization: Bearer <access token>"
```

When a 401 is returned because the access token expired, ask for a new pair:

```bash
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<latest refresh token>"}'
```

The server issues a fresh access token **and** rotates the refresh token (old tokens are deleted immediately).

## Call flow reference

- `cmd/server/main.go:main` loads env/config, instantiates the `auth.TokenManager`, in-memory `storage.RefreshStore`, provider map, middleware, and passes them into `internal/server/router.go:NewRouter`.

**OAuth login (`POST /auth/{google|apple}`)**
- Route wiring in `internal/server/router.go:NewRouter` maps the endpoint to `internal/auth/handler.go:HandleOAuthLogin`.
- The handler decodes the request and calls the matching provider's `Authenticate` implementation (`internal/oauth/google.go` or `internal/oauth/apple.go`) to validate the upstream credential and return an `oauth.UserProfile`.
- `internal/auth/handler.go:issueTokens` calls `internal/auth/tokens.go:TokenManager.GenerateAccessToken` and `GenerateRefreshToken`, then persists the refresh token through `internal/storage/refresh_store.go:RefreshStore.Save`.

**Token refresh (`POST /auth/refresh`)**
- `internal/auth/handler.go:HandleRefresh` pulls the submitted token from the `RefreshStore` (`Get`), checks expiry, and rebuilds the user profile.
- `issueTokens` issues a new pair and rotates the stored value via `RefreshStore.Replace`, ensuring the previous refresh token becomes invalid immediately.

**Protected profile (`GET /me`)**
- `internal/server/router.go:NewRouter` wraps the handler with `internal/auth/tokens.go:Middleware.RequireAuth`, which relies on `TokenManager.FromRequest`/`Parse` to validate the `Authorization` header and inject claims via `ContextWithClaims`.
- `internal/auth/handler.go:HandleProfile` reads the claims with `ClaimsFromContext` and returns the normalized identity payload.

## Notes

- Refresh tokens are kept in-memory for simplicity; plug in Redis, Postgres, or another datastore by implementing `internal/storage.RefreshStore`.
- Apple token verification fetches and caches the current JWKS from Apple. Google auth supports both auth-code exchanges and ID-token validation via the tokeninfo endpoint.
- Middleware in `internal/auth` validates JWTs on every protected route, returning `401` when missing/expired so the mobile client can trigger the silent refresh flow described in the app spec.
