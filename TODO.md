# TODO / Flow Map

High-level journey for the Ledger auth service, with current status for each hop in the flow.

1. **Client obtains provider credential** – user signs in with Google or Apple, client collects `authCode` or `identityToken`. _Status: external dependency (informational)._
2. **API receives `/auth/{provider}` request and validates payload** – rejects unsupported providers, bad JSON, or missing credentials. _Status: ✅ implemented via `auth.Handler.HandleOAuthLogin`.#
3. **OAuth provider adapters verify upstream tokens and normalize the profile** – Google OAuth code/ID token exchanges and Apple identity token verification. _Status: ✅ `internal/oauth`.#
4. **Token manager issues JWT access tokens and random refresh tokens** – uses symmetric signing, embeds profile claims, and sets TTLs. _Status: ✅ `internal/auth.TokenManager`.#
5. **Refresh tokens persist and rotate** – store saves new tokens, rotates on refresh, and expires stale entries. _Status: ✅ `internal/storage.MemoryRefreshStore`.#
6. **Protected routes enforce JWT auth + expose `/me` profile** – middleware validates Authorization headers, handler returns claims to clients. _Status: ✅ `auth.Middleware` + `HandleProfile`.#
7. **Future: durable refresh-store + provider webhooks** – move beyond in-memory storage, add revocation/webhook plumbing. _Status: ☐ planned enhancement._
