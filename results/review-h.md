# Review: stack h (Go + in-app OpenID provider on zitadel/oidc v3.51.16 + SpiceDB)

Reviewed 2026-10-19, branch `stack-h` (from `917b471`), against `ps-h` on cs-ws. Read `results/h.md`, the adapter (`go/internal/adapters/oidcop`), its migration, the tx-in-ctx change (`internal/db`, `core/executor.go`), `stacks/h/compose.yaml`, `conformance/stacks/h.ts`, and the parts of `zitadel/oidc` `pkg/op` the adapter relies on (authorize, callback, code and refresh exchange, revocation, end session, discovery, router, verifier). Probed the running stack with ad-hoc scripts (attacker flows, parallel requests, forged tokens).

**Suite after fixes:** **362/362** (30 skipped: the opt-in `idp-tenancy` tests), full run incl. the 65 s break-glass expiry, 109 s, stack rebuilt from this branch. Go: `go test ./...` passes; the issuer tests are 15 (was 12; `TestCallbackIssuesOneCode` replaced by `TestCodeOnlyToTheLogin`, plus `TestParallelGuessesCapped`, `TestHashConcurrency`, `TestAllKeysRetired`, and a wrong-secret start check in `TestKeysEncryptedAtRest`).

The builder's work holds up well. Every trap from reviews f and g was handled, and the checklist evidence reproduced: single-use codes (10 parallel → 1 × 200), refresh rotation (8 parallel → 1 winner; reuse revokes the family), ID token on the API → 401, forged `alg` / no signature / odd `kid` → 401, spoofed `Host` / `X-Forwarded-Host` / `Forwarded` → pinned issuer, PKCE plain/none and `response_type=token`/`id_token` refused, `request` objects refused, unknown grants refused. The one serious hole was in the part of the library the builder trusted without reading: the authorize callback.

## Findings, by severity

| # | sev | what | where | scenario | status |
|---|---|---|---|---|---|
| 1 | **high** | **The auth request id is a bearer token for the code.** The library's `GET /authorize/callback?id=` returns a 302 with the code to *anyone* who sends a done request's id; there is no binding to the browser that logged in. Whoever starts `/authorize` learns the id (it's in the redirect to `/login?id=`). | library `AuthorizeCallback` (`op/auth_request.go:505`), `users.go` `handleLogin` | Attacker starts `/authorize` with his own PKCE verifier, sends the victim the real login link (`/login?id=…`, on our domain), polls the callback. The victim logs in; the attacker reads the code from the callback's `Location` and redeems it with his verifier. **Reproduced**: attacker's token → `/api/me` 200 as the victim; the victim's own callback then got 400. Headless today, but this is exactly the flow a login page would have. | **fixed**: `POST /login` answers with the code itself (`op.AuthResponse` → 302 to the registered redirect URI); `/oidc/authorize/callback` is closed (404, also encoded and trailing-slash forms). Re-probed. Driver: one fewer hop |
| 2 | medium | **Lockout counted after the hash, so parallel guesses all got through.** `locked()` was checked before `authenticate`, `fail()` after; N requests in flight all pass the check. | `users.go`, `ratelimit.go` | 40 parallel wrong passwords on one email: **40 × 401** (cap is 10). Bounded by the IP bucket (burst 200), so ~200 guesses per 15 min window per source instead of 10. | **fixed**: `attempt()` counts before hashing (check and increment under one lock), a success gives the slot back. After: 10 × 401, 30 × 429. `TestParallelGuessesCapped` |
| 3 | medium | **Anyone can lock an app or agent out.** Failed `client_credentials` were counted per client id, from any source: 10 bad secrets for a known `cli_…` id → that client gets 429 for 15 min. Client ids aren't secret (token `sub`, shown to staff). With 256-bit secrets the lock protects nothing. | `ratelimit.go` `limitToken` | Reproduced: legit client → 429 after a third party's 10 failures. | **fixed**: key is client id + IP. Note: on this deployment every tailnet client arrives from one address (#4), so the probe from the Mac still shows 429 |
| 4 | medium | **All clients share one source IP here, so the per-IP and per-email+IP limits are global.** Requests from the Mac and from cs-ws localhost reach the app as the docker-proxy gateway (`192.168.96.1`); only a request to cs-ws's LAN address had its own key. So 10 wrong passwords from anyone locks that email for *every* user behind the same edge, and the 50/s bucket is shared by all. `X-Forwarded-For` is ignored (right by default), but there is no trusted-proxy setting. | `ratelimit.go` `clientIP`, deployment | 11 failures from the Mac → correct password from cs-ws `localhost` → 429. Production behind a load balancer has the same shape. | open: a `TRUSTED_PROXIES` CIDR list (rightmost untrusted `X-Forwarded-For` hop) plus a shared store for N instances; IPv6 needs /64 keys |
| 5 | low | argon2 concurrency followed CPUs, not memory. `hashSlots = GOMAXPROCS`: Go 1.27 reads the cgroup CPU quota, but the stack sets no CPU limit, so on a 32-core host 32 × 19 MiB would run inside the 256 MiB container and `GOMEMLIMIT` (soft) can't stop live memory. | `users.go` | By reading. | **fixed**: slots = min(GOMAXPROCS, GOMEMLIMIT/2 ÷ 19 MiB), ≥ 1. On cs-ws (4 CPUs, 200 MiB) still 4, so the builder's burst numbers stand. `TestHashConcurrency` |
| 6 | low | Retiring every key by hand (the "leaked key" step in h.md #8 without a rotation first) left no signing key: every login 500 until an instance restarted (`ensure` ran only at start). Also, a wrong `ISSUER_SECRET` started fine and then failed every token. | `keys.go`, `oidcop.go` | By reading; covered by tests now. | **fixed**: signing with no live key runs `ensure` (advisory lock, one key across instances); `New` loads and decrypts the keys at start and fails on a wrong secret. `TestAllKeysRetired`, `TestKeysEncryptedAtRest`. Still true: after `rotate`, retiring the old key before `PUBLISH_AHEAD` passes leaves no key that may sign yet (500s for up to a minute); the runbook is "rotate with `PUBLISH_AHEAD=0`, then retire" |
| 7 | low | Loopback match ignores the scheme and accepts the name `localhost`: with `http://127.0.0.1/callback` registered, `https://localhost/callback`, `http://localhost:9999/callback` and `http://[::ffff:127.0.0.1]:1/callback` are accepted. RFC 8252 §8.3 says not to use `localhost` (it resolves via DNS/hosts). | library `HTTPLoopbackOrLocalhost`, `matchesLoopbackRedirect` | Probed: all three → 302 to login. | open: a `CreateAuthRequest` check that the redirect's scheme and host equal the registered one (port free) |
| 8 | low | Stateless access tokens outlive everything for `ACCESS_TOKEN_TTL` (15 min): a deleted client, a disabled user, a revoked refresh family. `Verify` checks no row. | `oidcop.go` `Verify` | As h.md #11. | open (builder noted). In-process verification makes a cheap check possible: `idp_clients.deleted_at` / `idp_users.disabled_at` in the request's existing DB round trip |
| 9 | low | Hashing inside the request transaction: `CreateUser` waits for a hash slot while holding its pool connection; a sign-up burst queues logins behind it (40 connections, 4 slots). | `users.go` `CreateUser` | As h.md. No deadlock: slot holders don't need a second connection. | open (builder noted): hash before `Begin` |
| 10 | info | Discovery advertises what isn't served: `implicit`, `id_token` response types, `jwt-bearer`, the device, introspection and end-session endpoints. All refuse (probed: jwt-bearer 400, device 400 `unauthorized_client`, token-exchange/device-code `unsupported_grant_type`, introspection 401). `client_secret_post` works but isn't advertised. | library discovery | Cosmetic; a generic client may try them. | open |
| 11 | info | `end_session` accepts an **expired** ID token as `id_token_hint` (library choice) and revokes that user's refresh tokens for the client. Logout only; `post_logout_redirect_uri` to an unregistered URI → 400. | library `ValidateEndSessionRequest` | Probed the redirect. | open, acceptable |
| 12 | info | Test mode and the `ISSUER_SECRET` default in compose are public placeholders (same as every stack, P5). The secret also derives the library's code-encryption key, so it can't be rotated without re-encrypting keys and invalidating codes in flight. | `stacks/h/compose.yaml` | | open |

Checked and fine:
- **Code exchange**: the code is claimed in one `UPDATE … RETURNING` before client auth, so a stolen code presented by anyone is burned; `redirect_uri` and client id must match the request (library); public client must pass PKCE (ours enforces S256 at `/authorize`).
- **Refresh**: hashed, rotated in the statement that checks it, absolute family expiry, disabled users refused, client id must match (library `token_refresh.go:72`). `/revoke` revokes the family for raw tokens and for the library's hash id.
- **Token verification**: ES256 allowlist in the verifier *and* in `VerifySignature`, key looked up by `kid` among live keys only (embedded `jwk`/`jku` ignored), pinned `iss`, `exp`, then `token_use: access`, `aud`, and client rule. Only `GetPrivateClaimsFromScopes` adds `token_use`, and the library calls it for access tokens only (`CreateJWT`); `CreateIDToken` never does. ID tokens at `/userinfo` → 403.
- **Grants**: device and token exchange are off because storage doesn't implement them; JWT bearer is routed always but `GetKeyByIDAndClientID` refuses, and the same refusal covers `private_key_jwt` client assertions. Machine clients get no refresh token, can't use `/authorize` (no redirect URIs).
- **Encoded paths**: chi routes on `RawPath`, our wrapper checks `Path`; no path reaches a library route our checks miss.
- **Tx in ctx**: the only identity writes (`CreateUser` in testsupport, `CreateClient` in apps/agents) run inside `op.Run`; no goroutine gets the request ctx; reads that must not see uncommitted rows (login, client auth, token checks) use the pool. A rolled-back request leaves no row (builder's tests, re-run).
- **Keys at rest**: AES-256-GCM, random nonce, `kid` as AAD, key = SHA-256 of a domain-separated secret (≥ 32 chars enforced). Fine for a spike; production wants a KMS or at least a versioned key-encryption key.
- **CORS**: no CORS headers for any origin.

## Security checklist (h.md's 20), after this review

| # | item | h.md | now |
|---|---|---|---|
| 1 | Issuer from headers | library (pinned) | holds; re-probed |
| 2 | Open redirect / exact match | library | holds for non-loopback; loopback scheme/host looseness → #7 (low, open) |
| 3 | PKCE-only code flow | ours + library | holds; re-probed plain, none, `token`, `id_token`, request objects |
| 4 | Encoded-path gate bypass | n/a | holds; the new callback block checks both decoded and raw path |
| 5 | Single-use codes | ours | holds (10 parallel → 1). **Plus #1: who receives the code — was open, fixed** |
| 6 | Machine refresh tokens | library | holds |
| 7 | Multi-instance key race | ours | holds; `ensure` now also runs when no key is live (#6) |
| 8 | Rotation / retiring a leaked key | ours | holds; hand-retire without rotation no longer stops logins (#6); runbook note on `PUBLISH_AHEAD` |
| 9 | Enumeration by timing | ours | holds |
| 10 | Rate limiting / lockout | ours | **was bypassable in parallel (#2), fixed**; client lockout DoS (#3) fixed; still per instance, and per-IP collapses behind a proxy (#4, open) |
| 11 | Revocation, `DeleteClient` | partly open | unchanged (#8) |
| 12 | ID token as access token | ours | holds; re-probed, and checked the library adds `token_use` only to access tokens |
| 13 | Default CORS | ours | holds |
| 14 | Grants on by default | ours | holds; discovery still lists them (#10) |
| 15 | Keys at rest | ours | holds; wrong secret now fails at start (#6) |
| 16 | Machine client secrets | ours | holds |
| 17 | Refresh token theft | ours | holds; re-probed parallel refresh and reuse |
| 18 | Password hashing as DoS | ours | slots now bounded by memory too (#5) |
| 19 | Login CSRF, sessions | open | open, but the worse half (code to whoever holds the id, #1) is fixed; CSRF still needed with a login page |
| 20 | Test mode | open | open |

New items to add to the list: **21** who receives the code (the callback endpoint, #1); **22** client lockout as DoS (#3); **23** source IP behind a proxy (#4).

## Library claims (h.md "What production would still need"), checked in v3.51.16

All accurate:
- **MFA / passkeys**: nothing in `pkg/` (no WebAuthn, TOTP); `amr`/`acr` are passed through from storage.
- **SSO federation**: `pkg/client/rp` is an OIDC RP; no SAML anywhere.
- **RFC 8707 resource indicators**: `resource` is only a field of `TokenExchangeRequest` (`oidc/token_request.go:260`); the authorize and code/refresh token requests don't parse it.
- **Dynamic client registration / CIMD**: only discovery fields (`registration_endpoint`, `client_id_metadata_document_supported` in `oidc/discovery.go`); no endpoint, no fetching.
- **DPoP**: `oidc/dpop.go` binds ID tokens (`dpop_jkt`); no DPoP-bound access tokens.

## Ops (spot checks)

- Rebuilt twice on cs-ws (load high from other workspaces); `up --wait` healthy each time.
- 40-request parallel login burst after fix #2: 10 hashed, 30 refused before hashing, app stayed healthy.
- Two instances, OOM numbers and cold start: not re-measured; the fixes don't touch those paths except the hash cap, which is unchanged at 4 on cs-ws.

## Verdict: "own the issuer in-process with zitadel/oidc" for a Go platform

**Agree with the builder, with the price stated more sharply.**

- The library is good: certified protocol code, readable, and every protocol check I probed held. In h the bugs are in the glue, as h.md says.
- But the glue contains endpoints the builder didn't write. The callback hole (#1) sat in a library endpoint the integrator never calls; the library's example login flow redirects to the same callback with only the id. Binding the code to the browser that logged in is left to the login UI, and nothing in the storage contract says so. Finding it took reading `AuthorizeCallback`, not our code. That's the real cost of h: owning an auth server means reviewing the library's flows *as deployed*, not only the 930 lines we wrote. Three of the four medium/high findings here were in the space between the library and our login step or our limiter.
- After this review the auth core (codes, refresh, keys, verification) is in good shape for "password login + machine clients". What's left before production is ordinary auth-server work: a trusted-proxy and shared limiter (#4), a login page with a session and CSRF (19), a row check for revoked clients/users (#8), and a security review per feature added (MFA, reset, SSO), each of which Zitadel ships.
- So the recommendation stands as h.md wrote it: h if the roadmap stays near "login + machine clients" and the team commits to an auth-focused review whenever the login step or the library version changes; Zitadel (a) if MFA, passkeys, merchant SSO or self-service accounts are near. The port swap (no module changes) keeps the door open either way.

## Fixed in this review (commits on `stack-h`)

1. `0c2eaf2` Code only to the login POST, callback closed (#1); attempt-counted lockout (#2); client lock per client + IP (#3); hash slots bounded by `GOMEMLIMIT` (#5); key self-heal and start-time decrypt check (#6). Driver updated (one fewer redirect).
2. This report.
