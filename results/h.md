# Stack h results: Go + in-app OpenID provider (zitadel/oidc v3.51.16) + SpiceDB v1.56.2

Stack a with Zitadel replaced by an issuer inside the Go app: `github.com/zitadel/oidc/v3` `pkg/op` (OpenID Certified), with users, machine clients, auth requests, refresh tokens and signing keys in the app's own Postgres. SpiceDB, modules and kernel as in a. `IDP=oidcop` picks the adapter (`go/internal/adapters/oidcop`). Run 2026-10-19 against `ps-h` on cs-ws (`DOCKER_HOST=ssh://cs-ws docker compose -p ps-h --profile h up -d --build`), app on 8094, nothing else published. The fallback (`ory/fosite`) wasn't needed.

The question: what does it take for a Go app to own identity in-process on a maintained, certified library, and how much code and security surface do we then own?

## Conformance

`cd conformance && STACK=h HOST=cs-ws.lab.alexluong.com MAX_WORKERS=2 pnpm test`

| run | result |
|---|---|
| first run, `SKIP_SLOW=1` | 361 passed, 1 skipped (61 s) |
| full, incl. the 65 s break-glass expiry | **362 / 362** (112 s) |
| full again, on a fresh `down -v` stack with a second app instance running | **362 / 362** (69 s) |

The 30 skipped are the opt-in `idp-tenancy` tests (§15.4). No failures, none by design. cs-ws ran at load 9–14 on 4 CPUs throughout (other workspaces).

Go tests: 12 new integration tests in `go/internal/adapters/oidcop/oidcop_test.go` (real Postgres, `OIDCOP_TEST_DATABASE_URL`, skipped without it), one per checklist item below. `go test ./...` passes.

**Changes outside the adapter, composition roots, compose and driver:**
- `internal/db`: `Querier`, `WithTx`/`TxOr` (the request's tx in `ctx`), and `MigrateFS` (the old `Migrate` now calls it). +25 LOC.
- `internal/core/executor.go`: one line, `op.Run(db.WithTx(ctx, tx), r)`.
- `internal/identity`: `DeleteClient` on `Provisioner`, `ErrNotSupported`. Zitadel, Ory and Logto adapters return `ErrNotSupported` (3 lines each).
- Modules: none. Migrations of the app: none (the issuer has its own, `schema/001_issuer.sql`, run by the bootstrap).

## Lines of code we own (non-blank, non-comment)

| area | file | LOC |
|---|---|---|
| storage: auth requests and codes | `storage.go` | 90 |
| storage: access/refresh tokens (rotation, reuse detection, revoke) | `storage.go` | 95 |
| storage: clients (login client, machine clients, secret check) | `storage.go` | 68 |
| storage: claims, userinfo, refusals (introspection, JWT bearer), key glue | `storage.go` | 72 |
| signing keys (create under lock, encrypt at rest, cache + reload, rotate, verify) | `keys.go` | 203 |
| users and login (argon2id, dummy hash, headless login step) | `users.go` | 118 |
| rate limiting (per IP, per email+IP, per email, per client id) | `ratelimit.go` | 126 |
| provider setup, verifier, CreateClient/DeleteClient, mount, sweep | `oidcop.go` | 156 |
| **adapter total (Go)** | | **928** |
| migrations | `schema/001_issuer.sql` | 49 |
| composition roots (`server`, `bootstrap`: config, mount hook, `rotate-signing-key`) | `go/cmd` | +76 |
| kernel (tx in ctx, `MigrateFS`) and port | `internal/{db,core,identity}` | +31 |
| tests | `oidcop_test.go` | 588 |
| driver | `conformance/stacks/h.ts` | 70 |
| compose | `stacks/h/compose.yaml` | 91 |

**Compared with the other identity adapters:** Zitadel 265, Ory 180, Logto 295, Better Auth 113, OpenAuth 182 (142 + 40 storage). h is ~3.5× Zitadel's adapter and ~5× OpenAuth's. Every external-IdP adapter is HTTP glue around a server someone else runs; h's 928 lines are the auth server's policy and state.

**What the library gives for free** (~8k LOC in `pkg/op`, `pkg/oidc`, `pkg/crypto`, `pkg/http`): request parsing for every endpoint, client validation, exact redirect matching (RFC 8252 loopback rules), response-type and scope checks, PKCE verification, client authentication (basic, post, private_key_jwt), JWT signing and encoding, ID tokens, JWKS, discovery, userinfo, revocation and introspection endpoints, error responses that redirect only to registered URIs, and the grants (code, refresh, client_credentials, device, token exchange, JWT profile). We wrote no protocol code.

**What it leaves to us:** everything about state and policy. Roughly half our lines are rules the storage interface has to enforce and the library doesn't: atomic code redemption, one code per request, PKCE S256 only, refresh rotation and reuse detection, the key lifecycle, telling access tokens from ID tokens, refusing grants it turns on by default, rate limits.

## Security checklist (from review-f, review-g, review-a 8)

| # | item | who | how / evidence |
|---|---|---|---|
| 1 | Issuer from `Host` / `X-Forwarded-*` | **library**, if you pick it | `op.StaticIssuer(PUBLIC_URL + "/oidc")`. The library also ships `IssuerFromHost` / `IssuerFromForwardedOrHost`, so the trap is one constructor away. Probed from cs-ws with spoofed `Host`, `X-Forwarded-Host`, `Forwarded`: issuer unchanged. `TestIssuerPinned`. http issuers need `WithAllowInsecure()`. |
| 2 | Open redirect, exact redirect match | **library** | Exact match; unknown client or unregistered URI → 400, no redirect; errors go only to a registered URI. Native clients: a loopback redirect matches on path and query, **any port and any loopback host** (`127.0.0.2`, `localhost`, `[::1]`). That's RFC 8252's intent; not a hole (the code stays on the user's machine). `TestAuthorizeRejects` |
| 3 | PKCE-only code flow, no implicit | **ours** (5 lines) + library | The library accepts implicit flows, `plain` PKCE, and no PKCE at `/authorize` (it requires PKCE only at `/token`, for public clients). The login client allows only `code`; `CreateAuthRequest` refuses anything but S256. Discovery still advertises `implicit`, `id_token`, `jwt-bearer` (cosmetic, open). |
| 4 | Encoded-path gate bypass (`/%61uthorize`) | **n/a** | No gate of ours to bypass: the library validates inside `/authorize`. `/%61uthorize`, `/AUTHORIZE`, `/%6Fidc/…` → 404 (chi routes on the raw path); `//authorize` → redirect to our own clean path. |
| 5 | Single-use codes | **ours** | The storage contract is read (`AuthRequestByCode`), then delete after issuing: parallel `/token` calls could redeem one code twice. Our lookup *claims* the code in one `UPDATE … RETURNING`. 8 parallel exchanges → exactly 1 token; a wrong verifier burns the code. A second callback visit can't mint a second code. `TestCodeSingleUse`, `TestCallbackIssuesOneCode` |
| 6 | Refresh tokens for machine clients | **library** | None issued for `client_credentials`. Machine clients have only that grant (refresh → refused). Verified live and in `TestMachineClientsInTx`. |
| 7 | Multi-instance key race | **ours** | First key created at server start under `pg_advisory_xact_lock`. 3 × (`down -v`, two instances started together): 1 key, identical JWKS on both. |
| 8 | Key rotation, JWKS refresh, retiring a leaked key | **ours** | Keys reload every 30 s and on an unknown `kid` (at most every 5 s). `bootstrap rotate-signing-key` publishes a key that signs after `PUBLISH_AHEAD` and retires the old one after `RETIRE_AFTER`. Live with 2 instances: rotated without a restart, app2's new-key token → 200 on app1, old token still 200 during overlap; `retire_at=now()` on the old key → **401 on both within 30 s**. `TestTwoInstancesAndRotation` |
| 9 | Account enumeration by timing | **ours** | Unknown email verifies against a dummy argon2id hash. `TestLoginTimingUnknownVsWrong` (ratio within 0.5–2); live: unknown email 33 ms. |
| 10 | Rate limiting / lockout | **ours** | In-memory: 50/s burst 200 per IP on `/login` and `/token`; 10 failures per email+IP and 100 per email per 15 min; 10 failed `client_credentials` per client id. Live: 10 × 401, then 429 even with the right password. Per instance only (N instances allow N×). |
| 11 | Revocation, `DeleteClient` | **ours**, partly open | `DeleteClient` in the caller's tx: the secret stops at once. `/revoke` kills a refresh family. Access tokens are stateless JWTs: a disabled user or deleted client keeps a valid token for up to 15 min (`ACCESS_TOKEN_TTL`); the app's per-request checks on its own rows still apply. |
| 12 | ID token accepted as access token (P7) | **ours** | The library stamps `typ: JWT` on both and puts our audience in both (the ID token adds the client id). Access tokens carry a private `token_use: access` claim (`GetPrivateClaimsFromScopes` runs for access tokens only); the verifier requires it, plus `aud`, and the client rule (login client, or `client_id == sub`). Rejected in tests: ID token, other aud, other client, wrong iss, expired, `alg: none`, unknown key, unknown kid. No `at+jwt` (RFC 9068) without patching `op.SignerFromKey`. |
| 13 | Default CORS | **ours** (1 line) | The library's default reflects any origin with credentials. Turned off (no browser client). |
| 14 | Grants on by default | **ours** (6 lines) | The JWT bearer grant (RFC 7523) is advertised and routed unconditionally; storage returns no keys, so it always fails. Device and token-exchange grants are off unless storage implements them. Introspection answers "inactive". |
| 15 | Keys at rest | **ours** | ES256 private keys AES-256-GCM encrypted with `ISSUER_SECRET` (kid as AAD). A wrong secret can't load them. `TestKeysEncryptedAtRest`. The compose secret is a dev placeholder (same issue as `TEST_SECRET`, P5). |
| 16 | Machine client secrets | **ours** | 256-bit random, SHA-256 stored, constant-time compare; unknown client compares against a zero hash. |
| 17 | Refresh token theft | **ours** | Stored hashed, rotated on use (`UPDATE … WHERE rotated_at IS NULL`, so parallel refreshes can't both win); reusing a rotated token revokes the family; disabled users can't refresh; absolute family expiry. `TestRefreshRotationAndReuse` |
| 18 | Password hashing as DoS | **ours** | argon2id at OWASP's minimum (19 MiB, t=2), at most GOMAXPROCS at once. See Ops: this OOM-killed the app until `GOMEMLIMIT` was set. |
| 19 | Login CSRF, browser sessions | **open** | No session cookie, no CSRF token: fine headless, needed with a login page. Every `/authorize` asks for the password (no SSO session). |
| 20 | Test mode | **open** | Same as every stack: `TEST_MODE=1`, `test-secret`. `driver-config` hands out nothing secret. |

Two bugs in our own code, both found in this run: `keyRing.live` leaked a pooled connection when a key failed to decrypt (found by the at-rest test hanging on pool close), and the OOM (Ops). And one library doc trap: `RevokeToken`'s comment says refresh tokens arrive with an empty `userID`; the code passes the user id after `GetRefreshTokenInfo` succeeds. Written to the comment, refresh tokens would never be revoked (caught by the `/revoke` test).

## Transactions: does identity join the app's transaction?

**Yes, without changing a module.** The port only takes `ctx`, so the executor now puts its tx there (`db.WithTx`), and the adapter writes with `db.TxOr(ctx, pool)`. `POST /api/agents`, `POST /api/platform/apps` and `POST /api/_test/users` now create the `idp_*` row in the same transaction as the `agents` / `apps` / `users` row. A rolled-back request leaves no identity (tested for users and clients).

What that removes, compared with a (and its variants):
- **review-a #12** (an IdP machine user orphaned when the app's tx fails) can't happen. Neither can review-f #3 (Logto created users after our timeout; the email stuck at 422 → 500).
- **Projection lag**: a's driver retried `client_credentials` for up to 5 s (`Secret.NotExisting`, `client not found`); h's secret works on the next request, no retry.
- **No outbox to the IdP**: a had none either (direct calls outside the tx, which was the problem), and a2's identity outbox consumer (`zitadel/orgs.go`, ~330 LOC, partitioned relay, projection polling) belongs to IdP-owned tenancy, which h doesn't do. The "create the agent's client disabled, enable it from the `agent.registered` event" step (a2) isn't needed: the client exists only if the commit happens.
- **Runtime**: no Zitadel container, no PAT files, no project/app bootstrap, no `IAM_LOGIN_CLIENT` token in `driver-config`, no network call per user create or token check (keys are in-process).

Caveats:
- **The tx rides in `ctx`.** That's implicit: an adapter for an external IdP ignores it, an in-DB adapter depends on it. The explicit alternative is a port that takes a `db.Querier`. The `agents.go` comment "The IdP call can't join the transaction" is now wrong for h.
- **Hashing inside the tx**: `CreateUser` hashes (~30 ms, queued behind the hash slots) while the request holds its pool connection. Fine at 60 parallel creates; under heavier sign-up load, hash before `Begin` (a port change).

`DeleteClient` is on the port now, but no module calls it: the spec has no "delete app" or "delete agent" endpoint. In h it's one in-tx `UPDATE`; for an external IdP it would need the outbox.

## Ops

| | h | a (Zitadel) | f (Logto) | g (OpenAuth, TS) |
|---|---|---|---|---|
| containers | 5: postgres, spicedb, app + 2 one-shots (spicedb-migrate, bootstrap) | 6 | 7 | 3 |
| memory idle | app 38 MiB, postgres 56, spicedb 56: **~150 MiB** | ~300 MB | ~800 MB | ~124 MiB |
| memory after a run | app 143–208 MiB (holds up to `GOMEMLIMIT`), postgres 210, spicedb 131: ~500 MiB | ~550 MB | ~1.3 GB | ~164 MiB |
| cold start (`down -v`, images cached) | **14–16 s** (4 rounds) | 16 s | 31–34 s | 11 s |
| images | app 93 MB (a: 90), no IdP image | + Zitadel 235 MB | + Logto 1.98 GB | app 542 MB |
| CPU per user create + login | **~80 ms** (app 68 + postgres 12), argon2id at OWASP cost | ~100 ms with Zitadel's bcrypt cost *lowered to 6* | ~650 ms | n/a |
| CPU per login | ~41 ms (app 37, postgres 4) | | | |
| login latency (4 round trips, sequential) | 59 ms median | | | 131 ms (3 round trips) |

Bursts (60 parallel, from the Mac through the dev proxy, load 10–13):

| | h | g | c |
|---|---|---|---|
| create + login + `/api/me` | 60/60 in 4.9 s | | |
| logins of one user | 60/60 in 1.6–2.1 s | 4.0 s | 7.2 s |
| `/api/me/permissions` | 60/60 in 0.10 s | 0.9 s | 2.0 s |
| `client_credentials` | 60/60 in 0.09 s | 0.2 s | 1.0 s |

`/healthz` 200 after each burst.

**The OOM.** The first create+login burst killed the app (kernel OOM at the 256 MB `mem_limit`, 502 for everything, restart). argon2id allocates 19 MiB per hash; the semaphore caps live hashes at 4, but Go's GC let garbage pile up past the cgroup limit (Go sets no memory limit from the cgroup). `GOMEMLIMIT=200MiB` in compose fixed it: peak 218 MB, 60/60, no restart. The suite (2 workers) never triggered it. Whoever runs this owns that capacity math: cost × concurrency × container size.

**Two instances on one DB** (`--profile h2`, second instance not published, reached from inside the network): a code issued by app1 redeemed on app2; app2's token accepted by app1 and vice versa; identical JWKS; rotation and retirement as in checklist #8; the full suite passed with both running.

**Bootstrap pain:** none. Migrations in the one-shot; the first key is created by the server. Config is env only (`PUBLIC_URL`, `ISSUER_SECRET`, audience, client id, redirect URIs, TTLs).

## DX notes

- **zitadel/oidc is easy to read.** Storage contract in one file (`op/storage.go`), and the `example/server/storage` in-memory implementation is a template. Each trap above was found by reading `op/` (~5.6k LOC) in about an hour.
- **Traps, in the order they'd bite:**
  1. Issuer constructors: `StaticIssuer` vs `IssuerFromHost` / `IssuerFromForwardedOrHost`; http needs `WithAllowInsecure()`.
  2. PKCE `plain` and no-PKCE are accepted at `/authorize`.
  3. Code redemption is read-then-delete: make the lookup atomic.
  4. `typ: JWT` on access and ID tokens, same audience: add a claim to tell them apart.
  5. The default CORS policy is wide open; the JWT bearer grant is always on.
  6. `RevokeToken`'s doc comment doesn't match the code.
  7. Loopback redirects match any loopback host and port.
  8. argon2id memory × concurrency vs the container limit (ours, not the library's).
- **What the agent got wrong first:** the `RevokeToken` early return for refresh tokens (from the doc comment), the leaked pool connection on decrypt failure, a field/method name clash, and the OOM. All caught by the tests or the burst.

## What production would still need

zitadel/oidc is a protocol library (OP and RP). Everything below is ours to build, except where noted.

| need | zitadel/oidc | work for us |
|---|---|---|
| MFA, passkeys | none (it passes `amr`/`acr` through, parses `acr_values`) | TOTP + WebAuthn (`go-webauthn`), enrolment, recovery codes, step-up in the login step |
| email verification, password reset | none | tokens, mailer, pages, rate limits |
| browser login page, sessions, CSRF | none (login is "redirect to your URL") | the page, a session cookie (SSO across `/authorize`), CSRF |
| admin UI (users, clients, keys, lockouts) | none | all of it |
| SSO federation for merchants | `pkg/client/rp` is a certified OIDC RP for upstream IdPs; no SAML | per-merchant IdP config, account linking, JIT provisioning, SAML via another library |
| MCP: resource indicators (RFC 8707) | `resource` parsed only in token exchange, not at `/authorize` or `/token` for the code flow | carry `resource` through the auth request (a custom validator or a patch) and into `aud` |
| MCP: dynamic client registration (RFC 7591) | discovery field only, no endpoint | the endpoint, client storage with redirect URIs, abuse limits |
| MCP: client ID metadata documents (CIMD) | discovery flag only (`client_id_metadata_document_supported`), no fetching | URL-shaped client ids in `GetClientByClientID`: fetch, cache, SSRF guard |
| MCP: protected resource metadata (RFC 9728) | none (resource-server side) | a small JSON endpoint on the API |
| device flow, token exchange, JWT profile, request objects, back-channel logout | **supported** (storage methods to write) | storage |
| DPoP | experimental OIDC Key Binding (ID token) only; no DPoP-bound access tokens | |
| shared rate limits, CAPTCHA, auth audit log, KMS/HSM keys, client secret rotation | none | each one |

## Verdict: in-process issuer vs Zitadel/Ory server, for a Go platform

- **It works, and it's the fastest and leanest Go identity setup in the spike.** 362/362 on the first full run; one fewer service than a; ~80 ms CPU per create + login at a real hash cost (a: ~100 ms with Zitadel's cost turned down; f: ~650 ms); bursts 2–10× faster than g; 15 s cold start; tokens verified in-process.
- **The transaction win is real.** Identity writes commit or roll back with the app's data: the orphan-identity and projection-lag classes of bugs from a, a2 and f are gone, with no module change.
- **The price is owning an auth server.** 928 lines of security-relevant code (3.5× the Zitadel adapter) plus 588 lines of tests to keep it honest. The library removed all protocol code. What's left is policy: of the 20 checklist items the library handles 3 outright (issuer pinning, redirect matching, no machine refresh tokens) and part of a fourth (PKCE); 12 are ours; the rest are open or partial (access tokens can't be revoked, limits are per instance, no login CSRF/sessions, test mode). Building it turned up two bugs of ours and one misleading library doc. The library is maintained and certified, so unlike OpenAuth (g), what's left is our own code, not someone else's abandoned gaps.
- **The feature gap is where the cost grows.** MFA, passkeys, reset, email verification, admin UI and merchant SSO each add a project on top of the 928 lines. Zitadel ships them today; with h we'd build each one and its own security review.

**Recommendation.** For this platform as specified (password login, apps and agents as first-class machine clients, tenancy in the app), h is the best Go option measured: simplest runtime, transactional identity, the cheapest logins. Pick it if the team accepts owning the auth surface (security reviews, key ops, rate limits) and the roadmap stays close to "login + machine clients". Pick Zitadel (a) if merchant SSO, MFA/passkeys or a self-service account UI are on the near roadmap. Its adapter is a quarter of the code, and those features cost nothing to add. The identity port swap held again (no module changes), so starting with h and moving to Zitadel later is a contained adapter change. Moving the users (password hashes, client secrets) would be its own migration, not measured here.
