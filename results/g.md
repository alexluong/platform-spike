# Stack g results: TypeScript (Hono) + OpenAuth + Cerbos + Postgres

Stack c with Better Auth swapped for OpenAuth (`@openauthjs/openauth` 0.4.3, pinned). Same app image, same modules, same Cerbos policies; `IDENTITY=openauth` picks the adapter at the composition root. Run on 2026-10-18 against `ps-g` on cs-ws (`docker compose -p ps-g --profile g up -d --build`), app on 8093.

## Conformance

**362 / 362 passed**, including the slow break-glass expiry test (`STACK=g HOST=cs-ws.lab.alexluong.com pnpm test`, 84–88 s; twice, the second on a fresh `down -v` stack). The 30 skipped are the opt-in `idp-tenancy` tests (§15.4). No failures by design.

The suite passed on the first full run. Unit tests: 28 (4 new in `ts/src/adapters/openauth.test.ts`, pinning the two issuer traps below and the `/authorize` gate).

**Changes outside the adapter, composition root, compose and driver: none.** No module, kernel, schema or policy file changed. Plumbing only: `ts/package.json` (the dependency), `conformance/src/{env,stack}.ts` (register `g`), root `compose.yaml` (include). The `ClientRegistry` port still takes `actorCredential`; the OpenAuth adapter ignores it (it doesn't need the caller's session to register a client, which removes review-c #11's reason for passing the bearer around).

## Answers

### Where OpenAuth runs: in-process, works

The issuer is a Hono app, so it runs inside the app's server. Two catches, both handled in `handler()` in `ts/src/adapters/openauth.ts`:

- **It must sit at the root.** Routes are `/authorize`, `/token`, `/<provider>/authorize`, `/.well-known/*`, and it redirects to absolute paths (`/password/authorize`). No base path option (issue #125, open since 2025-01). No clash with `/api/*` here.
- **Don't `app.route('/', issuer)`.** The issuer's `logger()` middleware then runs for every API route (checked). Instead the app forwards an allow-list of paths to `issuerApp.fetch()`, like stack c does for Better Auth. Mounted: `/authorize`, `/password/authorize`, `/token`, `/.well-known/jwks.json`, `/.well-known/oauth-authorization-server`. Not mounted: `/password/register`, `/password/change`.

Verification is in-process too: OpenAuth's own `createClient().verify()` with its `fetch` pointed at the issuer handler, so the JWKS never goes over the network.

A separate service is not needed. It would make sense only to share one issuer between several apps, or to put it on Workers.

### Storage: no Postgres adapter, wrote one (40 LOC)

- **Shipped adapters:** memory (optionally persisted to a JSON file), DynamoDB, Cloudflare KV. No Postgres, Redis or SQLite (issues #41, #37, #289, #11, #51, all open). The interface is a tiny KV (get / set with expiry / remove / prefix scan), so the Postgres adapter is one table, `openauth_kv (key text collate "C" pk, value jsonb, expiry)`, in the app's database: `ts/src/adapters/openauth-pg-storage.ts`.
- **What OpenAuth stores:** its signing key (ES256) and cookie-encryption key (RSA-OAEP-512), created lazily on first use; password hashes at `email/<email>/password`; the `email/<email>/subject` link; authorization codes (60 s); refresh tokens (one row per login). After one suite run: 817 `email/*` rows, 435 refresh rows, 1 + 1 keys.
- **OpenAuth never deletes expired rows.** The adapter hides them on read and sweeps every 10 minutes.
- **What stays ours:** users (`app_users`: id, kind, platform role), membership, roles, everything else. `success` maps the login's email to our user row and issues the token with `sub` = our user id.
- **Transactions:** the KV writes run on their own pool (the auth pool, as in c), not in the request's transaction. Better Auth's advantage of one DB is kept, but nothing uses a shared transaction here: user creation is the test endpoint, and client registration is a single insert (same side-effect window as review-c #10).

### Users: password provider via code + PKCE, headless over HTTP

- **No admin API to create a user.** The password provider only knows its own register form, which emails a 6-digit code. The test endpoint therefore hashes with OpenAuth's `ScryptHasher` and writes the hash at the provider's internal key. It works, but it depends on an undocumented storage layout.
- **Driver (`conformance/stacks/g.ts`), 3 requests:**
  1. `GET /authorize?client_id=platform-cli&response_type=code&provider=password&code_challenge=…` sets an encrypted `authorization` cookie.
  2. `POST /password/authorize` (form: email, password, with the cookie) answers 302 to the redirect URI with `?code=`.
  3. `POST /token` with `grant_type=authorization_code` and the PKCE verifier returns the access token.

  This is the real browser flow minus the HTML. The password provider's `login` callback returns JSON instead of a page.
- **No password grant (ROPC)** (issue #18). The form flow is the cleanest headless path.
- **Hashing cost:** scrypt N=16384, r=8, p=1 on libuv's threadpool, so it doesn't block the event loop.
  - One login (3 round trips): 131 ms. Stack c: 163 ms.
  - 60 parallel logins of one user: all OK in 4.0 s (p95 4.0 s). Stack c: 7.2 s. The 4-thread pool queues them.
- **No rate limiting or lockout in OpenAuth.** Production would need it in front (a proxy or middleware on `/password/authorize` and `/token`).

### Apps and agents: the biggest gap, filled with ~35 LOC

- **What OpenAuth covers:** `/token` accepts `grant_type=client_credentials`, but only with a non-standard form field `provider=<name>`, and only through a provider that implements `client()`. **No built-in provider does** (issue #265, open). There is **no client registry at all**: `client_id` is any string the caller sends. The default `allow()` accepts any client whose redirect is on the issuer's domain.
- **What we wrote:**
  - A client table, `openauth_clients (client_id, secret_sha256, name)`. Secrets are 256-bit random, so SHA-256 is enough.
  - `createClient()` for apps and agents.
  - A `client` provider whose `client()` looks up the secret.
  - A catch: `client()` cannot reject. The issuer mints a token from whatever it returns. So it returns `{clientId, ok}`, and our `success` callback returns 401 `invalid_client` when `ok` is false. `success` may return any `Response`.
  - Tokens are still minted and signed by OpenAuth: subject type `client`, `sub` = `aud` = client id.
- **Gaps that remain:**
  - No scopes in tokens. The adapter gives a verified `client` subject the API scope; the app's own install and grant scopes do the real work, as in c.
  - Every `client_credentials` response also includes a refresh token, stored in the KV. We set its TTL to 60 s. `refresh_token` grants don't re-check the client secret or re-run `success` (issue #275).
  - No secret rotation and no client deletion API; we'd add them to our table.
- **Is it sound?** Yes for this spec. The registry is ~35 LOC that we own, and OpenAuth only signs. Compare c: Better Auth's oauth-provider plugin gave registered clients, `client_credentials`, RFC 8707 resources and scopes, at the price of the configuration traps in c.md.

### Token verification

- **Access token:** ES256 JWT, header `typ: JWT` (not `at+jwt`). Claims: `mode: "access"`, `type` (subject type), `properties` (subject payload), `aud`, `iss`, `sub`, `exp`. No `iat`, `jti` or `scope`.
- **Subjects schema:** `user: {id}`, `client: {clientId}` (zod; OpenAuth takes any Standard Schema). `verify()` checks signature, `iss`, `exp`, `mode`, and that `properties` match the schema for `type`.
- **Audience is left to the caller.** `aud` is always the OAuth `client_id`; there's no resource/audience parameter (issue #158). The adapter checks: user tokens need `aud == platform-cli`; client tokens need `aud == properties.clientId`. Tokens issued to another client fail the `aud` check. Another client can't get a user token here, because the `/authorize` gate admits only `platform-cli`.
- **Trap 1: `iss` comes from the request.** The issuer computes it from the request URL and trusts `X-Forwarded-Host/Proto/Port`. Any caller picks the `iss` of its own token (unit test). The handler rewrites every request to the configured `AUTH_BASE_URL` and drops those headers. Discovery with a spoofed header now still says `http://cs-ws.lab.alexluong.com:8093`.
- **Trap 2: `allow()` returning false still redirects to the rejected `redirect_uri`** with `?error=…`. That's an open redirect even with a strict `allow()`, issue #299 (reported 2025-09, unanswered). `allow()` also never sees `response_type` or PKCE. So the adapter checks `/authorize` itself before the issuer: exact client and redirect URI, `response_type=code` only (no implicit flow), PKCE S256 required. Otherwise 400.
- **TTLs:** the defaults are a 30-day access token and a 1-year refresh token. Set here to 15 min access and 1 day refresh (compose).
- **JWKS and rotation: none built in.**
  - Keys are generated on first use and stored forever.
  - The issuer caches them per process (`lazy()`), and `createClient` caches the JWKS per process with no refetch on an unknown `kid`.
  - Rotating means setting `expired` on the stored key and restarting every instance (issuer and verifiers).
  - Keys survive restarts (they're in Postgres; a token from before a restart still works).
  - Multi-instance cold start is racy. Each instance may create its own key (#322 on KV); harmless, since all are published. The adapter generates keys at boot so the first login burst doesn't race.

### Sessions and revocation

- **No server-side session.** Access tokens are stateless JWTs, with no revocation or logout endpoint (issues #131, #249). Refresh tokens can be invalidated only by deleting KV rows (`oauth:refresh/<sub>/…`); only providers can call the internal `invalidate`.
- **Immediate denial still holds.** Suspension, membership, roles, installs and grants are read from Postgres on every request (principal resolver plus the Cerbos PIP), as in c. Suspend → 403 `merchant_suspended` on the next request with an old token: suite-tested and passing. A deleted user row → 401.
- **What's lost vs c:** Better Auth's opaque session tokens are checked against the session table on every request, so a single session can be killed. Here a leaked token works until `exp` (15 min) for anything the DB still allows. Killing a user's access at once needs an app-side check (e.g. a `disabled` flag in `app_users`).

### Project health

- **Version:** pinned 0.4.3, released 2025-03-04, still `latest` on npm. Last snapshot build 2025-03-22. Last commit on the default branch 2025-04-09. **No release in 19 months.**
- **Cadence:** about weekly from 2024-12 to 2025-03, then stopped. The SST team moved to OpenCode.
- **Issues:** 100 open issues, 44 open PRs, 7.4k stars.
  - Issue #326 "Is this project still being maintained?" (2026-03): no maintainer reply. A community fork exists (`kagii-dev/openauth`).
  - The open-redirect report #299 got no response.
- **Open-issue themes:**
  - storage adapters (Postgres, Redis, SQLite, D1, Drizzle)
  - M2M/client_credentials
  - custom audience
  - OIDC (no ID tokens, no `/userinfo` standard)
  - base path
  - revocation
  - 2FA and passkeys
  - Cloudflare KV bugs (#302, #322)
  - refresh not re-running `success`
- **Licence:** MIT (the npm tarball has no LICENSE file, #301).
- **"Beta":** the README still says beta. That's accurate for features (0.x, no OIDC, no M2M); for maintenance, **dormant** is the better word.
- **Workers (assessed only):** built for it (Hono, WebCrypto, a Cloudflare KV adapter). The KV adapter has open bugs (TTL rejections, a key-creation race). The default scrypt hasher imports `node:crypto`: needs `nodejs_compat`, or use `PBKDF2Hasher`. Our app (pg, Cerbos gRPC) wouldn't run on Workers anyway.

## Lines of code (non-blank, non-comment)

| what | g (OpenAuth) | c (Better Auth) |
|---|---|---|
| identity adapter (issuer config, verify, user/client registration, `/authorize` gate, issuer pinning) | 142 | 113 |
| storage adapter (Postgres KV; OpenAuth ships none) | 40 | 0 (Better Auth ships Kysely/pg) |
| conformance driver | 64 | 33 |
| composition root change (`main.ts`: pick adapter) | +43 / −14 lines | — |
| compose | 62 lines (non-blank) | 60 |
| adapter unit tests | 51 | 28 (`better-auth.test.ts`) |

Of g's 182 adapter LOC, about 95 exist only because OpenAuth lacks the feature:
- Postgres storage: 40
- client registry, `client` provider and secret check: ~35
- `/authorize` gate: ~8
- issuer URL pinning: ~8
- user creation through storage internals: ~6

The rest is configuration, as in c.

## Design notes

- `IDENTITY=better-auth|openauth` in `ts/src/main.ts` picks the adapter. Both expose the same surface: `authenticate`, `createUser`, `createClient`, `handler`, `exposedPaths`. Each migrates its own tables at start (OpenAuth: `openauth_kv`, `openauth_clients`). Stack c's defaults are unchanged; `ts/` typechecks and c's unit tests still pass (c's running stack was not redeployed).
- Pools as in c (review-c #1): request pool, PIP pool, auth pool, all with connection timeouts. The issuer, the KV and the email → user lookup in `success` use the auth pool.
- Credentials map to principals exactly as in c: `session` (user id) → `app_users`; `client` (client id) → `apps` or `agents` by `client_id`.

## Ops

- **Containers:** 3, as in c: `g-postgres` (postgres:17-alpine), `g-cerbos` (c's Cerbos image build), `g-app` (node:24-alpine). No IdP container, no one-shot. Only port 8093 is published.
- **Memory:**

  | | app | Cerbos | Postgres | total |
  |---|---|---|---|---|
  | idle | 60 MiB | 38 MiB | 26 MiB | **~124 MiB** |
  | after a full suite run | 84 MiB | 49 MiB | 31 MiB | ~164 MiB |

  Stack c: 113 MiB idle, 175 MiB after a run.
- **Cold start:** `down -v` then `up -d --build --wait` takes **11 s** with the layer cache warm, 58 s when the app layer rebuilds. App restart to healthy: 13 s.
- **Image:** app 542 MB, vs 537 MB for c. The image carries both identity libraries; OpenAuth plus its deps (jose, aws4fetch, standard-schema) add ~5 MB. Cerbos 138 MB.
- **Bursts (60 parallel, one user; c measured the same way, same day):**

  | | g | c |
  |---|---|---|
  | logins | 4.0 s, all OK | 7.2 s |
  | `/me/permissions` | 60 × 200 in 0.9 s | 2.0 s |
  | `client_credentials` | 60/60 in 0.2 s | 1.0 s |

  `/healthz` stays 200 afterwards; no pool deadlock. The suite's own concurrent-load test passes too.
- **Bootstrap pain:** low. No secrets to configure: OpenAuth makes its keys in the DB on first boot (`AUTH_SECRET` isn't used in g).

## Traps (in the order they'd bite)

1. `iss` follows `Host` / `X-Forwarded-*`: pin the issuer URL in front of it.
2. `allow()` rejection still redirects to the bad `redirect_uri`, and `allow()` can't see `response_type` or PKCE: gate `/authorize` yourself.
3. Mounting with `app.route('/')` leaks the issuer's logger middleware onto every route.
4. `client()` can't reject; reject in `success`. `client_credentials` needs a `provider` form field; refresh tokens come along anyway.
5. Default TTLs: 30-day access, 1-year refresh.
6. No user admin API; writing hashes at internal keys works but is undocumented.
7. JWKS cached forever by the client lib; key rotation needs restarts.
8. Expired KV rows are never deleted by OpenAuth.
9. Bad `/token` requests (unknown grant, JSON body) answer 400 with a plain-text "The browser was in an unknown state…" message, not an OAuth error.

## Verdict: OpenAuth vs Better Auth vs an external IdP, for a Node platform

- **The in-process story is as good as Better Auth's**, and lighter.
  - Same server, same Postgres, no extra container; less memory, faster logins and token checks in this run.
  - Zero module changes; first suite run green.
  - The issuer is small enough to read in an hour (1.1k lines), which is how every trap above was found.
- **It covers only user login.** No client registry, no M2M provider, no scopes or resources, no OIDC, no revocation, no rate limiting, no user admin API, no MFA. For this platform (apps and agents are first-class), we wrote the machine-client half ourselves, plus storage and two security fixes. Better Auth's oauth-provider ships all of that (with its own config traps).
- **Maintenance is the deciding problem.** No release in 19 months, the maintainers are silent on a public open-redirect report, and the "is this maintained?" issue has no answer. For an auth dependency that's disqualifying unless you're prepared to fork (someone already has) and own it.
- **Pick OpenAuth when:** a small app or internal tool wants passwordless or social login on Workers or Lambda, with users only, and you're fine owning a fork.
- **Not for this platform.** Pick **Better Auth** for in-process TS identity: maintained, Postgres-native, M2M and organizations available. Pick an **external IdP (Logto/Zitadel)** when you want login, MFA, M2M clients and admin UI owned by someone else, and can afford the extra container and the token round trip. OpenAuth sits below both: Better Auth's deployment model with fewer features and no maintainer.
