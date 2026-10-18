# Stack i results: Go + Zitadel v4.19.4, one instance per merchant + SpiceDB v1.56.2

Run 2026-10-19 against `ps-i` on cs-ws (4 CPU / 11 GB VM, shared: other benches `pc-*`, `pr-*`, `ps-*` running, host load 5–50 during the runs; every timing below names the load it ran at). Branch `stack-i` (from main 94b2a48, main 1c034c5 merged in for the round 4 suite). Same Go app as `a`; `IDP=zitadel-instances AUTHZ=spicedb`, app on 8096; Zitadel is not published (the app is the gateway). Zitadel facts that don't depend on our app are in the bench agent's `results/zitadel-instances.md` (branch `round4-bench`); where both touched the same question the answers agree.

## Conformance

`cd conformance && STACK=i HOST=cs-ws.lab.alexluong.com MAX_WORKERS=2 pnpm test` (needs `*.cs.internal` to resolve: Tailscale DNS on, gw split DNS, see Runtime)

| run | result |
|---|---|
| full, fresh stack (`down -v`), host load ~10–20 | **401 / 401** (362 core + 39 `multi-pool`; 30 `idp-tenancy` skipped), 156 s |
| full, again on the same volume (114 → 368 instances), load ~20 | **401 / 401**, 146 s |
| `multi-pool` only, at 519 instances, `HandleActiveInstances=30m` | **39 / 39** |
| full at load 46–51 (other benches peaking), 519+ instances | 392 / 401: 2 logins found no user after 3 s (projection lag), one agent-grant expiry timing, 6 cascades in `auth.test.ts` from the failed fixture login. The user-search wait was raised to 8 s afterwards; see the final run below |
| `go test ./...` | pass (all stacks' Go unit tests) |

FINAL_RUN_PLACEHOLDER

Failures fixed on the way (all Zitadel eventual consistency or wiring, none in the suite):
1. Login right after user creation: the login stand-in's user search returns 0 rows for a moment, a session for a just-created user 404s, and the **token request** can 404 `User.NotFound` and spend the code. Fixed with short waits in the login stand-in and a whole-flow retry in the driver (a person would retry too). On a loaded host the window reaches seconds.
2. A merchant reported `active` before its login app, instance domain and trusted domain were visible: the provisioner now finishes with a real authorization request through the public host (must 302) before it marks the pool active.
3. Suspend/reinstate: Zitadel's instance block is read from a projection; the next login after suspend could still pass, and after reinstate got 429. Fix: the gateway enforces the block from our directory (below); reinstate waits (≤ 8 s) for an authorize to pass.
4. Tokens of a suspended merchant got 401 instead of 403: a blocked instance refuses its JWKS too, and the app had never fetched that pool's keys. Fix: keys are fetched at provisioning and before blocking, and the last good JWKS is kept in the directory row.
5. Sign in with Shop: Zitadel's outbound deny list blocks private IPs, so the tenant instance couldn't reach the platform issuer on the compose network (`address is denied by '192.168.0.0/16'`). The deny list now omits 172.16/12 and 192.168/16.
6. Core `customerId` assertions: Shop orders first carried the merchant's linked customer record id; the core suite asserts the order's `customerId` is the caller. Orders now keep the acting identity; ownership joins through the link (below).

## Design

| pool (§16.1) | Zitadel | public host = issuer |
|---|---|---|
| workforce | the first instance (`ExternalDomain` `workforce.zitadel.internal`), org `staff` | `http://workforce.cs.internal:8096` |
| platform + shop | instance `platform.zitadel.internal`, orgs `accounts` (owners, partners, and the apps' and agents' machine users) and `shop` | `http://platform.cs.internal:8096` (shared, R9 allows) |
| tenant | one instance per merchant `m-<id>.zitadel.internal`, orgs `staff` and `customers`, project+PKCE app `login`, generic OIDC IdP `Shop` on `customers` | `http://m-<id>.cs.internal:8096` |

- **Directory** (`zitadel_pools`, adapter-owned table in the app DB; the control plane's routing directory): pool → instance domain, public host, issuer, instance id, org ids, login project/client, Shop IdP id, `status` (provisioning/active), `blocked` (desired), last good JWKS. Cached in memory once active (routing data never changes after that); `blocked` is read per request.
- **Gateway** (`adapters/zitadel/gateway.go`, wraps the app's handler): a request for `<label>.cs.internal:8096` is an identity host. The app drops every client `x-zitadel-*`, `Forwarded` and `X-Forwarded-*` header (Zitadel also picks the instance from `Forwarded`/`X-Forwarded-Host`), sets `x-zitadel-instance-host` = the pool's instance domain and `x-zitadel-public-host` = the public host, and proxies only browser OIDC paths (`/oauth/v2/*`, `/oidc/v1/*`, discovery, `/idps/callback`). Admin, management, user, session and system APIs are not reachable through it (404). Unknown label → 404. Suspended merchant → 403 on everything but keys and discovery. Any other host is the API.
- **Login UI stand-in** (`/ui/v2/login/*` on each identity host): Zitadel redirects `authorize` to a relative `/ui/v2/login/login?authRequest=…` (`ZITADEL_OIDC_DEFAULTLOGINURLV2` set relative, so one setting serves every instance). JSON instead of HTML: `POST password`, `POST idp` (start Sign in with Shop), `GET idp/done` (the IdP intent's success URL). It calls Zitadel as the **`login` system API user** (`IAM_LOGIN_CLIENT` on every instance). This is what Login UI v2 does in multi-instance mode (bench probe 3); we wrote our own because the driver must be headless.
- **System API users** (JWT profile, keys generated at first start into a volume): `provisioner` (`SYSTEM_OWNER` + `IAM_OWNER` on every instance: create instances, admin/management calls) and `login` (`IAM_LOGIN_CLIENT`). No per-instance credential is stored. The cost: two god-mode keys in the app (a real split: provisioner in the control plane, login key in the login UI only).
- **Provisioning** (`instances.go`): `merchant.created` → outbox consumer `pool` (partitioned per merchant, **background**, 8 workers). Steps, each idempotent and saved in the directory row: CreateInstance (found by domain on retry) → wait for the instance to answer → org `customers` → trusted domain (the public hostname) → login project + PKCE app → in the platform instance an OIDC app `shop-<label>` (redirect = the tenant's `/idps/callback`) → generic OIDC IdP `Shop` on `customers` (scopes include `urn:zitadel:iam:org:id:<shop org>`, so the upstream login is refused for non-Shop users) → readiness check (an authorize through the public host must 302) → JWKS fetched → apply the desired block → `active` → `platform.MarkPoolReady` (app: `merchants.pool_ready`). The merchant shows `provisioning` until then.
- **Suspension**: consumer `pool-state` (drained in the request): `blocked` committed in the directory first (the gateway refuses logins from that commit on), then Zitadel `SetLimits {block: true}` (the instance refuses everything but the system API, also requests that bypass the gateway). Reinstate reverses both.
- **Verifier** (`verify.go`): unverified `iss` → directory (unknown or provisioning issuer → 401) → that pool's key set (JWKS fetched through the internal URL with the instance header; refreshed every 5 min, early on an unknown `kid` at most every 10 s, last good set kept on failure and in the DB) → go-oidc checks (RS256, `iss`, `aud` = the pool's login project, `exp`) → access-token checks as in a (P7) → client = the pool's login app, or a machine client in the platform pool only. Subject handed to the app = `<pool>|<sub>`, so the same Zitadel id in two pools could never collide, and a tenant subject never matches a platform record.
- **Agents and apps** stay machine users in the platform instance. Putting an agent in its merchant's instance would make suspension cut its tokens at the IdP, but every `client_credentials` caller would need its merchant's token endpoint; not needed for §16.

## Modules: what multi-pool changed (pattern 3/7)

No Zitadel name or concept reached a module. But the spec's model changes did, and they are not identity-adapter work:

| change | where | why |
|---|---|---|
| membership moves from `users.merchant_id` to a `memberships` table; `Principal.MerchantIDs`, `MemberOf` | migration 003, `core/principal.go`, `core/executor.go` (tenant precheck), merchants, invitations, roles, platform | §16.2 partners: a platform account in several merchants. Kernel change (the precheck), switchable: `MultiMerchant` off keeps "one merchant per user" for a/b/f/h/a2 |
| `users.pool`, `home_merchant_id`; emails unique per (pool, kind) | migration 003, testsupport | §16.4 same email in several pools; tenant staff can't join another merchant (404) |
| `POST /api/agents` takes an optional `merchantId` | agents | a partner must say which merchant the agent belongs to |
| tenant customers order only at their merchant; Shop buyers get a linked customer record per merchant; `/me/orders` and order ownership join through the link | orders, new `modules/customers` | §16.5 |
| `merchants.pool_ready`, status `provisioning` | platform, merchants | §16.3; `TenantPools` switch |
| `GET /api/merchants/:mid/identity`, `POST /api/_test/merchants/:mid/users`, `GET /api/_test/home-realm` | merchants, testsupport, optional port `identity.Pools` | §16.3/§16.4; home realm: the driver's identifier-first step (which platform-level kind holds this email) |
| outbox relay: `Background`, `Workers` | `outbox/relay.go` | provisioning takes ~1–4 s; in-request drain would block merchant create, and one queue would serialize all merchants |

The identity side reaches app state through two callbacks wired in the composition root (`OnReady` → `platform.MarkPoolReady`, `OnShopLink` → `customers.LinkShop`), so the adapter writes no app table and the modules see only opaque subjects.

**Finding: the core contract forced a split customer identity.** The core suite asserts an order's `customerId` equals the caller. So a Shop-token order at M carries the Shop account id, a Sign-in-with-Shop order carries M's linked record id, and ownership queries join both. A production design would give the merchant one customer id (the linked record) and show the Shop app its own view.

## LOC (non-blank, non-comment)

| area | files | LOC |
|---|---|---|
| pool provisioning (instance template, block/unblock, system API client, keygen, directory table) | `instances.go` (~450 of 713), `system.go` 183, `schema/*.sql` 18 | ~650 |
| issuer/directory resolution in the app | `verify.go` 124, directory part of `instances.go` ~120, gateway proxy part of `gateway.go` ~70 | ~315 |
| identity port methods (users, pool users, clients, driver config) | `instances.go` ~140 | ~140 |
| login stand-in + Shop federation | `gateway.go` ~230 (password, idp intent, linked-user creation, Shop link), `modules/customers` 45, orders +43 | ~320 |
| module/kernel changes for the model (memberships, pools, flags) | modules +285 −52, core +39 −9, outbox +28 −4, identity port +11, migration 003 18 | ~380 |
| composition roots | `cmd/server` +56, `cmd/bootstrap` +25 | ~80 |
| test support / driver / bench | testsupport +83, `stacks/i.ts` 197, `bench-i` 108, `bench/i/cpu.sh` 24, compose 146 | ~560 |

## Provisioning (§16.7)

**What one merchant creates:** a Zitadel instance (first org `staff`, owner machine user, default policies, ~490 copied permission events, web keys), org `customers`, a trusted domain, project + OIDC app (tenant), a confidential OIDC app in the platform instance, a generic OIDC IdP; app side: a directory row, one merchant row as before.

| measurement | load | result |
|---|---|---|
| create request (merchant row + outbox), C=1, n=100 | ~5–11 | p50 26 ms, p95 45 ms |
| create → `active` (polled every 100 ms), C=1, n=100 | ~5–11 | **p50 0.88 s, p95 1.10 s**, max 1.2 s |
| create → `active`, C=4, n=150 | ~9 | p50 2.4 s, p95 4.0 s, max 4.7 s |
| directory `created_at → ready_at`, all 508 merchants of the first full run (core suite bursts) | 10–20 | p50 2.7 s, p95 5.0 s |
| rule 9: 10 in parallel | various | all active well within 60 s in every passing run |
| Zitadel DB growth per merchant | | **~1.1 MB** (34 → 143 MB for 100 merchants; 143 → 585 MB for 405 more incl. test users). ~670 events per instance (`events2` ~0.6 MB, `eventstore.fields` ~0.35 MB, rest projections) |
| app DB growth per merchant | | ~7 KB (directory row + merchant) |

**Failure and compensation:** the merchant row commits first; provisioning is an outbox row retried forever (transient errors), each step resumable from the directory row. So a half-created merchant is `provisioning`, never half-active, and a retry completes it (§16.3 option 2). Measured with Zitadel stopped (`bench-i`, `BENCH=failure`): create → `201 provisioning`; 20 s later still `provisioning`; the merchant's own API keeps working (store create 201); `active` 37 s after `docker compose start i-zitadel` (Zitadel's cold start under load ~50, then the relay's next tick). Window: until Zitadel is back, the merchant's tenant logins don't exist; nothing else is affected. Leftovers: a merchant that is never wanted again leaves an instance (delete is one system call; the event store keeps its events, bench probe 7). Only `invalid_argument`/`unimplemented` dead-letter the row (then the merchant stays `provisioning` and needs a person).

## Running cost (§16.7)

Average CPU (cores) and memory from cgroup counters (`bench/i/cpu.sh`), on a shared host:

| state | Zitadel | Postgres | app | SpiceDB |
|---|---|---|---|---|
| idle, 2 instances (fresh) | 0.09 / 108 MiB | 0.02 / 311 MiB | 0.01 / 40 MiB | 0.00 / 57 MiB |
| idle, 12 instances | 0.11 / 199 MiB | 0.03 / 403 MiB | 0.01 / 31 MiB | 0.00 / 64 MiB |
| under the full suite (114 → 368 instances) | **1.00** / 303 MiB | **1.13** / 1.8 GiB (page cache; anon 640 MiB) | 0.11 | 0.12 |
| idle, ~510 instances (default projections) | **0.30–0.38** / 260 MiB | **0.25–0.34** / ~1 GiB (anon 700 MiB) | 0.01 | 0.00 |
| idle, 519 instances (default projections) | **0.51** / 224 MiB | **0.50** / 1.2 GiB | 0.01 | 0.00 |
| idle, 519 instances, `HandleActiveInstances=30m` | **0.08** / 79 MiB | **0.02** / 929 MiB (anon 256 MiB) | 0.01 | 0.00 |

- **Idle CPU grows linearly with instances by default**: every projection is requeued for every instance every 60 s (`Projections.RequeueEvery`, `HandleActiveInstances: 0` = all instances always active). ~1 ms of Zitadel + ~1 ms of Postgres CPU per instance per second idle: about one core per 500 merchants doing nothing, 20 cores at 10 000. `ZITADEL_PROJECTIONS_HANDLEACTIVEINSTANCES=30m` (set in compose) projects only instances with recent events: idle fell to 0.1 core at 519 instances, and the `multi-pool` suite plus the login bench still passed (queries trigger projections on demand). Not measured: the first login at an instance idle for > 30 min (it pays for catching up its projections).
- Postgres needed more than `a`'s 512 MiB: it sat at the 1 GiB limit at ~500 instances (raised to 2 GiB).

**Login latency** (sequential, 20 each, driver on the Mac through the gateway; whole flow authorize → login → callback → token):

| pool | 13 instances, load ~11 | 519 instances, default, load ~9 | 519 instances, active-only projections, load ~4 |
|---|---|---|---|
| workforce (staff) | 82 / 107 ms | 232 / 475 ms | 84 / 118 ms |
| platform (owner) | 83 / 121 | 161 / 353 | 80 / 151 |
| shop (buyer) | 82 / 137 | 93 / 153 | 89 / 101 |
| tenant staff | 84 / 110 | 82 / 130 | 72 / 110 |
| tenant customer | 75 / 105 | 177 / 515 | 76 / 98 |
| Sign in with Shop (both legs) | 178 / 224 | 239 / 667 | 213 / 330 |
| `GET /api/me` with a tenant token (verify with cached keys) | 5 / 7 | 6 / 10 | 6 / 11 |

(p50 / p95.) The instance count itself doesn't slow a login (instance lookup is one indexed query; no cache configured); the spread at 519 with default projections is the idle projection load competing on a 4-core host.

## Issuers and keys (§16.7)

- One JWKS per instance, fetched by the app through Zitadel's internal URL with the instance header (the public host isn't needed for keys). Cached per pool in memory, refreshed every 5 min or on an unknown `kid` (≤ every 10 s), **last good set kept on failure and stored in the directory**, so a restarted app or a second app instance verifies a blocked merchant's tokens (→ 403 `merchant_suspended`, not 401). This also covers the round-3 JWKS-refresh hole for stack i.
- The issuer list is the directory: an unknown issuer is rejected before any key fetch (no fetching keys for attacker-chosen issuers).
- Key rotation per pool is Zitadel's per-instance web keys; the refresh above picks up new keys. Not exercised.
- **A merchant moving cells**: its instance stays on the global deployment, so the issuer doesn't change. A move of the Zitadel instance to another deployment changes nothing in the issuer if the public host moves with it (the issuer is the public host, not the instance domain), but Zitadel's export/import doesn't carry passkeys (bench/identity-model research), so a cross-deployment move is the hard case.

## Shop federation (§16.7)

- Wiring: per merchant, a generic OIDC IdP `Shop` on org `customers` of its instance, issuer = the platform instance's public issuer, client = a per-merchant confidential app in the platform instance (redirect = that merchant's `/idps/callback`), scopes with the `shop` org scope. Zitadel (tenant) reaches the platform issuer server-side through the app container's network alias `platform.cs.internal` → gateway → platform instance; this needed the deny-list change.
- Flow (driver = browser): tenant authorize → login stand-in `POST idp` → `POST /v2/idp_intents` → platform authorize → platform login stand-in, password as the Shop buyer → tenant `/idps/callback` (Zitadel exchanges the code on the backchannel) → intent success URL → stand-in: `RetrieveIdentityProviderIntent`; first time, `POST /v2/users/human` in `customers` with the IdP link (username `shop.<sub>`, so it never collides with a local customer's `customers.<email>`); app callback `customers.LinkShop` (tenant subject ↔ Shop account) → session with the intent → finalize → tenant token.
- **Linking**: never by email (auto-linking off; the local customer with the Shop buyer's email stays apart, tested). The same Shop account links to one user per merchant instance.
- **#9535 did not bite**: the one-link-per-org limit is per instance and IdP; with an instance per merchant each instance has exactly one link per Shop account. Inside one instance it would (bench probe 5: 409 *External IDP already taken*, even across orgs), so a Shop account can't be both a customer and a staff member of the same merchant through the Shop IdP.
- **Linked identity per merchant comes from the login stand-in, not a token claim**: Zitadel puts nothing about the upstream in the tenant token. The stand-in learns it from the intent and tells the app before finalizing. A stock Login UI v2 would need Actions v2 (claim or webhook) for the same.
- Cost: one extra platform-side OIDC app per merchant (the platform instance grows with the merchant count), and Sign in with Shop is ~2.5× a password login.

## Custom store domains (§16.7, not built)

The public host is already distinct from the instance domain (that is how every pool runs here). A store domain `shop.brand.com` needs: (1) a trusted domain on the merchant's instance (`POST /admin/v1/trusted_domains`; otherwise Zitadel answers 404); (2) a directory row mapping the host to the pool (one pool, several public hosts); (3) the verifier accepting every issuer of that pool (tokens are bound to the issuer they were minted under: bench probe 2), with one key set per instance; (4) the Shop app's redirect URIs per domain (or one shared callback host); (5) TLS at the gateway and `ExternalSecure` for `https` issuers; (6) passkeys are bound to the domain (rpId) they were registered on. Estimated: the directory and verifier changes are small (issuer list per pool instead of one); TLS and DNS are the work.

## Staff invitation (§16.7, not built)

What Zitadel offers (bench probe 4, matches the APIs used here): create the staff user in the merchant instance's `staff` org with a pre-verified email and no password (`POST /v2/users/new`), then `password_reset`, `invite_code` or `passkeys/registration_link` with `returnCode` to get the setup code without Zitadel's SMTP, and send our own email linking to the login UI with the code. Our side: an invitation row (as in a2), the email, and a login UI page that redeems the code. With an instance per merchant the invitee is created directly in the right pool, so a2's "users can't move between orgs" problem doesn't exist for staff. **Forced MFA is not enforced by Zitadel's APIs** (bench probe 6): a password-only Session API login gets tokens even with `forceMfa`; the login stand-in (or Login UI v2) must check the login policy, and the app should check `amr` for staff pools. Our stand-in doesn't.

## Ops

| | i | a |
|---|---|---|
| containers | 7 (postgres, keygen one-shot, zitadel, spicedb, spicedb-migrate, bootstrap, app) | 6 |
| cold start `up -d --build --wait` from `down -v`, images cached | 84 s at load ~20 (Zitadel init dominates) | 16 s |
| bootstrap | idempotent: directory migration, workforce pool (trusted domain, login app), platform instance (CreateInstance, org `shop`, login app) | |
| published ports | 8096 only | 8081 + 8085 |

## Runtime notes

- Issuers are `http://<label>.cs.internal:8096`. `*.cs.internal` resolves to cs-ws through gw's DNS (Tailscale split DNS on the client; cs-ws resolves it too). Port 8096 had to be exempted from cs-ws's dev proxy (it rewrites Host to `localhost` on 3000–8999): collielab 8312075 extends the exemption from 8081–8089 to 8081–8099 (applied on cs-ws). `ctrl-vault/docs/dev-urls.md` still says 8081–8089.
- Inside the network only the platform issuer needs to resolve (Zitadel's backchannel for the Shop IdP): a network alias on the app container.

## DX notes

- **Eventual consistency everywhere a login follows a write**, now with one more layer: instance domain, trusted domain, apps, users (search, sessions, token issuance), limits. Every "ready" needs a probe of the real path (authorize must 302, a block must 429), not of the write's response. Under load the windows reach seconds; a production login UI will meet them too (a freshly invited user logging in at once).
- The SSRF deny list (`HTTPClient.DenyList`) silently breaks federation between instances of one deployment on internal addresses. The fix opens the private range to Actions targets too; the alternative is going through public ingress.
- `x-zitadel-public-host` must be a trusted domain, not just an instance domain; the error is a bare 404 "instance not found".
- Zitadel picks the instance from `Forwarded`/`X-Forwarded-Host` too (`origin_interceptor.go`), so a gateway that only strips `x-zitadel-*` leaves an instance-selection hole.
- A blocked instance refuses its JWKS: verification must not depend on reaching it.
- Projections for every instance every minute is the default; the knob that fixes idle cost is undocumented outside `defaults.yaml`.
- `IAM_OWNER` lacks `session.*`: the login side needs its own `IAM_LOGIN_CLIENT` system user (probe agrees).
- What I got wrong first: user lookup by email (a Shop-linked user and a local customer share it: lookups now use `<org>.<email>` usernames), assuming `active` after the last write, trusting Zitadel's block for read-your-writes, and `customerId` = the linked record.

## Spec issues

1. **§16.5 vs core §8** (`customerId`): see Modules. The spec could say whose id a Shop order carries.
2. **R8 / §16.6 rule 8** hold, but suspension "at the pool" is enforced first by our gateway (directory) and then by Zitadel (instance block, projection lag). Without the gateway check the next login after suspend could still succeed for a moment.
3. **Refresh tokens** of a suspended merchant's pool: blocked by the instance block (all requests refused), but only once the block projection catches up; not tested (no refresh grant on the login app).
4. **Same email as staff and customer of one merchant** works (usernames `staff.<email>` / `customers.<email>`), not tested (R6).
5. `GET /api/merchants/:mid/identity` returns more than `{issuer}` (`clientId`, `projectId`, org ids, `status`): what a storefront needs to start a login.
