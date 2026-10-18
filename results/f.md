# Stack f results: Go + Logto 1.45.0 + SpiceDB v1.56.2

Run 2026-10-18/19 against `DOCKER_HOST=ssh://cs-ws` (4 CPU / 24 GB VM, shared: stacks a, a2, c, d, e, g and other projects' containers running and under load, load average 17–43 during my runs). Branch `stack-f`. Same Go app as stack a, `IDP=logto AUTHZ=spicedb`.

## Summary

- **Suite: 362/362 core** (full run with the break-glass expiry, `MAX_WORKERS=4`). The adapter swap worked like a → b: no module, port or migration changed.
- **Logto costs ~6× Zitadel's CPU per user create + login**: 630 ms of CPU (Logto + its Postgres) vs 102 ms for stack a (Zitadel at bcrypt cost 6), measured from container cgroups over 60 parallel create + login. One Node process saturates at ~3 logins/s; the stack runs 3 Logto replicas. With the default worker count (9 on this Mac) the suite times out (10–53 tests at 30 s) on this shared VM.
- **Tokens are standards-clean.** `typ: at+jwt`, `aud` = the RFC 8707 resource indicator, `client_id` and `sub` in every access token. ID tokens, other apps' tokens, opaque tokens and tampered tokens all get 401 (checked live).
- **No eventual consistency.** A new M2M app's secret works on the next request; the driver has no retry (Zitadel needed one). Creates: 1 Management API call per user, 2 per machine client.
- **Ops is the weak side:** a 1.98 GB image, ~225 MB per replica at idle, no supported way to create the first Management API client without the admin console (seeded with SQL), and the Management API shares a port with OIDC (published only through a path-filtering nginx).

## Conformance

`cd conformance && STACK=f HOST=cs-ws.lab.alexluong.com pnpm test`

| run | result |
|---|---|
| full, `MAX_WORKERS=4`, 3 Logto replicas | **362 passed / 362** (30 idp-tenancy skipped), 199 s |
| `SKIP_SLOW=1 MAX_WORKERS=4`, 3 replicas | 361 passed, 1 skipped, 167 s |
| `SKIP_SLOW=1`, default workers, 3 replicas | 317–351 passed; the rest time out at 30 s (depends on VM load) |
| `SKIP_SLOW=1`, default workers, 1 replica | 308 passed, 53 time out, 166 s |

Every failure was a 30 s test timeout while users logged in; none was a wrong answer. Stack a ran `SKIP_SLOW=1` in 16 s on a quieter VM.

`MAX_WORKERS` is one of the suite's documented knobs (`conformance/README.md`). Nothing in the suite was changed.

Other checks:
- **Burst** (b's check, after review-c's pool deadlock): 60 `/api/me/permissions` (half `?storeId=`, half `?merchantId=`) + 15 product creates + 15 custom-role creates on one merchant at once, 3 rounds: 90/90 2xx each round, 0.7–1.3 s. Then 60 parallel logins of one user: 60/60, 18–23 s.
- **Cold start** from `down -v`: 31 s to app healthy (images built). Logto seed 4.5 s, 3 replicas healthy ~12 s later, SQL seed 0.6 s, bootstrap 3 s. With `--build`: 148 s (Go build on the loaded VM).
- **Negative tokens** (live, against `/api/me`): driver access token 200; ID token 401; access token from another SPA app in the tenant for the same resource 401; token without `resource` (opaque) 401; signature tampered 401; client_credentials token of an M2M app that is no app/agent here: passes `Verify`, then 401 because the subject maps to no principal (same as a and b).

## What changed between a and f

| file | lines | inside the allowed area? |
|---|---|---|
| `go/internal/adapters/logto/` (`logto.go`, `bootstrap.go`, `logto_test.go`) | new | yes |
| `go/cmd/server/main.go` | +8 | yes: one `case "logto"` + import + comment |
| `go/cmd/bootstrap/main.go` | +18 | yes: one `case "logto"` + import |
| `stacks/f/` (compose, Postgres image with init + Logto seed SQL, nginx edge) | new | yes |
| `compose.yaml` (root include) | +1 | yes |
| `conformance/stacks/f.ts` | new | yes |
| `conformance/src/env.ts`, `stack.ts` | +2 | driver plumbing (register `f`), as every stack does |

`go.mod` unchanged: `go-oidc` was already a dependency. No module, kernel, port or migration changed.

## Lines of code (non-blank, non-comment)

| area | f | a (Zitadel) | b (Ory) |
|---|---|---|---|
| identity adapter: verifier, provisioner, bootstrap | **295** (`logto.go` 212, `bootstrap.go` 83) | 265 | 180 |
| adapter tests | 37 | — | 21 |
| stack compose + images | 170 (compose, Postgres init, seed SQL, nginx) | 126 | 250 |
| login driver | 143 | 129 | 150 |

Counted with the same counter for all three (a and b at the commits of their reports). Of Logto's 295, ~45 are the Management API token cache (Zitadel and Ory need none: a PAT, or no auth inside the network) and ~15 the `typ` header check.

## Design notes

- **Verifier** (`logto.go` `Verify`): reject unless the JOSE `typ` is `at+jwt`; then go-oidc checks signature (allowlist ES384, Logto's default key, and RS256 for a rotation to RSA), `iss` = `<endpoint>/oidc`, `exp`, and `aud` contains the API resource indicator. Then the client: `client_id` is the login driver's SPA app, or `client_id == sub` (an M2M app; the app maps the subject to an app or agent row).
- **Why the client check is needed:** any app in the Logto tenant can get a token for any API resource. Logto filters scopes by role, not by app (except third-party apps). Without the check, a token from an unrelated SPA in the same tenant would be accepted.
- **Provisioner:** `POST /api/users {primaryEmail, password}` (1 call). Machine clients: `POST /api/applications {type: MachineToMachine}`, then `GET /api/applications/:id/secrets`, because the create response omits the secret (2 calls). No role or scope is assigned: the API resource has no scopes, and Logto still issues client_credentials tokens for it (`scope` absent).
- **Management API auth:** client_credentials of the seeded admin M2M app for `https://default.logto.app/api` scope `all`, cached until 1 min before expiry (1 h).
- **Bootstrap** (idempotent; 3 s on a cold start including migrations and the SpiceDB schema): finds or creates the API resource (by indicator) and the driver's SPA app (by name + redirect URI), then sets the sign-in experience to email + password, sign-in only (no self-registration), no breached-password lookup. Writes `stack.json` (endpoint, internal URL, resource, driver client id, admin M2M credentials).
- **Driver** (`conformance/stacks/f.ts`): the code + PKCE flow with Logto's Experience API standing in for the sign-in page. Logto's own integration-test client does the same: `GET /oidc/auth` (with `resource`) → `PUT /api/experience` → `POST /api/experience/verification/password` → `POST /api/experience/identification` → `POST /api/experience/submit` → follow `/oidc/auth/:uid` → `/consent` (auto-consent for first-party apps) → callback → `POST /oidc/token` with `resource`. 9 requests per login, all on the public edge. `driver-config` hands out nothing secret (stack a hands out Zitadel's `IAM_LOGIN_CLIENT` PAT, which can log in as anyone).

## Ops

| | |
|---|---|
| containers | 7 long-running: postgres (databases `logto`, `spicedb`, `app`), logto ×3, nginx edge, spicedb, app. 4 one-shots: logto-init (seed + alterations), logto-seed (SQL), spicedb-migrate, bootstrap. With `LOGTO_REPLICAS=1`: 5 long-running. |
| published | app 8091, Logto edge 8092 (OIDC, sign-in pages, `/api/experience*`, `/api/.well-known/*`; every other `/api/*` → 404). Nothing on 3001/3002. Admin console not started (`ADMIN_DISABLE_LOCALHOST=1`). |
| memory at idle (after restart) | app 17 MB, logto 3 × 224 MB, edge 5 MB, spicedb 50 MB, postgres 59 MB: **~800 MB** (~355 MB with 1 replica) |
| memory right after a full run | app 30 MB, logto 3 × ~290 MB, spicedb 145 MB, postgres 248 MB: **~1.3 GB** |
| images | **logto 1.98 GB** (Node + 57 bundled connectors), app 90 MB, nginx edge 93 MB, spicedb 136 MB, postgres 423 MB |
| cold start | 31 s from `down -v` (images built), see Conformance |
| upgrades | `logto-init` runs `db alteration deploy 1.45.0` on every start; bump the image tag and the target together |

## Answers

### Machine credentials (apps and agents)

- An app or agent is a Logto **machine-to-machine application**; its id is the OAuth `client_id`, and its secret lives in `application_secrets` (several named secrets per app, optional expiry, so rotation is supported).
- Tokens for our API: `client_credentials` with `resource=<API indicator>`. Access is governed by **API resources + scopes + M2M roles**: scopes on the resource, roles bundle scopes, roles are assigned to M2M apps. We use none (authorization stays in SpiceDB), and Logto issues a token anyway.
- **Calls per create:** user 1, machine client 2 (create, read secret). Stack a needed 2–3 per machine client.
- **Eventual consistency:** none. Logto writes straight to Postgres, and a secret works on the next request. Stack a's driver retries for up to 5 s.
- **The bootstrap gap:** the first M2M app with Management API access can only be made in the admin console. OSS has no env var or CLI for it (Zitadel has `FIRSTINSTANCE_*`). `stacks/f/postgres/logto-seed.sql` inserts it into Logto's tables and gives it the pre-seeded "Logto Management API access" role. It works, but it depends on Logto's schema (3 tables) and may need updating on upgrades.

### Password hashing and login speed

- **Argon2i, t=8, m=8 MiB, p=1, hard-coded** (`packages/core/src/workers/tasks/argon2i.ts`); no knob to lower it for dev, unlike Zitadel's `HASHER_COST` or Kratos's bcrypt cost. Hashing runs on a 2-thread worker pool; **verification runs on the main event loop**. Measured in the container (VM loaded): hash ~100 ms, verify ~130 ms.
- **The rest of Logto's request handling costs as much as the hashing.** CPU per create + login, from cgroup counters over 60 parallel runs:

  | | IdP | its Postgres | total |
  |---|---|---|---|
  | f: Logto (3 replicas) | 500 ms | 130 ms | **630 ms** |
  | a: Zitadel, bcrypt cost 6 | 56 ms | 46 ms | **102 ms** |

  Argon2 is ~230 ms of Logto's 500 ms; the other ~270 ms is the 9 requests of a login (~30 ms of CPU each: koa middleware, oidc-provider, sentinel and audit-log writes). Redis as Logto's cache (`REDIS_URL`) saved ~5%, so it was dropped.
- **Latency:** a single login on a quiet stack took 0.56–0.73 s (9 round trips from the Mac). 40 parallel create + login: 12 s wall with 1 replica, 9 s with 3. 60 parallel with 3 replicas: 12 s at VM load ~20, up to 27 s at load ~40. One replica runs at ~1.3 CPU and handles ~3 logins/s; replicas scale until the VM's CPUs run out.
- **Fairness caveat:** Zitadel was measured at bcrypt cost 6 (lowered for dev). At its default cost 14 it was ~1 s of CPU per hash (results/a.md), so in production settings the hashing gap reverses. The request-handling gap (~270 ms vs ~50 ms per login) stays.

### Token verification

- Access token (user, from the driver): header `{"alg":"ES384","typ":"at+jwt","kid":…}`, claims `jti, sub (Logto user id, 12 chars), iat, exp, scope ("" here), client_id, iss, aud`. `aud` is a single string: the resource indicator.
- client_credentials token: the same, with `sub == client_id` (the M2M app id) and no `scope`.
- ID token: header has no `typ`, `aud` = the SPA client id, extra `auth_time`. Rejected twice: by `typ` and by `aud`.
- Organization tokens (`aud: urn:logto:organization:<id>`) fail the `aud` check. A request without `resource` gets an **opaque** token, which fails at parse.
- Rules: an access token is a JWT only when a `resource` is requested (or an API resource is marked default). The resource must be passed at the token endpoint too (`useGrantedResource` is off). Logto lets any app request any resource, so the API checks the client itself (`checkClient`).
- P7 (spec §14) is fully met: alg allowlist, `iss`, `aud`, `exp`, token type from `typ: at+jwt`, allowed client.

### Logto organizations (assessment, not built)

What Logto offers: organizations with members, **organization roles and scopes defined once for the whole tenant** (a template every org shares), org roles that can carry API resource scopes, org tokens (`organization_id` on refresh_token or client_credentials grants), M2M apps added to orgs with org roles, invitations (Management API; the email goes out through your email connector), JIT membership by verified email domain or enterprise SSO connector, per-org MFA requirement and branding. Users are tenant-wide and belong to any number of orgs, so a2's "users live in a `people` org" workaround is not needed.

Against round 2's finding (IdP-owned tenancy didn't help):
- **Custom roles still can't move.** Org roles are tenant-wide templates; a merchant can't define its own role without every org seeing it. There is no store level under an org, no refund limit, no expiring grant and no guardrails. Authorization stays in SpiceDB and membership stays in SQL for the tenant precheck, so orgs would again be a second copy of tenancy with an outbox sync. Logto writes are immediate, so the sync would be simpler than a2's (no projection lag), but it is still a second writer.
- **No org suspension.** Organizations have no disabled state. Cutting a suspended merchant's people out at login means removing memberships or suspending each user (and JWTs live until `exp`). Zitadel at least deactivates an org's resident machine users.
- **Org-scoped M2M** gives an agent an org token naming its merchant. That is an extra tenant claim (what a2 used `MerchantID` for), not a replacement for grants and expiry in SpiceDB.
- **Where it would help:** merchants that bring their own IdP: enterprise SSO connectors (SAML/OIDC, in OSS) attached to an org, with JIT membership by email domain. Also invitation onboarding (Logto's invite + sign-up + verify flow), and per-merchant MFA policy and branding on the sign-in page. Same conclusion as round 2 for Zitadel: **worth it only when per-merchant SSO or IdP-side invitations are a real requirement**, with membership mirrored back into the app's DB.

### Licence, self-host vs cloud, project health

- **Licence:** MPL-2.0 (GitHub API, repo root), OSS image `svhd/logto`.
- **Self-host has everything this spike uses:** OIDC, password sign-in, M2M apps, API resources and RBAC, organizations, enterprise SSO (SP-initiated), invitations, custom JWT claims (run locally in OSS), the Management API. Cloud-quota checks are no-ops in OSS.
- **Cloud only or paid in self-host:**
  - Since v1.44–1.45 (2026-09/10), a **Self-Hosted Pro licence key** unlocks, on self-host: hiding "Powered by Logto" on the sign-in page, a custom sign-in UI uploaded to Logto plus custom CSP, IdP-initiated SSO, more than 3 SAML apps, several console admins with invitations, and mandatory console MFA. These were Cloud-only before (v1.43 rejected `hideLogtoBranding` outside Cloud), so this is an expansion, not a removal. It is still open-core: **a customer-facing sign-in page without Logto branding needs the licence** (or a custom UI served at Logto's origin through your own proxy, which the Experience API allows but Logto doesn't support).
  - Cloud only: Logto's hosted email/SMS sending (self-host brings its own connector, e.g. SMTP), Protected App, multiple tenants and dev tenants.
- **Health:** a release every month (v1.36.0 2026-01-30 … v1.45.0 2026-10-13), last push 2026-10-17, 100+ commits in the last 30 days, ~14.7k stars. Commercially backed (Silverhand); the company sells Cloud and the self-hosted licence.

## Traps hit

1. **No bind mounts with a remote Docker host.** Mounting `./edge/nginx.conf` made Docker create empty directories at the Mac's path on cs-ws (removed again). Configs are baked into images (`stacks/f/edge/Dockerfile`, the Postgres image carries the seed SQL), as stack b does.
2. **cs-ws's dev proxy rewrites redirects.** Tailnet traffic to ports 3000–8999 on cs-ws goes through a Caddy that turns `localhost` into `cs.internal` in `Location` headers. Ports 8081–8089 (this spike's earlier stacks) are excluded; **8091–8093 (stacks f and g) are not**. The driver's `http://localhost:3999/callback` came back as `cs.internal:3999`, so the driver's redirect URI is `http://127.0.0.1:3999/callback`. Extending the exclusion to 8090–8099 in collielab's dev-proxy script would put f and g on the same path as a–e.
3. **Sign-in experience validation:** email as a sign-up identifier requires email verification, which requires an email connector. Since users are created only through the Management API, sign-up identifiers are empty and the mode is sign-in only.
4. **Bootstrap of the first Management API client** (above): SQL seed.
5. **One Node event loop per Logto.** The first run had 53 timeouts. Fixed with replicas: seed and alterations moved to a one-shot (`logto-init`) so replicas don't race on first start, and nginx re-resolves `f-logto` every 10 s (Docker DNS round-robin) instead of pinning the addresses it saw at start.
6. **Management API and OIDC share port 3001.** Publishing Logto directly would expose `/api/*` to anything that can reach the host (token-protected, unlike Hydra's admin API, but still the full admin surface). The nginx edge allowlists `/api/experience` and `/api/.well-known/`.
7. **Dev-mode auth bypass:** with `NODE_ENV` other than `production`, Logto's Management API accepts a `development-user-id` header with no token. The image's `npm start` sets `production`; checked (401 without a token). Any custom entrypoint must keep it.

## Verdict: login-only IdP

- **Logto** has the cleanest tokens (`at+jwt`, RFC 8707 audiences), no consistency lag, a documented headless sign-in API that needs no admin endpoint, a usable sign-in UI out of the box and the strongest B2B features (orgs, per-org SSO/JIT, invitations). It is the heaviest to run: ~6× Zitadel's CPU per login at our settings, replicas needed for bursts, a 2 GB image, ~225 MB per instance, a SQL seed for its first API client and a proxy to hide the Management API. Branding removal and custom UI hosting are paid on self-host.
- **Zitadel** is the cheapest per login (Go, tunable hashing) and bootstraps from env. But it is eventually consistent (driver retries), binds the issuer to the Host header, has a heavier headless login (`IAM_LOGIN_CLIENT` PAT) and a console to lock down.
- **Ory (Kratos + Hydra)** has the smallest adapter and is config-as-code, but it is two services with no sign-in UI (you build one), an unauthenticated admin API that must stay on the private network, and the pool-deadlock trap.
- **For login only, Logto doesn't beat Zitadel or Ory** on what this spike measures: the cost is runtime and ops weight, and its standout features (orgs, SSO, hosted sign-in UI) matter only if per-merchant SSO or a ready-made sign-in page becomes a requirement. If it does, Logto is the easiest of the three to adopt for that, at the price of CPU and possibly a licence.
