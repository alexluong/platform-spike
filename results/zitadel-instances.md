# Zitadel: one virtual instance per merchant (round 4 bench, TASK-62)

Standalone answers about Zitadel itself for stack `i` (SPEC §16): one Zitadel deployment, one virtual instance per merchant, the instance picked by our gateway/app with `x-zitadel-instance-host`. Zitadel **v4.19.5** (latest, 2026-10-15) + Postgres 17, compose project `ps-zbench` on cs-ws (`bench/zitadel-instances/compose.yaml`, port 8099). Everything is scripted under `bench/zitadel-instances/` (Node 24, no dependencies); raw outputs in `bench/zitadel-instances/evidence/`.

```sh
DOCKER_HOST=ssh://cs-ws bench/zitadel-instances/up.sh           # stack (+ System API key in .keys/)
mise exec -- node bench/zitadel-instances/probe-routing.ts      # probes 1-2
mise exec -- node bench/zitadel-instances/probe-users.ts        # probe 4
ZBENCH_DENYLIST=... up.sh; node probe-federation.ts             # probe 5 (see there)
mise exec -- node bench/zitadel-instances/probe-settings.ts     # probe 6
mise exec -- node bench/zitadel-instances/probe-delete.ts       # probe 7
mise exec -- node bench/zitadel-instances/bench.ts grow|measure|restart   # part 2
```

Setup used by all probes: two System API users from one RSA key (`ZITADEL_SYSTEMAPIUSERS`): `zbench` (default `SYSTEM_OWNER`: create/delete instances) and `zlogin` (membership `System` with role `IAM_LOGIN_CLIENT`: the Session/OIDC services on **every** instance). Instances are created with `POST /system/v1/instances/_create` with `customDomain: m-<n>.idp.internal` and an owner machine user with a PAT (`IAM_OWNER` in that instance). No DNS anywhere: every request goes to `cs-ws:8099` with Host = the default instance's domain, so a request that lands on the merchant instance proves the header won.

## Probe answers

| # | question | answer |
|---|---|---|
| 1 | Every API honours `x-zitadel-instance-host`? | **Yes.** Discovery, JWKS, Management v1, Admin v1, Auth v1, User v2 (REST and Connect), Session v2, OIDC v2 (finalize), `/oauth/v2/authorize`, `/oauth/v2/token`, userinfo, Actions v2, settings v2. None needs the real Host. System API ignores it. |
| 2 | Issuer with `x-zitadel-public-host`? Must it be registered? Several per instance? | Issuer = `http(s)://<public host>` (else `<instance host>`). **The public host must be a *trusted domain* of that instance** (`POST /admin/v1/trusted_domains`), else **404 Instance not found**, even if it is an instance domain. One instance answers for **any number of trusted domains**, one issuer each, same keys. |
| 3 | Login UI v2 forwards the instance header? | **Yes, by design.** It reads `x-zitadel-instance-host`/`x-zitadel-public-host` from the incoming request and sets them on every API call; a **System API user with `IAM_LOGIN_CLIENT`** lets one Login UI deployment serve all instances. No custom login needed for routing. |
| 4 | Invite with pre-verified email + password / passkey setup codes, no SMTP? | **Yes.** `POST /v2/users/new` (`email.isVerified: true`, no password) → `POST /v2/users/{id}/password_reset {returnCode:{}}` / `POST /v2/users/{id}/invite_code {returnCode:{}}` / `POST /v2/users/{id}/passkeys/registration_link {returnCode:{}}`. Both completed headless (software authenticator for the passkey). |
| 5 | Federation between instances on the same deployment; #9535 across instances? | **Works**, after two gotchas: Zitadel's default **outbound deny list blocks private IPs** (the IdP backchannel to another instance on the same deployment fails), and the IdP's issuer must resolve **inside** the Zitadel container to Zitadel with the right Host. Auto-create + link at B, then the **same** Shop user at C: both fine. **#9535 does not bite across instances**; inside one instance an external identity links to one user (409 *External IDP already taken*, even across orgs). |
| 6 | SMTP, SMS, Actions v2, branding, login policy per instance? | **Yes, all five** (set on B, absent/default on C). Catch: forced MFA is **not enforced by the APIs**: a password-only Session API login at an instance with `forceMfa: true` still gets tokens (`amr: ["pwd"]`). Enforcement is the login UI's job. |
| 7 | Instance deletion? | `DELETE /system/v1/instances/{id}`: **28 ms**, instance unreachable at once, domain reusable at once. **Projection rows are removed; events are not** (681 of 1516 rows stay in `eventstore.events2`, plus a few in `current_states`/`milestones`): the event store only grows. |

### 1. Instance header (evidence: `evidence/probe-routing.txt`)

- Header A with Host = default instance → discovery `issuer=http://pa-….idp.internal`, JWKS has A's kids (different from B's and the default's), `orgs/me` returns A's org, the full login (authorize → `POST /v2/sessions` → `POST /v2/oidc/auth_requests/{id}` → token) issues `iss=http://pa-….idp.internal`.
- Host vs header (curl with explicit Host, run on cs-ws): Host = A, no header → A (Host is the fallback); Host = unknown, header A → A; Host = A, header B → **B (header wins)**; header unknown → **404, no fallback to Host**.
- Header with a port (`pa-….idp.internal:8099`) → matches A, and the port ends up in the issuer (`http://pa-….idp.internal:8099`). **Upper-case header → 404**: the domain lookup is an exact, case-sensitive match (`eventstore.fields.object_id = $1`, `internal/query/instance_by_domain.sql`). The gateway must lower-case.
- Isolation: A's access token at B's userinfo → 401; A's PAT at B's Management API or the default instance → 401 `Errors.Token.Invalid`.
- Each instance also gets a generated domain `<name>-<random>.<ExternalDomain>`; it is harmless if nothing routes it.
- Login UI v1 (`/ui/login`) redirects to the console; console `environment.json` advertises `api` = the ExternalDomain, `issuer` = the instance. Irrelevant if we only use Login UI v2/our own UI.
- The scheme in issuers comes from `ExternalSecure` (here `false` → `http://`). In production TLS terminates at the gateway and `ExternalSecure: true` gives `https://`.

### 2. Public host

- Code (`internal/query/instance.go`, `checkDomain`): a public host is accepted if empty, equal to the instance host, or in the instance's `TrustedDomains`; anything else → `QUERY-IuGh1` 404. Measured: unregistered → 404; registered as an **instance domain** (System API `POST /system/v1/instances/{id}/domains`) but not trusted → 404; another instance's domain → 404; **trusted domain → 200**, `issuer=http://shop-a3-….brand.test`, all endpoints under it.
- Instance domains are **globally unique** (409 `Errors.Instance.Domain.AlreadyExists`); trusted domains are per instance (no uniqueness across instances found).
- Instance domain vs trusted domain behave differently: an instance domain also selects the instance **by Host** (no headers needed); a trusted domain alone does not (Host = trusted domain → 404). For our gateway (always sets both headers), trusted domains are the right tool: **custom store domain = trusted domain on the merchant's instance**.
- Two trusted domains on one instance → two logins issue `iss=http://shop-a4…` and `iss=http://shop-a3…`, same `kid`, same JWKS under either host.
- **Tokens are bound to the issuer they were minted under**: a token with `iss=shop-a4` → 401 at userinfo under `shop-a3` and under the bare instance host. Our app's verifier must accept every issuer of a merchant (one per store domain) with one JWKS per instance, and a session started on one domain stays on it.
- `/oauth/v2/authorize` redirects to a **relative** `/ui/v2/login/login?authRequest=…`: the login UI must be served on the same public host under `/ui/v2/login` (gateway route), or the instance's login v2 base URI set.

### 3. Login UI v2 (code reading, v4.19.5 `apps/login`)

- `src/lib/server/host.ts`: `getInstanceHost` = `x-zitadel-instance-host` → `x-zitadel-forward-host` → `host`; `getPublicHost` = `x-zitadel-public-host` → `x-zitadel-forward-host` → `x-forwarded-host` → `host`.
- `src/lib/zitadel.ts` (Connect transport interceptor) and `src/proxy.ts` (Next middleware proxying `/oauth`, `/oidc`, `/.well-known`, …) set both headers on every call to `ZITADEL_API_URL`. `CUSTOM_REQUEST_HEADERS` adds more.
- Credentials: `ZITADEL_SERVICE_USER_TOKEN` (a PAT, valid in **one** instance only: probe 1 shows PATs are instance-bound) **or** `SYSTEM_USER_ID` + `SYSTEM_USER_PRIVATE_KEY` + `AUDIENCE` (`src/lib/api.ts`, `deployment.ts`): a System API user JWT, valid on every instance. Measured: the System API user needs an explicit `IAM_LOGIN_CLIENT` membership (default `SYSTEM_OWNER` → 403 `AUTH-AWfge` on `/v2/sessions`); with it, sessions + finalize work on any instance. The instance owner (`IAM_OWNER`) can create sessions but **not** finalize auth requests (403).
- So: gateway → Login UI v2 with the two headers (stripped from clients), Login UI → Zitadel with the same headers. A custom login on the Session API is optional (for our own UX), not required.

### 4. Invite flow without SMTP (`evidence/probe-users.txt`)

All calls through the instance header. Owner PAT for admin calls; `zlogin` (the login client) for the user-facing steps.

| step | endpoint | result |
|---|---|---|
| create staff user, verified email, no password | `POST /v2/users/new {organizationId, username, human:{profile, email:{email, isVerified:true}}}` | 200, `USER_STATE_ACTIVE`, `isVerified=true` |
| invite code | `POST /v2/users/{id}/invite_code {returnCode:{}}` | 200 `inviteCode` (6 chars) |
| password-setup code | `POST /v2/users/{id}/password_reset {returnCode:{}}` | 200 `verificationCode` |
| set password with code | `POST /v2/users/{id}/password {newPassword, verificationCode}` | 200; login with it 201; code reuse → 400 *Code not found* |
| passkey registration code | `POST /v2/users/{id}/passkeys/registration_link {returnCode:{}}` | 200 `code {id, code}` |
| start registration with code (no session) | `POST /v2/users/{id}/passkeys {code, domain}` | 200 `passkeyId`, creation options with `rp.id = domain` |
| finish registration | `POST /v2/users/{id}/passkeys/{passkeyId} {publicKeyCredential, passkeyName}` | 200 |
| passkey login | `POST /v2/sessions {checks:{user}, challenges:{webAuthN:{domain}}}` → `PATCH /v2/sessions/{id} {checks:{webAuthN:{credentialAssertionData}}}` | factors `user,webAuthN`, `userVerified=true` |

- `domain` (rpId) worked for the instance domain, a trusted store domain, and an **unregistered** domain: Zitadel does not tie rpId to its domains; the browser's origin check does. Our UI must pass the store's domain, and a passkey is then bound to that domain (a customer with two store domains needs a passkey per domain, or one shared login domain).
- The `send_link` variants (`sendLink: {urlTemplate}`) need the instance's SMTP; `returnCode` leaves delivery to us (our own email service).

### 5. Federation between instances (`evidence/probe-federation*.txt`)

Wiring: instance **S** (Shop/platform) owns domain `shop.idp.internal`, a docker network alias of the Zitadel container; its issuer is `http://shop.idp.internal:8080` both for the driver (instance header with the port) and for B's/C's server (dialling the alias). S has one confidential web app whose redirect URIs are `http://<tenant>/idps/callback` per tenant. B and C each have an **instance-level generic OIDC IdP** (`POST /admin/v1/idps/generic_oidc`, auto-creation on, **auto-linking off**, `isIdTokenMapping: false`). Flow per login, all headless: tenant authorize → `POST /v2/idp_intents` (tenant) → S authorize → S session + finalize → tenant `/idps/callback` (tenant ↔ S code exchange on the backchannel) → `POST /v2/idp_intents/{id}` → (first time) `POST /v2/users/human` in the tenant's `customers` org with `idpLinks` → tenant session with `idpIntent` check → finalize → tenant token.

| step | result |
|---|---|
| default deny list | **fails**: `OpenID Provider Configuration Discovery has failed … dial tcp 192.168.112.3:8080: address is denied by '192.168.0.0/16'` (`evidence/probe-federation-denylist-default.txt`) |
| deny list without the docker range | works |
| B first login | auto-created + linked; B token `iss=http://fb-….idp.internal`, `sub` = B's user |
| B again | intent returns the linked user, same `sub` |
| C first (same Shop user) | auto-created + linked in C, its own `sub` |
| C again | same C user |
| link the same Shop identity to a 2nd user in another org of B | **409 `External IDP already taken`** |
| local B customer with the Shop buyer's email | 0 links (auto-linking off: never linked by email) |

Gotchas:
- **Deny list** (`HTTPClient.DenyList`, default blocks 10/8, 172.16/12, 192.168/16, 127/8, …): a deployment whose instances federate with each other over internal addresses must allow that range, which also opens it to Actions targets and other admin-configured URLs (SSRF surface). Alternative: point the IdP at the **public** issuer of the Shop instance via the normal ingress (public IP, not denied).
- **Issuer reachability**: the tenant's server dials the upstream issuer URL itself. Internal-only names (`*.idp.internal`) work only if they resolve inside the Zitadel pods to something that forwards with the right instance header (gateway) or Host. The issuer string must be identical on the browser path and the backchannel (the port is part of it).
- Actions v2 targets with unresolvable hosts are rejected too (`Errors.Target.DeniedURL`).
- The ID token has no profile/email claims; map from userinfo (`isIdTokenMapping: false`).
- Auto-creation is not done by the API: Login UI v2 (or our UI) creates the user from `addHumanUser` in the intent response. Same for linking.
- Linking is unique **per instance and IdP**, not per org: in one tenant instance a Shop account can be one customer **or** one staff user, not both. With an instance per merchant this is the wanted rule.

### 6. Per-instance settings (`evidence/probe-settings.txt`)

| setting | API (instance B) | B | C |
|---|---|---|---|
| SMTP | `POST /admin/v1/smtp` + `_activate` | `SMTP_CONFIG_ACTIVE` | none |
| SMS | `POST /admin/v1/sms/twilio` | provider (inactive) | none |
| Actions v2 | `POST /v2/actions/targets`, `PUT /v2/actions/executions` (event `user.human.added`) | 1 target, 1 execution | none |
| branding | `PUT /admin/v1/policies/label` + `_activate` | primary `#ff0066` | default `#5469d4` |
| login policy | `PUT /admin/v1/policies/login {forceMfa:true}` | `forceMfa=true` | default |

**Forced MFA is advisory at the API level**: password-only login (Session API + finalize) at B still issues tokens, `amr=["pwd"]`. Login UI v2 enforces the policy; a custom login must check `GET /v2/settings/login` itself, and the app should check `amr` for pools where MFA is mandatory (merchant staff).

### 7. Deletion (`evidence/probe-delete.txt`)

Instance with a login setup, 21 users, one login: 1516 rows in 44 tables (`events2` 679, `fields` 496, …). `DELETE /system/v1/instances/{id}` → 200 in 28 ms; discovery 404 at once; domain reusable at once (re-create 200). After delete: 756 rows in 5 tables, unchanged after 90 s: **`eventstore.events2` 681 (all events kept, plus the removal event)**, `current_states` 64→67, `milestones3` 6, `instance_features5` 3, `web_keys1` 2. Deleting merchants does not shrink the event store; purging is a manual SQL job.

## Bench (part 2): **reduced, measured under load**

cs-ws never went quiet: after the ~2 h wait (load 10–50, `pc-bench` containers present the whole time) the bench ran the **reduced version**: up to **1,000 instances** (plus ~35 from probes/smoke = 1,034 in the DB), creation concurrency 2. During measurement the host load average was **13–70** on 4 CPUs (other workspaces' `pc-*`/`pr-*` benches and stack i's suite `ps-i`, whose Zitadel + Postgres were the top CPU users). **Latencies below are inflated and noisy; resource growth per instance and the idle-CPU mechanism are the reliable results.** The client ran on the Mac (RTT to cs-ws ~3.5 ms; `/debug/healthz` p50 ~5 ms is the floor). Zitadel `mem_limit` 2 GB, Postgres 2 GB, `MaxOpenConns` 30, bcrypt cost 6, caches off (Zitadel default).

Raw data: `bench/zitadel-instances/out/{grow,measure,restart}.jsonl`. Every 10th instance got a login setup (project, PKCE app, one user); logins pick random login-ready instances; JWKS/discovery hit random instances.

### Growth

| instances | create instance p50 / p95 (ms) | + login setup p50 / p95 (ms) | DB size | `events2` rows | `fields` rows | host load (1m) |
|---|---|---|---|---|---|---|
| 250 | 1,672 / 2,345 | 732 / 1,086 | 292 MB | 176 k | 138 k | 48 |
| 500 | 1,797 / 2,902 | 761 / 1,277 | 535 MB | 332 k | 262 k | 39 |
| 1,000 | 2,104 / 3,925 | 892 / 1,555 | 1,019 MB | 641 k | 509 k | 31 |

- **Per instance: ~1 MB of Postgres and ~620 events** (an empty instance from `_create` is most of it: default policies, texts, keys), linear so far. Largest relations at 1k: `events2` 553 MB, `fields` 362 MB, `custom_texts2` 21 MB. **Extrapolated 10k: ~10 GB, ~6.2 M events, before any users.**
- Create latency rose 1.7 → 2.1 s p50 (load also varied). 0 errors in 1,000 creates. At conc 2 that is ~1.1 s wall per instance: 10k ≈ 3 h.

### Latency (random instances)

| instances | login p50 / p95 (ms) | authorize / session / finalize / token p50 | JWKS p50 / p95 | discovery p50 / p95 | host load |
|---|---|---|---|---|---|
| 250 | 188 / 577 | 30 / 53 / 40 / 54 | 10.7 / 16.3 | 9.3 / 17.0 | 48 |
| 500 | 175 / 911 | 21 / 51 / 39 / 48 | 8.5 / 14.9 | 8.0 / 13.8 | 39–44 |
| 1,000 | 131 / 208 | 20 / 39 / 29 / 36 | 11.9 / 23.5 | 9.5 / 19.8 | 27–31 |
| 1,000, TTL settings, instance inactive | 221 / 648 | 34 / 65 / 41 / 65 | 16.0 / 30.7 | 13.7 / 36.8 | 13–34 |

No degradation with instance count visible up to 1k (the p95 swings follow host load). Login = 4 requests (authorize, `POST /v2/sessions` with password, finalize, token). JWKS on all 1,000 instances in one pass (conc 4): p50 16–22 ms, done in 5–7 s.

### Idle CPU: the main scaling cost

Mechanism (code, v4.19.5): each projection's scheduler runs every `RequeueEvery` (60 s) over `ActiveInstances()`, an in-memory LRU of instances **that served a request since start** (`internal/query/cache.go`, `internal/eventstore/handler/v2/handler.go`). `Projections.HandleActiveInstances` is that LRU's TTL (0 = never expires), `MaxActiveInstances` its size (0 = unlimited). Reads also trigger projections for their instance on demand, so an instance that dropped out still works.

| state (1,000 instances, no requests during the 60 s sample) | Zitadel CPU | Postgres CPU | Zitadel RSS |
|---|---|---|---|
| defaults, right after growing (all 1,000 active) | **36 %** | **31 %** | 238 MB |
| defaults, after restart (LRU empty) | 8 % | 3 % | 87 MB |
| defaults, after restart + one JWKS request to every instance | **35 %** | **40 %** | 150 MB |
| `HandleActiveInstances=2m`, `MaxActiveInstances=200`, just after touching all | 43 % | 29 % | 146 MB |
| same, 2.5 min later (TTL expired) | **6 %** | **0.5 %** | 137 MB |
| (reference) 250 / 500 instances, defaults, all active | 7 % / 24 % | 12 % / 27 % | 159 / 169 MB |

- **Idle cost scales with the number of instances that saw traffic**, not with the total. With defaults every instance that ever got one request (a JWKS fetch by our gateway counts) stays in the scheduler loop forever: ~0.35 core Zitadel + ~0.35 core Postgres per 1,000 active instances, here. Linear extrapolation: **10k active ≈ 3.5 + 3.5 cores doing nothing useful**, and one scheduler pass over 10k instances × ~100 projections may not finish in 60 s. Not measured (reduced bench).
- **With a TTL it drops to ~0**, and logins on inactive instances still work (table above: 0 errors; first request pays the on-demand projection trigger, p50 ~220 ms under load vs ~130–190). So **`HandleActiveInstances` (e.g. 10–30 m) plus a `MaxActiveInstances` cap is mandatory** for thousands of instances.
- Memory stays small: Zitadel RSS 80–240 MB at 1k (caches off). Postgres ~0.6–0.9 GB (shared_buffers 512 MB).

### Restart

| config | ready (`/debug/ready`) | first login | CPU settled < 15 % |
|---|---|---|---|
| 20 instances, defaults | 6.6 s | 7.9 s | 22 s |
| 1,000, defaults | **34 s** | 35 s | 70 s |
| 1,000, TTL 2 m / max 200 | 27 s | 28 s | 104 s (noisy, load 51) |

Startup time grows with instance count (34 s at 1k vs 7 s at 20; startup work scales with instances, cause not profiled). Catch-up after a restart is lazy (instances join the scheduler as they get requests), so there's no storm unless traffic touches every instance at once. Extrapolating linearly, 10k ≈ 5 min to ready: rolling restarts with ≥ 2 replicas are needed. Unmeasured.

## Verdict: one instance per merchant at 10k

**Feasible on functionality; scale is only proven to 1k under load, and 10k needs tuning and a real test before we commit.** Everything the model needs works per instance through the header: issuers, keys, users, sessions, invites, passkeys, per-merchant SMTP/SMS/branding/actions/MFA policy, custom store domains (trusted domains), Shop federation with per-instance linking, one shared Login UI v2. Per-instance cost is ~1 MB DB and ~2 s to create. Request latency did not grow from 250 to 1k.

Main risks:
1. **Idle projection load grows with active instances** (~0.7 core per 1k active, defaults). Must set `HandleActiveInstances` + `MaxActiveInstances`; behaviour at 10k (scheduler pass time, on-demand trigger latency for cold instances, many cold instances at once after an incident) is unmeasured.
2. **Startup time grows with instances** (34 s at 1k); ~5 min at 10k by extrapolation.
3. **Event store only grows**: ~6 M events at 10k before any user, deletes don't remove events.
4. **Security config is ours**: forced MFA isn't enforced by the API; the gateway must strip/lower-case the headers; federation between instances needs either a deny-list hole (SSRF surface) or routing the backchannel via public ingress.
5. One Postgres for all merchants: a noisy merchant or a bad migration hits everyone (blast radius). Zitadel's quotas/limits per instance exist but weren't tested.

**Next measurement** (when cs-ws or a dedicated box is quiet): `bench.ts grow --to 10000 --conc 4` with `ZBENCH_HANDLEACTIVEINSTANCES=15m ZBENCH_MAXACTIVEINSTANCES=1000`, then `measure` / `touch` / `restart` at 2.5k, 5k, 10k. The scripts are rerunnable as is (state in `out/state.jsonl`, gitignored).

## What stack i should do differently

- **Login client = a System API user with `IAM_LOGIN_CLIENT`** (`ZITADEL_SYSTEMAPIUSERS` membership `System`), not a per-instance PAT: one credential for all instances. Instance owner PATs (from `_create`) for admin calls; they can't finalize auth requests.
- **Select instances with `x-zitadel-instance-host: <lower-case internal domain>`**; instance domains are globally unique; **don't** include a port unless you want it in the issuer. Expect 404 (no Host fallback) for unknown/mis-cased names.
- **Custom store domains = trusted domains** (`POST /admin/v1/trusted_domains`) + `x-zitadel-public-host`; an unregistered public host → 404. The app's verifier needs **every issuer of a merchant** (instance domain + each store domain), same JWKS; tokens only validate at Zitadel under the issuer they were minted with.
- **Shop federation**: instance-level generic OIDC IdP per tenant instance, auto-linking **off**, `isIdTokenMapping: false`; the tenant must reach the Shop issuer from inside Zitadel (allow the range in `HTTPClient.DenyList`, or point at the public issuer via ingress). Auto-create the linked user ourselves from the intent's `addHumanUser` (the API doesn't). One link per instance and IdP is the wanted rule.
- **Invites**: create users with `email.isVerified: true`, then `invite_code` / `password_reset` / `passkeys/registration_link` with `returnCode` and send our own email; passkey `domain` = the store's domain.
- **Enforce MFA in our login path** (or rely on Login UI v2) and check `amr` for staff tokens; Zitadel's login policy alone doesn't block a password-only Session API login.
- **Set `Projections.HandleActiveInstances` (10–30 m) and `MaxActiveInstances`** from day one; don't fetch JWKS for every instance on a schedule at startup (it marks them all active), fetch lazily per issuer.
- Deleting a merchant: `DELETE /system/v1/instances/{id}` (fast, frees projections, keeps events; domain reusable).
