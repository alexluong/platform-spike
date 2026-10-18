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

## Bench

(pending: part 2)
