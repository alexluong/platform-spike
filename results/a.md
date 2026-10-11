# Stack a results: Go + Zitadel v4.19.4 + SpiceDB v1.56.2

Run 2026-10-11 against `DOCKER_HOST=ssh://cs-ws` (4 CPU / 11 GB VM), branch `go-a`.

## Conformance

`cd conformance && STACK=a HOST=cs-ws.lab.alexluong.com pnpm test`

| run | result |
|---|---|
| full (incl. 65 s break-glass expiry) | **341 passed / 341**, 81 s |
| `SKIP_SLOW=1`, stack fresh from `down -v` | 340 passed, 1 skipped, 16 s |

No failures, so nothing failing by design. Use `HOST=cs-ws.lab.alexluong.com`: bare `cs-ws` is an ssh alias and doesn't resolve on the Mac (see Ops).

First run: 57 pass / 124 fail. Three causes, all fixed:
1. Zitadel's default bcrypt cost (14) costs about 1 s of CPU per user create or login. With the suite's parallel user creation, `/api/_test/users` timed out. Dev compose sets `ZITADEL_SYSTEMDEFAULTS_PASSWORDHASHER_HASHER_COST=6`.
2. `client_credentials` right after `POST /v2/users/{id}/secret` sometimes gets `Errors.User.Machine.Secret.NotExisting`, because Zitadel projections are eventually consistent. The driver retries for up to 5 s.
3. `/api/me/permissions` listed `platform.break_glass` for support staff. It now lists merchant-data (grantable) actions only, per AMBIGUITIES #25.

## Lines of code (non-blank, non-comment)

| area | files | LOC |
|---|---|---|
| shared kernel: executor, registry, `can()`, guardrails, ports (`authz`, `identity`), catalog (`perm`), db + migrations, outbox relay | `go/internal/{core,perm,authz,identity,db,outbox}` | 1047 |
| modules: platform, merchants, roles, stores, catalog, orders, payments, delivery, apps, agents, me, testsupport, scope | `go/internal/modules` | 1592 |
| adapter: Zitadel (verifier, provisioner, bootstrap) | `go/internal/adapters/zitadel` | 265 |
| adapter: SpiceDB (schema generator, Authorizer, RelationSync) | `go/internal/adapters/spicedb` | 442 (+231-line generated `schema.zed`, 99-line `validation.yaml`) |
| composition roots (`server`, `bootstrap`) | `go/cmd` | 265 |
| compose, Dockerfile, Postgres init | `stacks/a`, `go/Dockerfile` | 143 |
| login driver | `conformance/stacks/a.ts` | 136 |
| Go tests | executor prechecks, denial codes, guardrail context, schema golden + `zed validate` | 156 |

## Design (what stack b reuses)

- **Ports.** `internal/identity`: `Verifier.Verify(token) → {Subject}`, `Provisioner.CreateUser(email, pw)` and `CreateClient(name) → {Subject, ClientID, ClientSecret}`. `internal/authz`: `Authorizer.Evaluate` / `EvaluateMany` (AuthZEN request/decision shape), plus `RelationSync.Apply(Event)`. Outbox events are engine-neutral and carry the full desired state of their object (`role.upserted` has the whole permission list and the limit), so re-applying one is idempotent.
- **One `can()`** (`core.Executor.Can`): token/scope check (principal kind vs action), then tenant check in SQL (a user or agent of another merchant → 404, before the engine), then suspension in SQL (→ 403 `merchant_suspended`), then the engine. The guardrails (`Req.HoldsAll`) call the same `can()` in batch. Refund limit: `order.refund` is checked with `context.amountCents`. Granting a role checks it with the role's limit; no limit means 2^53.
- **Executor** (`core/executor.go`), the same path for every op: authenticate → resolve target (SQL, in the request's transaction) → `can()` → run → commit (outbox rows written in the same transaction) → drain → respond. Break-glass reads are audited in the same transaction.
- **Outbox relay** (`internal/outbox`): one drainer at a time (advisory lock), rows applied in id order. The request that wrote rows drains before responding. A background loop retries every 1 s. A row is dropped after 10 failed attempts (logged).
- **Read-your-writes:** the SpiceDB adapter keeps the latest ZedToken from its own writes in memory and checks with `at_least_as_fresh` (`fully_consistent` until the first write). This is correct for one app instance only; several instances would need the token in the DB.
- **The schema is generated from the catalog** (`spicedb.Schema()`). A golden test keeps `schema.zed` in sync, and `zed validate validation.yaml` runs 33 assertions in `go test` and again in the Docker build (a stage that fails the build).

## Glue code for custom roles (SpiceDB)

- **Sync** (`spicedb.go`, ~200 LOC): one `switch` maps each event type to relationship writes.
  - Role edits read `role:<id>`'s relationships, then send one `WriteRelationships` that deletes the extras and touches the desired set, including the refund caveat context.
  - Each assignment writes four relationships: the binding's two subjects (`user:u` and `user:u#delegate`), the binding's role, and the scope's `binding`.
- **Cascades in the app:** deleting a role deletes its assignments, each with its own `assignment.deleted` event, then emits `role.deleted`, which deletes everything on `role:<id>`. Removing a member emits `assignment.deleted` per assignment.
- **System roles** live in code. At every start the app enqueues them through the outbox, so a permission the platform adds reaches `owner` and `admin` without a migration.
- **Expiry** needs no cleanup job: `use expiration`, with expiring relationships on `agent_grant` (`agent` + one per permission) and on `merchant#break_glass_viewer`.
- **Agents act only within the granting user's current rights.** Every role binding also has the subject `user:<grantor>#delegate`, and `user#delegate` points at `agent_grant#agent`. An agent passes a store check only when the grantor's bindings give the permission there, AND a live grant on that store lists it. Removing the user's role cuts the agent off (AMBIGUITIES #40), with no extra sync.
  - **Limit:** set algebra can't tie a grant to its grantor. If two users each granted the same agent, one user's roles could combine with the other's grant. The app refuses that case with 409 `agent_grantor_conflict` (live grants of one agent must come from one user). The suite doesn't exercise it.
- **Suspension:** `merchant#suspended@{user,agent,app}:*`, excluded from every merchant/store permission. Staff aren't excluded, so break-glass still works on a suspended merchant.

## Ops

| | |
|---|---|
| containers | 6: postgres (one instance, databases `zitadel`, `spicedb`, `app`), zitadel, spicedb, spicedb-migrate (one-shot), bootstrap (one-shot), app. No Zitadel login UI container and no Traefik. |
| memory at idle (after the suite, then restart) | app 13 MB, spicedb 57 MB, zitadel 95 MB (210 MB after load), postgres 137 MB (300 MB after load): about 300 MB idle, about 550 MB after a run |
| cold start `up -d --build --wait` from `down -v`, images cached | 16 s (first time on the VM, including image pulls and the Go build: about 49 s for `up` after the build) |
| images | zitadel 235 MB, spicedb 136 MB, app 80 MB, postgres 423 MB |
| bootstrap | idempotent; a re-run takes about 1 s (migrations, schema write, project and app found by name) |

Bootstrap pain:
- **The Zitadel issuer and instance come from the Host header.** `ExternalDomain` must be the exact name clients use, so the app, the bootstrap and the driver must all reach Zitadel under that one name. The compose file gives the Zitadel container a network alias equal to the external domain (`STACK_A_HOST`, default `cs-ws.lab.alexluong.com`) and runs Zitadel on 8085 inside and out, so `http://cs-ws.lab.alexluong.com:8085` works on both sides.
  - The domain is fixed when the instance is first created: changing `STACK_A_HOST` needs `down -v`.
  - The first attempt used `cs-ws`, which the containers resolve but the Mac doesn't.
- **First-instance env** creates both service accounts and writes their PATs to a shared volume: `FIRSTINSTANCE_ORG_MACHINE_*` gives an IAM owner for the app, `FIRSTINSTANCE_ORG_LOGINCLIENT_*` gives `IAM_LOGIN_CLIENT` for the driver. No clicking needed, but these variables are only documented in `steps.yaml`.
- **Login v2 is required by default (v4).** `/oauth/v2/authorize` redirects to `…/ui/v2/login/login?authRequest=V2_…`. The driver reads the id from that redirect, so no login container runs.
- **Project and app creation still use the v1 management REST API.** The v2 project/application services are Connect-only, and v1 is well documented and idempotent by name search.

## DX notes

- **Zitadel.**
  - The API reference pages omit request bodies (CreateUser human fields, Session checks). The proto files in the repo were the reliable source.
  - `CheckUser.login_name` matches the computed login name only, not email. It works here because the username is the email and `UserLoginMustBeDomain=false`.
  - Machine users authenticate with their **username** as `client_id`. `AddSecret` returns only the secret.
  - Tokens are opaque unless the app's `accessTokenType` / the machine user's `accessTokenType` is JWT.
  - `aud` carries the project id only when the `urn:zitadel:iam:org:project:id:<id>:aud` scope is requested.
- **SpiceDB.**
  - A subject relation to an expiring relation can't itself carry expiration (`user#delegate: agent_grant#agent` rejected `[expiration:…]`). Not needed: expiry flows from `agent_grant#agent`.
  - `zed validate` warns `arrow-references-relation` for every `grant->x` / `merchant->suspended`. These are harmless warnings, left unsilenced.
  - `authzed-go` + `grpcutil` pull in old `genproto` and `cloud.google.com/go`. `go mod tidy` failed with "ambiguous import" until both were bumped to latest.
- **What the agent got wrong first:** the issuer host (bare `cs-ws`), bcrypt cost, expiration on the delegate relationship, Zitadel secret propagation, and `/me/permissions` scope semantics (it first reported store actions at merchant level). All were fixed after reading AMBIGUITIES.md and the run output.

## Spec issues (choices made)

1. **Test mode:** added `GET /api/_test/driver-config` (needs `X-Test-Secret`). It hands the driver the Zitadel issuer, client id, project id and the `IAM_LOGIN_CLIENT` PAT that a real login UI would hold. The PAT is a Zitadel credential handed to the test driver; the app never trusts the driver's tokens without JWKS verification.
2. **Migrations** run in the bootstrap container (`bootstrap` binary); the app doesn't migrate at start.
3. **Internal actions** not in §4: `platform.app.register` (for `POST /api/platform/apps`) and `role.manage_owner` (the "only an owner manages owner" rule, held only through the `owner` role). Neither is listed in `/me/permissions`.
4. **Agent grants:** only users grant (an agent can't), and live grants of one agent must come from one user (409 `agent_grantor_conflict`). See the limit under Glue code.
5. **PATCH/DELETE of a system role** → 403 `system_role`.
6. **Refund** only on `paid` orders (AMBIGUITIES #20). State errors use 409 `invalid_transition`; over-refund uses 409 `over_refund`; over-limit is 403 `forbidden`.
7. `HOST=cs-ws` in the spec's run command doesn't resolve on the control Mac. Use `HOST=cs-ws.lab.alexluong.com`, or set `STACK_A_HOST` and recreate.

## What changed in Go between a and b

Not measured yet (stack b not built). Expected: `internal/adapters/{ory,openfga}`, plus one new `case` each in the `IDP` / `AUTHZ` switches of `cmd/server/main.go` and `cmd/bootstrap/main.go`. Anything else is a finding.
