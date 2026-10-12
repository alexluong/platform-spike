# Stack d results: TypeScript (Hono) + Better Auth with the organization plugin + Cerbos + Postgres

Run on 2026-10-13 against `ps-d` on cs-ws (`docker compose -p ps-d --profile d up -d --build`). Built from `c`; the app lives in `ts-org/` (copied from `ts/`, which is untouched) and will also host stack `e`.

## Conformance

**390 / 390 passed**: the 362 shared tests plus the 28 `idp-tenancy` tests (SPEC §15.2, §15.3), including the slow break-glass expiry test (`STACK=d HOST=cs-ws.lab.alexluong.com pnpm test`, 74 s). No failures by design.

The first full run failed most tests with pool timeouts; fixed in the second build (see DX notes: a login-policy hook took a second connection inside Better Auth's own transaction). Nothing else needed a change to pass.

Unit tests (vitest, `ts-org`): 28 (c: 24). Cerbos policies and their tests are c's, unchanged (`stacks/d/cerbos`, run by `cerbos compile` at image build).

## What the organization plugin owns

| concern | where it lives in d | mechanism |
|---|---|---|
| merchant | Better Auth `organization` row (id = merchant id, `status` additionalField) | org adapter `createOrganization` / `updateOrganization`, inside the app's transaction |
| membership | Better Auth `member` row, `role` always `"member"` | org adapter `createMember` / `deleteMember`; one merchant per user = a unique index on `member("userId")` (app migration `0001_idp_links.sql`) |
| invitations (§15.2) | Better Auth `invitation` rows | create/list/cancel through the org adapter; **accept through Better Auth's own `acceptInvitation` endpoint** (recipient check by email, pending + unexpired, member insert) |
| login policy, users (§15.3) | `databaseHooks.session.create.before` | no session for a member of a suspended organization: sign-in → 403 `MERCHANT_SUSPENDED` after the password check (wrong password stays 401) |
| login policy, agents (§15.3) | global `hooks.before` on `/oauth2/token` + `oauthClient.referenceId` = the merchant | client_credentials for a client whose owning organization is suspended → 400 `invalid_client`. Apps have no `referenceId` and are unaffected |
| roles, assignments, store scope, limits, guardrails | app (`roles`, `role_assignments`), Cerbos, as in c | unchanged (see Custom roles) |

The app never mounts the plugin's HTTP routes (`exposedPaths` is c's list) and never uses its role checks: who may invite, cancel or add a member is `member.manage` through `can()`. The app reads the plugin's tables in SQL through read-only Drizzle mirrors (`ts-org/src/db/idp-tables.ts`): the PIP, tenant scoping, `/api/me`, the last-owner row lock. Writes go only through the `Tenancy` port (`ts-org/src/kernel/tenancy.ts`), so the IdP is the single writer of tenancy data.

Membership is read from `member` on every request (principal resolver and PIP), never from the session. The session's `activeOrganizationId` is not used as a tenant source; only `acceptInvitation` sets it, as a side effect.

## Cross-system writes (§15.1): one transaction

**Finding: Better Auth's organization writes can run in the app's transaction.** Better Auth core and the organization plugin don't hold their adapter: every query goes through `getCurrentAdapter(base)`, which reads an AsyncLocalStorage (`@better-auth/core/context`). Inside it, `runWithTransaction` joins any transaction already marked active. The app uses that:

1. `withTransaction(pool, fn)` (`db/client.ts`) checks out one connection and opens the Drizzle transaction on it.
2. `identity.tenancyFor(client)` (`adapters/better-auth.ts`) binds a second Better Auth adapter to that same connection: `kyselyAdapter` over a Kysely whose "pool" hands out the current transaction's connection (`release()` is a no-op, and `BEGIN`/`COMMIT`/`ROLLBACK`/`SAVEPOINT` are refused on it). Every port call runs inside `als.run({ adapter: txAdapter, isTransactionActive: true, pendingHooks })`.
3. The executor hands modules `RunCtx.idp` (the bound port). Better Auth's after-commit hooks queued during the transaction run after the commit and are dropped on rollback.

Evidence (`ts-org/scripts/tx-probe.mjs`, run in the app container; Better Auth's own pool is checked out and held during each step, so any query on it would time out):

| step | result |
|---|---|
| create organization + member + invitation, then throw | the app's tx saw the member row; another connection saw no organization before the throw; **after rollback: 0 organization, 0 member, 0 invitation rows** |
| add a second membership for the same user | 409 `already_member` (unique index, inside the tx) |
| `auth.api.acceptInvitation` (session lookup, recipient check, invitation update, member insert, session update) inside the app's tx | succeeds with Better Auth's pool held: every query stayed on the tx connection |
| `adminCreateOAuthClient` inside the app's tx | **times out**: the OAuth provider writes through `ctx.context.adapter`, not `getCurrentAdapter` |

Pool rule (§1): the organization writes take no connection at all; they reuse the request's. The 60-request burst test passes.

| write | atomic with the app's rows? | failure window |
|---|---|---|
| merchant create (organization + owner member + owner assignment + outbox) | yes | none |
| suspend / reinstate (organization.status + outbox) | yes | none. Both the login policy and the PIP read that one column |
| member add / remove (member + assignments + outbox) | yes | none |
| invitation create / cancel / accept | yes | none. Without the outer transaction Better Auth's own accept is a two-step write with a compensating update (`pending → accepted`, then insert member, on error `accepted → pending`); inside ours it is one commit |
| agent registration (OAuth client, then agent row + `referenceId` link) | **no**: the client is committed on Better Auth's pool before the app's tx | if the app's tx rolls back, an OAuth client stays with no agent row and no organization link. Its tokens are valid JWTs that map to no principal (401), and suspension can't reach it because it has no organization. Recovery: a sweep deleting `oauthClient` rows with no `apps`/`agents` row older than a few minutes (not built; review-c #10 still open) |
| app registration (OAuth client, then app row) | no, same as c | same orphan, same recovery |

No outbox consumer is needed for the IdP: the IdP's tables are in the same Postgres and written in the same transaction. Membership events in the outbox now carry `merchantId` (an invitation accept emits `member.added`), so stack `e`'s relay to SpiceDB can consume them.

## Custom roles: dynamic access control not used

**Decision: roles stay in the app, as in c.** Better Auth's `member.role` is always `"member"`; nothing role-related is in two places. Evidence from the plugin source at 1.7.7 (`better-auth/dist/plugins/organization/`):

| §3 rule | plugin | holds? |
|---|---|---|
| store-scoped assignments | a role is a comma list in `member.role`, one per organization. Teams have members but no roles (`teamMember` has no role column) | **no** |
| assignments as objects (`id`, 409 `already_assigned`, delete by id → 404) | no assignment rows | **no** |
| refund limits, highest wins at the order's store | a permission is `resource → actions[]`; `organizationRole.additionalFields` can store a number, but `hasPermission` never reads it | **no** |
| guardrail on create: caller holds every permission of the role | `createOrgRole` checks it, but with `useMemoryCache: true`: `cacheAllRoles` is a process-global `Map` filled by whichever `hasPermission` call last loaded that organization. Another instance, or a role edited since, gives a stale answer | partly, and not across instances |
| guardrail on edit: old **and** new permissions | `updateOrgRole` checks `ac:update` and the new permissions only | **no** |
| guardrail on delete, assign, unassign | `deleteOrgRole`: `ac:delete` only. `updateMemberRole` (assign): `member:update` plus owner rules, no "hold the role" check | **no** |
| limit guardrail (caller's limit ≥ role's) | none | **no** |
| edits apply on the next request | `hasPermission` without the cache reloads `organizationRole` rows per call | yes |
| apps and agents (installs, grants, granter still holds it) | members only | **no** (app-side anyway) |
| system roles `owner`/`admin`/`developer`/`staff` | static `roles` via `createAccessControl` | yes, but they would need the same per-store semantics |

Carrying even the part that fits (merchant-scope role definitions) would split one concept: merchant-scope roles in Better Auth, store-scope assignments and limits in the app, with guardrails reimplemented over both. §15.1 says a role kept in two places is a finding; the cleaner answer was to keep one place.

## Lines of code (non-blank, non-comment)

| area | c (`ts/`) | d (`ts-org/`) | change |
|---|---|---|---|
| modules (domain, excl. PIP and tests) | 988 | 1045 | +57: invitations (4 actions) +52, member/merchant writes via the port ±0 |
| PIP (`modules/access.ts`) | 126 | 127 | reads `member`/`organization` instead of `members`/`merchants` |
| kernel | 284 | 308 | +20 `tenancy.ts` (port), +4 executor/`RunCtx` |
| identity + org glue (`adapters/better-auth.ts`) | 113 | 286 | +173: org plugin options 25, login-policy hooks 30, tx-bound adapter 25, `Tenancy` implementation 90 |
| Cerbos adapter | 107 | 107 | unchanged |
| DB: app schema + helpers | 229 | 243 | −2 tables (merchants, members) −19; read-only mirrors +25; `withTransaction` +8 |
| HTTP routes + main | 211 | 225 | 4 invitation routes; `transact` wiring |
| config: compose, Cerbos | c's | c's | identical apart from names and port |
| migrations | 180 lines SQL | 172 + 7 hand-written | FKs to `organization`, unique `member("userId")` |
| unit tests | 220 | 251 | login hook, org options, tx-control guard |

`git diff --no-index --stat ts/src ts-org/src`: 20 files, +536 −100 (diff lines, comments included).

**What the plugin removed vs c:** the `merchants` and `members` tables and their two inserts/deletes. That is all. Every merchant/member write still exists, now as a port call.

**What it pushed back into the app:**
- the port and its tx binding (a second DB adapter on the app's connection, an AsyncLocalStorage contract that is documented as "internal use" for `getCurrentDBAdapterAsyncLocalStorage`);
- read-only mirrors of Better Auth's tables and a hand-written migration linking to them (FKs, unique index), because the app's SQL (tenant scoping, PIP, row locks) needs them;
- two login-policy hooks;
- error mapping from Better Auth's `APIError` codes to the API's;
- the raw bearer still travels in `Principal.credential` (review-c #11): `acceptInvitation`, like `adminCreateOAuthClient`, needs the caller's session.

**What it gave:** invitation storage and the accept rules (recipient by email, case-insensitive; pending; unexpired; reinstated on failure), the organization/member schema with indexes and cascades, the client→organization link (`referenceId`), and a tested home for the login policy. Invitations written in-app would be about the same size as the glue they needed here.

## `d` → `e` readiness

- The Cerbos adapter has no identity or organization code; the PIP reads membership from `member`. For `e`, the SpiceDB adapter replaces `cerbos.ts` and the PIP; the `Tenancy` port, Better Auth glue, modules and executor stay.
- `e` will need membership in SpiceDB: the outbox events `merchant.created`, `member.added` (direct add and invitation accept), `member.removed`, `merchant.suspended/active` carry `merchantId` and are written in the same transaction as the IdP rows.

## Ops

- **Containers:** 3, as c (`d-postgres` postgres:17-alpine, `d-cerbos` cerbos 0.56.0 with policies baked in, `d-app` node:24-alpine). Migrations (Better Auth's, now including organization/member/invitation, then Drizzle's) run at app start.
- **Memory idle:** app 57 MiB, Cerbos 32 MiB, Postgres 23 MiB, **~112 MiB**. After a full suite run: 100 / 48 / 35 MiB, **~183 MiB** (c: ~113 / ~175).
- **Cold start:** `down -v` then `up -d --wait` with images built: **9.5 s**. First build ~45 s. App restart to healthy: 2 s.
- **Images:** app 538 MB, Cerbos 138 MB.
- **Bootstrap pain:** none beyond c's. The FK migration depends on Better Auth migrating first; app start does both in that order.

## DX notes

- **What was hard:** finding out whether Better Auth writes can join an outer transaction. The docs don't cover it. The answer is in `@better-auth/core/context/transaction.mjs` (`getCurrentAdapter`, `runWithTransaction`, `queueAfterTransactionHook`) and in which plugin files call `getCurrentAdapter` (core, organization, jwt: yes; oauth-provider: no). It works, but it rests on an internal-marked API and on each plugin's discipline; a Better Auth upgrade could move a write outside the transaction silently. `tx-probe.mjs` is the regression check.
- **What I got wrong first:** the session-create hook read through `ctx.context.adapter`. Sign-up creates the session inside Better Auth's own transaction, so the hook took a second connection from the auth pool while the sign-up held one. Parallel sign-ups exhausted the pool and most of the suite timed out. This is review-c's deadlock again, now inside the IdP's own code paths. Rule for Better Auth hooks: read through `getCurrentAdapter(ctx.context.adapter)`.
- **Docs vs code:**
  - The docs list `organizationHooks` but not that they fire only in the plugin's endpoints. The org adapter (`getOrgAdapter`, exported) bypasses them, so `beforeAcceptInvitation` runs here only because accept goes through the endpoint.
  - The docs say `addMember` is server-only, but every other member/invitation endpoint enforces the plugin's own role checks (`invitation:create`, `member:delete`), so they can't be used when roles live in the app. The usable surface is the adapter plus `acceptInvitation`.
  - `membershipLimit`/`invitationLimit` default to 100, which would cap a merchant at 100 members.
  - The `status` additionalField gets no DB default (the default is applied in code), so rows written outside Better Auth would have `NULL`. The app writes it explicitly and reads `NULL` as active.
  - Dynamic access control's create-role guard uses a process-global role cache.
- **Better Auth DB adapter on a foreign connection:** `kyselyAdapter` over a Kysely `PostgresDialect` whose `pool.connect()` returns the transaction's client works (Kysely 0.29 also wants `pool.options`). The Postgres code paths in the adapter open no inner transactions; the MySQL paths do, which is why the wrapper refuses transaction-control statements.
- Same as c: rate limiter and origin check, `VOLUME /policies`, client creation needs a session.

## Spec issues

- **§15.3 "the IdP refuses (not the app)":** with an in-process IdP that line is blurry. The refusal is Better Auth's (its sign-in and token endpoints answer 403/400 from its own hooks), but those hooks are app code, configured in the identity adapter. Recorded as met.
- **Accepting an invitation into a suspended merchant** is unspecified. d refuses it (403 `merchant_suspended`, `beforeAcceptInvitation`).
- **Invitation `status` values** are unspecified beyond `pending`. d returns Better Auth's (`pending`, `accepted`, `canceled`), plus `expired` for a pending one past `expiresAt` (Better Auth keeps those `pending` and refuses them on accept). The suite only checks "not pending" after a cancel.
- **`POST /members` still skips consent** (§14 P8) because §15.1 keeps it for the helpers. With invitations in place it could become platform-only or test-only.
- An invitation to a user who already belongs to another merchant is accepted at create time and fails at accept (409), as the suite expects. Refusing at create would leak whether an email belongs to some merchant.
