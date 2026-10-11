# Stack c results: TypeScript (Hono) + Better Auth + Cerbos + Postgres

Run on 2026-10-11 against `ps-c` on cs-ws (`docker compose -p ps-c --profile c up -d --build`).

## Conformance

**341 / 341 passed**, including the slow break-glass expiry test (`STACK=c HOST=cs-ws.lab.alexluong.com pnpm test`, 73–91 s). No failures are by design of the stack.

Earlier runs failed for these reasons, all fixed:

| symptom | cause | fix |
|---|---|---|
| sign-in 429 for most tests | Better Auth's rate limiter can't see a client IP, so every request lands in one shared bucket | `rateLimit: { enabled: false }` |
| sign-in 403 `MISSING_OR_NULL_ORIGIN` | Better Auth 1.7 requires an Origin header on sign-in (login CSRF); a headless client sends none | `advanced.disableCSRFCheck: true` (bearer-only API, no cookies) |
| every app/agent token → 401 | client_credentials JWTs carry `sub = client_id`; my check rejected any `sub` as "user-delegated" | accept `sub == client_id` |
| store-scoped `staff` assignment → 403 escalation | the guardrail asks "does the caller hold `merchant.view` at the store?"; the store policy only had rules for store-scope actions | merchant-scope permissions also get rules on the store resource (AMBIGUITIES #3) |
| rebuilt Cerbos image kept serving old policies | the `cerbos` base image declares `VOLUME /policies`, and Compose carries the anonymous volume over on recreate | bake policies into `/etc/platform/policies` |

## How custom roles were done with Cerbos

Cerbos is stateless and has no relationship store, so **custom roles stay data in Postgres** and Cerbos only sees what they resolve to.

- **The app is the PIP.** The adapter (`ts/src/adapters/cerbos.ts`) takes an AuthZEN request that carries only ids, then asks `modules/access.ts` for attributes on every check (no cache, so edits apply on the very next request):
  - user: `merchantId` plus `access = { owner, merchantPerms, merchantRefundLimits, stores: { <sid>: { perms, refundLimits } } }`. The app takes the union per scope; the policy combines merchant scope and store scope.
  - app: `installs: { <sid>: scopes }`.
  - agent: `merchantId` plus `grants: { <sid>: [ { perms, expiresAt, granter: <the granting user's access> } ] }`. Expired grants are sent too, and the policy compares `now() < timestamp(expiresAt)`, so expiry needs no cleanup job. The rule "granter still holds the action" is evaluated in the policy against the granter's access as it is now.
  - platform staff: `breakGlass: { <mid>: expiresAt }`.
  - resource: `merchantId`, `storeId`, `status` (the merchant's status), plus `amountCents` for refunds (passed as AuthZEN `context`).
- **The policy holds platform semantics only:** what each permission means, tenancy (`P.attr.merchantId == R.attr.merchantId`), suspension (a DENY rule for `user/app/agent` whose output is `"merchant_suspended"`, which becomes the 403 code), refund limits (highest wins, `-1` = no limit), the restrictions on what apps may hold, and break-glass. Break-glass is read-only, and its rule output `"break_glass"` tells the executor to write an audit row. Merchants never write policy.
- **Guardrails go through `can()`**: "the caller holds every permission in the role" is `evaluateMany` at the scope. "The caller's limit is ≥ the role's limit" is `can(order.refund, scope, {amountCents: roleLimit ?? MAX_SAFE_INTEGER})`, so the policy's own limit rule decides.
- **Wart: Cerbos CEL can't see the action being evaluated**, so the policy has one rule per permission (`'"order.view" in V.granted'`). `V.granted` is computed once per principal kind by policy variables. That makes 21 one-line rules on `merchant`, 22 on `store`, plus a few platform rules. The catalog is therefore duplicated in the YAML; nothing checks that they stay in sync, except the policy tests and the suite.
- **PlanResources** backs `GET /merchants/:mid/stores`. The obvious map lookup (`P.attr.access.stores[R.attr.storeId]`) planned into an unusable residual (`index` on an unknown key). The `store.view` user rule is therefore written as `R.attr.storeId in P.attr.access.stores.filter(k, "store.view" in ...perms)`, which plans to a plain `storeId IN [...]` that becomes SQL. Anything else the planner returns falls back to per-store `CheckResources`.
- **Alternative rejected:** generating a scoped policy per merchant role (Cerbos scoped policies plus the Admin API on a mutable store). It would turn Cerbos into a second store of role data that has to be synced, which is exactly what Cerbos avoids.

**Glue for custom roles:**

| concern | how |
|---|---|
| sync | none; nothing is copied to the engine |
| cascade deletes | role delete removes its assignments in the same transaction; member removal removes that member's assignments |
| expiry | attribute comparison in CEL |
| consistency | read-your-writes for free: attributes are read from the DB on every check |

The cost is DB reads per check: about 2–4 queries per principal per request; agents add one access lookup per granter.

## Patterns (SPEC §1)

- **Action registry and one executor:** `ts/src/kernel/{action,executor}.ts`. 41 actions. Order of checks: authenticate (401) → credential kind (403) → input validation (400) → `authorize()` resolves resources (404) and the executor runs the `can()` checks (403) → `run` plus outbox plus break-glass audit, all in one Postgres transaction.
- **Outbox:** written for every mutating action. Nothing consumes it, because Cerbos has nothing to sync. It is the hook a relationship engine would use.
- **`can()` in AuthZEN shape:** `evaluate`, `evaluateMany`, and `searchResources` (PlanResources) in `ts/src/kernel/authz.ts`. Modules never import Cerbos.
- **Tenant isolation twice:** SQL lookups are scoped by merchant for users and agents (`modules/lookup.ts`), and the policy checks tenancy again. Apps and platform staff are not confined in SQL; Cerbos alone gates them (install / break-glass).
- **Composition root:** `ts/src/main.ts`. No DI container.
- **Non-catalog policy actions:** `role.manage_owner` (owner-only assign/remove of `owner`), `agent.register`, `platform.app.register`.

## Identity (Better Auth 1.7.7)

- **Users:** email/password, with the `bearer` plugin. The driver reads `set-auth-token` from `POST /api/auth/sign-in/email`. The app validates via `auth.api.getSession` (DB lookup), so sessions are opaque and the app never trusts token claims for kind or merchant.
- **Apps and agents:** `@better-auth/oauth-provider` clients doing `client_credentials`. Tokens are JWTs with `aud = urn:platform-spike:api` (an RFC 8707 resource seeded in the config) and scope `api`. The app verifies them with `verifyJwsAccessToken` against its own JWKS, maps `azp` to an app or agent row, and requires scope `api` (the token check).
- Only `sign-in/email`, `oauth2/token`, `jwks` and the openid-configuration path are mounted; the other Better Auth routes are not exposed.

## Lines of code (non-blank)

| area | LOC |
|---|---|
| modules (domain logic: platform, merchants, roles, stores, catalog, orders, payments, delivery, apps, agents, me, guardrails, lookup, principals) | 956 |
| access resolution (the PIP that turns roles into attributes; custom-role glue) | 133 |
| kernel (catalog, AuthZEN types, action/registry, executor, errors) | 292 |
| adapters: Cerbos 114, Better Auth 114 | 228 |
| HTTP routes 105, main 104 | 209 |
| DB schema and helpers (TS) | 238 |
| Cerbos policies (YAML) | 228 |
| Cerbos policy tests (104 assertions, run by `cerbos compile` at image build) | 282 |
| unit tests (vitest, 12) | 114 |
| config: compose, Dockerfiles, Cerbos config, tsconfig, drizzle config | 114 |
| generated migration SQL | 179 |
| conformance driver | 39 |

## Ops

- **Containers:** 3 (`c-postgres` postgres:17-alpine, `c-cerbos` cerbos 0.56.0 with policies baked in, `c-app` node:24-alpine). No one-shot container: Better Auth's migrations and the Drizzle migrations run idempotently at app start.
- **Memory at idle:** app 55 MiB, Cerbos 34 MiB, Postgres 24 MiB, **~113 MiB total**. After a full suite run: 96 / 48 / 31 MiB, ~175 MiB.
- **Cold start:** `down -v` then `up -d --build --wait` took **18 s** with the layer cache warm. The first uncached build took ~60 s. App restart to healthy: ~13 s, measured over the network, including migration checks.
- **Images:** app 537 MB (pnpm prod `node_modules`; Better Auth pulls in a lot), Cerbos 138 MB.
- **Bootstrap pain:** low.
  - No IdP container, no service accounts, no client provisioning.
  - The OAuth resource is seeded from config.
  - The test secret and the auth secret are dev-only values in `stacks/c/compose.yaml`.
- `cs-ws` doesn't resolve as a bare name on this Mac; ssh resolves it through the ssh config. The suite was run with `HOST=cs-ws.lab.alexluong.com`.

## DX notes (what was hard, what an agent got wrong first)

- **Better Auth OAuth provider:** works, but several things are only found by reading the types or tripping on them:
  - `adminCreateOAuthClient` is "server only" yet still needs a session. The app passes the calling user's bearer through `principal.credential`, which is a leak in the identity port.
  - client_credentials requires `client_credentials_scopes` at creation, a configured resource, and `clientRegistrationDefaultResources` (otherwise `invalid_target ... not linked`).
  - The plugin seeds its resource row at init, so `getMigrations` must run on the options **before** `betterAuth()` is constructed (otherwise "schema mismatch" and no resource).
  - Rate limiting and the sign-in origin check are on by default and break headless or test clients.
- **Cerbos:**
  - Policy tests are excellent: 104 cases ran locally with the darwin binary in under a second, and they also run in the image build.
  - Pains: no access to the action in CEL (hence per-action rules); planner output depends on how a condition is phrased; rule outputs are the only way to carry a deny reason.
  - The base image's `VOLUME /policies` silently pins old policies across rebuilds under Compose.
- **Agent mistakes (mine):** rejecting `sub` on M2M tokens; not modelling "merchant-scope permission held at a store" for store-scoped guardrails. Both were caught by the suite, not by the policy tests (the policy tests encoded my own reading).
- No buildx on the Mac, so Compose uses the classic builder (it warns; it works).

## Spec issues (choices made)

- Merchant-scope permissions held at a store count for guardrails (AMBIGUITIES #3); `/me/permissions?merchantId=` reports merchant-scope actions only (AMBIGUITIES #1).
- An agent's grant may list any grantable action. The policy does not stop agents from holding `role.manage` / `agent.grant` (the spec doesn't forbid it; apps are blocked).
- Unassign applies the same guardrail as assign (hold the role's permissions at the scope). Now the rule for all stacks (SPEC §3) and tested.
- PATCH/DELETE of a system role → 403 `system_role`.
- 409 codes: `invalid_transition` for every status precondition, `over_refund`, `last_owner`, `already_member`, `already_assigned` (`not_captured` removed in the alignment: unreachable).
- No endpoint lists role assignments (as the suite also notes); not added.
