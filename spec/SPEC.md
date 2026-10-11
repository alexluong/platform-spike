# Platform spike: spec

A mini Shopify, built three times on different identity + authorization stacks, all passing one black-box test suite (`conformance/`). The goal is to compare stacks and test a few architecture patterns, not to ship a shop. Keep everything else (UI, real payments, email) out.

| stack | app | identity (who) | authorization (may they) | port |
|---|---|---|---|---|
| `a` | Go | Zitadel (OIDC) | SpiceDB | 8081 |
| `b` | Go (same app as `a`, other adapters) | Ory Kratos + Hydra (OIDC) | OpenFGA | 8082 |
| `c` | TypeScript (Hono) | Better Auth (in the app) | Cerbos | 8083 |

Stacks `a` and `b` are **one Go codebase**. Switching between them must be configuration plus adapters only; no module code may know which identity provider or authorization engine is behind it. How much had to change for `b` is one of the spike's results.

## 1. Patterns the code must follow

1. **Action = unit of capability.** Every operation is an action with an id `<module>.<verb>` (catalog in §4). A registry lists them. One executor runs every mutating action: authenticate → authorize (`can`) → run → write outbox in the same DB transaction. HTTP handlers are thin adapters onto actions.
2. **One `can()` in AuthZEN shape.** The executor calls `can({subject, action, resource, context}) → {decision, reason?}` (OpenID AuthZEN 1.0 Access Evaluation shape, in-process). SpiceDB / OpenFGA / Cerbos sit behind it as adapters. A batch form (`canMany`) backs `GET /api/me/permissions`.
3. **Custom roles are data.** The platform owns the permission catalog and the policy. Merchants create roles (subsets of grantable permissions) and assign them at a scope. Merchants never write policy.
4. **App DB is the source of truth.** Roles, assignments, installs and grants live in Postgres (Go) / SQLite or Postgres (TS). Where the authz engine stores relationships (SpiceDB, OpenFGA), they are written from an **outbox** row committed in the same transaction as the change. The request that made the change drains its own outbox rows before responding, and later checks use the engine's read-your-writes mechanism (SpiceDB ZedToken / OpenFGA `HIGHER_CONSISTENCY`), so a change is visible to the very next request. A background relay retries anything left over. Cerbos is stateless: the app sends attributes (the PIP is the app).
5. **Three checks.** Token/scope (is this credential allowed this kind of thing), relationship (is this subject connected to this resource), condition (attributes: refund limit, status, expiry). All must pass.
6. **Tenant isolation twice.** Every query is scoped by merchant in SQL, and the authz engine checks too. Customers (buyers) are never put in the authz engine: "my orders" is `WHERE customer_id = me`.
7. **Composition root by hand.** One `main` wires config → adapters → modules. No DI container, no globals.

## 2. Tenancy and principals

```
platform
└── merchant (tenant)            status: active | suspended
    ├── members (merchant users) role assignments at merchant scope or store scope
    ├── roles (system + custom)
    └── stores
        ├── products
        ├── orders ── payments, shipments
        ├── app installs (app + granted scopes)
        └── agent grants
customers: per store (a customer of store s1 is nobody to store s2)
```

Principal kinds (the `subject.type` in `can`):

| kind | authenticates with | notes |
|---|---|---|
| `platform` | user login (OIDC / Better Auth) | platform roles: `platform_admin`, `support` |
| `user` | user login | merchant users; permissions only through role assignments |
| `customer` | user login | can create orders in a store and read their own orders; nothing else |
| `app` | client credentials | permissions = scopes granted at install on a store |
| `agent` | client credentials | acts for the user who created the grant; see §6 |

A user belongs to at most one merchant in this spike.

## 3. Roles

**System roles** (exist in every merchant, maintained by the platform, not editable or deletable through the API):

| role id | permissions |
|---|---|
| `owner` | every grantable permission |
| `admin` | every grantable permission |
| `developer` | `merchant.view`, `store.view`, `product.view`, `order.view`, `app.install`, `app.uninstall`, `app.view` |
| `staff` | `merchant.view`, `store.view`, `product.view`, `product.create`, `product.update`, `order.view`, `order.cancel`, `shipment.view`, `shipment.create`, `shipment.update` |

`owner` vs `admin`: only an owner can assign or remove the `owner` role. The last owner assignment of a merchant cannot be removed (409 `last_owner`).

**Custom roles:** `{name, permissions: ActionId[], refundLimitCents?: number}`.
- Only grantable permissions (§4) are allowed (400 `not_grantable`).
- `refundLimitCents` applies to `order.refund` through this role. Absent = no limit. System roles have no limit.
- Editing a role's permissions takes effect for everyone holding it, on the next request.
- Deleting a role removes its assignments.

**Assignments:** `{userId, roleId, scope: {type: "merchant" | "store", id}}`.
- Merchant scope applies to every store of the merchant. Store scope applies to that store only.
- A user's permissions at a store = union over assignments at that store + at the merchant.
- For `order.refund` with several roles, the highest limit wins (no limit beats any limit).

**Guardrails (no escalation):** to create, edit, assign or delete a role, the caller needs `role.manage` at that scope **and** must hold every permission in that role at that scope. For limits: the caller's own refund limit must be ≥ the role's (or the caller has no limit). Violations are 403 `escalation`. These are checked in the action, through `can`.

**New permissions are deny by default:** a custom role holds exactly the permissions listed in it. (System roles are defined in code and get new permissions when the platform adds them.)

## 4. Permission catalog

`grantable` = may appear in a custom role. Scope = the resource the check runs against.

| action id | grantable | scope | notes |
|---|---|---|---|
| `platform.merchant.create` | no | platform | `platform_admin` |
| `platform.merchant.view` | no | platform | `platform_admin`, `support` |
| `platform.merchant.suspend` | no | platform | `platform_admin`; also reinstate |
| `platform.break_glass` | no | merchant | `support` and `platform_admin` may open one; see §7 |
| `platform.audit.view` | no | platform | `platform_admin` |
| `merchant.view` | yes | merchant | |
| `merchant.update` | yes | merchant | |
| `member.manage` | yes | merchant | add/remove members |
| `role.manage` | yes | merchant or store | create/edit/delete roles, assign/unassign (plus guardrails) |
| `store.create` | yes | merchant | |
| `store.view` | yes | store | |
| `product.create` | yes | store | |
| `product.update` | yes | store | |
| `product.view` | yes | store | |
| `order.view` | yes | store | |
| `order.cancel` | yes | store | only `pending` or `paid` orders not shipped |
| `order.refund` | yes | store | condition: amount ≤ role limit; order must be `paid` |
| `payment.capture` | yes | store | |
| `payment.view` | yes | store | |
| `shipment.create` | yes | store | order must be `paid` |
| `shipment.update` | yes | store | |
| `shipment.view` | yes | store | |
| `app.install` | yes | store | |
| `app.uninstall` | yes | store | |
| `app.view` | yes | store | |
| `agent.grant` | yes | store | create/revoke agent grants (plus §6 rules) |

Customer actions are not in the catalog (checked in SQL): `order.place` (create an order in a store), `order.view_own`.

## 5. Apps

- The platform registers apps (`POST /api/platform/apps`, `platform_admin`) with a list of requested scopes (catalog action ids, grantable only). Registering returns client credentials.
- A merchant user with `app.install` on a store installs an app with `scopes ⊆ requested`. The installer must hold every scope they grant, at that store (403 `escalation`).
- An app's request is allowed iff it is installed on the resource's store **and** the action is in the install's scopes. Apps never get `role.manage`, `member.manage`, `agent.grant`, `app.install`, `app.uninstall` even if requested (registration rejects them, 400 `not_grantable_to_apps`).
- Uninstall removes access immediately (next request).
- Refund limit for apps: none in this spike (scope only).

## 6. Agents

- An agent is registered by a merchant user (`POST /api/agents`) and gets client credentials. It belongs to that user's merchant.
- A user with `agent.grant` at a store creates a grant `{agentId, storeId, permissions, expiresInSeconds}`. The user must hold every permission in it at that store (403 `escalation`).
- An agent request is allowed iff an unexpired, unrevoked grant for (agent, store) lists the action **and** the user who created the grant **still** holds the action at that store now (so removing the user's role also cuts the agent off). `order.refund` through an agent uses the granting user's limit.
- Expiry must hold without a cleanup job running (SpiceDB: expiring relationships; OpenFGA: a condition on time; Cerbos: attribute comparison). Revocation: `DELETE` the grant.

## 7. Platform staff

- `platform_admin`: create, view, suspend, reinstate merchants; register apps; view the audit log. No access to merchant data (orders, products, roles) without break-glass.
- `support`: view merchants. No access to merchant data without break-glass.
- **Break-glass:** `POST /api/platform/break-glass {merchantId, reason, minutes}` grants **read-only** access to that merchant's data (`*.view` actions) until expiry. Every request made under break-glass writes an audit entry `{actor, action, merchantId, at}`. The grant itself is audited too.
- **Suspended merchant:** every action by its users, apps and agents is denied (403 `merchant_suspended`), and customers can't place orders in its stores. Platform actions still work. Reinstating restores access.

## 8. Orders, payments, delivery

- Order: `{id, storeId, customerId, items: [{productId, qty, unitPriceCents}], totalCents, status, refundedCents}`.
- Status: `pending` → (`payment.capture`) `paid` → (`shipment.create`) `fulfilling` → (shipment `delivered`) `delivered`. `order.cancel` from `pending` or `paid` (no shipment) → `cancelled`.
- Payment: fake provider. `capture` on a `pending` order captures `totalCents`. `refund` (via `order.refund`) needs a captured payment; total refunded ≤ captured (409 `over_refund`). Partial refunds allowed.
- Shipment: `{id, orderId, carrier, status: label_created | in_transit | delivered}`. Status moves forward only (409 `invalid_transition`).
- State-rule violations are 409 with a code; they are checked after authorization.

## 9. HTTP API

JSON in and out. Auth: `Authorization: Bearer <token>`. Ids are strings. Money in integer cents.

Errors: `{ "error": { "code": "<snake_case>", "message"?: "..." } }`
- 401 `unauthenticated`: missing/invalid token
- 403 `forbidden` (or a more specific code: `escalation`, `merchant_suspended`)
- 404 `not_found`. For resources in **another** merchant, either 403 or 404 is acceptable (the suite accepts both); never 200.
- 400 `invalid_input` / specific codes above; 409 for state rules.

### Platform
| method | path | action | body → response |
|---|---|---|---|
| POST | `/api/platform/merchants` | `platform.merchant.create` | `{name, ownerUserId}` → `201 {id, name, status}`; makes `ownerUserId` a member with `owner` at merchant scope |
| GET | `/api/platform/merchants` | `platform.merchant.view` | → `{items: Merchant[]}` |
| POST | `/api/platform/merchants/:mid/suspend` | `platform.merchant.suspend` | → `{id, status: "suspended"}` |
| POST | `/api/platform/merchants/:mid/reinstate` | `platform.merchant.suspend` | → `{id, status: "active"}` |
| POST | `/api/platform/apps` | `platform_admin` only | `{name, scopes}` → `201 {id, clientId, clientSecret}` |
| POST | `/api/platform/break-glass` | `platform.break_glass` | `{merchantId, reason, minutes}` → `201 {id, expiresAt}` |
| GET | `/api/platform/audit?merchantId=` | `platform.audit.view` | → `{items: [{actor, action, merchantId, at}]}` newest first |

### Merchant
| method | path | action | body → response |
|---|---|---|---|
| GET | `/api/merchants/:mid` | `merchant.view` | → `{id, name, status}` |
| POST | `/api/merchants/:mid/members` | `member.manage` | `{userId}` → `201` (member with no roles) |
| DELETE | `/api/merchants/:mid/members/:uid` | `member.manage` | → `204` (also removes assignments; last owner rule applies) |
| GET | `/api/merchants/:mid/roles` | `merchant.view` | → `{items: [{id, name, system, permissions, refundLimitCents?}]}` |
| POST | `/api/merchants/:mid/roles` | `role.manage` | `{name, permissions, refundLimitCents?}` → `201 Role` |
| PATCH | `/api/merchants/:mid/roles/:rid` | `role.manage` | `{name?, permissions?, refundLimitCents?}` → `Role` |
| DELETE | `/api/merchants/:mid/roles/:rid` | `role.manage` | → `204` |
| POST | `/api/merchants/:mid/role-assignments` | `role.manage` at the scope | `{userId, roleId, scope: {type, id}}` → `201 {id, ...}` |
| DELETE | `/api/merchants/:mid/role-assignments/:aid` | `role.manage` at the scope | → `204` |
| POST | `/api/merchants/:mid/stores` | `store.create` | `{name}` → `201 {id, merchantId, name}` |
| GET | `/api/merchants/:mid/stores` | — | → stores the caller has `store.view` on |

### Store modules
| method | path | action | body → response |
|---|---|---|---|
| GET | `/api/stores/:sid` | `store.view` | |
| POST | `/api/stores/:sid/products` | `product.create` | `{title, priceCents}` → `201 Product` |
| PATCH | `/api/products/:pid` | `product.update` | `{title?, priceCents?}` |
| GET | `/api/stores/:sid/products` | public (no auth) | → `{items}` |
| POST | `/api/stores/:sid/orders` | customer (`order.place`) | `{items: [{productId, qty}]}` → `201 Order` (prices from products) |
| GET | `/api/stores/:sid/orders` | `order.view` | → `{items}` |
| GET | `/api/orders/:oid` | `order.view`, or the order's customer | |
| GET | `/api/me/orders` | customer | → own orders across stores |
| POST | `/api/orders/:oid/cancel` | `order.cancel` | |
| POST | `/api/orders/:oid/refund` | `order.refund` | `{amountCents}` → `Order` (403 when over the limit) |
| POST | `/api/orders/:oid/payments/capture` | `payment.capture` | → `201 {id, orderId, status: "captured", amountCents}` |
| GET | `/api/orders/:oid/payments` | `payment.view` | → `{items}` |
| POST | `/api/orders/:oid/shipments` | `shipment.create` | `{carrier}` → `201 Shipment` |
| POST | `/api/shipments/:shid/status` | `shipment.update` | `{status}` |
| GET | `/api/orders/:oid/shipments` | `shipment.view` | |
| POST | `/api/stores/:sid/apps` | `app.install` | `{appId, scopes}` → `201 {id, appId, storeId, scopes}` |
| DELETE | `/api/stores/:sid/apps/:installId` | `app.uninstall` | → `204` |
| GET | `/api/stores/:sid/apps` | `app.view` | |
| POST | `/api/agents` | any merchant user | `{name}` → `201 {id, clientId, clientSecret}` |
| POST | `/api/stores/:sid/agent-grants` | `agent.grant` | `{agentId, permissions, expiresInSeconds}` → `201 {id, expiresAt}` |
| DELETE | `/api/stores/:sid/agent-grants/:gid` | `agent.grant` | → `204` |

### Me
| method | path | response |
|---|---|---|
| GET | `/api/me` | `{id, kind, merchantId?}` |
| GET | `/api/me/permissions?storeId=` or `?merchantId=` | `{actions: ActionId[]}`: catalog actions the caller may perform there (batch `can`; AuthZEN action search) |

### Test support (only when `TEST_MODE=1`, all need header `X-Test-Secret: <TEST_SECRET>`)
| method | path | body → response |
|---|---|---|
| POST | `/api/_test/users` | `{email, password, kind: "platform" \| "user" \| "customer", platformRole?}` → `201 {id, email}`: creates the identity in the real IdP (Zitadel / Kratos / Better Auth) and the app-side record |

Everything else is created through the real API. There is no reset: every test creates its own merchant, so tests are independent and can run in parallel.

`GET /healthz` → `200` once the app, DB and authz engine are reachable.

## 10. Login (how the suite gets tokens)

Each stack has a driver in `conformance/stacks/<stack>.ts` implementing:

```ts
interface StackDriver {
  baseUrl: string
  loginUser(email: string, password: string): Promise<string>        // bearer token for /api
  loginClient(clientId: string, clientSecret: string): Promise<string> // apps and agents
}
```

Drivers must use the **real** login path of the stack, headless:
- `a` Zitadel: OIDC authorization code flow (+PKCE) driven through Zitadel's session/OIDC APIs (no browser); client credentials for apps/agents.
- `b` Ory: Kratos API (native) login flow, and Hydra authorization code flow with login/consent accepted by the driver through Hydra's admin API (standing in for the login UI); Hydra client credentials for apps/agents.
- `c` Better Auth: email/password sign-in returning a bearer token (bearer or JWT plugin); apps/agents via an API key or OAuth client mechanism Better Auth provides.

The app validates tokens itself (JWT via JWKS, or introspection where the IdP requires it); it never trusts the test driver.

## 11. Runtime

- `compose.yaml` at the repo root with profiles `a`, `b`, `c`. `docker compose --profile a up -d --build` brings up stack `a` with everything it needs (Postgres, IdP, engine, app, migrations, IdP bootstrap) and leaves it healthy with no manual step. Each profile uses its own containers and volumes.
- Docker runs on a remote host (`DOCKER_HOST=ssh://cs-ws`). So: **no bind mounts of source code**; images are built from the build context; config files are baked into images or passed as `configs`. Published ports: app as in the table at the top; anything else the drivers need (IdP ports) published too and listed in `conformance/stacks/<stack>.ts`.
- Bootstrap (IdP clients, keys, the Zitadel service account, Hydra clients, engine schema/model, Cerbos policies) is done by a one-shot container in the profile, idempotent.
- Run the suite: `cd conformance && STACK=a HOST=cs-ws pnpm test`.

## 12. Results to record (per stack, in `results/<stack>.md`)

- Conformance pass/fail per test, and which failures are by design of the stack.
- Lines of code: modules (shared logic) vs adapters vs bootstrap/config.
- What changed in Go between `a` and `b` (files, lines). Anything outside adapters/config is a finding.
- Glue code for custom roles (sync, cascade deletes, expiry, consistency).
- Ops: containers, memory at idle, cold start time, bootstrap pain.
- DX notes: what was hard, what docs were wrong, what an agent got wrong first.
