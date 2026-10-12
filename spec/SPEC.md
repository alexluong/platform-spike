# Platform spike: spec

A mini Shopify, built three times on different identity + authorization stacks, all passing one black-box test suite (`conformance/`). The goal is to compare stacks and test a few architecture patterns, not to ship a shop. Keep everything else (UI, real payments, email) out.

| stack | app | identity (who) | authorization (may they) | port |
|---|---|---|---|---|
| `a` | Go | Zitadel (OIDC) | SpiceDB | 8081 |
| `b` | Go (same app as `a`, other adapters) | Ory Kratos + Hydra (OIDC) | OpenFGA | 8082 |
| `c` | TypeScript (Hono) | Better Auth (in the app) | Cerbos | 8083 |
| `d` | TypeScript (from `c`) | Better Auth + organization plugin | Cerbos | 8086 |
| `e` | TypeScript (same app as `d`, other authz adapter) | Better Auth + organization plugin | SpiceDB | 8087 |
| `a2` | Go (from `a`) | Zitadel, one organization per merchant | SpiceDB | 8088 |

Stacks `d`, `e` and `a2` are round 2 (§15): the identity provider owns the merchant's identity side.

Stacks `a` and `b` are **one Go codebase**. Switching between them must be configuration plus adapters only; no module code may know which identity provider or authorization engine is behind it. How much had to change for `b` is one of the spike's results.

**The suite is the ground truth.** This spec describes what `conformance/` enforces. Where the suite accepts several answers, the spec says so ("suite: any of …"). Rules marked **(not tested)** are agreed but the suite can't see them. Ideas not enforced yet are in §14.

## 1. Patterns the code must follow

1. **Action = unit of capability.** Every operation is an action with an id `<module>.<verb>` (catalog in §4). A registry lists them. One executor runs every mutating action: authenticate → authorize (`can`) → run → write outbox in the same DB transaction. HTTP handlers are thin adapters onto actions.
2. **One `can()` in AuthZEN shape.** The executor calls `can({subject, action, resource, context}) → {decision, reason?}` (OpenID AuthZEN 1.0 Access Evaluation shape, in-process). SpiceDB / OpenFGA / Cerbos sit behind it as adapters. A batch form (`canMany`) backs `GET /api/me/permissions`.
3. **Custom roles are data.** The platform owns the permission catalog and the policy. Merchants create roles (subsets of grantable permissions) and assign them at a scope. Merchants never write policy.
4. **App DB is the source of truth.** Roles, assignments, installs and grants live in Postgres (Go) / SQLite or Postgres (TS). Where the authz engine stores relationships (SpiceDB, OpenFGA), they are written from an **outbox** row committed in the same transaction as the change. The request that made the change drains its own outbox rows before responding, and later checks use the engine's read-your-writes mechanism (SpiceDB ZedToken / OpenFGA `HIGHER_CONSISTENCY`), so a change is visible to the very next request. A background relay retries anything left over (failure rules: Operational rules below). Cerbos is stateless: the app sends attributes (the PIP is the app).
5. **Three checks.** Token/scope (is this credential allowed this kind of thing), relationship (is this subject connected to this resource), condition (attributes: refund limit, status, expiry). All must pass.
6. **Tenant isolation twice.** Every query is scoped by merchant in SQL, and the authz engine checks too. Customers (buyers) are never put in the authz engine: "my orders" is `WHERE customer_id = me`. Apps have no merchant: their SQL boundary is the install. Before the engine, an app's check needs an `app_installs` row for (app, store), and apps are denied at merchant scope. All stacks check this in the executor, before the engine, for every `can` (guardrails and batch checks included).
7. **Composition root by hand.** One `main` wires config → adapters → modules. No DI container, no globals.

### Operational rules

Found by the reviews; the suite tests only the first.

| rule | why | where it bit |
|---|---|---|
| **No second connection from the same pool while the request's transaction is open.** Permission checks (`can`, the PIP, guardrails) run on the request's own transaction (`a`, `b`) or on a separate pool (`c`). Every pool has a connection timeout. | N concurrent requests each holding 1 of N connections and waiting for a second deadlock the app for good; `/healthz` hangs too and nothing restarts it. | `c` (60 parallel `/me/permissions` wedged the app). Suite: `permissions.test.ts` "under concurrent load" (60 checks + 30 guarded role creates). The same trap hit Hydra's own pool in `b`. |
| **The outbox relay retries transient failures forever, in order.** Only errors the adapter classifies as permanent (the engine will never accept the write: SpiceDB `InvalidArgument`/`FailedPrecondition`, OpenFGA 400 validation, unknown event types) are set aside, marked as dead and logged. A failing row blocks the rows after it; log loudly after 10 attempts. | Dropping a row after N attempts left revocations (`app.uninstalled`, `agent_grant.revoked`, `assignment.deleted`, `merchant.suspended`) unapplied in the engine forever. | `a` (fixed). Port: `authz.ErrPermanent`. |
| **Read-your-writes holds across app instances.** The next request may land on another instance; it must still see the change. | A revoked app or agent kept working on the other instance until the engine's revision caught up (up to 5 s at SpiceDB's default quantization). | **Known limitation in `a`:** the latest ZedToken lives in process memory, so read-your-writes holds for one instance only. Fix: keep the token in the DB or round-trip it to the client. `b` uses `HIGHER_CONSISTENCY` (no token); `c` reads attributes from the DB on every check. |

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

- A user belongs to at most one merchant in this spike.
- **Membership and permissions come from the app DB, never from token claims.** A token issued before the user joined a merchant reflects later membership and role changes on the next request.
- Only `customer` principals place orders and use `GET /api/me/orders`; anyone else → 403.

## 3. Roles

**System roles** (exist in every merchant, maintained by the platform, not editable or deletable through the API):

| role id | permissions |
|---|---|
| `owner` | every grantable permission |
| `admin` | every grantable permission |
| `developer` | `merchant.view`, `store.view`, `product.view`, `order.view`, `app.install`, `app.uninstall`, `app.view` |
| `staff` | `merchant.view`, `store.view`, `product.view`, `product.create`, `product.update`, `order.view`, `order.cancel`, `shipment.view`, `shipment.create`, `shipment.update` |

- The ids are the literal strings `owner`, `admin`, `developer`, `staff` in every merchant. They work as `roleId` and in `/roles/:rid`. `GET /roles` lists them with `system: true` and the permissions above.
- `PATCH` or `DELETE` of a system role → 403 `system_role` (suite: any of 400/403/409); the role is unchanged.
- `owner` vs `admin`: only an owner can assign or remove the `owner` role (403 `forbidden`). Removing an owner as a member (`DELETE /members/:uid`) counts as removing the role: 403 for a non-owner.
- The last owner assignment of a merchant cannot be removed, by unassign or by member removal (409 `last_owner`). A caller without the needed permission gets 403, not 409.

**Custom roles:** `{name, permissions: ActionId[], refundLimitCents?: number}`.
- Only grantable permissions (§4) are allowed (400 `not_grantable`; an unknown action id: 400 `not_grantable` or `invalid_input`).
- `refundLimitCents` applies to `order.refund` through this role. Absent = no limit. System roles have no limit.
- Editing a role's permissions takes effect for everyone holding it, on the next request.
- Deleting a role removes its assignments. Deleting one of those assignments afterwards → 404.
- Roles are merchant-level objects: create/edit/delete check `role.manage` at the merchant. A store-scoped `role.manage` holder can only assign and unassign at its store **(role CRUD by them: not tested)**.

**Assignments:** `{userId, roleId, scope: {type: "merchant" | "store", id}}`.
- Merchant scope applies to every store of the merchant, including stores created later. Store scope applies to that store only.
- A user's permissions at a store = union over assignments at that store + at the merchant.
- A store assignment grants nothing on the merchant resource, even when the role contains merchant-scope permissions (`staff` at a store holds `merchant.view` there, but can't `GET /api/merchants/:mid`).
- The assignee must be a member of the merchant: 400 `not_member` (suite: any of 400/403/404/409, never 201). A store scope must be a store of this merchant: another merchant's store → 404 `not_found`, hidden like any cross-tenant resource (§9).
- The same `(userId, roleId, scope)` twice → 409 `already_assigned`; no second row. The same role at another scope is a new assignment.
- For `order.refund` with several roles, the highest limit wins (no limit beats any limit). Only roles that apply at the order's store count: a no-limit role at another store does not lift the limit.

**Guardrails (no escalation):** to create, edit, assign, unassign or delete a role, the caller needs `role.manage` at that scope **and** must hold every permission in that role at that scope. For limits: the caller's own refund limit must be ≥ the role's (or the caller has no limit). Violations are 403 `escalation`. These are checked in the action, through `can`.
- "Holds at a store" = a role containing the permission is assigned to the caller at that store or at the merchant, whatever the permission's catalog scope. So an owner can assign `staff` (which contains `merchant.view`) at store scope.
- Editing a role (even a rename) needs every permission the role has now **and** every permission it will have.
- Unassign needs `role.manage` at the assignment's scope (403) **and** the same guardrail as assign: every permission of the role at that scope, and a refund limit ≥ the role's (403 `escalation`). Taking a role away needs the power to hand it out. Why: removing a role can't raise anyone's rights, but without the check a lesser manager (say `role.manage` + `order.view`) could strip `admin` from every admin, and role delete, which removes every assignment of the role, was already guarded while removing the same assignments one by one wasn't. The owner rule and the last-owner rule still apply (owner rule → guardrail → `last_owner`).
- Removing a member (`DELETE /members/:uid`) is governed by `member.manage` and the owner rules only, not the guardrail.

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
| `merchant.update` | yes | merchant | no endpoint; only visible in `/api/me/permissions` |
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

Stacks may add **internal actions** for checks the catalog doesn't name: `platform.app.register` (`POST /api/platform/apps`), `role.manage_owner` (held only through `owner`), `agent.register` (`c`). They are never grantable and never listed in `/api/me/permissions`.

## 5. Apps

- The platform registers apps (`POST /api/platform/apps`, `platform_admin`) with a list of requested scopes (catalog action ids, grantable only: a `platform.*` scope → 400 `not_grantable`; suite also accepts `not_grantable_to_apps` or `invalid_input`). Registering returns client credentials.
- A merchant user with `app.install` on a store installs an app with `scopes ⊆ requested` (otherwise 400 `scope_not_requested`). An unknown `appId` → 404 `not_found` (an unknown id is 404 wherever it appears, body included, like `agentId` and `userId`). The installer must hold every scope they grant, at that store (403 `escalation`); a scope held only at another store doesn't count.
- An app's request is allowed iff it is installed on the resource's store **and** the action is in the install's scopes. Apps never get `role.manage`, `member.manage`, `agent.grant`, `app.install`, `app.uninstall` even if requested (registration rejects them, 400 `not_grantable_to_apps`).
- Apps act on stores only. Merchant-level actions (role or store creation, agent registration) → 403.
- One app may be installed on stores of several merchants; installs are independent (uninstalling in one leaves the others).
- Uninstall removes access immediately (next request).
- Refund limit for apps: none in this spike (scope only).

## 6. Agents

- An agent is registered by a merchant user (`POST /api/agents`) and gets client credentials. It belongs to that user's merchant. Platform staff, customers and users with no merchant → 403.
- **Only the agent's registrant can grant it** (403 otherwise). A grant lends the granter's rights to whoever holds the agent's secret; a teammate's grant on someone else's agent would keep working after that person left the merchant. Another merchant's agent → 400/403/404.
- A user with `agent.grant` at a store creates a grant `{agentId, storeId, permissions, expiresInSeconds}`. Permissions must be grantable (400 `not_grantable`); `expiresInSeconds` is 1..31 536 000 (one year; 400 `invalid_input`). The user must hold every permission in it at that store (403 `escalation`).
- Order of the checks after `agent.grant`: the body (400 `invalid_input`, `not_grantable`), then the agent (404 when unknown or another merchant's), then the registrant rule (403), then the guardrail (403 `escalation`). The body comes first because it needs nothing but the catalog; the later checks each depend on the one before.
- An agent request is allowed iff an unexpired, unrevoked grant for (agent, store) lists the action **and** the user who created the grant **still** holds the action at that store now. Removing the user's role assignment, removing the permission from the role, or removing the user from the merchant cuts the agent off for exactly the actions lost; restoring the permission restores the agent (the grant itself is unchanged). `order.refund` through an agent uses the granting user's current limit.
- Grants on different stores are independent.
- Expiry must hold without a cleanup job running (SpiceDB: expiring relationships; OpenFGA: a condition on time; Cerbos: attribute comparison). Revocation: `DELETE` the grant (needs `agent.grant` at the store). After expiry or revocation the agent's token stays valid (no 401); its requests get 403.
- An agent's `GET /api/me` → `{id, kind: "agent", merchantId}` (its registrant's merchant).

## 7. Platform staff

- `platform_admin`: create, view, suspend, reinstate merchants; register apps; view the audit log. No access to merchant data (orders, products, roles, `GET /api/merchants/:mid`) without break-glass: 403.
- `support`: view merchants. No access to merchant data without break-glass.
- Without break-glass, `/api/me/permissions` for platform staff → `200 {actions: []}`, and `GET /api/merchants/:mid/stores` → 403: it reads merchant data like every other read here. An empty 200 would claim the merchant has no stores.
- **Break-glass:** `POST /api/platform/break-glass {merchantId, reason, minutes}` grants **read-only** access to that merchant's data (`*.view` actions) until expiry. `minutes` is 1..1440 (400 `invalid_input`). It covers only its opener and only that merchant. Reads include `merchant.view` (`GET /api/merchants/:mid`, `GET /roles`) and `app.view`. Writes → 403. Under break-glass `/api/me/permissions` lists `*.view` actions only.
- **Audit:** every request made under break-glass writes an entry `{actor, action, merchantId, at}`: `actor` = the staff user's id, `action` = the catalog action the request ran (e.g. `order.view`; `merchant.view` for `GET /roles`). **List endpoints count:** `GET /api/merchants/:mid/stores` filters through `store.view` and is audited as `store.view`, so a resource search or batch `can` must audit like a single check. The grant itself is audited with `action: "platform.break_glass"`. Denied requests are not audited. The suite requires ≥ 1 entry per allowed read; `actor` may also be the email.
- **Suspended merchant:** every action by its own users, apps and agents is denied (403 `merchant_suspended`), and customers can't place orders in its stores (403 `merchant_suspended`; suite: any 403). Principals of other merchants see no difference: they get their usual 403/404, never `merchant_suspended`. Platform actions still work. Reinstating restores access. The public product listing of a suspended store stays visible **(not tested)**.

## 8. Orders, payments, delivery

- Order: `{id, storeId, customerId, items: [{productId, qty, unitPriceCents}], totalCents, status, refundedCents}`.
- Placing: prices come from the products; a client-sent `unitPriceCents` is ignored. A later price change doesn't alter an existing order. Empty `items`, `qty` outside 1..1 000 000, or a total above 2^31-1 cents → 400 (bounds in §9). A product of another store → 400/404/409, no order.
- Status: `pending` → (`payment.capture`) `paid` → (`shipment.create`) `fulfilling` → (shipment `delivered`) `delivered`. `order.cancel` from `pending` or `paid` (no shipment) → `cancelled`.
- Payment: fake provider. `capture` on a `pending` order captures `totalCents`. `refund` (via `order.refund`) needs a `paid` order (exactly: `fulfilling`/`delivered` → 409). Total refunded ≤ captured (409 `over_refund`). Partial refunds allowed. `amountCents ≤ 0` → 400. The status stays `paid` after a full refund **(not tested)**.
- Refund limit: per refund request, not cumulative (two refunds of 400 under a 500 limit both succeed).
- Shipment: `{id, orderId, carrier, status: label_created | in_transit | delivered}`. Status moves forward only: backwards → 409 `invalid_transition`; the same status again → 409 `invalid_transition` **(not tested)**; skipping forward (`label_created` → `delivered`) is allowed **(not tested)**. An unknown status → 400.
- State-rule violations are 409 with a code (suite: any code for wrong-state cancel, capture, refund and shipment; today all three stacks return `invalid_transition`). They are checked after authorization: a caller without the permission gets 403, not 409. The refund limit is part of authorization: an over-limit refund that would also be `over_refund` → 403.

## 9. HTTP API

JSON in and out. Auth: `Authorization: Bearer <token>`. Ids are strings. Money in integer cents. Timestamps (`expiresAt`, `at`) are ISO 8601 strings.

Errors: `{ "error": { "code": "<snake_case>", "message"?: "..." } }`
- 401 `unauthenticated`: missing/invalid token, or a non-Bearer `Authorization` header. Protected endpoints answer 401 before any 404.
- 403 `forbidden` (or a more specific code: `escalation`, `merchant_suspended`)
- 404 `not_found`. For resources in **another** merchant, either 403 or 404 is acceptable (the suite accepts both); never 200. A nonexistent id inside one's own merchant → 403 or 404 (an unknown id can't be attributed to a merchant).
- 400 `invalid_input` / specific codes above; 409 for state rules.

Error codes the stacks return. "Suite" = what the suite asserts; where it asserts only the status, the code is the stacks' shared choice.

| status | code | when | suite |
|---|---|---|---|
| 401 | `unauthenticated` | no, invalid or non-Bearer token | code |
| 403 | `forbidden` | default deny: missing permission, wrong principal kind, owner-only rule, grant of another user's agent, over-limit refund, wrong test secret | status |
| 403 | `escalation` | guardrails: role create/edit/delete/assign, app install, agent grant | code |
| 403 | `merchant_suspended` | the merchant's own principals while it is suspended; customer orders in its stores | code (status only for customers) |
| 403 | `system_role` | `PATCH`/`DELETE` of a system role | any of 400/403/409 |
| 404 | `not_found` | unknown id (in the path or the body: `appId`, `agentId`, `userId`); another merchant's resource (403 also allowed; an assignment scope at another merchant's store: 404) | status (code for unknown `appId` and a foreign assignment scope) |
| 400 | `invalid_input` | malformed body, missing field, missing query parameter, out-of-range value (bounds below) | status |
| 400 | `not_grantable` | a non-grantable or unknown action in a role, a grant or an app registration | code (alternatives where §3/§5 say) |
| 400 | `not_grantable_to_apps` | an app requests `role.manage`, `member.manage`, `agent.grant`, `app.install` or `app.uninstall` | code |
| 400 | `not_member` | assigning a role to a user who isn't a member | any 4xx but 401 |
| 400 | `scope_not_requested` | installing an app with a scope it didn't request at registration | code |
| 409 | `last_owner` | removing the last owner assignment | code |
| 409 | `over_refund` | refunds above the captured amount | code |
| 409 | `invalid_transition` | shipment status not forward; today also every wrong-state cancel, capture, refund and shipment | code for shipments, status otherwise |
| 409 | `already_member` | adding a user who already belongs to a merchant | not tested |
| 409 | `already_assigned` | the same `(userId, roleId, scope)` assigned twice | code |

**Input bounds** (all → 400 `invalid_input`; the suite checks the status):

| field | allowed | why |
|---|---|---|
| `priceCents` | 0..2 147 483 647 (2^31-1) | money fits a 32-bit integer column |
| order `totalCents` (Σ qty × price) | ≤ 2 147 483 647 | overflow wrapped totals before the cap |
| `refundLimitCents` | 0..2 147 483 647 | |
| `qty` | 1..1 000 000 | per order line, checked before the total |
| refund `amountCents` | ≥ 1 (the upper bound is the captured amount, 409 `over_refund`) | |
| agent grant `expiresInSeconds` | 1..31 536 000 (one year) | a grant that never practically expires; overflow |
| break-glass `minutes` | 1..1440 | |

### Platform
| method | path | action | body → response |
|---|---|---|---|
| POST | `/api/platform/merchants` | `platform.merchant.create` | `{name, ownerUserId}` → `201 {id, name, status}`; makes `ownerUserId` a member with `owner` at merchant scope |
| GET | `/api/platform/merchants` | `platform.merchant.view` | → `{items: Merchant[]}` |
| POST | `/api/platform/merchants/:mid/suspend` | `platform.merchant.suspend` | → `200 {id, status: "suspended"}` |
| POST | `/api/platform/merchants/:mid/reinstate` | `platform.merchant.suspend` | → `200 {id, status: "active"}` |
| POST | `/api/platform/apps` | `platform_admin` only | `{name, scopes}` → `201 {id, clientId, clientSecret}` |
| POST | `/api/platform/break-glass` | `platform.break_glass` | `{merchantId, reason, minutes}` → `201 {id, expiresAt}` |
| GET | `/api/platform/audit?merchantId=` | `platform.audit.view` | → `{items: [{actor, action, merchantId, at}]}` newest first |

### Merchant
| method | path | action | body → response |
|---|---|---|---|
| GET | `/api/merchants/:mid` | `merchant.view` | → `{id, name, status}` |
| POST | `/api/merchants/:mid/members` | `member.manage` | `{userId}` → `201` (member with no roles) |
| DELETE | `/api/merchants/:mid/members/:uid` | `member.manage` | → `204` (also removes assignments; owner and last-owner rules apply) |
| GET | `/api/merchants/:mid/roles` | `merchant.view` | → `{items: [{id, name, system, permissions, refundLimitCents?}]}` |
| POST | `/api/merchants/:mid/roles` | `role.manage` | `{name, permissions, refundLimitCents?}` → `201 Role` |
| PATCH | `/api/merchants/:mid/roles/:rid` | `role.manage` | `{name?, permissions?, refundLimitCents?}` → `Role` |
| DELETE | `/api/merchants/:mid/roles/:rid` | `role.manage` | → `204` |
| POST | `/api/merchants/:mid/role-assignments` | `role.manage` at the scope | `{userId, roleId, scope: {type, id}}` → `201 {id, ...}` |
| DELETE | `/api/merchants/:mid/role-assignments/:aid` | `role.manage` at the scope | → `204` |
| POST | `/api/merchants/:mid/stores` | `store.create` | `{name}` → `201 {id, merchantId, name}` |
| GET | `/api/merchants/:mid/stores` | — | → stores the caller has `store.view` on; another merchant's user → 403/404 or `200 {items: []}`; platform staff without break-glass → 403 |

No endpoint lists role assignments, so the owner assignment created with the merchant has no id the API returns. The last-owner rule is reachable through `DELETE /members/:uid` and through owner assignments made via the API (§14 proposes a list endpoint).

### Store modules
| method | path | action | body → response |
|---|---|---|---|
| GET | `/api/stores/:sid` | `store.view` | |
| POST | `/api/stores/:sid/products` | `product.create` | `{title, priceCents}` → `201 Product` |
| PATCH | `/api/products/:pid` | `product.update` | `{title?, priceCents?}` |
| GET | `/api/stores/:sid/products` | public (no auth) | → `{items}` |
| POST | `/api/stores/:sid/orders` | customer (`order.place`) | `{items: [{productId, qty}]}` → `201 Order` (prices from products) |
| GET | `/api/stores/:sid/orders` | `order.view` | → `{items}` |
| GET | `/api/orders/:oid` | `order.view`, or the order's customer | another customer → 403/404 |
| GET | `/api/me/orders` | customer | → own orders across stores |
| POST | `/api/orders/:oid/cancel` | `order.cancel` | → any 2xx |
| POST | `/api/orders/:oid/refund` | `order.refund` | `{amountCents}` → `200 Order` with the new `refundedCents` (403 when over the limit) |
| POST | `/api/orders/:oid/payments/capture` | `payment.capture` | → `201 {id, orderId, status: "captured", amountCents}` |
| GET | `/api/orders/:oid/payments` | `payment.view` | → `{items}` |
| POST | `/api/orders/:oid/shipments` | `shipment.create` | `{carrier}` → `201 Shipment` |
| POST | `/api/shipments/:shid/status` | `shipment.update` | `{status}` → 2xx `Shipment` |
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
| GET | `/api/me` | `{id, kind, merchantId?}` (`merchantId` absent for customers, platform staff and users with no merchant; apps: not asserted) |
| GET | `/api/me/permissions?storeId=` or `?merchantId=` | `{actions: ActionId[]}`: catalog actions the caller may perform there (batch `can`; AuthZEN action search) |

`/api/me/permissions` reports each action at the resource type its §4 scope names:
- `?storeId=` → store-scope actions held at that store (through store or merchant assignments).
- `?merchantId=` → merchant-scope actions (`merchant.view`, `merchant.update`, `member.manage`, `role.manage`, `store.create`) held through merchant-scope assignments only.
- `role.manage` ("merchant or store") appears in both. Store actions are never reported at merchant level, even when held at merchant scope.
- Only grantable actions are listed: never `platform.*` or internal actions.
- `order.refund` is listed when held at any limit.
- Apps: their install's scopes at that store. Agents: the granted actions the granter still holds at that store. Customers: `[]`. Platform staff: `[]`, or `*.view` actions under break-glass.
- Edits show on the next request.
- Another merchant's store or merchant → 403/404, or `200 {actions: []}`. Neither parameter → 400.

### Test support (only when `TEST_MODE=1`, all need header `X-Test-Secret: <TEST_SECRET>`)
| method | path | body → response |
|---|---|---|
| POST | `/api/_test/users` | `{email, password, kind: "platform" \| "user" \| "customer", platformRole?}` → `201 {id, email}`: creates the identity in the real IdP (Zitadel / Kratos / Better Auth) and the app-side record |

| GET | `/api/_test/driver-config` | optional (`a`, `b`): what a real login UI would hold, for the driver (issuer, client id, audience; `a` also hands over Zitadel's `IAM_LOGIN_CLIENT` token) |

A missing or wrong `X-Test-Secret` → 401 or 403.

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

- `compose.yaml` at the repo root with profiles `a`, `b`, `c`. `docker compose -p ps-a --profile a up -d --build` brings up stack `a` with everything it needs (Postgres, IdP, engine, app, migrations, IdP bootstrap) and leaves it healthy with no manual step. Each profile uses its own containers and volumes; one compose project per stack (`-p ps-<stack>`) keeps `down -v` of one from touching the others.
- Docker runs on a remote host (`DOCKER_HOST=ssh://cs-ws`). So: **no bind mounts of source code**; images are built from the build context; config files are baked into images or passed as `configs`. Published ports: app as in the table at the top; anything else the drivers need (IdP ports) published too and listed in `conformance/stacks/<stack>.ts`.
- **Hostnames.** `cs-ws` is an ssh alias: it works for `DOCKER_HOST` but doesn't resolve as a hostname on the Mac. Clients use `cs-ws.lab.alexluong.com`.
  - Zitadel (`a`) takes its issuer and instance from the Host header, so the app, the bootstrap and the driver must all reach it under the exact external name. Compose sets `ExternalDomain` and a network alias from `STACK_A_HOST` (default `cs-ws.lab.alexluong.com`). The name is fixed when the instance is created: changing it needs `down -v`.
  - Hydra (`b`) only needs `iss` to match: `STACK_B_HOST` (same default) sets the issuer string; no `down -v` to change it.
- Bootstrap (IdP clients, keys, the Zitadel service account, Hydra clients, engine schema/model, Cerbos policies) is idempotent: a one-shot container in the profile (`a`, `b`), or app start when there is nothing outside the app to provision (`c`: Better Auth and Drizzle migrations).
- Run the suite: `cd conformance && STACK=a HOST=cs-ws.lab.alexluong.com pnpm test` (`SKIP_SLOW=1` skips the 65 s break-glass expiry test; `TEST_SECRET` must match the stack's).

## 12. Results to record (per stack, in `results/<stack>.md`)

- Conformance pass/fail per test, and which failures are by design of the stack.
- Lines of code: modules (shared logic) vs adapters vs bootstrap/config.
- What changed in Go between `a` and `b` (files, lines). Anything outside adapters/config is a finding.
- Glue code for custom roles (sync, cascade deletes, expiry, consistency).
- Ops: containers, memory at idle, cold start time, bootstrap pain.
- DX notes: what was hard, what docs were wrong, what an agent got wrong first.

## 13. Where the stacks differ (the suite can't see it)

Found by reading the Go (`a`, `b`) and TS (`c`) code against this spec. The gaps and open choices found earlier in v2 are resolved and in the sections above (changelog: "stacks aligned"); one difference remains.

| topic | `a` / `b` (Go) | `c` (TS) | status |
|---|---|---|---|
| read-your-writes across app instances | `a`: per-process ZedToken (§1.4); `b`: `HIGHER_CONSISTENCY`, no token | attributes read from the DB on every check | `a`: known limitation |

## 14. Proposed, not yet enforced by the suite

Each one would change the suite or a stack. None is in force until it moves into the sections above.

| # | proposal | finding that motivated it |
|---|---|---|
| P1 | **Agents get the apps' blocked list:** a grant can't list `role.manage`, `member.manage`, `agent.grant`, `app.install`, `app.uninstall` (400). One flag ("not for delegates") in the catalog, checked for both kinds. *Lead's default, pending Alex's confirmation.* | `a` (review-a 18) and `c` (review-c 2): an agent granted `role.manage` and `app.install` on a store assigned a role and installed an app; after the grant was revoked, the member kept the role and the app kept its install. The "granter still holds it" rule covers the agent's own requests, not the durable changes it made. |
| P2 | **A named 409 code for wrong-state actions:** `invalid_state` for cancel, capture, refund and shipment creation on an order in the wrong status. `invalid_transition` stays for shipment status moves. | AMBIGUITIES #19: the suite accepts any 409 code; the stacks return `invalid_transition` for all of them. Clients can't tell "wrong status" from "illegal move". |
| P3 | **`GET /api/merchants/:mid/role-assignments`** → `{items: [{id, userId, roleId, scope}]}` (`role.manage` at the merchant; store-scoped holders see their store's). Merchant creation returns the owner assignment id. | AMBIGUITIES #11: the owner assignment made with the merchant has no id the API returns, so the last-owner rule can't be tested on it directly, and nobody can see who holds what. |
| P4 | **Break-glass duration in seconds in test mode:** `seconds` accepted only when `TEST_MODE=1`. | AMBIGUITIES #27: the expiry test waits 65 s and dominates the suite's run time (`SKIP_SLOW=1` skips it). |
| P5 | **Random per-stack `TEST_SECRET`, test mode off by default.** Compose generates or requires the secret (no `test-secret` default); `TEST_MODE=1` only in a test profile. The app port with test mode on must not be reachable beyond the test host. | review-a 7, review-c 14: anyone on the tailnet can mint a `platform_admin`. In `a`, `/api/_test/driver-config` also hands out Zitadel's `IAM_LOGIN_CLIENT` token (log in as any user). `b` publishes Hydra's unauthenticated admin port for the driver. |
| P6 | **A failed relationship sync on revoke or uninstall doesn't return success.** Either 503 `sync_pending` (the change is committed; access ends when the relay catches up), or checks for the affected subject fall back to the DB until it does. Or, at minimum, document the window. | review-a 6: the transaction commits, the in-request drain fails, the request still answers 204, and the app or agent keeps access until the relay succeeds. |
| P7 | **Token checks are named:** signature with an algorithm allowlist, `iss`, `aud`, `exp`, token type (an access token, never an ID token; `typ: at+jwt` where the IdP sets it, otherwise introspection), and the client (`azp`) is one the API allows. | review-a 8: `a` verifies access tokens with go-oidc's ID-token verifier. ID tokens pass as access tokens, and any client allowed the project audience mints tokens the API accepts. Not exploitable here (only known subjects map to principals); a confused-deputy risk with third-party clients. |
| P8 | **Adding an unaffiliated user as a member needs their consent** (invite → accept). `POST /members` creates an invitation; the user joins on accept. | review-c 16: `POST /members` claims any user id without consent; that user then can't join the merchant they meant to (409 `already_member`). |

## 15. Round 2: identity-owned tenancy (`d`, `e`, `a2`)

**Question.** If the identity provider owns tenancy (organizations, members, invitations, login policy), does the spec get cleaner, and what does it push back into the app? Round 1 used every IdP as a plain login server, so this was never measured.

| stack | built from | what it tests |
|---|---|---|
| `d` | `c` | Better Auth's organization plugin instead of the app's own merchants/members; Cerbos unchanged |
| `e` | `d` | the same app with SpiceDB instead of Cerbos: the engine swap by adapter only, in TS (as `a` → `b` was in Go); TS vs Go on SpiceDB (`e` vs `a`) |
| `a2` | `a` | Zitadel organizations per merchant instead of one shared org |

Everything in §1–§11 still holds: **the full suite must pass** on `d`, `e` and `a2`, plus the tests below. Ports: app as in the table at the top; `a2`'s Zitadel on 8089; `e` runs its own SpiceDB. Compose profiles `d`, `e`, `a2`; projects `ps-d`, `ps-e`, `ps-a2`.

### 15.1 Who owns what

- **The IdP owns the merchant's identity side:** one organization per merchant, created with the merchant; membership (users in the organization); invitations; login policy (a suspended merchant's people can't log in, §15.3).
- **Authorization stays as in §3–§7:** roles, assignments, store scope, refund limits and guardrails, decided through `can()`, with the engine fed per §1. Using the IdP's own role features (Better Auth dynamic access control, Zitadel project roles and grants) is allowed only where every §3 rule still holds. A role kept in two places (IdP and app/engine) is a finding: record which you chose and why.
- **§2 "membership comes from the app DB, never from token claims" becomes:** membership comes from the IdP's organization membership (Better Auth: its tables, in the same Postgres; Zitadel: the organization). The "next request" rules still hold: a removed member loses access on the next request, even with a token issued earlier. A token's organization claim may be an extra tenant check, never the only one.
- **Writes that span the app and the IdP** (merchant create → organization, member add/remove, suspend/reinstate, agent registration) follow the §1 operational rules: no dual write without a recovery story. If the IdP's writes can't join the app's transaction, either sync through the outbox (the IdP as a second consumer, with the same retry and classification rules) or make the IdP the single writer and derive app state from it. Record the failure window either way.
- One user belongs to at most one merchant (unchanged). Platform staff and customers belong to no merchant organization (Zitadel: a separate platform organization is fine).
- `POST /api/merchants/:mid/members {userId}` stays: the suite's helpers use it. In `d`/`e`/`a2` it adds the user to the organization directly.

### 15.2 Invitations (tested, `idp-tenancy` only; §14 P8)

| method | path | action | body → response |
|---|---|---|---|
| POST | `/api/merchants/:mid/invitations` | `member.manage` | `{email}` → `201 {id, email, status: "pending"}` |
| GET | `/api/merchants/:mid/invitations` | `member.manage` | → `{items: [{id, email, status}]}` |
| DELETE | `/api/merchants/:mid/invitations/:iid` | `member.manage` | → `204` (cancelled) |
| POST | `/api/invitations/:iid/accept` | the invited user | → `200 {merchantId}`: the caller becomes a member with no roles |

- The invitee is an existing user (created through `/api/_test/users`); the email matches case-insensitively.
- Until acceptance the invitee is not a member: assigning them a role → 400 `not_member` (suite: any 4xx but 401), and their `GET /api/me` has no `merchantId`.
- Accepting as another user (email mismatch) → 403/404. Accepting a cancelled or already accepted invitation → 404/409. A user who already belongs to a merchant accepting → 409 `already_member` (suite: 409).
- Another merchant's `member.manage` holder can't list, cancel or see an invitation → 403/404. A member without `member.manage` → 403.
- After acceptance the new member's roles follow §3 like any member (assign → access on the next request).

### 15.3 Suspension at the IdP (tested, `idp-tenancy` only)

- While a merchant is suspended, **its users can't log in**: the driver's `loginUser` rejects because the IdP refuses (not the app). **Its agents can't get tokens**: `loginClient` rejects.
- Tokens issued before the suspension still get 403 `merchant_suspended` (§7, unchanged).
- Reinstating restores login for both.
- Platform staff, customers and apps (platform-level, not owned by a merchant) are unaffected; another merchant's users are unaffected.

### 15.4 Tests

`conformance/tests/idp-tenancy.test.ts` runs only when the stack's driver declares `features: ['idp-tenancy']` (optional `StackDriver.features`). Stacks `a`, `b`, `c` skip it.

### 15.5 Results to record (in addition to §12)

- What the IdP's organization features replaced (code removed vs the parent stack) and what they pushed back into the app (sync, hooks, cross-system writes).
- Custom roles: did the IdP's role feature carry any of §3? Why or why not.
- The cross-system write story: which writes, how they recover, the failure window.
- `d` → `e`: what changed outside the authz adapter and the composition root (anything else is a finding). `e` vs `a`: TS vs Go on the same engine.
- `a2` vs `a`: what changed in modules (expected: merchant/member/agent lifecycle), and what Zitadel's organizations gave that Ory OSS can't.

## 16. Changelog

### v3 (2026-10-13): round 2

- §15: stacks `d`, `e`, `a2` (identity-owned tenancy), invitations, suspension at the IdP, opt-in `idp-tenancy` tests.

### v2 (2026-10-11): stacks aligned

The three gaps in `c` are closed and every open choice of §13 is now one rule, enforced by the suite (362 tests).
- `c`: `qty` 1..1 000 000 (§9 bounds); apps checked in SQL in the executor (§1.6); `/api/me/permissions` under break-glass audited (§7).
- Unassign runs the escalation guardrail (§3; was `c` only). Reason in §3.
- Install with unrequested scopes → 400 `scope_not_requested` (§5; was `invalid_input` in `c`).
- Install with an unknown `appId` → 404 (§5; was 400 in `a`/`b`). Exception to "keep the `a`/`b` behaviour": the Go code already answered 404 for an unknown `agentId` or `userId` in a body, and §9 says an unknown id is 404.
- Assignment scope at another merchant's store → 404 (§3; was 400 in `c`).
- Duplicate assignment → 409 `already_assigned` (§3; `c` created a second row).
- Platform staff listing a merchant's stores without break-glass → 403 (§7; was an empty 200 in `a`/`b`). Exception to "keep `a`/`b`": every other merchant-data read by staff is 403, and an empty list is a false answer.
- Agent grant check order: body (`not_grantable`) before the registrant rule (§6; `c` checked the registrant first).
- `c`'s `not_captured` code removed (unreachable: a `paid` order is captured); `invalid_transition` if it ever happens.


### v2 (2026-10-11): proposals

- §14: P1–P8 (agent blocked list, `invalid_state`, assignment list, break-glass seconds, test-mode hardening, sync failure semantics, token checks, member consent).

### v2 (2026-10-11): runtime and operational rules

- §11: run with `HOST=cs-ws.lab.alexluong.com` (bare `cs-ws` is an ssh alias); Zitadel's exact-host issuer; one compose project per stack; bootstrap may run at app start (`c`).
- §1 Operational rules: no second same-pool connection while the request's transaction is open (review-c 1); relay retries transient failures forever and sets aside only adapter-classified permanent errors (review-a 2); read-your-writes across instances, with `a`'s per-process ZedToken as a known limitation (review-a).
- §9: optional `GET /api/_test/driver-config` (`a`, `b`).

### v2 (2026-10-11): shared rules encoded

Rules the stacks share, checked in the Go and TS code; the suite (349 tests) covers the cases named in §9. Three exceptions in `c` (qty bound, app SQL check, break-glass audit of `/me/permissions`) are listed in §13.
- Only the agent's registrant can grant it (§6; review-a finding 1).
- Money capped at 2^31-1 cents (prices, order totals, refund limits); `qty` 1..1 000 000; grant expiry ≤ 1 year; break-glass `minutes` 1..1440; all 400 `invalid_input` (§9 Input bounds; review-a 3, 15; review-c 6).
- Break-glass list reads are audited (§7; review-a 4, review-c 3).
- Apps are checked in SQL (install row) as well as in the engine (§1.6; review-a 5).
- `merchant_suspended` only for the merchant's own principals (§7; review-c 5).
- `/api/me/permissions` details (§9 Me) and the error code table (§9).
- Where a stack misses one of these: §13.

### v2 (2026-10-11): ambiguities resolved

Each item of `conformance/AMBIGUITIES.md`, by number, and where it now lives.

| # | resolved as | where |
|---|---|---|
| 1 | each action reported at its catalog scope type; `role.manage` at both | §9 Me |
| 2 | a store assignment grants nothing on the merchant resource | §3 Assignments |
| 3 | "holds at a store" = assigned at the store or the merchant, any catalog scope | §3 Guardrails |
| 4 | edit needs the old and the new permission set (rename too) | §3 Guardrails |
| 5 | role CRUD checks `role.manage` at the merchant; store-scoped holders assign/unassign only (CRUD not tested) | §3 Custom roles |
| 6 | unassign needs `role.manage` at the assignment's scope; escalation check not required | §3 Guardrails |
| 7 | owner-only rule → 403 `forbidden` | §3 |
| 8 | removing an owner member by a non-owner → 403 | §3 |
| 9 | system role ids are the literal names | §3 |
| 10 | system role PATCH/DELETE → 403 `system_role` (suite: 400/403/409) | §3 |
| 11 | no assignment list; last-owner reachable via member removal; list endpoint proposed | §9 Merchant, §14 |
| 12 | `merchant.update` has no endpoint | §4 |
| 13 | assigning to a non-member → 400 `not_member` (suite: 400/403/404/409) | §3 Assignments |
| 14 | deleting a removed assignment → 404 | §3 Custom roles |
| 15 | refund limit is per request | §8 |
| 16 | over-limit refund → 403 (`forbidden`; suite: any code) | §8, §9 |
| 17 | limit is checked before `over_refund` | §8 |
| 18 | only roles at the order's store count for the limit | §3 Assignments |
| 19 | wrong-state 409s: suite accepts any code; stacks use `invalid_transition`; `invalid_state` proposed | §8, §14 |
| 20 | refund only on exactly `paid`; status after a full refund stays `paid` (not tested) | §8 |
| 21 | backwards and same → 409 `invalid_transition`; skip forward allowed (same/skip not tested) | §8 |
| 22 | placement edge cases | §8 |
| 23 | only customers place orders and read `/me/orders` | §2 |
| 24 | cancel any 2xx; refund 200 Order; capture 201; shipment status 2xx | §9 |
| 25 | staff without break-glass: merchant data 403, `/me/permissions` `[]` | §7 |
| 26 | audit `actor` = user id, `action` = catalog action; denied requests not audited | §7 |
| 27 | `minutes` stays the unit; seconds in test mode proposed | §7, §14 |
| 28 | break-glass covers its opener and its merchant; includes `merchant.view`, `app.view` | §7 |
| 29 | suspended merchant: customer orders → 403 `merchant_suspended`; public listing visible (not tested) | §7 |
| 30 | `merchant_suspended` only for the merchant's own principals | §7 |
| 31 | suspend/reinstate → 200 | §9 Platform |
| 32 | install scopes ⊄ requested → 400, any code | §5 |
| 33 | non-grantable scope at registration → 400 `not_grantable` | §5 |
| 34 | apps act on stores only | §5 |
| 35 | one app on several merchants: independent installs | §5 |
| 36 | only the agent's registrant can grant it | §6 |
| 37 | agents registered by merchant users only | §6 |
| 38 | expired/revoked grant: token valid, requests 403 | §6 |
| 39 | agent `/me` has its registrant's `merchantId` | §6, §9 Me |
| 40 | agent loses exactly what the granter lost; restored with it | §6 |
| 41 | membership and permissions from the app DB, not the token | §2 |
| 42 | 401 before 404; non-Bearer → 401 | §9 |
| 43 | test-support guard → 401 or 403 | §9 Test support |
| 44 | nonexistent id in one's own merchant → 403 or 404 | §9 |
| 45 | cross-tenant store list and `/me/permissions` → 403/404 or empty 200 | §9 |
| 46 | `/me/permissions` without a parameter → 400 | §9 Me |
| 47 | timestamps are ISO 8601 | §9 |
