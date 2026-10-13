# Guide: authorization from zero, through this codebase

For someone who has never worked with authorization engines. Part 1 teaches the ideas with no code. Part 2 maps them onto this repo, folder by folder. Part 3 follows one request through the code, and Part 4 shows the same rule in all three engines. A glossary is at the end. Plan for about an hour; keep the code open next to it.

---

## Part 1: the ideas

### 1.1 Two questions: who are you, and may you do this?

Every request to an API raises two separate questions.

- **Authentication (authn): who is calling?** The caller proves an identity, usually by logging in and then sending a **token** (a signed string) with each request. The service that runs logins and issues tokens is the **identity provider (IdP)**. Here: Zitadel, Ory (Kratos + Hydra) or Better Auth.
- **Authorization (authz): may this caller do this thing to this object?** Knowing that the caller is Carol says nothing about whether Carol may refund order 9. That answer depends on Carol's roles, the store the order belongs to, the amount, whether the merchant is suspended, and so on.

This repo is mostly about the second question. The IdP only answers "this token belongs to user `u_123`"; everything after that is authorization.

### 1.2 Every check is the same four-part question

However it's implemented, an authorization check asks:

| part | meaning | example |
|---|---|---|
| **subject** | who is asking (the *principal*) | user Carol |
| **action** | what they want to do | `order.refund` |
| **resource** | what they want to do it to | store `s1` (the order's store) |
| **context** | extra facts about this request | `amountCents: 5000` |

The answer is **yes or no**, sometimes with a reason. This shape has a standard name, **OpenID AuthZEN**, and the whole codebase calls one function with exactly this shape: `can(subject, action, resource, context)`. Everything behind `can()` is swappable; that is the point of the spike.

Three roles in any authz system (standard names, used in comments):
- **PEP (policy enforcement point):** the code that asks and obeys. Here, the **executor**: it calls `can()` and refuses the request on "no".
- **PDP (policy decision point):** the thing that decides. Here, the **engine**: SpiceDB, OpenFGA or Cerbos.
- **PIP (policy information point):** where the decider gets facts it doesn't store itself. Matters for Cerbos (1.5).

### 1.3 Roles (RBAC) and why scope matters

The simplest model is **role-based access control (RBAC)**. Name some **permissions** (`order.view`, `order.refund`), group them into **roles** ("Refund clerk" = view + refund), and give people roles. A check asks: "does any of my roles contain this permission?"

Real products need more than that, and this spike tests three additions:

- **Scope.** Carol is a clerk *at store s1*, not at every store of the merchant. Giving a role *at a place* is an **assignment** (in Zanzibar terms, a *role binding*). A role at the merchant applies to all its stores; a role at a store applies to that store only.
- **Custom roles.** Merchants define their own roles from a fixed list of permissions the platform offers, the **permission catalog**. The platform owns what each permission means; merchants own which permissions go in which role. Merchants never write rules.
- **Guardrails (no escalation).** You may only hand out what you hold yourself. A manager with `order.view` can't create a role containing `order.refund` and give it to someone.

RBAC alone can't express "refund up to $50" or "only while the grant hasn't expired". Those are **conditions** on attributes (an amount, a time), covered next.

### 1.4 Relationships: Zanzibar (SpiceDB, OpenFGA)

**Zanzibar** is the system Google built for Drive, Calendar and YouTube permissions (a 2019 paper). SpiceDB and OpenFGA are open-source versions. The idea: store authorization data as a **graph of relationships**, and describe permissions as paths through that graph.

**A relationship (also called a tuple)** is one fact, written `object#relation@subject`:

```
store:s1#merchant@merchant:m1          store s1 belongs to merchant m1
role:clerk#order_refund@user:*         the clerk role contains order.refund (for any user)
role_binding:b2#role@role:clerk        binding b2 is of the clerk role
role_binding:b2#subject@user:carol     binding b2 is for Carol
store:s1#binding@role_binding:b2       binding b2 applies at store s1
```

**The schema** declares the types, the relations each may have, and **permissions** computed from relations with a few operators:

| SpiceDB | OpenFGA | meaning |
|---|---|---|
| `a + b` | `a or b` | union: either path works |
| `a & b` | `a and b` | intersection: both must hold |
| `a - b` | `a but not b` | exclusion (used for suspension) |
| `x->y` | `y from x` | follow relation `x`, then ask `y` there (an **arrow**) |

So "may Carol refund at store s1?" becomes a graph walk: store s1 → its bindings → binding b2 → is Carol its subject, and does its role contain `order_refund`? Plus the bindings inherited from merchant m1 (`merchant->...`). The engine walks the graph; the app sends one question and gets one answer.

More words you'll see:
- **Subject set:** a subject can be "everyone who has relation R on object O", written `user:carol#delegate`. This repo uses it to let an agent borrow the rights of the user who granted it (1.6).
- **Wildcard:** `user:*` means "any user". `role:clerk#order_view@user:*` says the role grants the permission to whoever holds the role.
- **Caveat (SpiceDB) / condition (OpenFGA):** a relationship that only counts when an expression is true, evaluated with the check's context. The refund limit is `amount <= limit`: the role stores `limit`, the request sends `amount`.
- **Expiring relationship:** a relationship with an end time (agent grants, break-glass). SpiceDB deletes them itself; OpenFGA uses a time condition.
- **Consistency token (ZedToken in SpiceDB):** the engine is a separate database. After the app writes a relationship, a check might still read an older snapshot. The write returns a token; checks can ask "at least as fresh as this token". That's **read-your-writes**.

The cost of Zanzibar: **the engine holds a copy of authorization data**, so every change in the app (role edited, member removed, app uninstalled) has to be copied into it. That copying is the hardest part of this spike (1.7).

### 1.5 Attributes and policies: Cerbos

**Cerbos** works the other way. It stores no data, only **policy files**: rules written in YAML with conditions in **CEL** (a small expression language). On every check the app sends everything the rule needs as **attributes**:

```
principal: { id: carol, roles: [user], attr: { access: { stores: { s1: { perms: [order.view, order.refund], refundLimits: [5000] } } } } }
resource:  { kind: store, id: s1, attr: { merchantId: m1, status: active, amountCents: 3000 } }
action:    order.refund
```

and a rule like `"order.refund" in V.granted && V.refundOk` decides. This is **attribute-based access control (ABAC)**.

Because Cerbos stores nothing, **the app has to look up those attributes on every check**. The code that does that is the **PIP**: here `modules/access.ts`, which reads Carol's role assignments and flattens them into "permissions per store". Benefits: nothing to copy, and edits apply instantly. Cost: queries on every check, and every new kind of relationship means more PIP code. The engines page of `docs/review.html` has a worked example of where that breaks down.

### 1.6 The kinds of caller in this spike

A **principal** is whoever is calling. The spike has five **kinds**, and many rules depend on the kind:

| kind | who | gets permissions from | logs in with |
|---|---|---|---|
| `platform` | platform staff (`platform_admin`, `support`) | platform roles; merchant data only via **break-glass** | user login |
| `user` | a merchant's staff (owner, admin, developer, staff, custom roles) | **role assignments** at merchant or store scope | user login |
| `customer` | a shopper | nothing in the engine: "my orders" is plain SQL (`customer_id = me`) | user login |
| `app` | a third-party app (think Shopify app) | the **scopes** granted when a merchant **installs** it on a store | client credentials |
| `agent` | an AI agent a merchant user registered | an **agent grant**: a list of permissions at one store, with an expiry, limited to what the granting user still holds | client credentials |

The special grants, explained:
- **Install (apps):** the merchant installs app X on store s1 with scopes `[order.view, product.view]`. The app can do exactly that, at that store. Some permissions are never for apps (`role.manage`, `member.manage`, `agent.grant`, `app.install`, `app.uninstall`).
- **Agent grant:** Carol lets her agent read orders at s1 for an hour. The agent's effective rights = (the grant's list) ∩ (what Carol holds right now). If Carol loses `order.view`, the agent does too, immediately. In Zanzibar this is the `user#delegate` subject set; in Cerbos it's the granter's access sent as an attribute.
- **Break-glass:** support staff can't see merchant data by default. To investigate, they open a **break-glass**: read-only, one merchant, expires (minutes), and every request under it is written to an **audit** log.
- **Suspension:** the platform suspends a merchant; all its users, apps and agents are denied (`403 merchant_suspended`) until reinstated. Modelled as one exclusion (`- suspended`) in Zanzibar, one deny rule in Cerbos.

"Grant kind", "install", "assignment" are all ways a principal comes to hold a permission somewhere. The spec (`spec/SPEC.md` §2–§7) is the full rulebook.

### 1.7 Three checks, and checking twice

Every request passes three different checks, in this order:

1. **Credential / kind check:** can this kind of caller *ever* do this? (A customer can never refund; an app can never manage roles.) Cheap, done in the app before the engine.
2. **Relationship check:** is this caller connected to this resource with this permission? (The engine.)
3. **Condition check:** do the attributes allow it? (Refund amount ≤ limit, grant not expired.) In the engine as a caveat/condition/CEL rule.

**Tenant isolation twice:** a **tenant** is a merchant. Every SQL query is scoped to the caller's merchant, *and* the engine checks too. A bug in one layer can't leak another merchant's data on its own.

### 1.8 Keeping the engine in sync: the outbox

With SpiceDB or OpenFGA, the app's database is the **source of truth**, and the engine holds a copy. The naive way, "write to the DB, then call the engine", breaks when the second call fails: the DB says Carol's role is gone, the engine still lets her in. That's a **dual write**.

The fix is the **transactional outbox**: in the same database transaction as the change, insert an **event** row ("role clerk changed") into an `outbox` table. Either both commit or neither does. A **relay** reads pending events and applies them to the engine, retrying until it works. Rules the spike learned the hard way (each one was a real bug):
- retry temporary failures forever, in order; only set aside errors that can never succeed;
- decide carefully which errors are "never" (three stacks got this wrong once);
- put a deadline on every engine call;
- know what you return if the sync fails after the commit.

Cerbos needs none of this, because it stores nothing.

---

## Part 2: the repo, folder by folder

### 2.1 Six stacks, one spec, one test suite

| stack | app code | identity | engine | port |
|---|---|---|---|---|
| a | `go/` | Zitadel | SpiceDB | 8081 |
| b | `go/` (same code as a) | Ory Kratos + Hydra | OpenFGA | 8082 |
| c | `ts/` | Better Auth | Cerbos | 8083 |
| d | `ts-org/` | Better Auth + organization plugin | Cerbos | 8086 |
| e | `ts-org/` (same code as d) | Better Auth + organization plugin | SpiceDB | 8087 |
| a2 | `go/` (same code as a) | Zitadel, one organization per merchant | SpiceDB | 8088 |

Round 1 (a, b, c) compares engines. Round 2 (d, e, a2, spec §15) tests letting the IdP own tenancy.

### 2.2 The tree

```
spec/SPEC.md               the contract every stack implements. §1 patterns, §2 principals, §3 roles,
                           §4 permission catalog, §5 apps, §6 agents, §7 staff, §9 API, §15 round 2
conformance/               the black-box test suite (TypeScript, vitest): talks HTTP only
  tests/*.test.ts          one file per area: custom-roles, guardrails, agents, apps, tenant-isolation…
  src/world.ts             helpers that build a test world (merchant, store, member with role…)
  stacks/<stack>.ts        login driver per stack: how to get a token from that IdP, headless
  tour/tour.tour.ts        `pnpm tour`: a narrated run of every case, readable output
go/                        Go app (stacks a, b, a2)
  cmd/server/main.go       composition root: picks IdP and engine from env (IDP=, AUTHZ=), wires everything
  cmd/bootstrap/main.go    one-shot setup: migrations, engine schema, IdP clients
  internal/perm/           THE PERMISSION CATALOG (pure data): actions, scopes, kinds, system roles
  internal/core/           the kernel: executor (the PEP), registry, can() prechecks, guardrails, principal
  internal/authz/          the authz PORT: AuthZEN request/decision types, Authorizer, RelationSync, events
  internal/identity/       the identity PORT: verify a token, create users and clients
  internal/outbox/         the relay: outbox rows → engine (and → Zitadel in a2)
  internal/db/             Postgres pool + SQL migrations
  internal/modules/        business modules: platform, merchants, roles, stores, catalog, orders,
                           payments, delivery, apps, agents, me (no engine or IdP code in here)
  internal/adapters/
    spicedb/               schema.zed (GENERATED from perm), schema.go (the generator), spicedb.go
                           (checks + sync), validation.yaml (engine-level tests)
    openfga/               model.fga (generated), model.go, openfga.go, model.fga.yaml (tests)
    zitadel/               zitadel.go (token check, users, clients), orgs.go (a2: org per merchant)
    ory/                   ory.go (Kratos + Hydra)
ts/                        TypeScript app (stack c)
  src/main.ts              composition root
  src/kernel/              catalog.ts (permission catalog), action.ts (defineAction), executor.ts (PEP),
                           authz.ts (the AuthZEN port), principal.ts
  src/modules/             business modules; access.ts = the PIP (roles → attributes for Cerbos);
                           guardrails.ts (no escalation); lookup.ts (tenant-scoped SQL lookups)
  src/adapters/            cerbos.ts (PDP adapter), better-auth.ts (identity)
  drizzle/                 SQL migrations
ts-org/                    TypeScript app (stacks d, e): ts/ plus
  src/kernel/tenancy.ts    the tenancy PORT (organizations, members, invitations) backed by Better Auth
  src/adapters/spicedb/    stack e's engine adapter: authorizer.ts, sync.ts, schema.ts (generated schema)
  src/outbox/relay.ts      stack e's relay
stacks/<stack>/            compose file per stack + IdP/engine config; Cerbos policies in stacks/c|d/cerbos/policies
results/                   per-stack builder reports, reviews, comparison.md, comparison-round2.md
docs/                      review.html (the review report), patterns.md, this guide
```

### 2.3 The rule of the codebase: ports and adapters

The business modules never import an engine or an IdP. They call two **ports** (interfaces):

- **authz port**: `can()` in AuthZEN shape (`go/internal/authz/authz.go`, `ts/src/kernel/authz.ts`), plus `RelationSync` (apply an outbox event to the engine).
- **identity port**: verify a token, create users and OAuth clients (`go/internal/identity/identity.go`, `ts*/src/adapters/better-auth.ts`).

**Adapters** implement the ports for one product (`go/internal/adapters/*`, `ts*/src/adapters/*`). The **composition root** (`main.go`, `main.ts`) picks the adapters. That's why going from stack a to stack b changed zero module lines: new adapters, one new `case` in `main.go`.

---

## Part 3: one request through the code

**`POST /api/orders/o1/refund {amountCents: 5000}`**, sent by Carol, a "Refund clerk" at store s1 with a $50 limit.

### 3.1 Go (stacks a, b, a2)

1. **Route → op.** `go/internal/modules/orders/orders.go`, `Ops()`: the line with `Action: "order.refund"` binds the route to the catalog action, a **target** resolver (`orderTarget`: which store/merchant is this order in), a **context** function (`refundContext`: puts `amountCents` into the check), and `Run` (the business logic). The registry (`core/registry.go`) refuses any action that isn't in the catalog.
2. **Authenticate.** `core/executor.go`, `run()` → `Authn.Authenticate` (`core/principal.go`): the identity adapter verifies the token (`adapters/zitadel/zitadel.go` or `ory/ory.go`, `Verify`), then the app looks up the principal row in its own DB: Carol, kind `user`, merchant m1. Membership comes from the DB, never from the token.
3. **Open the transaction, resolve the target.** `orderTarget` reads the order in SQL inside the request's transaction: store s1, merchant m1. Unknown order → 404.
4. **Prechecks, then the engine.** `Executor.Can` → `precheck`: the kind check (`perm.Action.AllowsKind`), the scope check, the tenant check (Carol's merchant must equal the order's: otherwise 404), the app install check (apps only), the suspension check (SQL). Only then `Authz.Evaluate` → the engine adapter:
   - SpiceDB (`adapters/spicedb/spicedb.go`, `Evaluate`): `CheckPermission store:s1#order_refund@user:carol` with context `{amount: 5000}`.
   - OpenFGA (`adapters/openfga/openfga.go`, `Evaluate`): `Check` with `{amount, current_time}`.
5. **Run.** `orders.refund`: business rules (order must be paid; refunds can't exceed the captured amount → 409). Writes in the same transaction.
6. **Commit, then drain.** If the request emitted outbox events (a refund doesn't; a role edit does), the executor drains them to the engine before answering (`outbox/relay.go`).
7. **Answer** `200` with the order, or `403`/`404` from the checks.

### 3.2 TypeScript (stacks c, d, e)

1. **Action.** `ts/src/modules/orders.ts`, the `refund` action (`defineAction`): zod `input`, an `authorize()` that returns the check `{action: 'order.refund', resource: store s1, context: {amountCents}}`, and `run()`.
2. **Authenticate.** `ts/src/adapters/better-auth.ts`, `authenticate`: session lookup (users) or JWT check (apps/agents); `modules/principals.ts` maps it to a principal.
3. **Executor.** `ts/src/kernel/executor.ts`, `execute`: kind check (`def.kinds`), input validation (400), `authorize()` (SQL lookups scoped to the merchant: `modules/lookup.ts`), then `can()` for each check, *before* the transaction opens.
4. **The engine.**
   - Cerbos (c, d): `adapters/cerbos.ts` asks the PIP (`modules/access.ts`) for Carol's access, then `CheckResources`; the policy `stacks/c/cerbos/policies/store.yaml`, rule `order_refund`, decides.
   - SpiceDB (e): `ts-org/src/adapters/spicedb/authorizer.ts`, the same `CheckPermission` as Go.
5. **Run + outbox in one transaction**, then (e only) the relay `ts-org/src/outbox/relay.ts` applies events via `adapters/spicedb/sync.ts`.

### 3.3 A role edit (where the engines really differ)

`PATCH /api/merchants/m1/roles/clerk {permissions: [order.view]}`:
- **Guardrail first:** the caller must hold every permission of the role, old and new (`core/guard.go` `HoldsAll`; `ts/src/modules/guardrails.ts`). It's just a batch `can()`.
- **SpiceDB/OpenFGA:** the roles module updates the row and emits `role.upserted` in the same transaction. The relay rewrites `role:clerk`'s relationships (`spicedb.go` `syncRole`, `openfga.go` `syncRole`). The next check sees it thanks to the consistency token.
- **Cerbos:** the row update is all there is. The next check's PIP load reads the new permissions.

---

## Part 4: the same rule in three engines

"May this caller refund at this store?" Read these side by side:

| engine | file | look for |
|---|---|---|
| SpiceDB | `go/internal/adapters/spicedb/schema.zed` | `definition store`, `permission order_refund` (and `caveat refund_limit` at the top) |
| OpenFGA | `go/internal/adapters/openfga/model.fga` | `type store`, `define order_refund`, `condition refund_limit` at the bottom |
| Cerbos | `stacks/c/cerbos/policies/store.yaml` | `variables` (`userPerms`, `agentPerms`, `refundOk`), then the rule named `order_refund` |

And the same *fact* ("Carol is a clerk at s1, limit $10") in each engine's own test file:
- `go/internal/adapters/spicedb/validation.yaml` (relationships, then `assertions`)
- `go/internal/adapters/openfga/model.fga.yaml` (tuples, then `tests`)
- `stacks/c/cerbos/policies/tests/store_test.yaml` (principals with attributes, then expected results)

The two Zanzibar files are **generated** from the Go catalog (`internal/perm/perm.go`) by `schema.go` / `model.go`; a golden test fails if they drift. The Cerbos YAML is hand-written; `ts/src/kernel/policy-sync.test.ts` fails if it drifts from the TS catalog.

Where each concept lives:

| concept | Go | TS | engine side |
|---|---|---|---|
| permission catalog | `internal/perm/perm.go` | `src/kernel/catalog.ts` | generated schema/model; Cerbos rules |
| `can()` / AuthZEN port | `internal/authz/authz.go`, `core/executor.go` (`Can`, `precheck`) | `src/kernel/authz.ts`, `executor.ts` (`bindCan`) | adapters |
| custom roles + assignments | `modules/roles/roles.go` | `src/modules/roles.ts` | `role`, `role_binding` (Zanzibar); PIP flattening (Cerbos) |
| guardrails | `core/guard.go`, `modules/roles` | `src/modules/guardrails.ts` | a batch `can()` |
| refund limit | `orders.go` `refundContext` | `orders.ts` `authorize` | caveat / condition / CEL `refundOk` |
| apps (installs) | `modules/apps/apps.go`, precheck in `executor.go` | `src/modules/apps.ts`, `appGate` in `executor.ts` | `app_install` (Zanzibar); `installs` attribute (Cerbos) |
| agents (grants) | `modules/agents/agents.go` | `src/modules/agents.ts` | `agent_grant` + `user#delegate`; `grants` attribute |
| break-glass + audit | `modules/platform/platform.go`, `auditBreakGlass` in `executor.go` | `src/modules/platform.ts`, executor | `break_glass_viewer` (expiring); `breakGlass` attribute |
| suspension | `precheck` in `executor.go` | Cerbos deny rule `merchant_suspended` | `- suspended` exclusion |
| tenant isolation in SQL | `precheck`, `modules/scope` | `src/modules/lookup.ts` | engine checks tenancy again |
| outbox + relay | `core/executor.go` `Emit`, `internal/outbox/relay.go` | `ts-org/src/outbox/relay.ts` (e) | `RelationSync.Apply` in each adapter |
| identity | `internal/identity` + `adapters/zitadel|ory` | `src/adapters/better-auth.ts` | n/a |
| tenancy in the IdP (round 2) | `adapters/zitadel/orgs.go` | `ts-org/src/kernel/tenancy.ts` + `better-auth.ts` | n/a |

---

## Part 5: try it

1. **Watch it work.** Start a stack and run the narrated tour (README §2): `cd conformance && STACK=c HOST=<docker host> pnpm tour`. Each printed request is one rule from Part 1.
2. **Read a test, then the code behind it.** Open `conformance/tests/custom-roles.test.ts`, pick "removing a permission takes effect on the very next request", then follow it through Part 3.3 in Go or TS.
3. **Add a permission** (e.g. `order.export`): one line in `go/internal/perm/perm.go`, regenerate (`go test ./internal/adapters/spicedb -update`, same for openfga), and see `schema.zed` change; in TS, one line in `catalog.ts`, and `policy-sync.test.ts` tells you which Cerbos rule to add.
4. **Break a rule on purpose.** Remove the tenant check in `precheck` and run `tests/tenant-isolation.test.ts`: the engine still blocks most of it, which is "isolation twice" working.

Further reading: `docs/review.html` (the review report: engines compared, a custom role end to end, where Cerbos struggles), `docs/patterns.md` (the seven patterns and how they held), `results/comparison.md` and `results/comparison-round2.md`.

---

## Glossary

| term | meaning |
|---|---|
| **authentication (authn)** | proving who the caller is; ends with a token |
| **authorization (authz)** | deciding whether the caller may do an action on a resource |
| **IdP** | identity provider: runs logins and issues tokens (Zitadel, Ory, Better Auth) |
| **token** | signed string the caller sends with each request; a **JWT** is a self-contained one the app can verify with the IdP's public keys (**JWKS**) |
| **client credentials** | how machines (apps, agents) log in: a client id + secret exchanged for a token |
| **principal / subject** | the caller; its **kind** is platform, user, customer, app or agent |
| **action / permission** | a named capability like `order.refund`; the full list is the **permission catalog** |
| **resource** | what the action is on; in this spike checks run against a platform, merchant or store |
| **tenant** | a merchant; data never crosses tenants |
| **scope** | where a role applies: the whole merchant or one store (also: an app's granted permissions, its "scopes") |
| **role** | a named set of permissions; **system roles** (owner, admin, developer, staff) are fixed, **custom roles** are merchant-defined |
| **assignment / role binding** | "user X has role R at scope S" |
| **guardrail / no escalation** | you can only grant what you hold, with a limit no higher than yours |
| **install** | an app added to a store with chosen scopes |
| **agent grant** | temporary, expiring permissions for an agent, capped by its granting user's current rights |
| **break-glass** | expiring, read-only, audited access for support staff to one merchant |
| **AuthZEN** | the OpenID standard shape of a check: subject, action, resource, context → decision |
| **PEP / PDP / PIP** | enforcement point (asks: the executor) / decision point (decides: the engine) / information point (supplies facts: the PIP) |
| **RBAC / ReBAC / ABAC** | role-based / relationship-based (Zanzibar) / attribute-based (Cerbos) access control |
| **Zanzibar** | Google's relationship-based authz system; SpiceDB and OpenFGA follow it |
| **relationship / tuple** | one fact `object#relation@subject` stored in a Zanzibar engine |
| **schema / model** | the Zanzibar type definitions and permission formulas (`schema.zed`, `model.fga`) |
| **arrow (`->`, `from`)** | follow a relation to another object and evaluate there (store → merchant) |
| **subject set** | a subject like `user:carol#delegate`: everyone with that relation |
| **wildcard (`user:*`)** | any subject of that type |
| **caveat / condition** | a relationship that counts only if an expression holds (refund amount ≤ limit, now < expiry) |
| **CEL** | the expression language in Cerbos rules (and SpiceDB caveats) |
| **policy (Cerbos)** | YAML rules per resource kind deciding allow/deny from attributes |
| **consistency / ZedToken / read-your-writes** | making a check see the writes that just happened |
| **outbox / relay** | events written in the same DB transaction as a change, then applied to the engine by a retrying worker |
| **dual write** | writing two systems without a shared transaction; one can fail and they diverge |
| **dead-letter** | setting aside an event that can never apply (only for truly permanent errors) |
| **port / adapter / composition root** | the interface modules use / its implementation for one product / the `main` that picks adapters |
