# platform-spike

A mini Shopify, built on six identity + authorization stacks, all checked by one black-box test suite. It exists to compare the stacks and test a set of architecture patterns before a real platform project. It is not a shop: no UI, fake payments, no email.

Read this top to bottom: what was built and why, then a guided tour you run yourself, then the reference.

**Short on time?** Download [`docs/review.html`](docs/review.html) and open it in a browser: the review report (how it works, SpiceDB vs OpenFGA vs Cerbos with a custom role end to end, each stack's code and feel, quality, round 2, open decisions). The patterns being tested: [`docs/patterns.md`](docs/patterns.md). **New to authorization?** Start with [`docs/GUIDE.md`](docs/GUIDE.md): the ideas from zero (roles, scopes, Zanzibar relationships, policies, grants), then where each one lives in this code.

## 1. What was built, and why

**The question.** For a multi-tenant platform where merchants define their own roles, install third-party apps and delegate to AI agents: which identity and authorization stack holds up, and do our architecture patterns survive swapping one for another?

**The plan.**
1. **Spec first** ([`spec/SPEC.md`](spec/SPEC.md)): personas, a permission catalog, system and custom roles with guardrails, the HTTP API, and seven patterns every stack must follow.
2. **One test suite for all stacks** ([`conformance/`](conformance/)): 362 black-box HTTP tests. Each stack only supplies a login driver that runs its real login flow without a browser.
3. **Three builds.** Stack `b` is the same Go code as `a` with new adapters only, so the a → b diff shows how swappable the engines really are.
4. **A review per stack**, looking for what the tests miss; fixes plus new regression tests.
5. **Align and compare**: spec v2, identical behaviour across stacks, [`results/comparison.md`](results/comparison.md).

**The three stacks.**

| stack | app | identity (who are you) | authorization (may you) | port |
|---|---|---|---|---|
| `a` | Go | Zitadel, an OIDC server with built-in tenancy | SpiceDB, a relationship engine (Google Zanzibar style) | 8081 |
| `b` | Go, **same code as `a`** | Ory Kratos + Hydra (OIDC) | OpenFGA, another Zanzibar engine | 8082 |
| `c` | TypeScript (Hono) | Better Auth, a library inside the app | Cerbos, stateless policies in YAML | 8083 |

The difference that matters most: in `a` and `b` the authorization engine keeps its own copy of who-relates-to-what (roles, installs, grants), synced from the app's database through an outbox. In `c` nothing is copied; the app looks up the caller's roles on every check and sends them to Cerbos.

**Result in one paragraph.** All three pass all 362 tests. Swapping `a` → `b` changed no business code. The weakest pattern was the outbox: both Go stacks nearly lost revocations through their failure handling. SpiceDB beat OpenFGA for this design; Cerbos is the lightest for simple tenancy. Details in §4.

## 2. Follow along: the tour

The tour plays the whole story against a running stack, printing every request, who sent it and what came back. It takes about 10 seconds.

**Start a stack** (skip if it's already up). You need Docker, local or remote, and [`mise`](https://mise.jdx.dev):

```sh
mise install
# export DOCKER_HOST=ssh://<host>      # optional: run the containers on another machine
docker compose -p ps-c --profile c up -d --build --wait     # stack c: 3 containers, the quickest
```

**Run the tour:**

```sh
cd conformance && pnpm install
STACK=c HOST=<name of the Docker host, or localhost> pnpm tour
```

Swap `c` for `a` or `b` and it tells the same story on another stack. Each line looks like this:

```
  clerk      POST   /api/orders/o_JBg3.../refund {"amountCents":8000}
             ← 403 {"error":{"code":"forbidden"}}
```

That's who sent it, the request, and the answer. Green means allowed, cyan a refusal the tour expects, red a surprise (the tour stops there).

What each chapter shows, and where to look in the code:

### Chapter 1: Platform staff create a merchant
The platform admin creates a merchant and names its owner; the owner opens a store. Support staff can list merchants but not create them. **Neither can read the merchant's orders**: platform staff get no tenant data by default.
Code: `go/internal/modules/platform`, `ts/src/modules/platform.ts`.

### Chapter 2: System roles
Every merchant gets four fixed roles: owner, admin, developer, staff. A staff member can add a product but can't create roles. The role catalog is the list of **actions** (`product.create`, `order.refund`, …); a role is a set of them.
Code: the catalog in `go/internal/perm/perm.go` and `ts/src/kernel/catalog.ts` (actions register in `go/internal/core/registry.go`); every request runs through one executor (`go/internal/core/executor.go`, `ts/src/kernel/executor.ts`).

### Chapter 3: Orders, payments, delivery
A customer orders; the owner captures payment and ships. A shipment can't move backwards (409). A customer trying to capture gets 403, not 409: **permission is checked before business rules**, so a caller without rights learns nothing about the order's state. Customers are never put in the authorization engine; "my orders" is a plain SQL filter.
Code: `go/internal/modules/{orders,payments,delivery}`, `ts/src/modules/{orders,payments,delivery}.ts`.

### Chapter 4: Custom roles are data
The owner builds "Refund clerk" (view orders, refund up to $50) and assigns it at one store. The clerk refunds $30 (allowed) and $80 (over the limit, 403). The owner then removes refunds from the role, and **the clerk loses it on the very next request**, without logging in again. Roles live in the app's database; tenants edit data, never policy.
How each engine sees it: SpiceDB schema `go/internal/adapters/spicedb/schema.zed`, OpenFGA model `go/internal/adapters/openfga/model.fga`, Cerbos policies `stacks/c/cerbos/policies/` (the app resolves roles itself: `ts/src/modules/access.ts`).

### Chapter 5: Guardrails, no escalation
A manager may manage roles but holds only "view orders". Creating a role with view orders works; adding refunds is refused (403 `escalation`): **you can only hand out what you hold**, at that scope, with a limit no higher than yours.
Code: `go/internal/modules/roles`, `ts/src/modules/guardrails.ts`.

### Chapter 6: Apps
The platform registers an app that asks for "view orders" and "create products"; the owner installs it with only "view orders". The app can read orders and can't create products. Uninstalling cuts it off immediately. Apps can never manage roles, members, agents or other apps.
Code: `go/internal/modules/apps`, `ts/src/modules/apps.ts`.

### Chapter 7: AI agents
A team lead registers an agent and grants it "view orders" for 5 seconds. The agent reads orders, can't refund (not granted), and after 5 seconds is cut off. An agent **never exceeds the user who granted it**: remove that user's role and the agent stops too. Expiry needs no cleanup job (SpiceDB expiring relationships, an OpenFGA time condition, a Cerbos time comparison).
Code: `go/internal/modules/agents`, `ts/src/modules/agents.ts`.

### Chapter 8: Break-glass
Support is refused on the merchant's orders, opens a 5-minute read-only break-glass grant, can now read but still not write, and every read lands in the audit log the admin can see.

### Chapter 9: Tenant isolation
Another merchant's owner tries this merchant's store, order and roles. All refused, as 404 so they can't even tell those exist. Isolation is enforced twice: in SQL and in the authorization engine.

### Chapter 10: Suspension
The platform suspends the merchant; its owner is locked out with `merchant_suspended`. Reinstating restores access.

**Where the swap shows.** Run the tour on `a`, then on `b`: the same story, and the Go code between them differs only in `go/internal/adapters/` and one line per adapter in `go/cmd/*/main.go`. Business code talks to two small interfaces: `go/internal/identity/identity.go` (who is this token) and `go/internal/authz/authz.go` (may they: an [OpenID AuthZEN](https://openid.net/specs/authorization-api-1_0.html)-shaped `Evaluate`). Changes reach SpiceDB or OpenFGA through the outbox (`go/internal/outbox/relay.go`), written in the same database transaction as the change.

## 3. Cases covered by the test suite

The tour shows one path through each case; the suite covers each rule from both sides. One file per case in `conformance/tests/`:

| case | what the tests pin down | file |
|---|---|---|
| Auth | no or bad token → 401; `/api/me` for every kind of caller | `auth.test.ts` |
| Platform staff | admin vs support; suspension blocks users, apps, agents and customers | `platform.test.ts` |
| Break-glass | read-only, audited, ends at expiry (the slow test: 65 s) | `break-glass.test.ts` |
| System roles | each role's exact permission set over the whole catalog; owner rules, last owner | `system-roles.test.ts` |
| Custom roles | grantable only, merchant vs store scope, union across roles, edits/deletes apply next request, refund limits (highest wins) | `custom-roles.test.ts` |
| Guardrails | no escalation on create, edit, assign, unassign; limits; store-scoped managers stay in their store | `guardrails.test.ts` |
| Apps | registration limits, install ⊆ requested ∩ installer's, exact scopes, other stores denied, uninstall | `apps.test.ts` |
| Agents | registrant-only grants, subset of own rights, expiry, revoke, granting user loses role → agent stops | `agents.test.ts` |
| Tenant isolation | merchant A's owner, app and agent against every endpoint of merchant B; customers see only their orders | `tenant-isolation.test.ts` |
| Orders, payments, delivery | lifecycle, cancel rules, partial refunds, forward-only shipments, 403 before 409, input bounds | `orders.test.ts` |
| Effective permissions | `/api/me/permissions` returns exactly what the caller may do at a store or merchant | `permissions.test.ts` |

Run the whole suite: `STACK=a HOST=<host> pnpm test` in `conformance/` (`SKIP_SLOW=1` skips the 65 s test).

## 4. What came out

From [`results/comparison.md`](results/comparison.md):

| | a: Go + Zitadel + SpiceDB | b: Go + Ory + OpenFGA | c: TS + Better Auth + Cerbos |
|---|---|---|---|
| Tests | 362/362 | 362/362 | 362/362 |
| Containers | 6 | 9 | 3 |
| Memory idle | ~300 MB | ~155 MB | ~113 MB |
| Permission data copied into the engine | yes, via outbox | yes, via outbox | none |

- **Engine swap:** a → b changed no business code. What the interfaces don't capture: which engine errors count as permanent (decides which sync events get dropped), the single-writer assumption in OpenFGA syncing, deploy steps (OpenFGA needs every instance restarted after a model change), and ops exposure (admin ports).
- **SpiceDB vs OpenFGA:** same semantics; SpiceDB needed less sync code and has fewer failure windows. OpenFGA handles read-your-writes across several app instances more simply.
- **Cerbos:** least to run and nothing to sync; custom roles work by resolving them in the app, and its policies need one rule per permission.
- **Reviews found real bugs the tests missed**, now fixed with regression tests: an ex-member keeping access through an agent, a connection-pool deadlock that hung the app, ID tokens accepted as access tokens, an order-total overflow, and an outbox that gave up on revocations.
- **Open proposals** (not enforced yet) are in spec §14, e.g. stopping agents from creating roles or installs that outlive their grant.

Per stack: `results/{a,b,c}.md`; reviews: `results/review-{a,b,c}.md`.

### Round 2: the identity provider owns tenancy (spec §15)

Stacks `d` (TS + Better Auth organization plugin + Cerbos, 8086), `e` (`d` with SpiceDB, 8087) and `a2` (Go + one Zitadel organization per merchant + SpiceDB, 8088), plus 30 opt-in `idp-tenancy` tests (invitations, suspension at login). Run them like the others: `STACK=d|e|a2`. From [`results/comparison-round2.md`](results/comparison-round2.md):

- **No, IdP-owned tenancy didn't make the spec cleaner.** Neither IdP could carry custom roles, and the app still needs membership in SQL. Better Auth's gain (one transaction for identity and app data) comes from being in-process and sharing the DB, not from the plugin; Zitadel added ~1000 lines and a second sync, removing none.
- **Zitadel organizations are worth it only for per-merchant SSO or delegated user admin.**
- **The TS engine swap (d → e) changed one module line**, but showed d's executor had let Cerbos decide deny reasons and audit markers. e's SpiceDB relay is the most correct one built (consistency token in the DB, call deadlines).

## 5. Reference

**Running.** Nothing is bind-mounted, so a remote Docker host works like a local one.

```sh
docker compose -p ps-a --profile a up -d --build --wait     # or b, c, d, e, a2 (-p ps-<stack>)
docker compose -p ps-a --profile a down -v                  # stop and wipe
```

- `HOST` must be a name this machine resolves to the Docker host (an ssh alias won't do). Some defaults in code and compose name the original lab host; set `HOST`, `STACK_A_HOST` / `STACK_A2_HOST` / `STACK_B_HOST` for yours.
- Stack `a`: Zitadel issues tokens for the exact host clients use (`STACK_A_HOST`); changing it needs `down -v`.
- **Test mode is on** in every compose file with a known secret (`/api/_test/users` creates any user, including platform admins), and stack `b` publishes Hydra's unauthenticated admin API. Don't expose these ports beyond a trusted network (spec §14 P5).

**Layout.**

```
spec/SPEC.md   the contract (v3): rules, API, error codes, proposals (§14), round 2 (§15)
conformance/   test suite (tests/), the tour (tour/), login drivers per stack (stacks/),
               AMBIGUITIES.md (how the suite read spec v1)
go/            Go app for stacks a, b and a2; engine- and IdP-specific code only in go/internal/adapters/
ts/            TypeScript app for stack c
ts-org/        TypeScript app for stacks d and e (Better Auth organization plugin; Cerbos or SpiceDB)
stacks/<s>/    compose file, IdP and engine config, bootstrap; Cerbos policies for c
results/       per-stack results, reviews, comparison.md (round 1), comparison-round2.md
docs/          GUIDE.md (authz from zero + code map), review.html (the review report), patterns.md
```
