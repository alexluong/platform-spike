# Platform patterns

Distilled from an architecture brainstorm before the spike. Each pattern: the rule, why, when not, and the shape in code. Tested 2026-10-11 by this spike: one spec, three stacks (Go+Zitadel+SpiceDB, Go+Ory+OpenFGA, TS+Better Auth+Cerbos), all passing the same 362-test suite. Verdicts per pattern are under **Spike** below each; the full comparisons are [`results/comparison.md`](../results/comparison.md) and [`results/comparison-round2.md`](../results/comparison-round2.md).

## 1. Action = unit of capability

**Rule.** Every operation is an action with an id `<module>.<verb>` (`order.refund`, `role.manage`). A registry lists them with metadata (input schema, errors, `grantable`, scope). One executor runs every mutating action: authenticate → authorize → run → write outbox in the same transaction → audit. HTTP, MCP, CLI, agents and imports are thin adapters onto the registry.

**Why.** One shared vocabulary for product, code, permissions and agents. The permission catalog, the role editor, the MCP tool list and the API docs are all the registry viewed differently.

**When not.** Pure reads with no authorization beyond tenant scope can stay plain queries. Don't build a framework; keep it a small kernel (actions-pattern §16).

```ts
const refund = defineCommand({
  id: "order.refund", grantable: true, scope: "store",
  input: z.object({ orderId: z.string(), amountCents: z.number().int().positive() }),
  errors: ["order.not_paid", "order.over_refund"],
  resource: (i, tx) => tx.orders.scopeOf(i.orderId),          // → { type: "store", id }
  context: (i) => ({ amount: i.amountCents }),                 // for conditions (limits)
  run: async (i, { tx, emit }) => { /* rules, writes */ emit("order.refunded", {...}) },
})
```

Go shape: a module exposes `Register(r *Registry)` adding `Action{ID, Scope, Grantable, Run}` values; no `defineX` magic (actions-pattern §14).

**Spike: holds.** Every mutation went through one executor in all three stacks. Round 2 (e) added: the executor, not the engine, owns deny reasons and audit markers; d let Cerbos supply them and the SpiceDB adapter had to rebuild them. Watch: checks made inside an action's `run` (batch checks, lists) must still go through the executor's audit path (stack c missed break-glass audits there).

## 2. CRUD rows + events, outbox in the same transaction

**Rule.** Default storage is plain tables plus domain events written in the same transaction (an outbox table). Event sourcing is opt-in per module where history *is* the domain (ledger, folio). Anything outside the database (Kafka, K2, an authz engine, webhooks) gets events from the outbox, never by dual write.

**Why.** Atomicity without 2PC; CRUD stays simple for contributors; events exist for reactions and audit.

**Shape.** `tx.insert(...)` + `tx.outbox.append(event)` → commit → relay (drains the request's own rows before responding, background worker retries the rest) → idempotent consumers keyed by event id.

**Spike: bent; the rules below are now part of the pattern.** Both relationship-engine stacks nearly lost revocations: the relay gave up after 10 tries (a), and an engine 400 for a missing store was classed permanent (b). So:
- retry transient failures forever, in order; set aside only errors the adapter positively knows are permanent;
- don't report success for a revoke/uninstall whose sync failed (or document the window);
- state the single-writer assumption if the sync does read-then-write (OpenFGA did);
- read-your-writes must hold across instances (SpiceDB's ZedToken kept per process didn't);
- never take a second pooled DB connection while the request's transaction is open (stack c deadlocked its pool for good; stack d did it again inside a Better Auth hook);
- put a deadline on every engine call (stack e: one request hung 72 s with SpiceDB down);
- every state change emits an event, even when today's engine doesn't need one (stack d skipped break-glass because Cerbos reads the table);
- an external IdP that owns tenancy is another outbox consumer with all of these rules (round 2, a2); an in-process IdP sharing the DB can join the transaction instead (d).

## 3. One `can()`, AuthZEN-shaped

**Rule.** The executor asks one function: `can({subject, action, resource, context}) → {decision, reason?}` — the OpenID AuthZEN 1.0 request shape, used in-process. The engine behind it (hand-written, Cedar, Cerbos, OpenFGA, SpiceDB, a remote PDP) is an adapter. A batch form (`canMany`) serves UI menus, `GET /me/permissions` and agent tool lists.

**Why.** Swap engines without touching modules (the same insulation OIDC gives identity). The action id is AuthZEN's `action.name`, so the registry is the policy's vocabulary.

**When not.** Never skip the seam; it costs ~20 lines. Do skip a remote PDP until several services share decisions.

Levels: (0) in-process function with `roleActions` → (1) policy engine in-process → (2) PDP over HTTP (`/access/v1/evaluation`). 

**Spike: holds.** Swapping Zitadel+SpiceDB for Ory+OpenFGA changed zero module, kernel, port or migration lines (new adapters + one switch case per `main`). What the interface does not carry: error classification, single-writer assumptions, deploy procedure (OpenFGA needs every instance restarted after a model change), and ops exposure (admin ports).

## 4. Custom roles are data

**Rule.** The platform owns the **permission catalog** (= grantable registry actions) and the **policy** (how bindings, scopes and inheritance resolve). Tenants own **roles** (named subsets of the catalog, optional limits) and **bindings** (user × role × scope), as data. Tenants never write policy.

**Guardrails** (enforced in the action, through `can`): no escalation (you can only grant what you hold, at that scope, with limits ≤ yours); system roles fixed; last owner can't be removed; new catalog permissions are denied to custom roles by default.

**Shape.** App DB is the source of truth (`roles`, `role_permissions`, `role_assignments`); a relationship engine gets a copy through the outbox (SpiceDB/OpenFGA role-binding pattern); a stateless engine (Cerbos) gets resolved permissions as attributes. Role editor and "effective permissions" views are generated from the registry.

**Spike: holds.** SpiceDB and OpenFGA used the same role-binding pattern; Cerbos resolved roles in app code and sent permissions as attributes (no sync, instant edits, 3 queries per check). Guardrails the spike added: only an agent's registrant can grant it; removing a role needs the power to assign it; agents should get the apps' blocked list (proposal, pending).

## 5. Three checks, all must pass

| check | question | where |
|---|---|---|
| credential / scope | may this token do this kind of thing? | token scopes (OIDC/OAuth), app install scopes |
| relationship | is this subject connected to this resource? | `can()` → engine |
| condition | do attributes allow it (limit, status, expiry)? | engine conditions/caveats, or domain rules |

"Needs approval" is not a deny; it's a domain outcome (approvals), kept out of the policy engine. Scopes attenuate, never grant: effective = the subject's rights ∩ the credential's scopes.

Delegated principals: an **app** is checked on its install scopes on that store; an **agent** acts for a user and gets the intersection of its grant and that user's current rights, with expiry.

**Spike: holds after fixes.** Token checks were loose in both Go stacks (ID tokens and other clients' tokens accepted on audience alone). Name the token checks explicitly: issuer, audience, expiry, alg allowlist, access token not ID token, allowed client.

## 6. Tenant isolation twice

**Rule.** Every query is scoped by tenant in SQL (ideally Postgres RLS), and the authz engine checks too. Buyers/end customers stay out of the engine: "my orders" is `WHERE customer_id = me`. Platform staff have no tenant data access by default; support uses expiring, read-only, audited break-glass grants.

**Spike: holds after fixes.** Apps were checked only in the engine in stacks a and c; both now check the install in SQL too.

## 7. Composition root by hand, plus a testkit

**Rule.** One root per entry point (`main`, test, worker) wires config → adapters → modules. Inject only side effects and second implementations; interfaces are defined by the consumer; no container, no ambient lookup. A testkit builds the same graph with a real database (in-memory SQLite / test Postgres), a fixed clock and counting ids; test setup goes through commands only.

**Why.** Readable by people and agents; swapping Zitadel+SpiceDB for Ory+OpenFGA should be a different root, not different modules (the spike measures exactly this).

**Spike: holds.** The a → b swap was a different root, as intended.

## Related

- [`spec/SPEC.md`](../spec/SPEC.md) §1: the patterns as the spike's rules.
- [`results/`](../results/): per-stack reports, reviews and both comparisons.
- [`review.html`](review.html): the review report (open in a browser).
